#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""NBE pellet furnace <-> Home Assistant MQTT bridge.

Single-process Python 3 successor to the PellMon + pellmonMQTT.py stack:
talks the NBE V7/V10/V13 UDP protocol directly (vendored from the
PellMon author's own py3 implementation) and exposes the furnace to
Home Assistant over MQTT with a fail-closed, validated control path.

- Publishes every controller item to ``pellmon/<item>`` (retained,
  topic-compatible with PellMon's nbecom naming: ``boiler-temp``,
  ``operating_data-boiler_temp``, ...).
- Announces entities via HA MQTT Discovery: sensors for everything,
  number/select/button controls ONLY for explicitly allowlisted items.
- Accepts commands ONLY on ``pellmon/set/<item>`` for allowlisted
  items, validated by validation.py (UTF-8 strict decode, tightest-of
  device/config range check, rate limits, retained-message rejection,
  no-op suppression).
- Publishes every command outcome to ``pellmon/set/<item>/result`` and,
  on rejection, republishes the authoritative current state.
- Emits one structured audit line per command.

The legacy unvalidated ``pellmon/settings/#`` subscription is
deliberately not reproduced.

Copyright (C) 2026 ha-pellmon contributors.
Lineage: pellmonMQTT.py and nbetest, Copyright (C) 2013 Anders Nylund.

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version. It is distributed WITHOUT ANY WARRANTY; see
the GNU General Public License for details.
"""

import json
import logging
import math
import os
import queue
import ssl
import sys
import threading
import time

import paho.mqtt.client as mqtt
import yaml

from nbe_gateway import NbeGateway
from validation import AllowedItem, CommandValidator, Outcome, RateLimiter, _tightest

LOG = logging.getLogger("pellmon-ha-bridge")
AUDIT = logging.getLogger("pellmon-ha-bridge.audit")


def load_config(path):
    cfg = {}
    if path and os.path.exists(path):
        if os.path.isdir(path):
            # Docker silently creates a DIRECTORY when a bind-mount source
            # file is missing — the classic compose footgun. Fail with a
            # message that names the fix.
            LOG.error(
                "%s is a directory. The compose bind-mount source file is "
                "missing — create bridge/bridge_config.yaml (see the "
                ".example) before starting.", path,
            )
            sys.exit(2)
        with open(path, "r") as fh:
            cfg = yaml.safe_load(fh) or {}

    m = cfg.setdefault("mqtt", {})
    # Secrets and connection details come from the environment first so
    # nothing sensitive needs to live in the config file.
    m["host"] = os.environ.get("MQTT_HOST", m.get("host", "localhost"))
    m["port"] = int(os.environ.get("MQTT_PORT", m.get("port", 1883)))
    m["username"] = os.environ.get("MQTT_USERNAME", m.get("username"))
    m["password"] = _env_secret("MQTT_PASSWORD", m.get("password"))
    m["tls"] = _env_bool("MQTT_TLS", m.get("tls", False))
    m["tls_ca"] = os.environ.get("MQTT_TLS_CA", m.get("tls_ca"))
    m["tls_cert"] = os.environ.get("MQTT_TLS_CERT", m.get("tls_cert"))
    m["tls_key"] = os.environ.get("MQTT_TLS_KEY", m.get("tls_key"))

    n = cfg.setdefault("nbe", {})
    n["serial"] = os.environ.get("NBE_SERIAL", n.get("serial"))
    n["password"] = _env_secret("NBE_PASSWORD", n.get("password"))
    # An empty NBE_ADDR (blank line copied from .env.example) must mean
    # "discover", not the dead-address "" that pins to INADDR_ANY.
    n["addr"] = (os.environ.get("NBE_ADDR") or n.get("addr")) or None
    n["allow_broadcast"] = _env_bool("NBE_ALLOW_BROADCAST", n.get("allow_broadcast", False))
    n["port"] = int(os.environ.get("NBE_PORT", n.get("port", 8483)))
    n["poll_interval_s"] = float(
        os.environ.get("POLL_INTERVAL", n.get("poll_interval_s", 10))
    )

    cfg["base_topic"] = os.environ.get("MQTT_BASE_TOPIC", cfg.get("base_topic", "pellmon"))
    cfg.setdefault("discovery_prefix", "homeassistant")
    cfg.setdefault("device_name", "NBE Pellet Furnace")
    cfg.setdefault("allowlist", {})
    rate = cfg.setdefault("rate_limit", {})
    rate.setdefault("max_writes", 10)
    rate.setdefault("window_s", 60)
    return cfg


def _env_secret(name, default):
    """Secret lookup: <NAME> env var, or <NAME>_FILE pointing at a file
    (docker secrets pattern), else the config-file value."""
    if os.environ.get(name):
        return os.environ[name]
    path = os.environ.get(name + "_FILE")
    if path:
        with open(path, "r") as fh:
            return fh.read().strip()
    return default


def _env_bool(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    return raw.strip().lower() in ("1", "true", "yes", "on")


def build_allowlist(cfg):
    """Coerce and validate the allowlist schema — fail fast at startup so
    a YAML typo (e.g. min: "fifty") cannot surface mid-command instead."""
    allowlist = {}
    for name, opts in (cfg.get("allowlist") or {}).items():
        opts = opts or {}
        try:
            lo = float(opts["min"]) if opts.get("min") is not None else None
            hi = float(opts["max"]) if opts.get("max") is not None else None
            interval = float(opts.get("min_interval_s", 2.0))
        except (TypeError, ValueError) as exc:
            LOG.error("allowlist entry %r has a non-numeric bound: %s", name, exc)
            sys.exit(2)
        options = opts.get("options")
        if options is not None and not isinstance(options, list):
            LOG.error("allowlist entry %r: options must be a list", name)
            sys.exit(2)
        press = opts.get("press_payload")
        allowlist[name] = AllowedItem(
            name=name,
            min=lo,
            max=hi,
            options=options,
            # Coerce a YAML scalar (e.g. `press_payload: 1`) to str so the
            # button is not permanently unpressable against a str payload.
            press_payload=str(press) if press is not None else None,
            min_interval_s=interval,
        )
    return allowlist


class Bridge:
    def __init__(self, cfg):
        self.cfg = cfg
        self.base = cfg["base_topic"]
        self.disc = cfg["discovery_prefix"]
        self.allowlist = build_allowlist(cfg)
        self.validator = CommandValidator(
            self.allowlist,
            RateLimiter(
                max_writes=int(cfg["rate_limit"]["max_writes"]),
                window_s=float(cfg["rate_limit"]["window_s"]),
            ),
        )
        self.availability_topic = "%s/bridge/availability" % self.base
        self._announced = threading.Event()
        # Debounce HA-triggered re-announces: a full announce is ~5 QoS-1
        # publishes per item (hundreds of messages), so an HA client that
        # loops `homeassistant/status`=online must not be amplified into a
        # publish storm on the network thread.
        self._announce_min_interval_s = 30.0
        self._last_announce = 0.0

        # Commands run on a dedicated worker so a slow furnace write
        # (up to ~5 s) never blocks the paho network thread. Bounded
        # queue: under a flood we drop-and-log rather than grow.
        self._commands = queue.Queue(maxsize=32)
        self._worker = threading.Thread(target=self._command_worker, daemon=True)

        self.gateway = NbeGateway(
            cfg["nbe"],
            on_online=self._controller_online,
            on_changed=self._controller_changed,
            on_offline=self._controller_offline,
            allowlist=self.allowlist.keys(),
        )

        self.mq = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id="pellmon-ha-bridge",
            clean_session=True,  # no persistent-session command redelivery
        )
        m = cfg["mqtt"]
        if m.get("username") and m.get("password"):
            self.mq.username_pw_set(m["username"], m.get("password"))
        else:
            LOG.warning("connecting to MQTT anonymously (no username/password)")
        if m.get("tls"):
            if m.get("tls_ca") and not os.path.isfile(m["tls_ca"]):
                LOG.error(
                    "MQTT_TLS_CA=%s is not a file — mount the CA cert (see "
                    "docker-compose.yml volumes) or fix the path.", m["tls_ca"],
                )
                sys.exit(2)
            # Certificate verification stays ON. There is deliberately no
            # "insecure" switch here.
            self.mq.tls_set(
                ca_certs=m.get("tls_ca"),
                certfile=m.get("tls_cert"),
                keyfile=m.get("tls_key"),
                cert_reqs=ssl.CERT_REQUIRED,
                tls_version=ssl.PROTOCOL_TLS_CLIENT,
            )
        # Bound memory during broker outages, but leave room for the online
        # announce burst: ~6 QoS 1 publishes per item (discovery config,
        # stale-component clears, state), i.e. thousands for a full-size
        # controller. _publish applies backpressure when this fills.
        self.mq.max_queued_messages_set(PUBLISH_QUEUE_MAX)
        self.mq.will_set(self.availability_topic, "offline", qos=1, retain=True)
        self.mq.on_connect = self._mqtt_connected
        self.mq.on_disconnect = self._mqtt_disconnected
        self.mq.on_subscribe = self._mqtt_subscribed
        self.mq.on_message = self._mqtt_message

    # ---------------- lifecycle ----------------

    def run(self):
        m = self.cfg["mqtt"]
        while True:
            try:
                self.mq.connect(m["host"], m["port"], keepalive=60)
                break
            except OSError as exc:
                LOG.warning(
                    "MQTT connect to %s:%s failed (%s), retrying",
                    m["host"], m["port"], exc,
                )
                time.sleep(5)
        self.mq.reconnect_delay_set(min_delay=1, max_delay=120)
        self._worker.start()
        self.gateway.start()
        self.mq.loop_forever(retry_first_connection=True)

    # ---------------- controller side ----------------

    def _controller_online(self, items, values):
        LOG.info("controller online; announcing %d items", len(items))
        self._announce_all(items, values)
        self._announced.set()

    def _controller_offline(self):
        LOG.warning("controller offline")
        self._publish(self.availability_topic, "offline", retain=True)

    def _controller_changed(self, changed):
        for item_id, value in changed.items():
            self._publish("%s/%s" % (self.base, item_id), value, retain=True)

    # ---------------- MQTT side ----------------

    def _mqtt_connected(self, client, userdata, flags, reason_code, properties=None):
        if reason_code.is_failure:
            LOG.error("MQTT connection refused: %s", reason_code)
            return
        LOG.info("connected to MQTT broker")
        client.subscribe("%s/status" % self.disc)
        for name in self.allowlist:
            client.subscribe("%s/set/%s" % (self.base, name), qos=1)
        if self._announced.is_set():
            self._announce_all(self.gateway.items, self.gateway.values)
        else:
            self._publish(self.availability_topic, "offline", retain=True)

    def _mqtt_disconnected(self, client, userdata, flags, reason_code, properties=None):
        LOG.warning("disconnected from MQTT broker: %s", reason_code)

    def _mqtt_subscribed(self, client, userdata, mid, reason_codes, properties=None):
        # An ACL-refused SUBACK would otherwise leave the bridge looking
        # healthy but deaf to commands.
        for rc in reason_codes:
            if rc.is_failure:
                LOG.error("broker refused a subscription (check the ACL): %s", rc)

    def _mqtt_message(self, client, userdata, msg):
        if msg.topic == "%s/status" % self.disc:
            payload = msg.payload.decode("utf-8", errors="replace").strip()
            if payload == "online" and self._announced.is_set():
                if (time.monotonic() - self._last_announce) < self._announce_min_interval_s:
                    LOG.info("HA status re-announce suppressed (debounce)")
                    return
                LOG.info("Home Assistant restarted; republishing discovery and state")
                self._announce_all(self.gateway.items, self.gateway.values)
            return
        prefix = "%s/set/" % self.base
        if msg.topic.startswith(prefix) and not msg.topic.endswith("/result"):
            # Hand off to the worker: furnace I/O must not block this
            # (paho network) thread. Bounded queue drops on flood.
            try:
                self._commands.put_nowait((msg.topic[len(prefix):], msg))
            except queue.Full:
                LOG.warning("command queue full — dropping %s", msg.topic)

    def _command_worker(self):
        while True:
            item, msg = self._commands.get()
            try:
                self._handle_command(item, msg)
            except Exception:
                # Fail closed AND stay alive: a crafted payload must never
                # take down the worker. Logged with traceback.
                LOG.exception("command handling failed for %s", item)

    # ---------------- command path ----------------

    def _handle_command(self, item, msg):
        outcome = self.validator.validate(
            item,
            msg.payload,
            retained=bool(msg.retain),
            device_meta=self.gateway.items.get(item),
            current_value=self.gateway.values.get(item),
        )
        if outcome.accepted and not outcome.noop:
            try:
                result = self.gateway.set_item(item, outcome.value)
                outcome = Outcome(True, "ok: %s" % result, value=outcome.value)
            except Exception as exc:  # published + logged, never swallowed
                LOG.error("write to %s failed: %s", item, exc)
                outcome = Outcome(False, "write error: %s" % exc)

        self._audit(item, msg.payload, outcome)
        self._publish(
            "%s/set/%s/result" % (self.base, item),
            json.dumps({"ok": outcome.accepted, "reason": outcome.reason}),
            retain=False,
        )
        if outcome.accepted and not outcome.noop:
            # Fresh authoritative read-back after a real write.
            self._readback(item)
        elif not outcome.accepted:
            # Reject-then-republish: snap the UI back to reality — from the
            # cache, so an MQTT rejection flood cannot be amplified into
            # UDP traffic toward the furnace.
            cached = self.gateway.values.get(item)
            if cached is not None:
                self._publish("%s/%s" % (self.base, item), cached, retain=True)

    def _readback(self, item):
        try:
            value = self.gateway.read_item(item)
        except Exception as exc:
            LOG.error("read-back of %s failed: %s", item, exc)
            return
        self._publish("%s/%s" % (self.base, item), value, retain=True)

    def _audit(self, item, payload, outcome):
        AUDIT.info(
            json.dumps(
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "item": item,
                    "payload": repr(payload)[:64],
                    "accepted": outcome.accepted,
                    "noop": outcome.noop,
                    "reason": outcome.reason,
                }
            )
        )

    # ---------------- discovery + state ----------------

    def _announce_all(self, items, values):
        self._last_announce = time.monotonic()
        writable = []
        for name, meta in sorted(items.items()):
            self._announce_item(name, meta)
            if name in values:
                self._publish("%s/%s" % (self.base, name), values[name], retain=True)
            if meta.get("type") == "R/W":
                writable.append("%s (min=%s max=%s)" % (name, meta.get("min"), meta.get("max")))
        # Availability reflects the CONTROLLER, not this announce call: an
        # MQTT reconnect while the furnace is unreachable must not present
        # frozen values as live.
        self._publish(
            self.availability_topic,
            "online" if self.gateway.online else "offline",
            retain=True,
        )
        LOG.info(
            "discovered %d items; writable candidates for the allowlist: %s",
            len(items),
            ", ".join(writable) or "none",
        )

    def _announce_item(self, name, meta):
        uid = "pellmon_%s" % name.replace("-", "_")
        device = {
            "identifiers": ["pellmon_%s" % self.base],
            "name": self.cfg["device_name"],
            "manufacturer": "NBE",
            "model": "NBE pellet burner (ha-pellmon bridge)",
        }
        common = {
            "availability_topic": self.availability_topic,
            "state_topic": "%s/%s" % (self.base, name),
            "unique_id": uid,
            "name": meta.get("longname", name),
            "device": device,
        }

        allowed = self.allowlist.get(name)
        writable = meta.get("type") == "R/W"

        if allowed is not None and writable:
            if allowed.press_payload is not None:
                component = "button"
                config = dict(common)
                config.pop("state_topic")
                config.update(
                    {
                        "command_topic": "%s/set/%s" % (self.base, name),
                        "payload_press": allowed.press_payload,
                    }
                )
            elif allowed.options:
                component = "select"
                config = dict(common)
                config.update(
                    {
                        "command_topic": "%s/set/%s" % (self.base, name),
                        "options": [str(o) for o in allowed.options],
                    }
                )
            else:
                # Advertise exactly the range the validator enforces: the
                # tighter of config and device bounds on each side. The
                # validator rejects every write when either side is missing,
                # so announcing a number entity then would create a control
                # that can never work — fall back to a sensor and say why.
                lo = _tightest(_num(meta.get("min")), allowed.min, max)
                hi = _tightest(_num(meta.get("max")), allowed.max, min)
                if lo is None or hi is None:
                    LOG.error(
                        "allowlist item %s has no %s bound from config or "
                        "device; announcing it read-only. Set min AND max in "
                        "bridge_config.yaml.",
                        name, "lower" if lo is None else "upper",
                    )
                    component = "sensor"
                    config = common
                else:
                    component = "number"
                    config = dict(common)
                    config.update(
                        {
                            "command_topic": "%s/set/%s" % (self.base, name),
                            "mode": "box",  # never slider: avoids command bursts
                            "min": lo,
                            "max": hi,
                        }
                    )
                    step = _step(meta.get("decimals"))
                    if step is not None:
                        config["step"] = step
        else:
            component = "sensor"
            config = common

        # Clear every OTHER component's retained discovery config for this
        # uid: removes stale entities when an item leaves the allowlist or
        # changes component type (number -> select, etc.).
        for other in {"sensor", "number", "select", "button"} - {component}:
            self._publish("%s/%s/%s/config" % (self.disc, other, uid), "", retain=True)

        self._publish(
            "%s/%s/%s/config" % (self.disc, component, uid),
            json.dumps(config),
            retain=True,
        )

    def _publish(self, topic, payload, retain=False):
        # Defense in depth behind the gateway's name sanitization: paho
        # raises ValueError on a wildcard/invalid topic, and letting that
        # unwind through the poll thread turns one bad item into a
        # permanent reconnect loop. Degrade to losing one publish instead.
        #
        # Callers run on the gateway or command-worker thread, never on
        # paho's network thread, so waiting here lets the network loop
        # drain the queue: a full queue (MQTT_ERR_QUEUE_SIZE) is
        # backpressure, not a reason to drop discovery configs.
        deadline = time.monotonic() + PUBLISH_QUEUE_WAIT_S
        while True:
            try:
                info = self.mq.publish(topic, payload, qos=1, retain=retain)
            except ValueError as exc:
                LOG.error("refusing publish to invalid topic %r: %s", topic, exc)
                return
            if info.rc == mqtt.MQTT_ERR_SUCCESS:
                return
            if info.rc == mqtt.MQTT_ERR_QUEUE_SIZE and time.monotonic() < deadline:
                time.sleep(PUBLISH_QUEUE_POLL_S)
                continue
            LOG.warning("publish to %s failed: rc=%s", topic, info.rc)
            return


PUBLISH_QUEUE_MAX = 5000      # paho outgoing queue bound (small messages)
PUBLISH_QUEUE_WAIT_S = 30.0   # max backpressure wait per publish
PUBLISH_QUEUE_POLL_S = 0.05


def _num(raw):
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def _step(decimals):
    """Number-entity step from the device's decimals count. Bounded so a
    bogus value cannot underflow to a 0.0 step in the discovery payload."""
    try:
        d = int(decimals)
    except (TypeError, ValueError):
        return None
    if d == 0:
        return 1
    return 10 ** -d if 0 < d <= 6 else None


def config_problem(cfg):
    """Return a startup-refusal message for MQTT config that would otherwise
    degrade into a silent retry loop or an unintended anonymous connection,
    or None when the config is usable."""
    m = cfg["mqtt"]
    host = (m.get("host") or "").strip()
    if not host or "<" in host or ">" in host:
        return (
            "MQTT_HOST is unset or still the .env.example placeholder (%r). "
            "Set it to your Home Assistant host IP or DNS name." % host
        )
    if not (m.get("username") and m.get("password")) and not _env_bool(
        "MQTT_ALLOW_ANONYMOUS", False
    ):
        return (
            "Refusing to start without complete MQTT credentials (username AND "
            "password). Set MQTT_USERNAME/MQTT_PASSWORD, or "
            "MQTT_ALLOW_ANONYMOUS=true to accept the risk."
        )
    return None


def main():
    logging.basicConfig(
        stream=sys.stdout,
        level=os.environ.get("BRIDGE_LOGLEVEL", "INFO").upper(),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    cfg = load_config(os.environ.get("BRIDGE_CONFIG", "/config/bridge_config.yaml"))

    if not cfg["nbe"].get("serial") or not cfg["nbe"].get("password"):
        LOG.error("NBE_SERIAL and NBE_PASSWORD are required (furnace menu 18)")
        sys.exit(1)
    # Fail fast here rather than let Proxy.__init__ raise the same refusal
    # inside the poll thread, where it degrades into an endless retry warning.
    if not cfg["nbe"].get("addr") and not cfg["nbe"].get("allow_broadcast"):
        LOG.error(
            "Refusing broadcast discovery: set NBE_ADDR to pin the controller "
            "address, or NBE_ALLOW_BROADCAST=true to accept the risk (writes "
            "stay disabled in broadcast mode)."
        )
        sys.exit(1)
    problem = config_problem(cfg)
    if problem:
        LOG.error(problem)
        sys.exit(1)
    if not cfg["mqtt"].get("tls"):
        LOG.warning(
            "MQTT is plaintext: broker credentials, telemetry and commands "
            "cross the network unprotected. Set MQTT_TLS=true where the broker "
            "has certificates (see SECURITY.md, residual risk 5)."
        )
    if cfg.get("allowlist"):
        LOG.info("write allowlist: %s", ", ".join(sorted(cfg["allowlist"])))
    else:
        LOG.info("write allowlist is empty: bridge is read-only")
    Bridge(cfg).run()


if __name__ == "__main__":
    main()
