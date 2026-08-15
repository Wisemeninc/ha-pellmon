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
import os
import ssl
import sys
import threading
import time

import paho.mqtt.client as mqtt
import yaml

from nbe_gateway import NbeGateway
from validation import AllowedItem, CommandValidator, Outcome, RateLimiter

LOG = logging.getLogger("pellmon-ha-bridge")
AUDIT = logging.getLogger("pellmon-ha-bridge.audit")


def load_config(path):
    cfg = {}
    if path and os.path.exists(path):
        with open(path, "r") as fh:
            cfg = yaml.safe_load(fh) or {}

    m = cfg.setdefault("mqtt", {})
    # Secrets and connection details come from the environment first so
    # nothing sensitive needs to live in the config file.
    m["host"] = os.environ.get("MQTT_HOST", m.get("host", "localhost"))
    m["port"] = int(os.environ.get("MQTT_PORT", m.get("port", 1883)))
    m["username"] = os.environ.get("MQTT_USERNAME", m.get("username"))
    m["password"] = os.environ.get("MQTT_PASSWORD", m.get("password"))
    m["tls"] = _env_bool("MQTT_TLS", m.get("tls", False))
    m["tls_ca"] = os.environ.get("MQTT_TLS_CA", m.get("tls_ca"))
    m["tls_cert"] = os.environ.get("MQTT_TLS_CERT", m.get("tls_cert"))
    m["tls_key"] = os.environ.get("MQTT_TLS_KEY", m.get("tls_key"))

    n = cfg.setdefault("nbe", {})
    n["serial"] = os.environ.get("NBE_SERIAL", n.get("serial"))
    n["password"] = os.environ.get("NBE_PASSWORD", n.get("password"))
    n["addr"] = os.environ.get("NBE_ADDR", n.get("addr"))  # None = discover
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


def _env_bool(name, default):
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    return raw.strip().lower() in ("1", "true", "yes", "on")


def build_allowlist(cfg):
    allowlist = {}
    for name, opts in (cfg.get("allowlist") or {}).items():
        opts = opts or {}
        allowlist[name] = AllowedItem(
            name=name,
            min=opts.get("min"),
            max=opts.get("max"),
            options=opts.get("options"),
            press_payload=opts.get("press_payload"),
            min_interval_s=float(opts.get("min_interval_s", 2.0)),
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

        self.gateway = NbeGateway(
            cfg["nbe"],
            on_online=self._controller_online,
            on_changed=self._controller_changed,
            on_offline=self._controller_offline,
        )

        self.mq = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id="pellmon-ha-bridge",
            clean_session=True,  # no persistent-session command redelivery
        )
        m = cfg["mqtt"]
        if m.get("username"):
            self.mq.username_pw_set(m["username"], m.get("password"))
        if m.get("tls"):
            # Certificate verification stays ON. There is deliberately no
            # "insecure" switch here.
            self.mq.tls_set(
                ca_certs=m.get("tls_ca"),
                certfile=m.get("tls_cert"),
                keyfile=m.get("tls_key"),
                cert_reqs=ssl.CERT_REQUIRED,
                tls_version=ssl.PROTOCOL_TLS_CLIENT,
            )
        self.mq.will_set(self.availability_topic, "offline", qos=1, retain=True)
        self.mq.on_connect = self._mqtt_connected
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
        LOG.info("connected to MQTT broker")
        client.subscribe("%s/status" % self.disc)
        for name in self.allowlist:
            client.subscribe("%s/set/%s" % (self.base, name), qos=1)
        if self._announced.is_set():
            self._announce_all(self.gateway.items, self.gateway.values)
        else:
            self._publish(self.availability_topic, "offline", retain=True)

    def _mqtt_message(self, client, userdata, msg):
        if msg.topic == "%s/status" % self.disc:
            payload = msg.payload.decode("utf-8", errors="replace").strip()
            if payload == "online" and self._announced.is_set():
                LOG.info("Home Assistant restarted; republishing discovery and state")
                self._announce_all(self.gateway.items, self.gateway.values)
            return
        prefix = "%s/set/" % self.base
        if msg.topic.startswith(prefix) and not msg.topic.endswith("/result"):
            self._handle_command(msg.topic[len(prefix):], msg)

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
            self._readback(item)
        elif not outcome.accepted:
            # Reject-then-republish: snap the UI back to reality.
            self._readback(item)

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
        writable = []
        for name, meta in sorted(items.items()):
            self._announce_item(name, meta)
            if name in values:
                self._publish("%s/%s" % (self.base, name), values[name], retain=True)
            if meta.get("type") == "R/W":
                writable.append("%s (min=%s max=%s)" % (name, meta.get("min"), meta.get("max")))
        self._publish(self.availability_topic, "online", retain=True)
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
                component = "number"
                config = dict(common)
                config.update(
                    {
                        "command_topic": "%s/set/%s" % (self.base, name),
                        "mode": "box",  # never slider: avoids command bursts
                    }
                )
                lo = allowed.min if allowed.min is not None else _num(meta.get("min"))
                hi = allowed.max if allowed.max is not None else _num(meta.get("max"))
                step = _step(meta.get("decimals"))
                if lo is not None:
                    config["min"] = lo
                if hi is not None:
                    config["max"] = hi
                if step is not None:
                    config["step"] = step
        else:
            component = "sensor"
            config = common
            # Proactively clear any stale control-entity discovery configs
            # for items that are writable on the device but not allowlisted.
            if writable:
                for stale in ("number", "select", "button"):
                    self._publish(
                        "%s/%s/%s/config" % (self.disc, stale, uid), "", retain=True
                    )

        self._publish(
            "%s/%s/%s/config" % (self.disc, component, uid),
            json.dumps(config),
            retain=True,
        )

    def _publish(self, topic, payload, retain=False):
        self.mq.publish(topic, payload, qos=1, retain=retain)


def _num(raw):
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _step(decimals):
    try:
        return 10 ** -int(decimals) if int(decimals) > 0 else 1
    except (TypeError, ValueError):
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
    if not cfg["mqtt"].get("password") and not _env_bool("MQTT_ALLOW_ANONYMOUS", False):
        LOG.error(
            "Refusing to start without MQTT credentials. Set MQTT_USERNAME/"
            "MQTT_PASSWORD, or MQTT_ALLOW_ANONYMOUS=true to accept the risk."
        )
        sys.exit(1)
    if cfg.get("allowlist"):
        LOG.info("write allowlist: %s", ", ".join(sorted(cfg["allowlist"])))
    else:
        LOG.info("write allowlist is empty: bridge is read-only")
    Bridge(cfg).run()


if __name__ == "__main__":
    main()
