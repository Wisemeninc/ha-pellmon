# -*- coding: utf-8 -*-
"""Polling gateway between the NBE controller and the bridge.

Owns the Proxy session, an item registry, and a poll thread. Item ids
follow PellMon's nbecom naming so existing dashboards keep their
topics: settings items are ``<group>-<name>`` (e.g. ``boiler-temp``,
R/W), operating and advanced data are ``operating_data-<name>`` /
``advanced_data-<name>`` (R).

Copyright (C) 2026 ha-pellmon contributors, GPL-2.0-or-later.
"""

import logging
import threading
import time

from nbe.protocol import Proxy, NbeError, NbeTimeout, NbeRejected, SETTINGS_GROUPS

LOG = logging.getLogger("nbe.gateway")

HEARTBEAT_FILE = "/tmp/bridge-heartbeat"


class NbeGateway:
    """Threaded poller with change callbacks.

    Callbacks (all invoked from the poll thread):
      on_online(items, values)  - connected + full registry built
      on_changed({id: value})   - values that changed since last poll
      on_offline()              - controller unreachable
    """

    def __init__(self, config, on_online, on_changed, on_offline, allowlist=None):
        self._cfg = config
        self._on_online = on_online
        self._on_changed = on_changed
        self._on_offline = on_offline
        # Independent last-layer write gate: even if the MQTT-side
        # validator were bypassed, nothing outside this set is written.
        self._allowlist = frozenset(allowlist or ())
        self._proxy = None
        self._online = False
        self.items = {}
        self.values = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    @property
    def online(self):
        return self._online

    # ── used by the MQTT command path ───────────────────────────────────

    def read_item(self, item_id):
        """Fresh read of one settings item (authoritative read-back)."""
        proxy = self._proxy
        if proxy is None:
            raise NbeError("controller offline")
        group, name = self._split(item_id)
        value = proxy.get_setting(group, name)
        self.values[item_id] = value
        return value

    def set_item(self, item_id, value):
        """Validated upstream; writes one settings item, returns 'OK'."""
        proxy = self._proxy
        if proxy is None:
            raise NbeError("controller offline")
        if item_id not in self._allowlist:
            raise NbeError("%s is not in the write allowlist (gateway gate)" % item_id)
        meta = self.items.get(item_id)
        if meta is None or meta.get("type") != "R/W":
            raise NbeError("%s is not a writable settings item" % item_id)
        group, name = self._split(item_id)
        return proxy.set_setting(group, name, value)

    @staticmethod
    def _split(item_id):
        group, _, name = item_id.partition("-")
        if not name:
            raise NbeError("malformed item id %r" % item_id)
        return group, name

    # ── poll thread ─────────────────────────────────────────────────────

    def _run(self):
        interval = float(self._cfg.get("poll_interval_s", 10))
        while not self._stop.is_set():
            try:
                if self._proxy is None:
                    self._connect()
                self._poll()
            except (NbeError, OSError) as exc:
                LOG.warning("controller poll failed: %s", exc)
                self._disconnect()
            except Exception:
                # A malformed datagram or bug must never kill the poll
                # thread silently: log with traceback, drop the session,
                # and keep the loop (availability goes offline) alive.
                LOG.exception("unexpected error in poll loop")
                self._disconnect()
            # Heartbeat proves the LOOP is alive; controller reachability
            # is reported separately via the availability topic.
            self._heartbeat()
            self._stop.wait(interval if self._proxy else min(interval, 15))

    def _connect(self):
        LOG.info("discovering controller (serial %s)", self._cfg["serial"])
        self._proxy = Proxy(
            password=self._cfg["password"],
            serial=self._cfg["serial"],
            addr=self._cfg.get("addr"),
            port=int(self._cfg.get("port", 8483)),
        )
        self._build_registry()
        self._online = True
        LOG.info(
            "controller online at %s; %d items (%d writable)",
            self._proxy.ip,
            len(self.items),
            sum(1 for m in self.items.values() if m["type"] == "R/W"),
        )
        self._on_online(dict(self.items), dict(self.values))

    def _disconnect(self):
        if self._proxy is not None:
            self._proxy.close()
            self._proxy = None
        if self._online:
            self._online = False
            self._on_offline()

    def _build_registry(self):
        items, values = {}, {}
        for group in SETTINGS_GROUPS:
            try:
                ranges = self._proxy.get_ranges(group)
                settings = self._proxy.get_settings(group)
            except NbeTimeout:
                LOG.debug("group %s not answered; skipping", group)
                continue
            for name, value in settings.items():
                item_id = "%s-%s" % (group, name)
                meta = {"name": item_id, "group": group, "type": "R/W",
                        "longname": name.replace("_", " ")}
                if name in ranges:
                    lo, hi, default, decimals = ranges[name]
                    meta.update({"min": lo, "max": hi, "default": default,
                                 "decimals": decimals})
                items[item_id] = meta
                values[item_id] = value
        for prefix, reader in (
            ("operating_data", self._proxy.get_operating_data),
            ("advanced_data", self._proxy.get_advanced_data),
        ):
            try:
                data = reader()
            except NbeTimeout:
                LOG.debug("%s not answered; skipping", prefix)
                continue
            for name, value in data.items():
                item_id = "%s-%s" % (prefix, name)
                items[item_id] = {"name": item_id, "group": prefix, "type": "R",
                                  "longname": name.replace("_", " ")}
                values[item_id] = value
        if not items:
            raise NbeError("controller answered discovery but no data groups")
        self.items, self.values = items, values

    def _poll(self):
        if self._proxy is None:
            return
        changed = {}
        readers = [
            ("operating_data", self._proxy.get_operating_data),
            ("advanced_data", self._proxy.get_advanced_data),
        ]
        for group in sorted({m["group"] for m in self.items.values() if m["type"] == "R/W"}):
            readers.append((group, lambda g=group: self._proxy.get_settings(g)))
        for prefix, reader in readers:
            for name, value in reader().items():
                item_id = "%s-%s" % (prefix, name)
                if item_id in self.items and self.values.get(item_id) != value:
                    self.values[item_id] = value
                    changed[item_id] = value
        if changed:
            self._on_changed(changed)

    @staticmethod
    def _heartbeat():
        try:
            with open(HEARTBEAT_FILE, "w") as fh:
                fh.write(str(int(time.time())))
        except OSError:
            pass
