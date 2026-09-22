# -*- coding: utf-8 -*-
"""Bridge-level guard-wiring tests.

The validator is unit-tested in isolation; these assert the wiring — that
`_handle_command` actually runs every payload through the validator (with
the retained flag and device metadata) BEFORE anything reaches the gateway
write. Deleting the validate() call or the `retained=` argument must turn a
test here red.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nbe.protocol import NbeError, NbeRejected, NbeTimeout
from nbe_gateway import NbeGateway
from pellmon_ha_bridge import Bridge, config_problem


class StubGateway:
    def __init__(self):
        self.items = {"boiler-temp": {"type": "R/W", "min": "10", "max": "90"}}
        self.values = {"boiler-temp": "70"}
        self.online = True
        self.set_calls = []

    def set_item(self, item, value):
        self.set_calls.append((item, value))
        return "OK"

    def read_item(self, item):
        return self.values.get(item)


class _StubResult:
    rc = 0  # mqtt.MQTT_ERR_SUCCESS


class StubMQ:
    def __init__(self):
        self.published = []

    def publish(self, topic, payload, qos=1, retain=False):
        self.published.append((topic, payload, retain))
        return _StubResult()


class Msg:
    def __init__(self, payload, retain=False, item="boiler-temp"):
        self.payload = payload
        self.retain = retain
        self.topic = "pellmon/set/%s" % item


def make_bridge(allowlist=None):
    cfg = {
        "base_topic": "pellmon",
        "discovery_prefix": "homeassistant",
        "device_name": "Test Furnace",
        "allowlist": allowlist
        if allowlist is not None
        else {"boiler-temp": {"min": 40, "max": 80}},
        "rate_limit": {"max_writes": 10, "window_s": 60},
        "mqtt": {"host": "localhost", "port": 1883},
        "nbe": {"serial": "1", "password": "x", "addr": "127.0.0.1", "port": 1},
    }
    bridge = Bridge(cfg)
    bridge.gateway = StubGateway()
    bridge.mq = StubMQ()
    return bridge


class StubProxy:
    """Answers the 'boiler' settings group and operating data only."""

    def __init__(self, settings, operating=None):
        self._settings = settings
        self._operating = operating or {}

    def get_settings(self, group):
        if group == "boiler":
            return dict(self._settings)
        raise NbeTimeout("no answer")

    def get_ranges(self, group):
        if group == "boiler":
            return {}
        raise NbeTimeout("no answer")

    def get_operating_data(self):
        return dict(self._operating)

    def get_advanced_data(self):
        raise NbeTimeout("no answer")


class TestRegistrySanitization(unittest.TestCase):
    """Security finding: controller-supplied item names become MQTT topic
    segments; wildcards/separators from an unauthenticated (broadcast-mode)
    responder must never reach topic construction."""

    def _registry(self, settings, operating=None):
        gw = NbeGateway({"serial": "1", "password": "x"}, lambda *a: None,
                        lambda *a: None, lambda *a: None)
        gw._proxy = StubProxy(settings, operating)
        gw._build_registry()
        return gw.items

    def test_unsafe_names_are_dropped(self):
        items = self._registry(
            {"temp": "70", "we#ird": "2", "a/b": "3", "pl+us": "4",
             "nul\x00": "5", "": "6"},
            {"power_pct": "48", "sneaky#": "1"},
        )
        self.assertIn("boiler-temp", items)
        self.assertIn("operating_data-power_pct", items)
        for bad in items:
            self.assertNotIn("#", bad)
            self.assertNotIn("+", bad.partition("-")[2])
            self.assertNotIn("/", bad)
            self.assertNotIn("\x00", bad)
        self.assertEqual(len(items), 2)

    def test_overlong_name_is_dropped(self):
        items = self._registry({"x" * 49: "1", "temp": "70"})
        self.assertEqual(list(items), ["boiler-temp"])


class RejectingProxy(StubProxy):
    """Answers 'boiler', then rejects (not times out) every other group —
    firmware that answers an unsupported group with a non-zero status."""

    def get_settings(self, group):
        if group == "boiler":
            return dict(self._settings)
        raise NbeRejected("status 1")

    def get_ranges(self, group):
        if group == "boiler":
            return {}
        raise NbeError("bad frame for function 3")

    def get_advanced_data(self):
        raise NbeError("bad frame for function 11")


class TestRegistryResilience(unittest.TestCase):
    """Review finding: one rejected or malformed group reply must not abort
    the whole registry build and keep the bridge offline forever."""

    def test_rejected_group_is_skipped(self):
        gw = NbeGateway({"serial": "1", "password": "x"}, lambda *a: None,
                        lambda *a: None, lambda *a: None)
        gw._proxy = RejectingProxy({"temp": "70"}, {"power_pct": "48"})
        gw._build_registry()
        self.assertIn("boiler-temp", gw.items)
        self.assertIn("operating_data-power_pct", gw.items)


class TestStartupConfigGuard(unittest.TestCase):
    """Review findings: a leftover MQTT_HOST placeholder must fail fast, not
    loop on DNS errors; an incomplete credential pair must not silently
    connect anonymously."""

    def _cfg(self, **mqtt):
        base = {"host": "ha.local", "username": "u", "password": "p"}
        base.update(mqtt)
        return {"mqtt": base}

    def test_placeholder_host_refused(self):
        for host in ("<ha-host>", "", "   ", None):
            self.assertIsNotNone(config_problem(self._cfg(host=host)), host)

    def test_missing_username_refused(self):
        self.assertIsNotNone(config_problem(self._cfg(username="")))
        self.assertIsNotNone(config_problem(self._cfg(username=None)))

    def test_missing_password_refused(self):
        self.assertIsNotNone(config_problem(self._cfg(password="")))

    def test_complete_config_accepted(self):
        self.assertIsNone(config_problem(self._cfg()))

    def test_anonymous_requires_explicit_optin(self):
        with mock.patch.dict(os.environ, {"MQTT_ALLOW_ANONYMOUS": "true"}):
            self.assertIsNone(config_problem(self._cfg(username="", password="")))


class _QueueFullResult:
    rc = 15  # mqtt.MQTT_ERR_QUEUE_SIZE


class QueueFullMQ(StubMQ):
    """Reports a full outgoing queue for the first N publishes — what paho
    does when the online announce burst outruns max_queued_messages."""

    def __init__(self, full_for):
        super().__init__()
        self.full_for = full_for
        self.attempts = 0

    def publish(self, topic, payload, qos=1, retain=False):
        self.attempts += 1
        if self.attempts <= self.full_for:
            return _QueueFullResult()
        return super().publish(topic, payload, qos, retain)


class TestPublishBackpressure(unittest.TestCase):
    """Field finding: 349 items x ~6 publishes overflowed the 1000-message
    queue and every later discovery config was dropped with rc=15. A full
    queue must be waited out, not treated as a failed publish."""

    def test_queue_full_is_retried_until_it_drains(self):
        bridge = make_bridge()
        bridge.mq = QueueFullMQ(full_for=3)
        bridge._publish("pellmon/boiler-temp", "70", retain=True)
        self.assertEqual(bridge.mq.attempts, 4)
        self.assertEqual(bridge.mq.published, [("pellmon/boiler-temp", "70", True)])

    def test_other_errors_are_not_retried(self):
        bridge = make_bridge()

        class OtherErr(StubMQ):
            calls = 0

            def publish(self, *a, **k):
                self.calls += 1

                class R:
                    rc = 4  # MQTT_ERR_NO_CONN

                return R()

        bridge.mq = OtherErr()
        bridge._publish("pellmon/boiler-temp", "70")
        self.assertEqual(bridge.mq.calls, 1)


class RaisingMQ(StubMQ):
    def publish(self, topic, payload, qos=1, retain=False):
        if "#" in topic or "+" in topic:
            raise ValueError("Publish topic cannot contain wildcards.")
        return super().publish(topic, payload, qos=qos, retain=retain)


class TestPublishGuard(unittest.TestCase):
    def test_wildcard_topic_does_not_unwind(self):
        """Second layer: even if a bad topic reaches paho, the ValueError
        must be contained, not unwind the poll thread into a reconnect loop."""
        b = make_bridge()
        b.mq = RaisingMQ()
        b._publish("pellmon/we#ird", "2")  # must not raise
        b._publish("pellmon/ok", "1")
        self.assertEqual(b.mq.published, [("pellmon/ok", "1", False)])


class TestBridgeCommandWiring(unittest.TestCase):
    def test_valid_command_reaches_gateway(self):
        b = make_bridge()
        b._handle_command("boiler-temp", Msg(b"65"))
        self.assertEqual(b.gateway.set_calls, [("boiler-temp", "65")])

    def test_retained_command_never_reaches_gateway(self):
        b = make_bridge()
        b._handle_command("boiler-temp", Msg(b"65", retain=True))
        self.assertEqual(b.gateway.set_calls, [])

    def test_out_of_range_never_reaches_gateway(self):
        b = make_bridge()
        b._handle_command("boiler-temp", Msg(b"999"))
        self.assertEqual(b.gateway.set_calls, [])

    def test_non_allowlisted_never_reaches_gateway(self):
        b = make_bridge()
        b._handle_command("auger-output", Msg(b"5", item="auger-output"))
        self.assertEqual(b.gateway.set_calls, [])


if __name__ == "__main__":
    unittest.main()
