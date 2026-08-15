# -*- coding: utf-8 -*-
"""End-to-end protocol tests: Proxy/NbeGateway against a fake NBE
controller over real UDP on localhost, including RSA-encrypted writes.
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fake_controller import FakeController
from nbe.protocol import Proxy, NbeRejected, NbeTimeout, NbeError
from nbe_gateway import NbeGateway


def make_proxy(fake):
    return Proxy(
        password=fake.pincode,
        serial=fake.serial,
        addr="127.0.0.1",
        port=fake.port,
        timeout=1.0,
    )


class TestProxy(unittest.TestCase):
    def setUp(self):
        self.fake = FakeController()
        self.fake.start()
        self.proxy = make_proxy(self.fake)

    def tearDown(self):
        self.proxy.close()
        self.fake.stop()
        self.fake.join(timeout=2)

    def test_discovery(self):
        self.assertEqual(self.proxy.serial, self.fake.serial)
        self.assertEqual(self.proxy.ip, "127.0.0.1")

    def test_get_settings(self):
        self.assertEqual(
            self.proxy.get_settings("boiler"), {"temp": "70", "diff_over": "5"}
        )

    def test_get_ranges(self):
        ranges = self.proxy.get_ranges("boiler")
        self.assertEqual(ranges["temp"], ("10", "90", "60", "0"))

    def test_get_operating_and_advanced(self):
        self.assertEqual(self.proxy.get_operating_data()["boiler_temp"], "71.5")
        self.assertEqual(self.proxy.get_advanced_data()["oxygen"], "12.1")

    def test_get_single_setting(self):
        self.assertEqual(self.proxy.get_setting("boiler", "temp"), "70")

    def test_oversize_write_payload_refused(self):
        """Forge finding: a >31-char 'group.name=value' silently corrupts
        the fixed 64-byte encrypted frame — must be refused locally."""
        with self.assertRaises(NbeError):
            self.proxy.set_setting("hot_water", "temp", "9" * 20)
        self.assertEqual(self.fake.writes, [])

    def test_encrypted_write_roundtrip(self):
        """The load-bearing test: RSA-encrypted SetItem reaches the device."""
        self.assertEqual(self.proxy.set_setting("boiler", "temp", "65"), "OK")
        self.assertEqual(self.fake.writes, [("boiler.temp", "65")])
        self.assertEqual(self.proxy.get_setting("boiler", "temp"), "65")

    def test_write_timeout_is_never_retried(self):
        """A lost write response may still have landed — one attempt only."""
        self.fake.drop_writes = 1
        with self.assertRaises(NbeTimeout):
            self.proxy.set_setting("boiler", "temp", "65")
        time.sleep(0.3)
        self.assertEqual(self.fake.write_attempts, 1)

    def test_rejected_write_raises(self):
        self.fake.reject_next_write = True
        with self.assertRaises(NbeRejected):
            self.proxy.set_setting("boiler", "temp", "65")
        self.assertEqual(self.fake.writes, [])

    def test_wrong_password_rejected(self):
        self.proxy.close()
        self.fake.pincode = "another-pin"
        proxy = make_proxy(self.fake)  # discovery needs no password
        self.fake.pincode = "0000000000"
        with self.assertRaises(NbeRejected):
            proxy.set_setting("boiler", "temp", "65")
        proxy.close()

    def test_unknown_group_refused_locally(self):
        with self.assertRaises(NbeError):
            self.proxy.get_settings("nonsense")

    def test_datagram_from_wrong_source_ignored(self):
        """Audit finding: replies were accepted from any source address."""
        import socket as socketmod

        rogue = socketmod.socket(socketmod.AF_INET, socketmod.SOCK_DGRAM)
        try:
            # Inject a rogue datagram into the proxy's receive queue, then
            # issue a real request: the rogue frame must be discarded and
            # the genuine controller answer used.
            local = self.proxy.s.getsockname()
            rogue.sendto(b"garbage-from-elsewhere", ("127.0.0.1", local[1]))
            time.sleep(0.1)
            self.assertEqual(self.proxy.get_setting("boiler", "temp"), "70")
        finally:
            rogue.close()

    def test_sequence_number_wraps(self):
        self.proxy.request.sequencenumber = 99
        self.assertEqual(self.proxy.get_setting("boiler", "temp"), "70")
        self.assertLess(self.proxy.request.sequencenumber, 100)


class TestProxyOffline(unittest.TestCase):
    def test_discovery_timeout(self):
        with self.assertRaises(NbeTimeout):
            Proxy(password="x", serial="1", addr="127.0.0.1", port=1, timeout=0.2)

    def test_non_numeric_serial_refused(self):
        with self.assertRaises(NbeError):
            Proxy(password="x", serial="not-a-serial", addr="127.0.0.1", port=1)

    def test_wrong_controller_serial_refused(self):
        fake = FakeController(serial="99999")
        fake.start()
        try:
            with self.assertRaises(NbeError):
                Proxy(password=fake.pincode, serial="10039",
                      addr="127.0.0.1", port=fake.port, timeout=1.0)
        finally:
            fake.stop()
            fake.join(timeout=2)


class TestGateway(unittest.TestCase):
    def setUp(self):
        self.fake = FakeController()
        self.fake.start()
        self.events = {"online": None, "changed": [], "offline": 0}

    def tearDown(self):
        self.gw.stop()
        self.fake.stop()
        self.fake.join(timeout=2)

    def _start_gateway(self, poll=0.2, allowlist=("boiler-temp",)):
        self.gw = NbeGateway(
            {
                "serial": self.fake.serial,
                "password": self.fake.pincode,
                "addr": "127.0.0.1",
                "port": self.fake.port,
                "poll_interval_s": poll,
            },
            allowlist=allowlist,
            on_online=lambda items, values: self.events.__setitem__(
                "online", (items, values)
            ),
            on_changed=lambda ch: self.events["changed"].append(ch),
            on_offline=lambda: self.events.__setitem__(
                "offline", self.events["offline"] + 1
            ),
        )
        self.gw.start()
        deadline = time.time() + 5
        while self.events["online"] is None and time.time() < deadline:
            time.sleep(0.05)
        self.assertIsNotNone(self.events["online"], "gateway never came online")

    def test_registry_ids_types_and_bounds(self):
        self._start_gateway()
        items, values = self.events["online"]
        self.assertEqual(items["boiler-temp"]["type"], "R/W")
        self.assertEqual(items["boiler-temp"]["min"], "10")
        self.assertEqual(items["boiler-temp"]["max"], "90")
        self.assertEqual(items["operating_data-boiler_temp"]["type"], "R")
        self.assertEqual(values["boiler-temp"], "70")

    def test_poll_detects_change(self):
        self._start_gateway()
        self.fake.operating["boiler_temp"] = "72.5"
        deadline = time.time() + 5
        while not any(
            "operating_data-boiler_temp" in c for c in self.events["changed"]
        ) and time.time() < deadline:
            time.sleep(0.05)
        self.assertTrue(
            any("operating_data-boiler_temp" in c for c in self.events["changed"])
        )

    def test_set_and_readback(self):
        self._start_gateway()
        self.assertEqual(self.gw.set_item("boiler-temp", "65"), "OK")
        self.assertEqual(self.gw.read_item("boiler-temp"), "65")

    def test_set_readonly_item_refused(self):
        self._start_gateway(allowlist=("boiler-temp", "operating_data-boiler_temp"))
        with self.assertRaises(NbeError):
            self.gw.set_item("operating_data-boiler_temp", "65")

    def test_gateway_gate_blocks_non_allowlisted_writable(self):
        """Last-layer gate: device-writable but not allowlisted is refused
        even if the MQTT-side validator were bypassed."""
        self._start_gateway(allowlist=())
        with self.assertRaises(NbeError):
            self.gw.set_item("boiler-temp", "65")
        self.assertEqual(self.fake.writes, [])


if __name__ == "__main__":
    unittest.main()
