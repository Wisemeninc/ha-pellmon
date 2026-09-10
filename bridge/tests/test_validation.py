# -*- coding: utf-8 -*-
"""Unit tests for the fail-closed command validator (SSDLC guard tests).

These are the standing tripwire for the control path: the historical
integration shipped a py2->py3 port whose write path failed on every
command (bytes into a D-Bus '(ss)' call) with the exception swallowed.
Every invariant here maps to an ISC in ISA.md.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from validation import AllowedItem, CommandValidator, RateLimiter


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def make_validator(allowlist=None, max_writes=10, window_s=60.0):
    clock = FakeClock()
    validator = CommandValidator(
        allowlist
        if allowlist is not None
        else {"boiler-temp": AllowedItem("boiler-temp", min=40, max=80)},
        RateLimiter(max_writes=max_writes, window_s=window_s, clock=clock),
    )
    return validator, clock


class TestPayloadContract(unittest.TestCase):
    """ISC-16, ISC-26, ISC-53: the bytes defect cannot recur."""

    def test_bytes_payload_is_decoded_and_value_is_str(self):
        v, _ = make_validator()
        out = v.validate("boiler-temp", b"65", device_meta={"min": "40", "max": "80"})
        self.assertTrue(out.accepted)
        self.assertIsInstance(out.value, str)
        self.assertEqual(out.value, "65")

    def test_undecodable_bytes_rejected(self):
        v, _ = make_validator()
        out = v.validate("boiler-temp", b"\xff\xfe")
        self.assertFalse(out.accepted)
        self.assertIn("UTF-8", out.reason)

    def test_float_string_normalized_to_int(self):
        v, _ = make_validator()
        out = v.validate("boiler-temp", "65.0")
        self.assertTrue(out.accepted)
        self.assertEqual(out.value, "65")

    def test_oversize_payload_rejected(self):
        v, _ = make_validator()
        out = v.validate("boiler-temp", "6" * 33)
        self.assertFalse(out.accepted)

    def test_empty_payload_rejected(self):
        v, _ = make_validator()
        out = v.validate("boiler-temp", "   ")
        self.assertFalse(out.accepted)


class TestAllowlist(unittest.TestCase):
    """ISC-15, ISC-55, ISC-64: nothing outside the allowlist is writable."""

    def test_non_allowlisted_item_rejected(self):
        v, _ = make_validator()
        out = v.validate("auger-output", "50")
        self.assertFalse(out.accepted)
        self.assertIn("allowlist", out.reason)

    def test_device_writable_but_not_allowlisted_still_rejected(self):
        v, _ = make_validator()
        out = v.validate(
            "auger-output", "50", device_meta={"type": "R/W", "min": "0", "max": "100"}
        )
        self.assertFalse(out.accepted)


class TestRangeValidation(unittest.TestCase):
    """ISC-18, ISC-19, ISC-54: tightest bound wins, rejection not clamping."""

    def test_below_config_min_rejected(self):
        v, _ = make_validator()
        out = v.validate("boiler-temp", "10")
        self.assertFalse(out.accepted)
        self.assertIn("below", out.reason)

    def test_above_config_max_rejected(self):
        v, _ = make_validator()
        out = v.validate("boiler-temp", "95")
        self.assertFalse(out.accepted)
        self.assertIn("above", out.reason)

    def test_device_bound_tighter_than_config_wins(self):
        v, _ = make_validator()
        out = v.validate("boiler-temp", "78", device_meta={"min": "40", "max": "75"})
        self.assertFalse(out.accepted)

    def test_config_bound_tighter_than_device_wins(self):
        v, _ = make_validator()
        out = v.validate("boiler-temp", "85", device_meta={"min": "0", "max": "100"})
        self.assertFalse(out.accepted)

    def test_excess_decimals_rejected(self):
        """Forge finding: device decimals metadata was ignored.
        Fresh validator per case: accepted writes consume rate budget."""
        meta = {"min": "40", "max": "80", "decimals": "0"}
        v, _ = make_validator()
        self.assertFalse(v.validate("boiler-temp", "65.4", device_meta=meta).accepted)
        v, _ = make_validator()
        self.assertTrue(v.validate("boiler-temp", "65.0", device_meta=meta).accepted)
        meta1 = {"min": "40", "max": "80", "decimals": "1"}
        v, _ = make_validator()
        self.assertTrue(v.validate("boiler-temp", "65.4", device_meta=meta1).accepted)

    def test_garbage_device_bounds_ignored(self):
        v, _ = make_validator()
        out = v.validate("boiler-temp", "65", device_meta={"min": "n/a", "max": None})
        self.assertTrue(out.accepted)

    def test_nonfinite_device_bounds_do_not_void_config_bounds(self):
        """Security finding: float('nan')/('inf') as a DEVICE bound must be
        treated as absent — otherwise NaN wins _tightest and voids the
        operator's own min/max (fail-open on the last safety control)."""
        for evil in ("nan", "NaN", "inf", "-inf", "Infinity"):
            v, _ = make_validator()  # config min=40 max=80
            meta = {"min": evil, "max": evil}
            self.assertFalse(
                v.validate("boiler-temp", "9999999999", device_meta=meta).accepted,
                "device bound %r let an out-of-range value through" % evil,
            )
            v, _ = make_validator()
            self.assertTrue(
                v.validate("boiler-temp", "65", device_meta=meta).accepted,
                "device bound %r wrongly rejected an in-range value" % evil,
            )

    def test_numeric_item_with_no_bounds_is_rejected(self):
        """Security finding: an allowlisted numeric item with neither config
        nor device bounds must fail closed, not accept an arbitrary value."""
        v, _ = make_validator({"regulation-x": AllowedItem("regulation-x")})
        out = v.validate("regulation-x", "9999999999")
        self.assertFalse(out.accepted)
        self.assertIn("bounds", out.reason)
        # Absent device min/max is the same as no bound.
        v, _ = make_validator({"regulation-x": AllowedItem("regulation-x")})
        self.assertFalse(
            v.validate("regulation-x", "50", device_meta={"type": "R/W"}).accepted
        )

    def test_numeric_item_with_one_sided_bounds_is_rejected(self):
        """Security finding: a single usable bound must still fail closed —
        min-only leaves the safety-relevant upper side unguarded, and hostile
        device metadata (max: 'n/a') produces exactly that shape."""
        # Config-side: min only.
        v, _ = make_validator({"regulation-x": AllowedItem("regulation-x", min=10)})
        out = v.validate("regulation-x", "9999999999")
        self.assertFalse(out.accepted)
        self.assertIn("no usable max", out.reason)
        # Config-side: max only.
        v, _ = make_validator({"regulation-x": AllowedItem("regulation-x", max=80)})
        out = v.validate("regulation-x", "-9999999999")
        self.assertFalse(out.accepted)
        self.assertIn("no usable min", out.reason)
        # Device-metadata side: unparseable max voids that bound only.
        v, _ = make_validator({"regulation-x": AllowedItem("regulation-x")})
        out = v.validate(
            "regulation-x", "9999999999", device_meta={"min": "10", "max": "n/a"}
        )
        self.assertFalse(out.accepted)
        # Device-metadata side: min present, max absent entirely.
        v, _ = make_validator({"regulation-x": AllowedItem("regulation-x")})
        out = v.validate("regulation-x", "9999999999", device_meta={"min": "10"})
        self.assertFalse(out.accepted)

    def test_small_decimal_not_emitted_as_exponent(self):
        """Security finding: repr(0.00005)=='5e-05' would be sent verbatim
        and could be misread as 5. The emitted string must stay decimal."""
        v, _ = make_validator({"regulation-x": AllowedItem("regulation-x", min=0, max=1)})
        meta = {"min": "0", "max": "1", "decimals": "5"}
        out = v.validate("regulation-x", "0.00005", device_meta=meta)
        self.assertTrue(out.accepted, out.reason)
        self.assertNotIn("e", out.value.lower())
        self.assertEqual(out.value, "0.00005")

    def test_non_numeric_value_rejected(self):
        v, _ = make_validator()
        out = v.validate("boiler-temp", "warm")
        self.assertFalse(out.accepted)

    def test_non_finite_floats_rejected(self):
        """Audit finding: float('nan') passes range comparisons (NaN
        comparisons are always False) then crashes normalization."""
        v, _ = make_validator()
        for evil in ("nan", "NaN", "inf", "-inf", "Infinity", "1e400", "1_0", "0x41"):
            out = v.validate("boiler-temp", evil)
            self.assertFalse(out.accepted, "accepted %r" % evil)

    def test_frame_metacharacters_rejected(self):
        """Audit finding: ';' and '=' would inject key=value pairs into
        the NBE frame payload."""
        v, _ = make_validator(
            {"misc-mode": AllowedItem("misc-mode", options=["auto", "x=1", "a;b"])}
        )
        for evil in ("x=1", "a;b", "65;boiler.temp2", "a\nb"):
            out = v.validate("misc-mode", evil)
            self.assertFalse(out.accepted, "accepted %r" % evil)


class TestEnum(unittest.TestCase):
    """ISC-20, ISC-58."""

    def setUp(self):
        self.v, _ = make_validator(
            {"misc-mode": AllowedItem("misc-mode", options=["auto", "manual", "off"])}
        )

    def test_member_accepted(self):
        out = self.v.validate("misc-mode", "manual")
        self.assertTrue(out.accepted)

    def test_non_member_rejected(self):
        out = self.v.validate("misc-mode", "turbo")
        self.assertFalse(out.accepted)


class TestButton(unittest.TestCase):
    def test_press_payload_only(self):
        v, _ = make_validator({"misc-start": AllowedItem("misc-start", press_payload="1")})
        self.assertTrue(v.validate("misc-start", "1").accepted)
        self.assertFalse(v.validate("misc-start", "0").accepted)


class TestRetained(unittest.TestCase):
    """ISC-21, ISC-56: anti-replay."""

    def test_retained_command_rejected(self):
        v, _ = make_validator()
        out = v.validate("boiler-temp", "65", retained=True)
        self.assertFalse(out.accepted)
        self.assertIn("retained", out.reason)


class TestRateLimits(unittest.TestCase):
    """ISC-22, ISC-23, ISC-57."""

    def test_per_item_interval_enforced(self):
        v, clock = make_validator()
        self.assertTrue(v.validate("boiler-temp", "65").accepted)
        out = v.validate("boiler-temp", "66")
        self.assertFalse(out.accepted)
        self.assertIn("interval", out.reason)
        clock.advance(2.5)
        self.assertTrue(v.validate("boiler-temp", "66").accepted)

    def test_global_window_enforced(self):
        allow = {
            "item-%d" % i: AllowedItem("item-%d" % i, min=0, max=100, min_interval_s=0)
            for i in range(12)
        }
        v, clock = make_validator(allow, max_writes=10, window_s=60)
        accepted = 0
        for i in range(12):
            if v.validate("item-%d" % i, "5").accepted:
                accepted += 1
        self.assertEqual(accepted, 10)
        clock.advance(61)
        self.assertTrue(v.validate("item-11", "5").accepted)


class TestNoopSuppression(unittest.TestCase):
    """ISC-66: equal value acks without SetItem and without rate budget."""

    def test_equal_value_is_noop(self):
        v, _ = make_validator()
        out = v.validate("boiler-temp", "65", current_value="65.0")
        self.assertTrue(out.accepted)
        self.assertTrue(out.noop)

    def test_noop_consumes_no_rate_budget(self):
        v, _ = make_validator()
        for _ in range(20):
            self.assertTrue(v.validate("boiler-temp", "65", current_value="65").noop)
        # A real change is still allowed afterwards.
        out = v.validate("boiler-temp", "66", current_value="65")
        self.assertTrue(out.accepted)
        self.assertFalse(out.noop)

    def test_button_never_noop(self):
        v, _ = make_validator({"misc-start": AllowedItem("misc-start", press_payload="1")})
        out = v.validate("misc-start", "1", current_value="1")
        self.assertFalse(out.noop)


if __name__ == "__main__":
    unittest.main()
