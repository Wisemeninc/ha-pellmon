# -*- coding: utf-8 -*-
"""Command validation for the PellMon Home Assistant bridge.

Pure logic, deliberately free of paho/gi imports so it is unit-testable
in isolation. Every decision here fails closed: a command is rejected
unless it positively passes every applicable check.

Copyright (C) 2026  ha-pellmon contributors
Derived from the pellmonMQTT.py lineage, Copyright (C) 2013 Anders Nylund.
Licensed under the GNU General Public License v3 or later.
"""

from dataclasses import dataclass, field
from typing import Optional
import re
import time

MAX_PAYLOAD_LEN = 32

# Strict decimal only: no nan/inf, no exponents, no '1_0' underscores —
# float() accepts all of those and NaN even passes range comparisons.
_NUMBER_RE = re.compile(r"[+-]?[0-9]{1,10}(\.[0-9]{1,6})?")

# Characters that would inject into the NBE frame ("group.name=value",
# ';'-separated pairs) or corrupt logs. Applied to every payload.
_FORBIDDEN_CHARS = set(";=\x00\r\n\t")


@dataclass
class AllowedItem:
    """One entry of the write allowlist, from bridge_config.yaml."""

    name: str
    # Optional config-side bounds. The effective bound is the TIGHTER of
    # these and the device-reported metadata bounds.
    min: Optional[float] = None
    max: Optional[float] = None
    # For enum/select items: allowed values. If None, the device-reported
    # enum list (if any) is used.
    options: Optional[list] = None
    # Momentary "press" items (buttons). The only accepted payload.
    press_payload: Optional[str] = None
    # Per-item minimum seconds between accepted writes.
    min_interval_s: float = 2.0


@dataclass
class Outcome:
    accepted: bool
    reason: str
    # Normalized value to hand to D-Bus SetItem (always str when accepted).
    value: Optional[str] = None
    # True when the command equals the current value: ack without SetItem,
    # without consuming rate budget (breaks echo-mirror write loops).
    noop: bool = False


@dataclass
class RateLimiter:
    """Global sliding-window limiter plus per-item minimum interval."""

    max_writes: int = 10
    window_s: float = 60.0
    clock: callable = time.monotonic
    _events: list = field(default_factory=list)
    _last_write: dict = field(default_factory=dict)

    def check_and_record(self, item: str, min_interval_s: float) -> Optional[str]:
        """Return a rejection reason, or None (and record) if allowed."""
        now = self.clock()
        self._events = [t for t in self._events if now - t < self.window_s]
        last = self._last_write.get(item)
        if last is not None and (now - last) < min_interval_s:
            return "per-item interval: min %.1fs between writes" % min_interval_s
        if len(self._events) >= self.max_writes:
            return "global rate limit: max %d writes per %.0fs" % (
                self.max_writes,
                self.window_s,
            )
        self._events.append(now)
        self._last_write[item] = now
        return None


def _parse_bound(raw) -> Optional[float]:
    """Device metadata bounds arrive as strings; parse defensively."""
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _normalize_number(value: float) -> str:
    """HA number entities send '65.0'; controllers expect '65'."""
    if value == int(value):
        return str(int(value))
    return repr(value)


class CommandValidator:
    """Validates one MQTT command against the allowlist and device metadata."""

    def __init__(
        self,
        allowlist: dict,
        rate_limiter: Optional[RateLimiter] = None,
        max_payload_len: int = MAX_PAYLOAD_LEN,
    ):
        self.allowlist = dict(allowlist)
        self.rate = rate_limiter or RateLimiter()
        self.max_payload_len = max_payload_len

    def validate(
        self,
        item: str,
        payload,
        retained: bool = False,
        device_meta: Optional[dict] = None,
        current_value: Optional[str] = None,
    ) -> Outcome:
        # Anti-replay: a retained command would re-fire on every
        # reconnect/restart. Commands must be live.
        if retained:
            return Outcome(False, "retained command rejected (anti-replay)")

        allowed = self.allowlist.get(item)
        if allowed is None:
            return Outcome(False, "item not in write allowlist")

        # The historical defect: bytes handed to D-Bus '(ss)'. Decode
        # strictly; anything undecodable is rejected, and the accepted
        # value is guaranteed to be str.
        if isinstance(payload, bytes):
            try:
                payload = payload.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                return Outcome(False, "payload is not valid UTF-8")
        if not isinstance(payload, str):
            return Outcome(False, "unsupported payload type %s" % type(payload).__name__)

        payload = payload.strip()
        if not payload:
            return Outcome(False, "empty payload")
        if len(payload) > self.max_payload_len:
            return Outcome(False, "payload exceeds %d chars" % self.max_payload_len)
        if _FORBIDDEN_CHARS.intersection(payload):
            return Outcome(False, "payload contains forbidden characters")

        meta = device_meta or {}

        if allowed.press_payload is not None:
            if payload != allowed.press_payload:
                return Outcome(False, "button item accepts only %r" % allowed.press_payload)
            normalized = payload
        else:
            options = allowed.options
            if options is None:
                options = meta.get("options")
            if options is not None:
                if payload not in [str(o) for o in options]:
                    return Outcome(False, "value not in allowed options")
                normalized = payload
            else:
                if not _NUMBER_RE.fullmatch(payload):
                    return Outcome(False, "value is not a plain decimal number")
                number = float(payload)
                lo = _tightest(_parse_bound(meta.get("min")), allowed.min, max)
                hi = _tightest(_parse_bound(meta.get("max")), allowed.max, min)
                if lo is not None and number < lo:
                    return Outcome(False, "value %s below minimum %s" % (payload, lo))
                if hi is not None and number > hi:
                    return Outcome(False, "value %s above maximum %s" % (payload, hi))
                normalized = _normalize_number(number)

        # No-op suppression: an equal value is acknowledged without touching
        # D-Bus and without spending rate budget. Buttons are exempt — a
        # "press" is an action, not a state.
        if (
            allowed.press_payload is None
            and current_value is not None
            and _values_equal(normalized, current_value)
        ):
            return Outcome(True, "no-op: value unchanged", value=normalized, noop=True)

        reason = self.rate.check_and_record(item, allowed.min_interval_s)
        if reason is not None:
            return Outcome(False, reason)

        return Outcome(True, "ok", value=normalized)


def _values_equal(a: str, b) -> bool:
    """Compare command and current value, numerically when possible."""
    b = str(b)
    try:
        return float(a) == float(b)
    except (TypeError, ValueError):
        return a == b.strip()


def _tightest(device_bound: Optional[float], config_bound: Optional[float], pick):
    """Combine device and config bounds; the tighter one wins.

    `pick` is max() for lower bounds and min() for upper bounds.
    """
    bounds = [b for b in (device_bound, config_bound) if b is not None]
    if not bounds:
        return None
    return pick(bounds)
