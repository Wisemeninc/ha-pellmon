# -*- coding: utf-8 -*-
"""NBE controller proxy (V7/V10/V13 pellet burners, UDP).

Adapted for ha-pellmon from motoz/nbetest protocol.py,
Copyright (C) 2013 Anders Nylund, GPL-2.0-or-later.

Changes from upstream (kept minimal and reviewable):
- Raw-RSA adapter for pycryptodome: pycrypto's ``key.encrypt(h, None)``
  (textbook RSA — what the controller implements) was removed in
  pycryptodome; ``_RawRsaAdapter`` reproduces it with modular
  exponentiation so the vendored frames.py stays byte-identical.
- Sequence number wraps at 99 (the '%02d' frame field corrupts frames
  from 100 upward in upstream).
- Function 3 range queries (``get_ranges``) ported from PellMon's
  nbecom plugin: settings metadata as name -> (min, max, default,
  decimals).
- Thread lock around request/response (one in-flight datagram per
  proxy), bounded retries with fresh sequence numbers, logging instead
  of prints, and the broken test-server Controller class removed.

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 2 of the License, or (at your
option) any later version. Distributed WITHOUT ANY WARRANTY.
"""

import base64
import logging
import socket
import threading
from random import randrange

from Crypto.PublicKey import RSA

from .frames import Request_frame, Response_frame

LOG = logging.getLogger("nbe.protocol")

DEFAULT_PORT = 8483
SETTINGS_GROUPS = (
    "boiler", "hot_water", "regulation", "weather", "weather2", "oxygen",
    "cleaning", "hopper", "fan", "auger", "ignition", "pump", "sun",
    "vacuum", "misc", "alarm", "manual",
)


class NbeError(Exception):
    pass


class NbeTimeout(NbeError):
    pass


class NbeRejected(NbeError):
    """The controller answered with a non-zero status."""


class _RawRsaAdapter:
    """pycrypto-compatible textbook-RSA encrypt on top of pycryptodome.

    The controller decrypts with raw modular exponentiation, so no
    padding scheme may be added here. frames.Request_frame.encode()
    retries with fresh random padding until the ciphertext is exactly
    64 bytes, which reproduces upstream behaviour.
    """

    def __init__(self, key):
        self._n = key.n
        self._e = key.e

    def encrypt(self, data, _ignored):
        c = pow(int.from_bytes(data, "big"), self._e, self._n)
        out = c.to_bytes((c.bit_length() + 7) // 8, "big")
        return (out,)


class Proxy:
    """One authenticated session with an NBE controller."""

    def __init__(self, password, serial, addr=None, port=DEFAULT_PORT, timeout=2.0, retries=2):
        if not serial or not str(serial).isdigit():
            raise NbeError("a numeric controller serial is required")
        self._lock = threading.Lock()
        self._timeout = timeout
        self._retries = retries

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", 0))
        s.settimeout(timeout)
        self.s = s

        request = Request_frame()
        request.controllerid = str(serial)
        request.pincode = str(password)
        request.sequencenumber = randrange(0, 100)
        self.request = request
        self.response = Response_frame(request)

        try:
            if addr is None:
                self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                target = ("<broadcast>", port)
                LOG.warning(
                    "broadcast discovery in use — pin the controller address "
                    "(NBE_ADDR) so an on-LAN spoofer cannot answer first"
                )
            else:
                target = (addr, port)
            request.function = 0
            request.payload = "NBE Discovery"
            self.s.sendto(request.encode(), target)
            while True:
                try:
                    data, server = self.s.recvfrom(4096)
                except socket.timeout:
                    raise NbeTimeout(
                        "controller discovery timed out (serial %s)" % serial
                    )
                if addr is not None and server != (addr, port):
                    # Pinned mode: ONLY the pinned controller may answer.
                    LOG.warning("dropping discovery reply from %s (pinned to %s)", server, addr)
                    continue
                break
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 0)
            self.addr = server
            self.response.decode(data)
            try:
                info = self.response.parse_payload()
            except ValueError as exc:
                raise NbeError("malformed discovery payload: %s" % exc)
            self.serial = info.get("Serial", str(serial))
            self.ip = info.get("IP", server[0])
            if self.serial != str(serial):
                raise NbeError(
                    "controller at %s reports serial %s, expected %s — refusing"
                    % (server[0], self.serial, serial)
                )

            # Fetch the controller's RSA public key; writes are encrypted.
            # frames.py raw-RSA operates on 64-byte blocks, so ONLY a
            # 512-bit key is usable: anything else would corrupt frames
            # (or spin forever), so the write path fails closed instead.
            request.public_key = None
            response = self._transact(1, "misc.rsa_key")
            try:
                key = RSA.importKey(base64.b64decode(response.payload.split("rsa_key=")[1]))
                if key.size_in_bits() == 512:
                    request.public_key = _RawRsaAdapter(key)
                else:
                    LOG.error(
                        "controller RSA key is %d-bit, need 512 — writes disabled",
                        key.size_in_bits(),
                    )
            except (IndexError, ValueError) as exc:
                LOG.warning("controller offered no usable RSA key: %s — writes disabled", exc)
        except Exception:
            s.close()
            raise

    def close(self):
        # Take the transact lock so we never close the socket out from
        # under an in-flight request on another thread.
        with self._lock:
            self.s.close()

    # ── high-level API ──────────────────────────────────────────────────

    def get_settings(self, group):
        """All settings of a group as {name: value}."""
        self._check_group(group)
        return _parse_pairs(self._transact(1, group + ".*").payload)

    def get_ranges(self, group):
        """Settings metadata: {name: (min, max, default, decimals)}."""
        self._check_group(group)
        out = {}
        for name, raw in _parse_pairs(self._transact(3, group + ".*").payload).items():
            parts = raw.split(",")
            if len(parts) == 4:
                out[name] = tuple(parts)
        return out

    def get_operating_data(self):
        return _parse_pairs(self._transact(4, "*").payload)

    def get_advanced_data(self):
        return _parse_pairs(self._transact(5, "*").payload)

    def get_setting(self, group, name):
        self._check_group(group)
        payload = self._transact(1, "%s.%s" % (group, name)).payload
        return payload.split("=", 1)[1] if "=" in payload else payload

    def set_setting(self, group, name, value):
        """Encrypted write. Returns 'OK' or raises NbeRejected."""
        self._check_group(group)
        if not isinstance(value, str):
            raise NbeError("value must be str")
        if self.request.public_key is None:
            raise NbeError("no usable controller RSA key — write path disabled")
        payload = "%s.%s=%s" % (group, name, value)
        # The encrypted block is fixed at 64 bytes with a 33-byte frame
        # skeleton: an oversize payload would silently corrupt the frame.
        if len(payload) > 31:
            raise NbeError("write payload %r exceeds 31 chars" % payload)
        # retries=0: a timed-out write may still have landed on the
        # controller — retrying could double-apply. Fail loudly instead.
        response = self._transact(2, payload, encrypt=True, timeout=5.0, retries=0)
        if response.status != 0:
            raise NbeRejected(response.payload or "status %d" % response.status)
        return "OK"

    # ── plumbing ────────────────────────────────────────────────────────

    @staticmethod
    def _check_group(group):
        if group not in SETTINGS_GROUPS:
            raise NbeError("unknown settings group %r" % group)

    def _transact(self, function, payload, encrypt=False, timeout=None, retries=None):
        with self._lock:
            last_error = None
            if retries is None:
                retries = self._retries
            for attempt in range(retries + 1):
                self.request.sequencenumber = (self.request.sequencenumber + 1) % 100
                self.request.payload = payload
                self.request.function = function
                self.request.encrypted = encrypt
                self.s.settimeout(timeout or self._timeout)
                try:
                    self.s.sendto(self.request.encode(), self.addr)
                    data, server = self.s.recvfrom(4096)
                    if server != self.addr:
                        # Datagram from an unexpected source: ignore it and
                        # let the retry (with a fresh sequence number) run.
                        LOG.warning("dropping datagram from unexpected source %s", server)
                        raise IOError("unexpected source")
                    self.response.decode(data)
                    if self.response.function != function:
                        raise IOError(
                            "response function %d != request %d"
                            % (self.response.function, function)
                        )
                    return self.response
                except socket.timeout as exc:
                    last_error = NbeTimeout("no response to function %d" % function)
                    LOG.debug("timeout on function %d (attempt %d)", function, attempt + 1)
                except (IOError, ValueError) as exc:
                    # Frame/sequence mismatch: drain stale datagrams, retry
                    # with a fresh sequence number.
                    last_error = NbeError("bad frame for function %d: %s" % (function, exc))
                    self._drain()
            raise last_error

    def _drain(self):
        self.s.settimeout(0.05)
        try:
            for _ in range(50):  # bounded: a datagram flood must not pin us here
                self.s.recvfrom(4096)
        except (socket.timeout, OSError):
            return


def _parse_pairs(payload):
    """'a=1;b=2' -> {'a': '1', 'b': '2'} (defensive about '=' in values)."""
    out = {}
    for chunk in payload.split(";"):
        if "=" in chunk:
            name, value = chunk.split("=", 1)
            if name:
                out[name] = value
    return out
