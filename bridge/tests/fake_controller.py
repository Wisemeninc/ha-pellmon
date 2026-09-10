# -*- coding: utf-8 -*-
"""A fake NBE controller speaking the real UDP frame protocol.

Used by the test suite to exercise Proxy/NbeGateway end-to-end on
localhost, including RSA-encrypted writes: the fake generates a real
RSA key, serves its public half via ``misc.rsa_key``, and decrypts
incoming function-2 frames with textbook RSA — exactly what the real
controller does.
"""

import base64
import socket
import threading

from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, inverse

START = b"\x02"
END = b"\x04"


def make_512bit_key():
    """pycryptodome refuses to *generate* keys under 1024 bits, but the
    real controller uses 512-bit keys (raw RSA on 64-byte blocks), and
    importing them works fine. Construct one from 256-bit primes."""
    e = 65537
    while True:
        p, q = getPrime(256), getPrime(256)
        n = p * q
        phi = (p - 1) * (q - 1)
        if p != q and n.bit_length() == 512 and phi % e != 0:
            return RSA.construct((n, e, inverse(e, phi), p, q), consistency_check=True)


def parse_block(h):
    """Parse the request block: START ff ss pin(10) time(10) pad(4) lll payload END."""
    if h[0:1] != START:
        raise ValueError("no START")
    function = int(h[1:3])
    seq = int(h[3:5])
    pincode = h[5:15].decode("ascii")
    size = int(h[29:32])
    payload = h[32 : 32 + size].decode("ascii")
    if h[32 + size : 33 + size] != END:
        raise ValueError("no END")
    return function, seq, pincode, payload


class FakeController(threading.Thread):
    """Answers discovery, reads, range queries, and encrypted writes."""

    def __init__(self, serial="10039", pincode="1234567890", key_bits=512):
        super().__init__(daemon=True)
        self.serial = serial
        self.pincode = pincode
        # key_bits != 512 exercises the fail-closed RSA key-size gate: the
        # bridge must refuse to use a non-512-bit key (raw RSA needs the
        # exact 64-byte block) and disable writes.
        self.key = make_512bit_key() if key_bits == 512 else RSA.generate(key_bits)
        self.settings = {"boiler": {"temp": "70", "diff_over": "5"}}
        self.ranges = {"boiler": {"temp": "10,90,60,0", "diff_over": "0,20,5,0"}}
        self.operating = {"boiler_temp": "71.5", "state": "5"}
        self.advanced = {"oxygen": "12.1"}
        self.writes = []          # (path, value) accepted
        self.write_attempts = 0   # function-2 frames received
        self.reject_next_write = False
        self.drop_writes = 0      # swallow N write requests (no response)

        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", 0))
        self.s.settimeout(0.2)
        self.port = self.s.getsockname()[1]
        self._halt = threading.Event()

    def stop(self):
        self._halt.set()

    def run(self):
        while not self._halt.is_set():
            try:
                data, addr = self.s.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                response = self._handle(data)
            except Exception as exc:  # test double: surface loudly
                print("fake controller error:", exc)
                continue
            if response is not None:
                self.s.sendto(response, addr)

    # ── protocol handling ───────────────────────────────────────────────

    def _handle(self, data):
        appid = data[0:12]
        controllerid = data[12:18]
        encrypted = data[18:19] == b"*"
        if encrypted:
            cipher = data[19:]
            m = pow(int.from_bytes(cipher, "big"), self.key.d, self.key.n)
            block = m.to_bytes(64, "big")
        else:
            block = data[19:]
        function, seq, pincode, payload = parse_block(block)

        if function == 0:
            return self._respond(appid, controllerid, 0, seq, 0,
                                 "Serial=%s;IP=127.0.0.1" % self.serial)
        if function == 1 and payload == "misc.rsa_key":
            pub = base64.b64encode(self.key.publickey().export_key("DER")).decode()
            return self._respond(appid, controllerid, 1, seq, 0, "rsa_key=" + pub)
        if function == 1:
            group, _, name = payload.partition(".")
            values = self.settings.get(group, {})
            if name == "*":
                body = ";".join("%s=%s" % kv for kv in sorted(values.items()))
                return self._respond(appid, controllerid, 1, seq, 0, body)
            if name in values:
                return self._respond(appid, controllerid, 1, seq, 0,
                                     "%s=%s" % (name, values[name]))
            return self._respond(appid, controllerid, 1, seq, 1, "unknown")
        if function == 3:
            group, _, _name = payload.partition(".")
            ranges = self.ranges.get(group, {})
            body = ";".join("%s=%s" % kv for kv in sorted(ranges.items()))
            return self._respond(appid, controllerid, 3, seq, 0, body)
        if function == 4:
            body = ";".join("%s=%s" % kv for kv in sorted(self.operating.items()))
            return self._respond(appid, controllerid, 4, seq, 0, body)
        if function == 5:
            body = ";".join("%s=%s" % kv for kv in sorted(self.advanced.items()))
            return self._respond(appid, controllerid, 5, seq, 0, body)
        if function == 2:
            self.write_attempts += 1
            if self.drop_writes > 0:
                self.drop_writes -= 1
                return None
            if not encrypted:
                return self._respond(appid, controllerid, 2, seq, 1, "not encrypted")
            if pincode != self.pincode:
                return self._respond(appid, controllerid, 2, seq, 1, "wrong password")
            if self.reject_next_write:
                self.reject_next_write = False
                return self._respond(appid, controllerid, 2, seq, 1, "value rejected")
            path, _, value = payload.partition("=")
            group, _, name = path.partition(".")
            self.settings.setdefault(group, {})[name] = value
            self.writes.append((path, value))
            return self._respond(appid, controllerid, 2, seq, 0, "")
        return self._respond(appid, controllerid, function, seq, 1, "illegal function")

    @staticmethod
    def _respond(appid, controllerid, function, seq, status, payload):
        out = appid[:12].ljust(12)
        out += controllerid[:6].ljust(6)
        out += START
        out += ("%02u" % function).encode("ascii")
        out += ("%02d" % seq).encode("ascii")
        out += str(status).encode("ascii")
        out += ("%03u" % len(payload)).encode("ascii")
        out += payload.encode("ascii")
        out += END
        return out
