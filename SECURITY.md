# Security model — ha-pellmon

This document is the threat note (SSDLC G0) and standing security
reference for the bridge. The protected asset is **a combustion
appliance**: the worst-case impact of a security failure is unwanted
physical actuation (setpoint changes, start/stop), plus loss of heating.

## Trust boundaries

```
[LAN / furnace VLAN]          [docker network]              [HA network]
 NBE controller ◄── UDP ──► bridge container ◄── TLS ──► mosquitto ◄──► Home Assistant
```

- The **NBE controller** authenticates writes with a 10-char password
  (menu 18) and RSA-encrypts the write frame with its own 512-bit key.
  Reads are plaintext UDP. This is vendor firmware behaviour we cannot
  change — treat the furnace LAN segment as sensitive.
- The **bridge** is the only component that can reach the controller's
  write path from this stack.
- The **broker** is the only ingress to the bridge (no listening ports).

## STRIDE against the new surface

| Threat | Vector | Control |
|---|---|---|
| **S**poofing | Rogue MQTT client posing as HA | broker auth (no anonymous), per-user ACL: only `homeassistant` may publish `pellmon/set/#` |
| | Rogue controller answering discovery | serial pinning: bridge refuses a controller whose reported serial ≠ `NBE_SERIAL` |
| **T**ampering | Malicious/malformed command payloads | fail-closed validator: allowlist, strict UTF-8, length cap, numeric/enum check, tightest-bound range check |
| | MQTT traffic interception/injection | TLS 8883 with verified certificates (no insecure switch exists in the client), optional mTLS |
| **R**epudiation | "Who changed the setpoint?" | one structured audit line per command (accepted and rejected) with timestamp, payload, outcome, reason; per-command result topic |
| **I**nfo disclosure | Secrets in image/repo/logs | secrets only via env at runtime; `.env` gitignored; bridge never logs credentials |
| **D**oS | Command floods reaching the furnace | per-item min interval + global 10 writes/min budget; no-op suppression; container mem/pids limits |
| | Retained-command replay storms | retained messages rejected; clean MQTT session (no queued command redelivery) |
| **E**levation | Container escape / lateral movement | unprivileged user, `cap_drop: ALL`, `no-new-privileges`, read-only rootfs, no published ports, current patched base image |

## Deliberate design decisions

- **The allowlist is empty by default.** Device-writable is not
  bridge-writable; every control is a conscious operator decision with
  explicit bounds.
- **Rejection, not clamping.** An out-of-range command is refused and
  the authoritative value republished — the UI is never allowed to
  believe a value the furnace did not accept.
- **Defense in depth on the write path.** Broker ACL *and* bridge
  allowlist *and* controller password are independent layers; any one
  failing does not open the furnace.
- **The burner's own controller is the safety authority.** Its
  interlocks (over-temperature, flame supervision, etc.) are below this
  stack and are never bypassed; software here only narrows the command
  space.

## Residual risks (accepted, documented)

1. **Controller reads are plaintext UDP; the write password travels
   inside the RSA-encrypted frame, but the RSA key is 512-bit** —
   vendor firmware; factorable by a determined attacker. Mitigation:
   keep the furnace on a trusted LAN/VLAN; the exposure exists with any
   NBE client (including the vendor's own apps).
2. **No per-user authorization inside HA** — anyone who can operate
   your HA instance can use the exposed controls. Mitigation: keep the
   allowlist minimal and bounds tight; HA login security is out of this
   project's scope.
3. **Broadcast discovery mode** (only if `NBE_ADDR` is unset and host
   networking used) accepts the first answer matching the serial.
   Mitigation: serial pinning; prefer `NBE_ADDR`.

## Reporting

This is a personal project; open an issue or contact the repo owner
directly for anything security-relevant.
