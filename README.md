# ha-pellmon

Secure, bidirectional bridge between an **NBE pellet furnace** (V7/V10/V13
ethernet controllers — Scotte, Woody, RTB, Aduro-style burners) and
**Home Assistant**, over MQTT.

A single Python 3 process on a current base image replaces the old
PellMon + pellmonMQTT Docker stack (`lakelake/pellmondocker`): it speaks
the NBE UDP protocol directly (protocol code vendored from the PellMon
author's own Python 3 implementation, [motoz/nbetest]), publishes every
controller value to MQTT, auto-creates Home Assistant entities via MQTT
Discovery, and provides a **fail-closed, allowlisted, audited control
path** for writing setpoints back to the furnace.

[motoz/nbetest]: https://github.com/motoz/nbetest

## Why replace the old stack?

The historical setup was read-only *by accident*: its forwarder ran a
Python 2 script under Python 3, where every incoming MQTT command turned
into a `TypeError` (bytes handed to a D-Bus call requiring str) that a
bare `except: pass` swallowed without a trace. At the same time it
subscribed to **every** writable parameter with no validation — the only
thing preventing any broker client from commanding the furnace was that
bug. This project fixes control and locks it down in the same move, and
removes the EOL surface entirely (Debian buster, Python 2, CherryPy web
UI with default credentials, `network_mode: host`).

## Architecture

```
┌────────────────┐  UDP 8483 (LAN)   ┌──────────────────────────────┐
│ NBE controller │◄─────────────────►│  ha-pellmon bridge (py3)     │
│  (the furnace) │  reads: plaintext │  · poll + change detection   │
└────────────────┘  writes: RSA-enc  │  · validation + allowlist    │
                                     │  · audit log                 │
                                     └──────────┬───────────────────┘
                                                │ MQTT (1883, or TLS 8883)
                                     ┌──────────▼───────────────────┐
                                     │ HA Mosquitto add-on (auth +  │
                                     │ per-user topic ACLs)         │
                                     └──────────┬───────────────────┘
                                                │ MQTT Discovery
                                     ┌──────────▼───────────────────┐
                                     │ Home Assistant device:       │
                                     │ sensors / numbers / selects  │
                                     └──────────────────────────────┘
```

**Topics** (compatible with PellMon's nbecom naming, so existing
dashboards keep working):

| Topic | Direction | Purpose |
|---|---|---|
| `pellmon/<item>` | bridge → HA | states, retained (`boiler-temp`, `operating_data-boiler_temp`, …) |
| `pellmon/set/<item>` | HA → bridge | commands, **allowlisted items only** |
| `pellmon/set/<item>/result` | bridge → HA | `{"ok": bool, "reason": …}` for every command |
| `pellmon/bridge/availability` | bridge → HA | `online`/`offline` (LWT) |
| `homeassistant/…/config` | bridge → HA | MQTT Discovery |

## Quick start

```sh
git clone <this repo> && cd ha-pellmon
cp .env.example .env && chmod 600 .env          # fill in NBE_* and MQTT_*
cp bridge/bridge_config.example.yaml bridge/bridge_config.yaml
docker compose up -d --build
docker compose logs -f bridge
```

No broker is shipped. The bridge connects to the **Home Assistant
Mosquitto add-on** (or any broker you already run):

1. Set `MQTT_HOST` in `.env` to your HA host.
2. Create a dedicated broker-only login for the bridge with the
   add-on's `logins:` option (preferred over an HA user account, which
   would carry HA permissions) and put its name and password in
   `MQTT_USERNAME` / `MQTT_PASSWORD`.
3. Restrict what that user may do: enable the add-on's *customize*
   option and install `mosquitto/ha-addon-acl.example` as its ACL, so
   the bridge credential can never publish `pellmon/set/#`. Without an
   ACL, the bridge allowlist is the only layer between the broker and
   the furnace.

`NBE_SERIAL` and `NBE_PASSWORD` come from the furnace panel, menu 18.
Set `NBE_ADDR` to the controller's IP (give it a DHCP reservation) —
broadcast discovery does not cross the docker bridge network.

The furnace appears in Home Assistant automatically (MQTT integration
with discovery enabled) as one device with all sensors.

## Enabling control (deliberately opt-in)

The bridge starts **read-only**. To enable a control:

1. Read the startup log line `writable candidates for the allowlist:` —
   it lists every writable item with the controller's own min/max.
2. Add the item to `bridge/bridge_config.yaml` under `allowlist:` with
   `min` and `max`. Numeric items need a bound on both sides, from your
   config or from the device; the tighter one wins per side, and a
   missing side leaves the item read-only:

   ```yaml
   allowlist:
     boiler-temp:
       min: 60
       max: 75
       min_interval_s: 5
   ```

3. `docker compose restart bridge`. The item becomes a `number` (or
   `select`/`button`) entity in Home Assistant.

Every command — accepted or rejected — is answered on
`pellmon/set/<item>/result` and logged as a structured audit line. A
rejected command also triggers a fresh read of the real value, so the
HA UI can never sit on a value the furnace never accepted.

### What the validator enforces (all fail-closed)

- item must be in the allowlist (device-writable is **not** enough)
- payload: strict UTF-8, ≤32 chars, numeric/enum as appropriate
- range: the **tightest** of device metadata and your config wins;
  out-of-range is rejected, never clamped silently
- retained messages rejected (no command replay on restarts)
- per-item minimum interval (default 2 s) + global budget (10/min)
- equal-to-current values acknowledged without touching the furnace

## Going live safely

Tests prove the protocol implementation against a faithful fake — not
your controller's firmware quirks. Stage the cut-over:

1. **Read-only soak (24–48 h).** Run with the allowlist empty alongside
   your old setup. Compare values in HA against the burner's own panel.
2. **First write = most harmless parameter.** Allowlist one benign
   setpoint (e.g. `boiler-temp` with tight bounds), change it by one
   degree from HA, and confirm the change on the furnace panel and on
   `pellmon/set/boiler-temp/result`.
3. **Then hand over control** — grow the allowlist one item at a time.
   Leave combustion-relevant parameters (feed/auger timing, oxygen,
   power limits) OFF the allowlist: range validation stops typos, not
   valid-but-wrong values in safety-relevant settings.

Keep the old stack stopped-but-intact until the soak passes, as a
rollback path.

## Migration from lakelake/pellmondocker

| Old (`lakelake/pellmondocker`) | New (ha-pellmon) |
|---|---|
| `nbeserial` env | `NBE_SERIAL` |
| `nbepass` env | `NBE_PASSWORD` |
| `mqtthost`/`mqttport`/`mqttuser`/`mqttpass` | `MQTT_HOST`/`MQTT_PORT`/`MQTT_USERNAME`/`MQTT_PASSWORD` |
| `webuser`/`webpass` + web UI on 8081 | removed — Home Assistant is the UI |
| `network_mode: host` | bridge network + `NBE_ADDR` |
| `pellmon/settings/<item>` write topic | `pellmon/set/<item>`, allowlisted + validated |
| RRD graphs in PellMon web | Home Assistant recorder/history |

State topics keep the same item names (`boiler-temp`,
`operating_data-boiler_temp`, …), so existing MQTT sensors and
dashboards continue to work. RRD history is not migrated; HA keeps
history from the moment you switch. Before switching, clear any retained
messages under the legacy `pellmon/settings/#` if you ever published
there.

## TLS (optional)

The add-on speaks plaintext on 1883 by default, which is fine when the
bridge and HA share a trusted network. If you enable certificates on
the add-on (port 8883), set `MQTT_TLS=true`, uncomment the `ca.crt`
volume in `docker-compose.yml`, and place the CA at `certs/ca.crt`.
Certificate verification is always on; there is no insecure switch.

## Security model

See [SECURITY.md](SECURITY.md) for the threat model. Summary of layers:

1. **Broker authentication + per-user ACLs** (configured on the HA
   add-on) — only the `homeassistant` user may publish `pellmon/set/#`;
   the bridge cannot command itself.
2. **Bridge allowlist + validation** — independent second layer; an
   attacker with broker access still cannot exceed the allowlist/bounds.
3. **Controller password + serial pinning** — writes are RSA-encrypted
   with the controller's key; the bridge refuses a controller whose
   serial does not match `NBE_SERIAL`.
4. **Container hardening** — unprivileged user, `cap_drop: ALL`,
   read-only rootfs, no published ports, current base image.
5. **The burner's own controller remains the safety authority** — this
   stack only narrows what can be commanded; it never bypasses the
   device's interlocks.

## Development

```sh
uv venv .venv && uv pip install --python .venv/bin/python \
  -r bridge/requirements.txt pytest
.venv/bin/python -m pytest bridge/tests/   # includes an end-to-end fake
                                           # NBE controller over real UDP,
                                           # with real RSA-encrypted writes
```

## License

GPL-3.0-or-later. Protocol code under `bridge/nbe/` is derived from
[motoz/nbetest] (GPL-2.0-or-later), Copyright (C) 2013 Anders Nylund.
