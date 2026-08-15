---
project: ha-pellmon
task: Upgrade PellMon furnace link to secure bidirectional Home Assistant integration
slug: ha-pellmon-secure-control
effort: E4
phase: execute
progress: 0/64
mode: standard
started: 2026-08-15T19:40:00-07:00
updated: 2026-08-15T19:40:00-07:00
---

# ha-pellmon — Secure bidirectional PellMon ⇄ Home Assistant integration

## Problem

The furnace (NBE V7/V10/V13 pellet burner, NBEcom UDP protocol) is monitored through the
third-party `lakelake/pellmondocker` image (source: thel1988/pellmon-docker, last updated
4+ years ago). The link to Home Assistant is one-way in practice and insecure by design:

- `pellmonMQTT.py` runs under Python 3 but passes raw MQTT `bytes` payloads to D-Bus
  `SetItem('(ss)')`, which requires `str` — every write raises `TypeError`, swallowed by a
  bare `except: pass`. Control is silently broken, which is why the setup is read-only.
- The same script subscribes to `pellmon/settings/<item>` for EVERY writable parameter
  with zero validation, no allowlist, no range checks — any client on the broker could
  command the furnace if the bug were fixed naively.
- `network_mode: host`, Debian buster (EOL), Python 2 CherryPy web UI with default
  credentials `testuser/12345`, plaintext MQTT with default `mosquitto/mosquitto`
  credentials, secrets sed-ed into configs from env vars.

## Vision

Peter opens Home Assistant and the furnace is simply *there* — a proper device with
auto-discovered sensors, alarms, setpoint controls, and burner start/stop — no YAML
hand-wiring. Changing the boiler setpoint from HA works within seconds and echoes back the
confirmed value from the controller. Meanwhile the attack surface has collapsed: no
default credentials anywhere, TLS + per-client ACLs on the broker, an explicit allowlist
guarding every write to the combustion appliance, and an audit trail of every command.

## Out of Scope

- PellMon itself (pellmonsrv, web UI, RRD graphs, plugins) — replaced entirely; HA
  recorder provides history. RRD data is not migrated.
- Modifying upstream lakelake/pellmondocker or thel1988/pellmon-docker (not our project).
- A Home Assistant custom component (HACS integration) — MQTT Discovery achieves native
  entities without shipping code into HA.
- Cloud access, remote (off-LAN) control, and the StokerCloud service.
- Automatic firmware- or burner-safety logic — the NBE controller's own interlocks remain
  the safety authority; this project only clamps and audits what is sent to it.

## Principles

- Fail closed: any command that cannot be positively validated is rejected and logged.
- The furnace's own controller is the safety authority; software above it may only narrow,
  never widen, what can be commanded.
- Every write to a physical appliance is attributable: authenticated origin + audit line.
- Attack surface not needed for the goal is removed, not merely hardened.
- Compatibility with the existing read topics (`pellmon/<item>`) is preserved so the
  current dashboards keep working during migration.

## Constraints

- Python 3 only, on a currently-supported base image — no EOL runtime anywhere
  (supersedes the earlier keep-PellMon constraint; see Changelog).
- The NBE UDP protocol implementation is vendored from motoz/nbetest (the PellMon
  author's own py3 code), adapted minimally and covered by end-to-end tests against a
  fake controller — no from-scratch protocol re-implementation.
- MQTT is the only integration channel to Home Assistant (HA MQTT Discovery).
- No secret is baked into the image or committed to the repo; runtime injection only.
- Command topics are a NEW namespace `pellmon/set/<item>` — the legacy unvalidated
  `pellmon/settings/#` subscription is not reproduced.
- GPL-3.0 license inherited from pellmonMQTT.py lineage for derived bridge code.

## Goal

`/github/ha-pellmon` contains a buildable, hardened replacement stack — a single-process
Python 3 bridge speaking the NBE UDP protocol directly (vendored motoz/nbetest code) with
HA MQTT Discovery and an allowlist/range-validated, rate-limited, audited write path; a
current-base hardened Dockerfile + compose file; mosquitto TLS/ACL configuration; and
migration + security documentation — with validation logic AND the full protocol path
(including RSA-encrypted writes) proven by a passing test suite against a fake controller.

## Criteria

### Repo & structure
- [ ] ISC-1: `README.md` exists documenting architecture, setup, migration from lakelake/pellmondocker
- [ ] ISC-2: `SECURITY.md` exists with STRIDE threat note covering the MQTT command path
- [ ] ISC-3: Repo is a git repository with an initial commit and `.gitignore` covering `.env`, certs, `__pycache__`
- [ ] ISC-4: `.env.example` documents every runtime secret/variable with no real values
- [ ] ISC-5: `LICENSE` present (GPL-3.0)

### Bridge — read path
- [ ] ISC-6: `bridge/pellmon_ha_bridge.py` compiles under `python3 -m py_compile`
- [ ] ISC-7: Bridge publishes every discovered controller item to `pellmon/<item>` with nbecom-compatible ids (`boiler-temp`, `operating_data-*`), retained
- [ ] ISC-8: Gateway poll loop detects value changes and republishes them (refined: was D-Bus signal)
- [ ] ISC-9: Bridge publishes availability (`online`/`offline`) on `pellmon/bridge/availability` with MQTT LWT
- [ ] ISC-10: Bridge publishes HA MQTT Discovery configs under `homeassistant/<component>/.../config` for discovered items
- [ ] ISC-11: Discovery maps item metadata: R→sensor, R/W numeric+allowlisted→number, enum→select, momentary W→button
- [ ] ISC-12: All discovered entities share one HA device (identifiers, name, manufacturer)
- [ ] ISC-13: Bridge re-publishes discovery + states when `homeassistant/status` announces `online` (HA restart)

### Bridge — control path (fail-closed)
- [ ] ISC-14: Command subscription is ONLY `pellmon/set/<item>` for items present in the configured allowlist
- [ ] ISC-15: Item not in allowlist → no subscription and any received command rejected + logged
- [ ] ISC-16: Payload decoded as UTF-8 with strict error handling; undecodable payload rejected (fixes the bytes bug)
- [ ] ISC-17: Payload length capped (≤32 chars); oversize rejected
- [ ] ISC-18: Numeric commands validated against min/max from device metadata AND config override — the tighter bound wins
- [ ] ISC-19: Out-of-range numeric command rejected, not clamped silently, with reason logged
- [ ] ISC-20: Enum/select commands validated against the item's enum list; non-member rejected
- [ ] ISC-21: Retained command messages are rejected (anti-replay on bridge/broker restart)
- [ ] ISC-22: Per-item minimum write interval enforced (default ≥2 s); violations rejected
- [ ] ISC-23: Global write rate limit enforced (default ≤10 writes/min); violations rejected
- [ ] ISC-24: Every accepted and rejected command produces one structured audit log line (timestamp, item, payload, outcome, reason)
- [ ] ISC-25: Every write result (or exception) published to `pellmon/set/<item>/result` — no swallowed exceptions
- [ ] ISC-26: Controller writes take `str` values only, enforced in nbe/protocol.py (the py3 bytes defect cannot recur)
- [ ] ISC-27: Validation logic lives in `bridge/validation.py` with no paho/gi imports (unit-testable in isolation)

### Bridge — configuration & transport security
- [ ] ISC-28: `bridge/bridge_config.example.yaml` documents allowlist entries with min/max/interval overrides and safe commented candidates
- [ ] ISC-29: Default example allowlist ships EMPTY (read-only unless the user consciously enables items)
- [ ] ISC-30: MQTT username/password read from env/file, never from committed config
- [ ] ISC-31: TLS supported: CA cert, optional client cert/key (mTLS), configurable via config/env
- [ ] ISC-32: TLS certificate verification is ON when TLS is enabled; no `insecure` default
- [ ] ISC-33: Bridge never logs secrets (grep of source shows no password/token in log statements)

### Container & compose hardening
- [ ] ISC-34: `Dockerfile` builds the single py3 bridge on a currently-supported base image (refined: was PellMon-on-buster — see Changelog)
- [ ] ISC-35: [DROPPED — see Decisions 2026-08-15: supervisord/multi-process design removed with PellMon]
- [ ] ISC-36: `docker-compose.yml` uses a dedicated bridge network — no `network_mode: host`
- [ ] ISC-37: Compose sets `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`
- [ ] ISC-38: Root filesystem read-only with tmpfs for `/tmp`
- [ ] ISC-39: No port published on the bridge container (UDP to furnace and MQTT are outbound-only)
- [ ] ISC-40: [DROPPED — see Decisions 2026-08-15: web UI removed entirely, stronger than opt-in]
- [ ] ISC-41: [DROPPED — see Decisions 2026-08-15: no web UI, no web credentials exist]
- [ ] ISC-42: All secrets arrive via env_file/secrets at runtime; `docker compose config` shows none baked in image
- [ ] ISC-43: Container healthcheck probes bridge liveness
- [ ] ISC-44: Resource limits (memory) set in compose

### Broker security
- [ ] ISC-45: `mosquitto/mosquitto.conf.example` disables anonymous access and enables TLS listener 8883
- [ ] ISC-46: `mosquitto/acl.example` gives bridge user readwrite only on `pellmon/#` + discovery publish; HA user read `pellmon/#` + write `pellmon/set/#` only
- [ ] ISC-47: README documents generating per-client credentials and certs (commands included)

### Documentation & migration
- [ ] ISC-48: README migration section: how to move from lakelake/pellmondocker preserving `nbeserial`/`nbepass` and RRD volume
- [ ] ISC-49: README security model section: who may write what, and why the furnace's own interlocks remain authoritative
- [ ] ISC-50: README documents the discovered-writable-items startup log as the way to choose allowlist entries
- [ ] ISC-51: SECURITY.md documents residual risks (512-bit controller RSA, plaintext UDP reads, HA-side authorization) with mitigations (refined: py2-containment risk eliminated by the pivot)

### Tests & gates (SSDLC G2/G3)
- [ ] ISC-52: `bridge/tests/test_validation.py` exists and passes under `python3 -m unittest` / `pytest`
- [ ] ISC-53: Test: bytes payload decode + str-only SetItem argument contract
- [ ] ISC-54: Test: out-of-range value rejected (both metadata bound and config override)
- [ ] ISC-55: Test: non-allowlisted item rejected
- [ ] ISC-56: Test: retained message rejected
- [ ] ISC-57: Test: rate limits (per-item interval + global) enforced
- [ ] ISC-58: Test: enum non-member rejected, member accepted
- [ ] ISC-59: All Python files pass `python3 -m py_compile`; YAML files parse
- [ ] ISC-60: Independent review pass (Forge quality + Cato security audit) completed with findings addressed or accepted in Decisions

### Control-loop stability (added from SystemsThinking CausalLoop analysis)
- [ ] ISC-65: On every rejected command, bridge republishes the authoritative current value to `pellmon/<item>` and the reason to the result topic (kills optimistic-UI false success)
- [ ] ISC-66: No-op suppression — commanded value equal to current value acks on the result topic without calling SetItem (breaks echo-mirror write loops structurally)
- [ ] ISC-67: Every writable discovery config uses `mode: box` (no slider bursts) and every entity carries the availability topic
- [ ] ISC-68: Bridge connects with a clean session (no QoS-1 persistent-session command redelivery on reconnect)

### Architecture pivot (added 2026-08-15 after the buster-EOL challenge)
- [ ] ISC-69: Container runs as an unprivileged user (`USER bridge` in Dockerfile)
- [ ] ISC-70: Protocol end-to-end tests pass against a fake NBE controller over real UDP, including the RSA-encrypted write round trip
- [ ] ISC-71: Discovery refuses a controller whose reported serial differs from `NBE_SERIAL` (tested)
- [ ] ISC-72: No Python 2 code, PellMon source, or D-Bus dependency remains in the repo
- [ ] ISC-73: Base image is a currently-supported release (python:3.13-slim)
- [ ] ISC-74: Healthcheck probes poll-loop liveness via the gateway heartbeat file

### Anti-criteria
- [ ] ISC-61: Anti: no code path subscribes to the legacy `pellmon/settings/#` wildcard
- [ ] ISC-62: Anti: no default credential value appears in any runtime config produced by the stack
- [ ] ISC-63: Anti: no bare `except: pass` in any new Python file
- [ ] ISC-64: Anti: the bridge cannot write any item absent from the allowlist even if the item is R/W on the device

## Test Strategy

| isc | type | check | threshold | tool |
|---|---|---|---|---|
| 1-5 | file | files exist with required sections | present | Read/Bash |
| 6, 59 | build | py_compile + YAML parse | exit 0 | Bash |
| 7-27 | code+unit | code inspection + unit tests on validation.py | tests green | Read/Bash pytest |
| 28-33 | config+code | example config content, env sourcing, TLS params | present, fail-closed | Read/Grep |
| 34-44 | config | Dockerfile/compose inspection; `docker compose config` | hardening flags present | Read/Bash |
| 45-47 | config | mosquitto conf + ACL content | deny-by-default | Read |
| 48-51 | docs | README/SECURITY sections | present | Read |
| 52-58 | unit | pytest suite | all pass | Bash |
| 60 | review | Forge + Cato verdicts | no unaddressed critical | Agent |
| 61-64 | anti | grep for forbidden patterns | zero matches | Grep |

Live end-to-end probe (real furnace + broker) is impossible from this host →
image build/run and on-site control test are [DEFERRED-VERIFY] follow-ups (see Verification).

## Features

| name | description | satisfies | depends_on | parallelizable |
|---|---|---|---|---|
| bridge-core | py3 D-Bus⇄MQTT bridge, read path + discovery | 6-13 | — | no |
| bridge-control | validated command path (validation.py) | 14-27, 61-64 | bridge-core | no |
| bridge-config | YAML config, TLS, secrets sourcing | 28-33 | bridge-core | yes |
| container | Dockerfile, supervisord, init, healthcheck | 34-35, 40-43 | — | yes |
| compose-hardening | compose file, network, caps, ro-fs, limits | 36-39, 42, 44 | container | yes |
| broker-security | mosquitto conf + ACL examples | 45-47 | — | yes |
| docs | README, SECURITY.md, migration, .env.example | 1-5, 47-51 | all | partial |
| tests | unit test suite for validation | 52-59 | bridge-control | yes |
| review | Forge + Cato independent review | 60 | all | no |

## Decisions

- 2026-08-15: Root cause of "read-only today" confirmed: py3 bytes payload → D-Bus `(ss)` TypeError swallowed by bare except in pellmonMQTT.py on_message. Fix is decode+validate, not just decode.
- 2026-08-15: Keep PellMon 0.7.0 (py2) as device gateway rather than re-implementing NBE UDP/XTEA protocol in py3 — proven with this furnace; protocol re-implementation is higher risk to the physical link. Compensating controls: container isolation, no exposed ports, web UI off. Direct-py3-NBE recorded as future option.
- 2026-08-15: New command namespace `pellmon/set/<item>` instead of legacy `pellmon/settings/<item>` — avoids retained legacy commands replaying into the new bridge and makes ACLs cleaner.
- 2026-08-15: ISC soft floor (E4 ≥128) relaxed to 64 — show-your-math: single-author greenfield repo; further splitting would duplicate probes (e.g., one ISC per hardening flag) without adding verification power. Thinking floor (HARD) met with 7 capabilities.
- 2026-08-15: Delegation floor: Forge (EXECUTE quality) + Cato (VERIFY audit) = 2, meets E4 soft floor.

- 2026-08-15: SystemsThinking CLD adopted: reject-then-republish (ISC-65), no-op suppression (ISC-66), box mode + universal availability (ISC-67), clean session (ISC-68). RootCauseAnalysis confirmed swallowing pattern is codebase-wide → ISC-63 stays a blanket ban. progress denominator now 68.
- 2026-08-15: EnterPlanMode skipped — autonomous session; user learning signals favor action over ceremony.

- 2026-08-15 (pivot): Peter rejected the EOL buster base mid-build ("debian:buster LTS ended in 2024") after "do a new container if needed, dont depend on lakelake". Discovered motoz/nbetest — the PellMon author's own py3 NBE protocol implementation. Dropped PellMon/py2/D-Bus/supervisord/web entirely; vendored nbetest with a raw-RSA pycryptodome adapter, seqnum wraparound fix, function-3 range queries, and serial pinning. ISC-35/40/41 tombstoned; ISC-8/26/34/38/51 refined; ISC-69..74 added. Progress denominator now 71 active.

## Changelog

- conjectured: keeping PellMon 0.7.0 as the device gateway was the lowest-risk path because re-implementing the NBE protocol risks the physical furnace link.
  refuted by: every base image able to run PellMon's Python 2 is EOL (buster LTS 2024, bullseye LTS ends 2026-08-31) — "contained EOL" cannot satisfy a tightened-security goal, as Peter pointed out; and motoz/nbetest turned out to be the protocol author's own Python 3 implementation, collapsing the re-implementation risk the conjecture rested on.
  learned: when a constraint is justified by risk, check whether the risk owner has already retired it upstream — the author's py3 code existed for years; also, an end-to-end fake-device test harness (real UDP + real RSA) substitutes for hardware access far better than containment substitutes for currency.
  criterion now: ISC-70 (protocol e2e tests incl. encrypted write), ISC-72 (no py2/PellMon remains), ISC-73 (current base image).

- conjectured: MQTT control required adding a write path to a read-only forwarder.
  refuted by: reading pellmonMQTT.py — a write path exists, subscribed to every R/W item, but is both broken (py3 bytes TypeError silently swallowed) and dangerously unvalidated.
  learned: the integration was "read-only" by accident, not by design; security must assume the write path exists and gate it, not assume absence.
  criterion now: ISC-14..27 (fail-closed validated control path), ISC-61 (legacy wildcard must not return).

## Verification

- [DEFERRED-VERIFY] Image build + live furnace control test require Docker + on-site network — follow-up task: `ha-pellmon-live-deploy` (build image, run against real broker, set boiler setpoint from HA, observe echo).
