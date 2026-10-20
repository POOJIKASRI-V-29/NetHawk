# NetHawk — final verification record

**Date:** 20 October 2026
**Machine:** MacBook (Apple Silicon, arm64), macOS Darwin 25.5.0
**Verified by:** re-executing every check from an empty working tree, after all
code changes were complete.

This document records the *final* run. Detailed per-area evidence is in
[TESTING.md](TESTING.md); requirement-level status is in
[REQUIREMENTS_TRACEABILITY.md](REQUIREMENTS_TRACEABILITY.md).

---

## 1. Final run results

| Check | Command | Result |
|-------|---------|--------|
| Cold start from an empty tree | `rm -rf models/* database/*.db data/demo/*` then `python3 app.py --headless --simulate --duration 6` | **PASS, 16 s** — generated the demo dataset, trained the model, created the database, logged 15 events (10 threats) |
| Full test suite | `python3 -m pytest` | **156 passed**, 1 expected warning |
| Clean-environment suite | fresh venv, `pip install -r requirements.txt`, `pytest` | **156 passed** with pandas 3.0.6 / scikit-learn 1.9.1 / numpy 2.5.4 / scapy 2.8.0 |
| Replay of real packets | `python3 app.py --replay` | **PASS** — sample capture auto-generated, 981 packets parsed, 24 flows, flood detected as DDoS at risk 74 (HIGH) |
| Every documented command | 16 commands, exit codes checked | **16 passed, 0 failed** (includes the two packaged-binary commands) |
| Packaged artifact | `pyinstaller packaging/nethawk.spec` then run it | **PASS** — 132 MB bundle; `--paths`, `--replay`, `--headless --simulate` and the dashboard all run; the packaged GUI wrote 17 events to its own SQLite database |
| Live capture, loopback | `app.py --headless --mode live --iface lo0 --filter "tcp port 8088"` | **PASS** — real packets captured, 5 flows, `NORMAL`, risk 0, `mode=LIVE` |
| Live capture, Wi-Fi `en0` | host-pinned filter, self-generated HTTPS | **PASS** — 65 packets, 3 IPv6 flows, `NORMAL`, persisted, no threads leaked |
| Risk/decision/database consistency | audit script, 8 cross-checks over 15 events | **0 inconsistencies** |
| UI drive, every control | widget state read back after each step | **PASS** — 14 steps, see TESTING §10 |
| Git diff review | `git diff --cached --name-status` | 30 files changed, +1853/−225, **0 file deletions**, 3 intentional doc renames |

## 2. Final project statistics

| Metric | Value |
|--------|-------|
| Python source (src + scripts + tests + app.py) | 5 767 lines |
| Documentation (README + docs + data/README) | 2 535 lines |
| Python modules under `src/` | 34 |
| Test files / test functions / test cases | 11 / 124 / **156** |
| Scripts | 6 |
| Requirements tracked | 50 |
| Defects found and fixed across the two completion passes | 22 (8 + 14) |
| Packaged bundle | 132 MB, builds in ~80 s |

## 3. Model in the repository at the time of this run

| Field | Value |
|-------|-------|
| `data_source` | `DEMO_SYNTHETIC` |
| `is_demo_data` | `true` |
| Rows | 10 800 (synthetic) |
| Multiclass accuracy | 0.9978 |
| Macro-F1 | 0.9981 |
| 5-fold CV macro-F1 | 0.9982 ± 0.0004 |
| Classes | Botnet, Brute Force, DDoS, DoS, Normal, Port Scan, Web Attack |
| Random seed | 42 |
| Dataset fingerprint | `bfc5f307c98d0d61a3700ab85ebd7dc0` |
| Repeat with | `python3 scripts/train_model.py --demo --seed 42 --test-size 0.25` |

**These are demo-data figures.** They measure separability of the demo
generator's own classes, not real-world intrusion detection. The dashboard
shows a `MODEL: DEMO DATA` badge for exactly this reason.

## 4. Completion status by category

### Verified — implemented and demonstrated (42 requirements)

Packet capture and interface discovery · PCAP replay · flow assembly and
expiry · micro-flow aggregation · feature extraction across three adapters ·
dataset cleaning and leakage guards · model training, evaluation, persistence
and reproducibility · threat classification · risk scoring with visible
arithmetic · decision policy · simulated response and blocklist · SQLite
persistence, corruption recovery and thread safety · dashboard with every
control, empty states and long histories · reports · configuration and path
overrides · CLI · clean shutdown and restart · graceful degradation ·
clean-environment installation · **PyInstaller packaging** · automated testing ·
documentation set.

### Demonstrated using synthetic data only

- Attack **classification accuracy**. Every metric in this repository comes
  from the synthetic demo dataset. Attack *detection on real packets* was
  demonstrated separately (replay and live), including its false positives.

### Implemented but not verified on real data (1 requirement)

- **Training on genuine CIC-IDS2017.** The loader is verified against CSVs
  that reproduce the real files' quirks — padded headers, `Infinity`/`NaN`,
  latin-1 labels, extra columns, cross-file duplicates — but the real dataset
  is not present on this machine, so no real-data metrics exist.

### Blocked — needs action outside this environment (2 requirements)

| Blocker | Why | Who can clear it |
|---------|-----|------------------|
| CIC-IDS2017 download | Requires a UNB account and acceptance of their terms | The project owner |
| Real-data metrics | Depends on the above | The project owner |

### Not implemented — deliberate, and corrected in the deck (4 requirements)

| Gap | Why | What it would take |
|-----|-----|--------------------|
| 802.11 frame parsing / monitor mode | No monitor-mode adapter; recent macOS removed `airport` monitor mode; capturing management frames would collect data about networks that are not ours | A USB adapter + Linux, `scapy.layers.dot11` parsing, a new feature adapter |
| MAC / SSID / BSSID device identity | Follows from the above; devices are keyed by IP | Same as above |
| Rogue-AP / evil-twin / deauthentication detection | Needs 802.11 frames **and** a labelled 802.11 dataset | Monitor mode + AWID3 + new categories |
| Real response enforcement | A student project must not be able to cut off a real network | An explicit opt-in firewall backend with an audit trail |

Also not done: **code-signing/notarisation** of the bundle (needs an Apple
Developer account), so macOS warns when the bundle runs on another Mac.

## 5. Honest statement of completeness

NetHawk is **complete and verified as a network-layer intrusion-detection
system with a Wi-Fi-facing capture path, a transparent risk model, a simulated
response policy, local persistence and a desktop dashboard** — demonstrated on
three independent traffic sources, packaged as a standalone bundle, and covered
by 156 automated tests.

It is **not complete against the proposal's 802.11 frame-level promise**, and
it has **no real-world accuracy figures**, because the real dataset could not be
obtained here. Both gaps are stated in the README, the viva notes and the deck
corrections rather than being worked around.

Nothing in this repository claims a result it did not produce. The measured
false positives on benign replayed traffic are published in TESTING §8 instead
of being tuned away.

## 6. What the project owner must still do

1. **Download CIC-IDS2017** (~220 MB, UNB terms acceptance) into
   `data/cicids2017/`, then run:
   ```bash
   python3 scripts/train_model.py
   python3 scripts/evaluate_model.py --cv 5 --audit-port
   ```
   The `MODEL` badge will change from `DEMO DATA` to `CIC-IDS2017` and the
   metrics become real-data metrics.
2. **Re-run `python3 scripts/check_capture.py`** on the demo machine on the day
   — BPF permissions can change after a reboot or OS update.
3. **Apply the 8 deck corrections** in
   [PROPOSAL_ALIGNMENT.md](PROPOSAL_ALIGNMENT.md).
4. **Take a real screenshot** of the running dashboard for deck slide 11
   (screen capture is not available to the automation used here).
5. **Optional:** code-sign the bundle if it will run on another Mac.
