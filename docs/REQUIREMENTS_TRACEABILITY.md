# NetHawk — requirements traceability matrix

Every requirement is taken from the project proposal deck (`NetHawk.pptx` /
`NetHawk.pdf`, 13 slides, dated 6 Sep 2026) and from the course brief for the
MVP. The proposal and the implementation are treated as **separate sources of
truth**: where they disagree, the disagreement is recorded rather than resolved
by redefining the project.

**Status key**

| Status | Meaning |
|--------|---------|
| **VERIFIED** | Implemented, and its behaviour was executed and observed |
| **IMPLEMENTED, NOT VERIFIED** | Code exists; execution has not been demonstrated |
| **PARTIALLY IMPLEMENTED** | Only part of the required behaviour exists |
| **BLOCKED** | Needs data, permissions or action that is unavailable here |
| **NOT IMPLEMENTED** | Missing |

Evidence references point at `docs/TESTING.md` sections and at named tests in
`tests/`. Run `python3 -m pytest` to reproduce the test evidence.

---

## A. Network and capture layer

| ID | Requirement (source) | Implementation | Verification method | Status | Evidence |
|----|---------------------|----------------|---------------------|--------|----------|
| R1 | "Live **802.11 frames** on the monitored WLAN" (slide 5/6) | `capture/live.py` captures IP/TCP/UDP from a Wi-Fi interface; no 802.11 frame parsing | Live capture on `en0` observed; no 802.11 code exists | **PARTIALLY IMPLEMENTED** | TESTING §4c. Gap recorded in PROPOSAL_ALIGNMENT #1–3 |
| R2 | Packet capture from the wireless interface (slide 5) | `LiveCapture` (Scapy `AsyncSniffer`) | Captured real packets on `lo0` and `en0`, flows reached the pipeline, events persisted | **VERIFIED** | TESTING §4c: 84 pkts `lo0`, 65 pkts `en0` |
| R3 | Interface discovery and selection | `list_interfaces()`, `default_interface()`, `--iface` | 20 interfaces enumerated; `en0` confirmed as default route | **VERIFIED** | `scripts/check_capture.py` output, TESTING §4c |
| R4 | Capture permission handling + graceful failure | `capture_available()`, fallback in `NetHawkEngine.start_monitoring` | Probe run privileged and unprivileged; invalid interface and invalid filter both fall back | **VERIFIED** | `test_live_mode_falls_back_to_demo_without_privileges`, `test_nonexistent_interface_falls_back_to_demo`, `test_invalid_filter_falls_back_to_demo` |
| R5 | Traffic replay from prerecorded capture (course brief: "prerecorded/sample traffic") | `capture/replay.py`, `capture/sample.py`, `--replay` | 981 real packets parsed → 24 flows → events | **VERIFIED** | TESTING §4b |
| R6 | Bidirectional flow assembly with expiry | `capture/flows.py` (`FlowTable`, 5-tuple, idle timeout) | Both directions merge into one flow; direction set by first packet; derived rates consistent | **VERIFIED** | `test_both_directions_land_in_one_flow`, `test_flow_direction_is_set_by_first_packet`, `test_derived_rates_are_consistent` |
| R7 | Packet counters, src/dst, timestamps, protocol | `LiveCapture._handle_packet`, `Flow` | Counters and addresses observed in live and replay runs; IPv6 and non-IP handled | **VERIFIED** | `test_ipv6_packets_are_handled`, `test_non_ip_packets_are_ignored` |
| R8 | 802.11 monitor-mode capture | `monitor_mode_available()` reports only; never enabled | No adapter in monitor mode; no 802.11 parsing implemented | **NOT IMPLEMENTED** (deliberate) | README §8, VIVA Q10 |
| R9 | Device identification by MAC / SSID / BSSID (slide 6) | Devices keyed by **IP address** in `devices.identifier` | Inspected schema and live events | **NOT IMPLEMENTED** | PROPOSAL_ALIGNMENT #3 |
| R10 | Rogue-AP / evil-twin / deauthentication detection (implied slide 2) | None | No such code | **NOT IMPLEMENTED** | PROPOSAL_ALIGNMENT #4 |

## B. Preprocessing, features and dataset

| ID | Requirement | Implementation | Verification method | Status | Evidence |
|----|-------------|----------------|---------------------|--------|----------|
| R11 | Traffic preprocessing / cleaning (slide 6) | `preprocessing/clean.py` | Padded headers, aliases, `Infinity`/`NaN`, duplicates, non-numeric all handled | **VERIFIED** | `test_cleaning_handles_real_cicids_quirks`, `test_vector_from_dict_orders_and_sanitises` |
| R12 | Feature extraction to a defined schema | `schema.FEATURE_NAMES` (27 CIC-IDS2017 names) + 3 adapters | All three adapters produce exactly the schema | **VERIFIED** | `test_*_adapter_produces_full_schema` |
| R13 | Common interface `extract_features(record)` | `features/adapters.py` dispatcher | Dataset row, demo flow and live `Flow` all accepted | **VERIFIED** | `test_dispatcher_picks_the_right_adapter` |
| R14 | Dataset preparation and labelling (slide 10, phase 3) | `datasets/loader.py`, `scripts/prepare_dataset.py` | Loader exercised against CSVs reproducing the real files' quirks | **VERIFIED** (loader) | TESTING §6 |
| R15 | Train on genuine CIC-IDS2017 | Loader + `scripts/train_model.py` support it | Dataset not present on this machine; needs UNB account + terms acceptance | **BLOCKED** | TESTING §8 item 1 |
| R16 | Leakage prevention across evaluation splits | Cross-file de-duplication; seeded random sampling | Constructed overlapping files → 100 duplicates removed; label-ordered file → 7 classes kept vs 1 under truncation | **VERIFIED** | `test_cross_file_duplicates_are_dropped_before_splitting`, `test_large_files_are_sampled_randomly_not_truncated` |
| R17 | AWID / AWID3 (802.11) dataset integration | Not integrated; adapter seam exists | No code | **NOT IMPLEMENTED** (future work) | data/README §3, VIVA Q8 |

## C. Machine learning

| ID | Requirement | Implementation | Verification method | Status | Evidence |
|----|-------------|----------------|---------------------|--------|----------|
| R18 | Random Forest classifier (slide 9) | `ml/model.py` (`n_estimators=200`, `class_weight=balanced_subsample`) | Trained, evaluated, persisted, reloaded | **VERIFIED** | `test_training_produces_usable_metrics`, `test_save_and_reload_roundtrip` |
| R19 | Binary NORMAL vs ATTACK | Derived from the category so the two cannot disagree | Reported each run | **VERIFIED** | `models/metrics.json` → `binary` |
| R20 | Multiclass attack classification | 7 classes learned from the demo labels | Per-class report + confusion matrix | **VERIFIED (demo data)** | `scripts/evaluate_model.py` |
| R21 | Model persistence (joblib) | `ml/model.save`, `ml/predictor.load` | Round-trip; corrupt/foreign/ drifted bundles rejected with clear errors | **VERIFIED** | `test_corrupt_model_file_raises_a_clear_error`, `test_feature_order_drift_is_detected_at_load` |
| R22 | Evaluation methodology | Stratified 75/25 split, macro-F1, confusion matrix, k-fold CV, feature-ablation audit | Executed | **VERIFIED (demo data)** | TESTING §6 |
| R23 | Real-world accuracy figures | — | Cannot exist without R15 | **BLOCKED** | TESTING §6, §8 |
| R24 | Synthetic-vs-real provenance recorded and displayed | `metadata.is_demo_data`, `metrics.caveat`, dashboard `MODEL` badge | Badge observed as `DEMO DATA`; metrics file carries the caveat | **VERIFIED** | `test_demo_training_is_flagged_as_demo`, TESTING §7 |
| R25 | Live/offline feature compatibility examined | Same schema enforced; distribution gap measured | Flood + scan detected on real packets; benign HTTPS/DNS false positives recorded | **VERIFIED (and documented as a limitation)** | TESTING §6 cross-domain table |

## D. Decision, response and persistence

| ID | Requirement | Implementation | Verification method | Status | Evidence |
|----|-------------|----------------|---------------------|--------|----------|
| R26 | Transparent risk scoring, 0–100, with bands | `risk/scoring.py` (0.50 severity + 0.30 confidence + 0.20 intensity) | Bounds, ordering, banding, damping, non-finite inputs | **VERIFIED** | `tests/test_risk.py`, `test_non_finite_rates_do_not_inflate_intensity` |
| R27 | Risk explanation shown to the user | `RiskResult.explanation`, stored per event, shown in the detail panel | Arithmetic observed in the UI and in SQLite | **VERIFIED** | TESTING §7 |
| R28 | Decision engine with LOW / MEDIUM / HIGH policy | `response/engine.py` | Policy per level; escalation reproducible | **VERIFIED** | `test_decision_policy_per_level`, `test_simulation_escalates_from_recon_to_flood` |
| R29 | Controlled response, clearly simulated | `enforcement_enabled = False`; `[SIMULATED]` label; footer banner | Every response row carries `simulated=1` | **VERIFIED** | `test_all_responses_are_simulated` |
| R30 | No destructive/real network action | No enforcement backend exists | Code inspected; no firewall/deauth/injection calls | **VERIFIED** | `response/engine.py` docstring |
| R31 | SQLite tables: events, devices, system_status (+ blocklist) | `database/db.py` | Schema asserted; CRUD and aggregates exercised | **VERIFIED** | `tests/test_database.py` |
| R32 | Event fields required by the brief | All present incl. `mode`, `simulated`, `explanation`, `features_json` | Inspected rows | **VERIFIED** | `test_insert_and_read_event` |
| R33 | Persistence across restart | History reloaded from SQLite, features rehydrated | Second dashboard instance shows full detail | **VERIFIED** | `test_history_reloaded_from_sqlite_populates_detail_panel` |
| R34 | Database resilience | Corrupt file moved aside and recreated; unwritable path reported | Corrupt and read-only cases executed | **VERIFIED** | `test_corrupt_database_is_moved_aside_and_recreated`, `test_unwritable_database_location_raises_a_clear_error` |
| R35 | Thread-safe writes | Connection per operation | 6 threads × 40 writes → no loss, no errors | **VERIFIED** | `test_concurrent_writers_do_not_lose_rows` |
| R36 | Reports | `utils/report.py`, Export Report button | Report generated and written | **VERIFIED** | `test_report_contains_the_expected_sections` |

## E. Application, UI and operations

| ID | Requirement | Implementation | Verification method | Status | Evidence |
|----|-------------|----------------|---------------------|--------|----------|
| R37 | Desktop dashboard (CustomTkinter), dark theme | `dashboard/app.py`, `dashboard/theme.py` | Built and driven; every control exercised | **VERIFIED** | TESTING §7 |
| R38 | Header: status, mode, model provenance | Three pills | Observed switching DEMO/LIVE/REPLAY | **VERIFIED** | TESTING §7 |
| R39 | Summary cards: devices, packets, threats, risk | 4 `Card` widgets + risk bar | Values update during simulation | **VERIFIED** | `test_simulation_updates_table_alerts_and_cards` |
| R40 | Recent alerts panel | `CTkScrollableFrame`, risk-coloured rows | Populated during simulation | **VERIFIED** | same |
| R41 | Attack history table | `ttk.Treeview`, 8 columns incl. MODE | Rows inserted, capped, colour-tagged | **VERIFIED** | same |
| R42 | Detail panel on selection | `_on_select_event` | All sections present for live, replay and reloaded events | **VERIFIED** | `test_detail_panel_shows_full_explanation` |
| R43 | Controls: start, stop, simulate, replay, probe, clear, export, mode switch | Buttons + segmented control | Each driven in sequence | **VERIFIED** | TESTING §7 |
| R44 | Real-time updates without freezing the GUI | Worker threads + 200 ms queue drain | Probe moved off the Tk thread; no cross-thread Tk calls | **VERIFIED** | `test_capture_probe_never_touches_tk_from_a_worker_thread` |
| R45 | Clean shutdown and restart | `_closing` guard, `after_cancel`, thread joins | 6 start/stop cycles, stop during simulation, stop during replay → 0 threads left | **VERIFIED** | `test_repeated_start_stop_cycles_are_clean`, `test_stopping_during_a_replay_leaves_no_threads` |
| R46 | Worker exceptions do not kill monitoring | try/except in each loop + notices | Predictor forced to raise on every record; thread survived | **VERIFIED** | `test_monitor_thread_survives_a_failing_predictor` |
| R47 | DEMO mode works with no adapter, no dataset, no privileges | `capture/demo.py` + auto-train + auto-seed | Cold start from an empty tree | **VERIFIED** | TESTING §2 |
| R48 | One-command launch | `python3 app.py` | Auto-creates data, model, database | **VERIFIED** | TESTING §2, §3 |
| R49 | OS-aware paths, no hardcoded absolutes | `config.py` + `NETHAWK_*` overrides | `--paths` output; env override test | **VERIFIED** | `test_paths_are_relative_to_the_project_root`, `test_env_override_is_respected` |
| R50 | Standalone desktop packaging (slide 9: PyInstaller) | `packaging/nethawk.spec`, frozen-aware `config.py` | 132 MB bundle built; the executable was run (dashboard wrote 17 events, `--replay` parsed 981 packets, `--paths` confirmed path relocation) | **VERIFIED** (unsigned) | TESTING §9, `test_frozen_layout_relocates_writable_paths` |
| R51 | Clean-environment installation | `requirements.txt` | Fresh venv, newer library majors (pandas 3.0, sklearn 1.9, scapy 2.8) | **VERIFIED** | TESTING §5 |
| R52 | Automated testing (slide 10, phase 8) | `tests/` (11 files, 156 cases) | Full suite executed in both the dev and a clean environment | **VERIFIED** | TESTING §1, §5 |
| R53 | Documentation set | README + 7 docs | Commands re-executed as written | **VERIFIED** | TESTING §3 |

---

## Contradictions between sources of truth

These are recorded, not resolved by redefinition. Wording fixes are in
`docs/PROPOSAL_ALIGNMENT.md`.

1. **The title and slides 2/5/6 promise 802.11/Wi-Fi frame-level intrusion
   detection. The implementation detects network-layer intrusions on traffic
   carried over Wi-Fi.** This is the single biggest gap. Closing it needs
   monitor-mode capture plus an 802.11 dataset (AWID3) — see "What closing the
   Wi-Fi gap requires" below.
2. **Slide 6 lists MAC/SSID/BSSID.** Devices are keyed by IP.
3. **Slide 9 lists PyInstaller as part of the stack.** Packaging status is in
   `docs/TESTING.md` §9; the proposal implied it was planned, not done.
4. **Slide 11 shows mock dashboard values.** The deck labels them as mock,
   which is accurate; real screenshots can now replace them.
5. **CIC-IDS2017 is the chosen dataset but is not 802.11-specific.** The deck's
   slide 3 already cites AWID/AWID3 correctly, so the gap is acknowledged
   there; the risk is claiming Wi-Fi attack coverage in the viva.

## What closing the Wi-Fi gap requires (scoped, not implemented)

For honesty in the viva, here is the concrete work, with why it was not done:

1. **Monitor-mode capable adapter + `airport`/`tcpdump -I` setup.** Apple
   removed `airport` monitor mode on recent macOS; a USB adapter with an
   `mt76`/`rt2800` chipset plus Linux is the practical path. Not available here.
2. **802.11 frame parsing** — `scapy.layers.dot11` (`Dot11`, `Dot11Beacon`,
   `Dot11Deauth`), extracting addr1/addr2/addr3, SSID, BSSID, channel, RSSI.
   This is a new adapter, not a change to the pipeline.
3. **A labelled 802.11 dataset** — AWID3, which requires a request to the
   authors. Its features are frame-level, so it needs its own feature schema
   and its own trained model.
4. **New attack categories** — deauthentication, disassociation, evil twin,
   KRACK — plus rules in `detection/classifier.py` and severities in
   `schema.CATEGORY_SEVERITY`.
5. **Safety review.** Capturing 802.11 management frames collects data about
   nearby networks that are not the user's, which is why this MVP deliberately
   does not do it.

Items 1 and 3 are external blockers (hardware, dataset access). Items 2, 4 and
5 are feasible once those exist, and the adapter seam is already in place.

## Summary counts

| Status | Count |
|--------|-------|
| VERIFIED | 43 (incl. R50 packaging) |
| PARTIALLY IMPLEMENTED | 1 (R1) |
| BLOCKED | 2 (R15, R23 — both the real dataset) |
| NOT IMPLEMENTED | 4 (R8, R9, R10, R17) |

| **Total requirements tracked** | **50** |

NetHawk is complete and verified as a **network-layer** IDS with a Wi-Fi-facing
capture path. It is **not** complete against the proposal's 802.11 frame-level
promise, and that is stated rather than papered over.
