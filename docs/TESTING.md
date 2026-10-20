# NetHawk — testing & verification report

**Development machine:** MacBook (Apple Silicon, arm64), macOS Darwin 25.5.0
**Primary environment:** Python 3.13.9 (Anaconda) · scikit-learn 1.7.2 ·
pandas 2.3.3 · numpy 2.3.5 · scapy 2.7.0 · customtkinter 6.0.0
**Clean environment:** Python 3.13.9 venv · scikit-learn 1.9.1 · pandas 3.0.6 ·
numpy 2.5.4 · scapy 2.8.0 · pytest 9.1.1
**Date of this run:** 20 October 2026

Every result below was produced by running the command shown. Nothing here is
estimated, predicted or carried over from an earlier report without being
re-executed.

---

## 1. Automated test suite

```bash
python3 -m pytest
```

**Result: 156 passed, 1 warning, in ~39 s** (124 test functions; 156 cases
after parametrisation). The single warning is scikit-learn noting a
single-label confusion matrix, raised by the test that deliberately trains on a
one-class dataset.

| File | Tests | Covers |
|------|-------|--------|
| `test_app_integration.py` | 14 | CLI flags, config env overrides, frozen-path relocation, packaging spec, report generation, restart, thread-free shutdown |
| `test_classifier.py` | 5 | Label normalisation (incl. latin-1 `Web Attack – Brute Force`, bytes labels), binary mapping, unknown labels |
| `test_dashboard.py` | 11 | Widget construction, cards/alerts/table updates, detail panel, replay button, provenance badge on first frame, history truncation notice, clear, idempotent close, thread-safe probe, history reload |
| `test_database.py` | 8 | Schema, CRUD, aggregates, device upsert accumulation, blocklist, clear, directory creation |
| `test_datasets.py` | 12 | Demo generation, CIC-IDS2017 cleaning quirks, cross-file duplicate leakage, random vs head sampling, error messages |
| `test_features.py` | 8 | All three adapters, flow direction, bidirectional merge, derived-rate consistency, empty flow |
| `test_model.py` | 7 | Training metrics, demo-data flagging, save/reload round-trip, seed reproducibility, reproducibility record, prediction stability |
| `test_pipeline.py` | 12 | Prediction structure, benign/attack classification, decision policy, simulated-only responses, engine stages, escalation, LIVE→DEMO fallback |
| `test_replay.py` | 11 | Real Scapy dissection, flow assembly, IPv6, non-IP rejection, flood detection, micro-flow aggregation |
| `test_risk.py` | 8 | Bounds, ordering, banding, intensity damping, explanation contents |
| `test_robustness.py` | 28 | Malformed captures, corrupt/foreign/drifted models, incomplete features, non-finite values, unusable datasets, invalid filters, database corruption and permissions, concurrency, thread hygiene, failing predictor |

## 2. Cold-start reproducibility

```bash
rm -rf models/*.joblib models/metrics.json database/nethawk.db data/demo/*.csv data/demo/*.pcap
python3 app.py --headless --simulate --duration 6
```

**Result: PASS.** With no model, no database, no demo dataset and no sample
capture, the application generated the demo dataset, trained the Random Forest,
created `database/nethawk.db`, ran the pipeline and logged events — in ~14 s
with no manual steps. `python3 app.py --replay` on the same empty tree
generated the sample capture itself (981 packets) before analysing it.

## 3. Documented commands

Every command in `README.md` and `docs/DEMO.md` was executed and its exit code
checked.

| Command | Exit | Result |
|---------|------|--------|
| `python3 -m pytest` | 0 | 156 passed |
| `python3 app.py` | 0 | dashboard opens, monitoring starts |
| `python3 app.py --help` | 0 | all flags listed |
| `python3 app.py --paths` | 0 | resolved locations printed |
| `python3 app.py --headless --simulate --duration 4` | 0 | full pipeline in terminal |
| `python3 app.py --replay` | 0 | 981 packets → 24 flows |
| `python3 app.py --headless --mode live --iface lo0 --filter "tcp port 8088"` | 0 | real packets analysed |
| `python3 scripts/check_capture.py` | 0 | reports capture available |
| `python3 scripts/prepare_dataset.py` | 0 | dataset report |
| `python3 scripts/prepare_dataset.py --make-demo --rows 1200` | 0 | 10 800 rows |
| `python3 scripts/make_sample_pcap.py` | 0 | 981 packets written |
| `python3 scripts/train_model.py` | 0 | model + metrics + provenance |
| `python3 scripts/train_model.py --demo` | 0 | forced demo dataset |
| `python3 scripts/train_model.py --data-dir /nonexistent` | 1 | clean error, no traceback |
| `python3 scripts/evaluate_model.py --cv 5 --audit-port` | 0 | full evaluation |
| `python3 scripts/run_demo.py --fresh` | 0 | scripted demo + report |
| `sqlite3 database/nethawk.db "SELECT ..."` | 0 | rows returned |

## 4. Pipeline verified end to end — three traffic sources

### 4a. DEMO mode (generated traffic)

```bash
python3 scripts/run_demo.py --fresh
```

Escalation ladder observed in order, from one attacker host:

| Stage | Detected as | Confidence | Risk | Level | Response |
|-------|-------------|-----------|------|-------|----------|
| Port scan ×3 | Port Scan | 1.00 | 59–64 | MEDIUM | WARN + flag suspicious |
| FTP brute force ×2 | Brute Force | 1.00 | 72–73 | HIGH | ALERT + BLOCK (simulated) |
| DoS flood ×3 | DoS | 1.00 | 87–91 | HIGH | ALERT + BLOCK (simulated) |
| DDoS flood ×2 | DDoS | 0.96–1.00 | 94–98 | HIGH | ALERT + BLOCK (simulated) |

Benign background traffic: `NORMAL`, risk 0, action `MONITOR`. All events
persisted; blocklist and device statuses updated.

**Reproducibility:** with a fixed `demo_seed`, two independent runs produced an
identical `(attack_type, risk_score)` sequence — verified in the Phase 6 audit
(§7).

### 4b. REPLAY mode (real Scapy packet dissection, no privileges)

```bash
python3 scripts/make_sample_pcap.py && python3 app.py --replay
```

**981 real packets parsed → 24 flows analysed**, `mode = REPLAY`.

| Traffic in the capture file | Flows | Detected as | Risk |
|---|---|---|---|
| SYN flood, 900 packets → port 80 | 1 (aggregated) | **DDoS** | **74 HIGH** |
| SYN scan across 18 ports | 21 | **Port Scan** | 58–60 MEDIUM |
| Benign HTTPS conversations ×2 | 2 | *Web Attack* — **false positive** | 63–67 MEDIUM |
| Benign DNS exchanges | 4 | *Port Scan* — **false positive** | 48 MEDIUM |

The packets are synthetic (crafted in memory by `scripts/make_sample_pcap.py`
and written straight to disk — no socket is opened), but they are well-formed
Ethernet/IP/TCP/UDP frames, and the path that reads them is the real one:
`sniff(offline=...)` → Scapy dissection → flow assembly → micro-flow
aggregation → feature extraction → model → risk → response → SQLite.

**Malformed-input cases tested** (all produce a notice, never a traceback):
zero-byte file, random bytes, valid header with no packets, a packet file
truncated mid-record, and a directory passed as a path.

### 4c. LIVE mode (real captured packets) — **VERIFIED**

Two independent tests, each generating its own traffic and pinning a BPF filter
so no unrelated traffic was captured.

**Loopback (fully local, nothing left the machine):**

```bash
python3 -m http.server 8088 --bind 127.0.0.1          # terminal 1
python3 app.py --headless --mode live --duration 13 \
        --iface lo0 --filter "tcp port 8088"          # terminal 2
curl -s "http://127.0.0.1:8088/?n=1"  # ×5             # terminal 3
```

Result: **real packets captured on `lo0` → 5 flows → classified `NORMAL`,
risk 0, `mode=LIVE`, persisted to SQLite.** An earlier run of the same shape
captured 84 packets → 6 flows (14 packets / 5 168 bytes each).

**Real Wi-Fi interface (`en0`):**

Filter pinned to the addresses of one host the test itself contacted, three
HTTPS requests.

Result: **65 packets captured on `en0` → 3 flows → `NORMAL`, confidence
0.54–0.56, risk 0, `mode=LIVE`**, persisted; no threads left behind. The flows
were IPv6 TCP/443, exercising the IPv6 code path.

> **Why live capture works here without `sudo`:** Wireshark's `ChmodBPF`
> LaunchDaemon is installed on this Mac
> (`/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist`, dated 22 Apr) and the
> account is in the `access_bpf` group, so `/dev/bpf*` is group-readable
> (`crw-rw---- root access_bpf`). On a Mac without that helper, live mode needs
> `sudo`, and NetHawk falls back to DEMO mode with the reason displayed.
> **This is environment-specific — re-run `scripts/check_capture.py` on the
> demo machine on the day.**

**Finding recorded during this testing:** an IPv4-only BPF filter captured
**0 packets** because macOS preferred IPv6 for the connection, while the
request itself succeeded. Interface *and* address family both matter.
`scripts/check_capture.py` and README §19 now say so.

**Capture failure paths tested:** unprivileged probe → DEMO fallback;
nonexistent interface (`nosuchif0`) → DEMO fallback; invalid BPF filter
(`!!! nope`) → rejected before starting, DEMO fallback with the reason.

## 5. Clean-environment installation

```bash
python3 -m venv venv && venv/bin/python -m pip install -r requirements.txt
venv/bin/python -m pytest
```

The fresh environment resolved **newer major versions** than the development
environment — pandas **3.0.6** (a major release), scikit-learn **1.9.1**,
numpy **2.5.4**, scapy **2.8.0**, pytest **9.1.1**.

| Check in the clean venv | Result |
|---|---|
| `pip install -r requirements.txt` | PASS (~30 s) |
| Full test suite | **156 passed** |
| Cold start (`app.py --headless --simulate`) | PASS |
| `app.py --replay` | PASS — 981 packets, 24 flows |
| `scripts/train_model.py` | PASS — accuracy 0.9978, identical to the dev environment |
| `scripts/evaluate_model.py --cv 3` | PASS — macro-F1 0.9981 ± 0.0004 |
| PyQt5 import | **absent** — confirms the dashboard needs only CustomTkinter/tkinter |

So `requirements.txt` is complete and the project is forward-compatible with
the current releases of its dependencies.

## 6. Robustness and failure handling

20+ hostile inputs were probed directly. Everything below either handles the
input or fails with a clear, actionable message — no tracebacks, no silent
wrong answers.

| Input / situation | Behaviour |
|---|---|
| Capture file: 0 bytes, random bytes, header-only, truncated, directory | Notice, pipeline continues |
| Model file: corrupt, not a bundle, not a classifier | `ModelLoadError` naming the fix command |
| Model trained on a different feature **order** | `ModelLoadError` — "same features in a different order" |
| Model trained on a different feature **set** | `ModelLoadError` listing the differences |
| Feature record missing keys / not a dict | `FeatureSchemaError` naming the count and the adapters |
| Feature values NaN / inf / negative / text (complete record) | Sanitised to 0, prediction proceeds |
| Risk scoring with NaN, inf, negative, `None`, out-of-range confidence, unknown category | Score stays within 0–100 |
| Dataset: zero usable rows | `ValueError` pointing at `data/README.md` |
| Dataset: fewer than 10 samples per class | `ValueError` explaining why |
| Dataset: a single class | Trains, and records an explicit `single_class_warning` |
| CSV: whole column `Infinity`/`NaN` | Cleaned to finite values |
| Malformed CSV (random bytes) | Clean error, exit 1 |
| Database: corrupt file | Moved aside to `*.corrupt`, fresh database created, launch continues |
| Database: unwritable directory | `DatabaseUnavailableError` suggesting `NETHAWK_DB_PATH` |
| Database: 6 threads × 40 writes | 240/240 rows, 240/240 device packets, 0 errors |
| Interface: nonexistent | DEMO fallback |
| Filter: invalid BPF | Rejected before capture starts; DEMO fallback |
| Predictor raising on **every** record | Monitoring thread survives; error notices emitted |
| 6× start/stop cycles | No thread leaks, restart works |
| Stop during a running simulation | Clean, 0 threads left |
| Stop during a running replay | Clean, 0 threads left |
| Window closed twice | Idempotent, no `TclError` |
| 410 events pushed into the table | Capped at 400 rows, header says "showing 400 of 410", UI responsive, nothing lost in SQLite |

### Defects found and fixed during this pass

| # | Defect | How it was found | Status |
|---|--------|------------------|--------|
| 1 | Malformed capture files raised instead of reporting (blocking replay path) | probe | fixed + test |
| 2 | Stopping during a replay **leaked two threads** | probe | fixed + test |
| 3 | An invalid BPF filter was accepted; NetHawk reported "LIVE capture started" and then saw zero packets forever | probe | fixed + test |
| 4 | A corrupt `nethawk.db` crashed startup with a raw `sqlite3.DatabaseError` | probe | fixed + test |
| 5 | An unwritable database path raised `OperationalError` with no guidance | probe | fixed + test |
| 6 | A corrupt model file raised a bare `KeyError: 110` | probe | fixed + test |
| 7 | Feature-schema drift produced a cryptic sklearn message at predict time instead of a clear one at load time | probe | fixed + test |
| 8 | **NaN rates scored as maximum intensity** — missing data looked exactly like a flood (risk 90 for a record of NaNs) | probe | fixed + test |
| 9 | An incomplete feature record was silently zero-padded and still produced a confident label, hiding schema changes | probe | fixed + test |
| 10 | A zero-row dataset was accepted, failing later and less clearly | probe | fixed + test |
| 11 | A single-class dataset trained silently, producing meaningless metrics | probe | fixed + test |
| 12 | **Packaged app:** joblib spawned helper processes that re-executed the frozen app (`unrecognized arguments: -B -S -I -c from multiprocessing...`) | packaging test | fixed (`freeze_support()` + single-threaded inference) + test |
| 13 | The `MODEL` provenance badge showed `LOADING` on the first frame | UI drive | fixed + test |
| 14 | A truncated history table gave no indication that it was truncated | UI drive | fixed + test |

Items 2, 3, 8, 9 and 12 were capable of producing a **wrong answer or a silent
failure**, not just an ugly error.

## 7. Risk, decision and persistence consistency audit

An audit script re-derived every number independently and cross-checked four
representations (formula → stored explanation → database row → dashboard).

| Check | Result |
|---|---|
| Weights sum to 1.0 (0.50 + 0.30 + 0.20) | PASS |
| Score recomputed from stored features matches the stored score | PASS, 15/15 events |
| The arithmetic in the stored explanation ends in the stored score and level | PASS |
| The three displayed terms sum to the score (±1 rounding) | PASS |
| Risk band matches the documented thresholds | PASS |
| Severity weight used equals the published table value | PASS |
| Database row agrees with what the dashboard was handed (type, score, level, prediction, response, mode) | PASS |
| Response matches the policy for the level (LOW→MONITOR, MEDIUM→WARN, HIGH→ALERT) | PASS |
| Every response recorded as simulated | PASS |
| Benign events presented as benign (risk 0) | 6/6 |
| Blocklist entries == HIGH-risk events | 6 == 6 |
| Escalation sequence reproducible with a fixed seed | PASS (identical across runs) |

**Total inconsistencies found: 0.**

## 8. Machine-learning validation

```bash
python3 scripts/evaluate_model.py --cv 5 --audit-port
```

**Training data: `DEMO_SYNTHETIC` — 10 800 synthetic rows generated by
`src/nethawk/datasets/synthetic.py`.** The figures below describe how well the
model separates the *demo generator's* classes. They are **not** real-world
intrusion-detection results and must not be presented as experimental findings.

| Metric (demo data) | Value |
|---|---|
| Multiclass accuracy | 0.9978 |
| Macro-F1 | 0.9981 |
| 5-fold stratified CV macro-F1 | 0.9982 ± 0.0004 |
| Binary attack precision / recall / F1 | 0.9994 / 0.9972 / 0.9983 |
| Class imbalance | 3:1 (benign over-represented) |

Per-class F1: Brute Force, DDoS, DoS, Port Scan, Web Attack 1.00; Normal 0.997;
Botnet 0.99. Confusion matrix: 5 Botnet→Normal, 1 Normal→Botnet.

**Why the numbers are suspiciously high, stated plainly:** the training data
and the demo traffic come from the same generator, so the classes are far more
cleanly separated than real traffic. This is the expected outcome of
synthetic-data training, not evidence of a strong detector. The honest tests
are §4b and §4c, where the model meets traffic it did not generate.

### Reproducibility record

`models/metrics.json` now carries everything needed to repeat a run:

```
random_seed        : 42
test_size          : 0.25
split              : sklearn train_test_split, stratified on the normalised label
duplicates_removed : <count>
dataset fingerprint: sha256 (first 32 hex chars of a stable hash of the data)
model params       : n_estimators=200, min_samples_leaf=2,
                     class_weight=balanced_subsample, random_state=<seed>
command            : python3 scripts/train_model.py --demo --seed 42 --test-size 0.25
library versions   : python / scikit-learn / pandas / numpy
```

Verified: the same seed produces an identical accuracy, macro-F1 and confusion
matrix; a save/reload cycle produces identical predictions on 120 rows; dataset
generation is deterministic per seed and differs across seeds.

### Leakage audit — two real bugs found and fixed

1. **Cross-file duplicate leakage.** Each CSV was de-duplicated individually,
   but rows shared between two CIC-IDS2017 files survived into the concatenated
   frame and could land in both the train and the test split. Fixed by
   de-duplicating after concatenation; the count is reported by the loader.
   Regression test: a constructed pair of overlapping files yields **100**
   removed duplicates.
2. **Biased sampling.** `nrows=150_000` kept the *first* N rows of a
   time-ordered file. On a label-ordered test file, head-truncation yielded
   **1 class** while random sampling yielded **7**. CIC-IDS2017 clusters each
   day's attacks in a time window, so truncation can silently drop whole attack
   classes. Fixed with seeded random sampling.

### Feature-reliance audit

In CIC-IDS2017 each attack targets a specific service, so `Destination Port`
can act as a shortcut that will not generalise. Retraining with it zeroed out:

| Macro-F1 with port | Macro-F1 without port | Drop |
|---|---|---|
| 0.9981 | 0.9973 | 0.0008 |

The model does **not** lean on the port; behavioural features (`PSH Flag
Count` 0.118, `Total Fwd Packets` 0.091, `ACK Flag Count` 0.087,
`Flow Packets/s` 0.072) carry the decision.

### Cross-domain compatibility — measured, not assumed

The feature *schema* is identical across all three sources (all 27 names,
enforced by tests and by a load-time schema check). The feature
*distributions* are not, and this was measured on real parsed packets:

| Real traffic | Correct answer | NetHawk said | Verdict |
|---|---|---|---|
| 900-packet SYN flood | attack | **DDoS, risk 74 HIGH** | correct |
| 18-port SYN scan | attack | **Port Scan, risk 58–60** | correct |
| Benign HTTPS conversation (replay) | normal | Web Attack, 0.54–0.67 conf | **false positive** |
| Benign DNS exchange (replay) | normal | Port Scan, 0.60 conf | **false positive** |
| Benign HTTP on loopback (live) | normal | **Normal, risk 0** | correct |
| Benign HTTPS on `en0` (live) | normal | **Normal, 0.54–0.56 conf** | correct |

**Conclusion for the viva:** attack patterns transfer well; benign traffic
transfers unevenly, with false positives on short encrypted and UDP flows, and
confidence on real traffic (~0.5) is far below confidence on demo traffic
(~1.0) — the model is visibly less certain outside its training distribution.
The cause is that it is trained on synthetic flow statistics rather than
CICFlowMeter features from real captures.

**What was deliberately *not* done:** no threshold was tuned and no filter was
added to suppress these false positives. Hiding them would have produced a
better-looking demo and a false claim. The fix is training on the real dataset.

## 9. Packaging (PyInstaller) — built and tested

```bash
pyinstaller packaging/nethawk.spec --noconfirm
```

| Fact | Value |
|---|---|
| Build result | **success**, exit 0 |
| Build time | ~80 s |
| Bundle size | **132 MB** (one-directory) |
| Output | `dist/NetHawk/NetHawk` |

**The artifact was executed, not just built:**

| Test on the built executable | Result |
|---|---|
| `./dist/NetHawk/NetHawk --paths` | Reports `run mode: PyInstaller bundle`, resources in `_internal`, writable root relocated to `~/Library/Application Support/NetHawk` |
| First launch seeding | Copied the model, metrics, demo CSV and sample pcap out of the read-only bundle into the writable tree |
| `--headless --simulate --duration 5` | 26 events, 17 threats, DDoS detected at risk 94 |
| `--replay` | 981 packets → 24 flows, DDoS at risk 74 |
| Dashboard launch | Process ran 30 s, **no errors**, wrote **17 events** to the packaged SQLite database in DEMO mode |
| multiprocessing error check | **0 occurrences** after the fix |

Two changes were required and are worth knowing about:
`multiprocessing.freeze_support()` in `app.py`, and forcing single-threaded
inference. Without them joblib spawns helper processes that re-execute the
frozen application, which fails with
`unrecognized arguments: -B -S -I -c from multiprocessing.resource_tracker...`.
Single-threaded inference is also simply correct here: NetHawk predicts one
flow at a time, where a parallel backend is pure overhead (measured ~10 ms per
prediction).

**Not done:** the bundle is **unsigned and un-notarised**, so macOS Gatekeeper
will warn when it is copied to another Mac (right-click → Open once). Signing
needs an Apple Developer account.

## 10. User-interface verification

The real dashboard was driven through every control, in order, with the widget
state read back after each step. Screen capture is not available to the
automation in this environment, so verification is by **widget-state
inspection on the real Tk widgets** plus the SQLite side effects — not by
screenshot. That limitation is stated rather than worked around.

| Step | Observed |
|---|---|
| Launch | 1390×810 window; empty state shows placeholders in alerts and detail panel |
| Badges on first frame | `IDLE` / `DEMO` / `DEMO DATA` (no placeholder) |
| Start Monitoring | `MONITORING`, rows appear |
| Run Security Simulation | 19 rows, 7 alert cards, cards read devices 5 / packets 9 636 / threats 10 / risk HIGH |
| Replay Sample PCAP | table contains both `DEMO` (24) and `REPLAY` (24) rows; database agrees |
| Event detail on a REPLAY row | title `DDoS · HIGH`; all six sections present; arithmetic line `severity(DDoS)=95 x 0.50 = 47.5 \| confidence=42.1 x 0.30 = 12.6 \| intensity=70.0 x 0.20 = 14.0 => risk 74/100 (HIGH)` |
| 410 extra events | table capped at 400, header reads "showing 400 of 410 stored events", UI responsive, SQLite holds all |
| Export Report | file written, path shown in the footer |
| Check Live Capture | runs off the Tk thread; result "Live capture available. Interfaces: 20. Monitor mode: no." |
| Mode switch DEMO↔LIVE | engine, pill and segmented control all agree |
| Stop Monitoring | `IDLE`, buttons re-enabled |
| Clear Demo Data | table empty, database empty, placeholder restored |
| Close (twice) | idempotent; 0 `nethawk-*` threads remain |

The packaged dashboard was additionally launched from `dist/NetHawk/NetHawk`
and confirmed to run and persist events (§9).

## 11. Status summary

### Verified end to end

- DEMO pipeline with the full escalation ladder, risk scoring, simulated response, SQLite logging
- REPLAY of real packets through genuine Scapy dissection
- **LIVE packet capture on loopback and on the real Wi-Fi interface (`en0`)**
- Dashboard: every control, empty states, long histories, detail panel, provenance badge
- SQLite persistence across all four tables and across restarts; corruption recovery
- Cold-start reproducibility from an empty working tree
- Clean-environment installation with newer dependency majors
- Model training, evaluation, cross-validation, persistence, seed reproducibility, provenance recording
- Risk/decision/database/dashboard consistency (0 inconsistencies)
- Clean shutdown with no leaked threads under every stop path tested
- Graceful degradation for privileges, interfaces, filters, files, models and databases
- **PyInstaller packaging: built and the artifact exercised**

### Implemented but not verified on real data

- **Training on genuine CIC-IDS2017.** The loader is verified against CSVs that
  reproduce the real files' quirks, but the real dataset is not on this machine,
  so no real-data metrics exist. Blocked on the download (§12).

### Not implemented (deliberate, and stated in the deck corrections)

- 802.11 frame parsing and monitor-mode capture
- Device identification by MAC / SSID / BSSID (devices are keyed by IP)
- Rogue-AP, evil-twin and deauthentication detection
- AWID/AWID3 integration
- Real response enforcement (every response is simulated)
- Code-signing/notarisation of the bundle

## 12. Manual steps that remain

1. **To report real intrusion-detection metrics**, download CIC-IDS2017
   (`MachineLearningCSV.zip`, ~220 MB) from
   <https://www.unb.ca/cic/datasets/ids-2017.html> — it requires accepting
   UNB's terms — unzip it, copy the `*.pcap_ISCX.csv` files into
   `data/cicids2017/`, then:
   ```bash
   python3 scripts/train_model.py
   python3 scripts/evaluate_model.py --cv 5 --audit-port
   ```
   This could not be done here: it needs an account and terms acceptance.
2. **Confirm live capture on the demo machine on the day:**
   `python3 scripts/check_capture.py`. BPF permissions can change after a
   reboot or an OS update.
3. **Correct the presentation** using `docs/PROPOSAL_ALIGNMENT.md`.
4. **Optional:** replace the mock dashboard screenshot on deck slide 11 with a
   real screenshot of the running app (automation here cannot capture the
   screen; a human can).
5. **Optional:** code-sign the bundle if it will be run on another Mac.
