# NetHawk — testing & verification report

Machine: MacBook (Apple Silicon, arm64), macOS Darwin 25.5.0
Python 3.13.9 (Anaconda) · scikit-learn 1.7.2 · pandas 2.3.3 · numpy 2.3.5 ·
scapy 2.7.0 · customtkinter 6.0.0
Date of this run: **20 October 2026**

Every result below was produced by running the command shown. Nothing in this
document is estimated or predicted.

---

## 1. Automated test suite

```bash
python3 -m pytest
```

**Result: 110 passed in ~22 s.** (84 test functions; 110 cases after
parametrisation.)

| File | Tests | Covers |
|------|-------|--------|
| `test_app_integration.py` | 8 | CLI flag parsing, config env overrides, report generation, restart, thread-free shutdown |
| `test_classifier.py` | 5 | Label normalisation (incl. latin-1 `Web Attack – Brute Force`), binary mapping, unknown labels |
| `test_dashboard.py` | 8 | Widget construction, simulation updating table/alerts/cards, detail panel, replay button, clear, idempotent close, history reload, thread-safe probe |
| `test_database.py` | 8 | Schema, insert/read, aggregates, device upsert accumulation, blocklist, clear, directory creation |
| `test_datasets.py` | 12 | Demo generation, CIC-IDS2017 cleaning quirks, **cross-file duplicate leakage**, **random vs head sampling**, error messages |
| `test_features.py` | 8 | All three adapters, flow direction, bidirectional merge, derived-rate consistency, empty flow |
| `test_model.py` | 4 | Training metrics, demo-data flagging, save/reload round-trip, missing-model error |
| `test_pipeline.py` | 12 | Prediction structure, benign/attack classification, decision policy, simulated-only responses, engine stages, escalation, LIVE→DEMO fallback |
| `test_replay.py` | 11 | Real Scapy dissection, flow assembly, IPv6, non-IP rejection, flood detection, **micro-flow aggregation** |
| `test_risk.py` | 8 | Bounds, ordering, banding, intensity damping, explanation contents |

## 2. Cold-start reproducibility

```bash
rm -rf models/*.joblib models/metrics.json database/nethawk.db data/demo/*.csv data/demo/*.pcap
python3 app.py --headless --simulate --duration 8
```

**Result: PASS.** With no model, no database and no demo data present, the app
generated the demo dataset, trained the Random Forest, created
`database/nethawk.db`, ran the pipeline and logged events — in ~14 s, no
manual steps.

## 3. Documented commands

Every command in `README.md` and `docs/demo.md` was executed:

| Command | Result |
|---------|--------|
| `python3 -m pytest` | PASS (110) |
| `python3 app.py` | PASS — dashboard opens, monitoring starts |
| `python3 app.py --headless --simulate --duration 4` | PASS |
| `python3 app.py --replay` | PASS — 981 packets, 24 flows |
| `python3 app.py --headless --mode live --iface lo0 --filter "tcp port 8077"` | PASS — real packets analysed |
| `python3 app.py --help` | PASS |
| `python3 scripts/prepare_dataset.py` | PASS |
| `python3 scripts/prepare_dataset.py --make-demo --rows 1200` | PASS — 10 800 rows |
| `python3 scripts/train_model.py` | PASS |
| `python3 scripts/train_model.py --demo` | PASS |
| `python3 scripts/train_model.py --data-dir /nonexistent` | PASS — clean error + exit 1 (no traceback) |
| `python3 scripts/evaluate_model.py --cv 5 --audit-port` | PASS |
| `python3 scripts/make_sample_pcap.py` | PASS — 981 packets written |
| `python3 scripts/check_capture.py` | PASS |
| `python3 scripts/run_demo.py --fresh` | PASS |
| `sqlite3 database/nethawk.db "SELECT ... FROM events ..."` | PASS |

## 4. Pipeline verified end to end — three traffic sources

### 4a. DEMO mode (generated traffic)

```bash
python3 scripts/run_demo.py --fresh
```

Escalation ladder observed, in order, from one attacker host:

| Stage | Detected as | Confidence | Risk | Level | Response |
|-------|-------------|-----------|------|-------|----------|
| Port scan ×3 | Port Scan | 1.00 | 59–64 | MEDIUM | WARN + flag suspicious |
| FTP brute force ×2 | Brute Force | 1.00 | 72–73 | HIGH | ALERT + BLOCK (simulated) |
| DoS flood ×2 | DoS | 1.00 | 87–91 | HIGH | ALERT + BLOCK (simulated) |
| DDoS flood ×2 | DDoS | 0.99–1.00 | 95–98 | HIGH | ALERT + BLOCK (simulated) |

Benign background traffic was classified `NORMAL`, risk 0, action `MONITOR`.
All events persisted; blocklist and device statuses updated.

### 4b. REPLAY mode (real Scapy packet dissection, no privileges)

```bash
python3 scripts/make_sample_pcap.py && python3 app.py --replay
```

**981 crafted-but-real packets parsed → 24 flows analysed.**

| Traffic in the capture file | Flows | Detected as | Risk |
|---|---|---|---|
| SYN flood, 900 packets → port 80 | 1 (aggregated) | **DDoS** | **74 HIGH** |
| Port scan across 18 ports | 21 | **Port Scan** | 58–60 MEDIUM |
| Benign HTTPS conversations ×2 | 2 | *Web Attack* (false positive) | 63–67 MEDIUM |
| Benign DNS exchanges | 4 | *Port Scan* (false positive) | 48 MEDIUM |

This is the real packet path: `sniff(offline=...)` → Scapy dissection → flow
assembly → micro-flow aggregation → feature extraction → model → risk →
response → SQLite, with `mode = REPLAY`.

**The false positives are reported, not hidden** — see §6.

### 4c. LIVE mode (real captured packets) — **VERIFIED**

Two independent tests, both with traffic generated by the test itself and a BPF
filter pinned so that no unrelated traffic was captured.

**Loopback (fully local, nothing left the machine):**

```bash
python3 app.py --headless --mode live --duration 12 --iface lo0 --filter "tcp port 8077"
# (a local python http.server on 127.0.0.1:8077 was requested 4 times)
```

Result: **84 packets captured → 6 flows → classified `NORMAL`, risk 0, `mode=LIVE`,
persisted to SQLite.** Each flow: 14 packets / 5 168 bytes / dport 8099.

**Real Wi-Fi interface (en0):**

Filter pinned to the addresses of one host the test itself contacted
(`host <ipv6> or host <ipv4>`), one HTTPS GET ×3.

Result: **66 packets captured on en0 → 3 flows → `NORMAL`, confidence 0.55,
risk 0, `mode=LIVE`.** The flows were IPv6 TCP/443, confirming the IPv6 code
path works.

> **Why live capture works here without `sudo`:** Wireshark's `ChmodBPF`
> LaunchDaemon is installed on this Mac (`/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist`)
> and the user is in the `access_bpf` group, so `/dev/bpf*` is group-readable
> (`crw-rw---- root access_bpf`). On a Mac without that, live mode needs
> `sudo` — and NetHawk falls back to DEMO mode with the reason displayed.

**Finding during this test:** an IPv4-only BPF filter captured **0 packets**
because macOS preferred IPv6 for the connection. Interface and address family
both matter when choosing a filter; `scripts/check_capture.py` and the README
troubleshooting section now say so.

## 5. Robustness, threading and shutdown

| Check | Command / method | Result |
|-------|------------------|--------|
| No GUI freeze during capture/inference | engine runs on worker threads; UI drains a queue every 200 ms | PASS |
| Capture probe does not block the UI | `_probe_capture` moved to a worker thread (was a 2 s block on the Tk thread) | FIXED + PASS |
| Clean shutdown | `test_shutdown_leaves_no_background_threads` | PASS — 0 `nethawk-*` threads remain |
| Monitoring restart | `test_monitoring_can_be_restarted` | PASS |
| Double window close | `test_closing_cancels_scheduled_callbacks` | FIXED + PASS (close is now idempotent) |
| Tk callbacks after destroy | `_closing` guard + `after_cancel` | FIXED + PASS |
| History survives restart | `test_history_reloaded_from_sqlite_populates_detail_panel` | FIXED + PASS (features rehydrated from `features_json`) |
| Missing capture file | `test_missing_pcap_is_reported_not_raised` | PASS — notice, not crash |
| Bad dataset path | `python3 scripts/train_model.py --data-dir /nonexistent` | FIXED + PASS — clean message, exit 1 |
| Malformed CSV | random bytes in the dataset dir | PASS — clean message, no traceback |
| Non-IP packets (ARP) | `test_non_ip_packets_are_ignored` | PASS |
| LIVE without privileges | `test_live_mode_falls_back_to_demo_without_privileges` | PASS |

## 6. Machine-learning validation

```bash
python3 scripts/evaluate_model.py --cv 5 --audit-port
```

**Training data: `DEMO_SYNTHETIC` (10 800 synthetic rows).** The numbers below
describe how well the model separates the *demo generator's* classes. They are
**not** real-world intrusion-detection results.

| Metric (demo data) | Value |
|---|---|
| Multiclass accuracy | 0.9978 |
| Macro-F1 | 0.9981 |
| 5-fold CV macro-F1 | 0.9982 ± 0.0004 |
| Binary attack precision / recall / F1 | 0.9994 / 0.9972 / 0.9983 |
| Class imbalance | 3:1 (benign over-represented) |

Per-class F1 (demo data): Brute Force, DDoS, DoS, Port Scan, Web Attack 1.00;
Normal 0.997; Botnet 0.99. Confusion matrix: 5 Botnet→Normal, 1 Normal→Botnet.

### Leakage audit — two real bugs found and fixed

1. **Cross-file duplicate leakage.** `prepare_dataframe` de-duplicated each CSV
   individually, but rows shared between two CIC-IDS2017 files survived into
   the concatenated frame and could land in both the train and the test split.
   Fixed by de-duplicating after concatenation; the count is reported.
   Regression test: `test_cross_file_duplicates_are_dropped_before_splitting`
   (a constructed pair of overlapping files yields 100 removed duplicates).
2. **Biased sampling.** `nrows=150_000` kept the *first* N rows of a
   time-ordered file. On a label-ordered test file, head-truncation yielded
   **1 class**; random sampling yielded **7**. CIC-IDS2017 clusters each day's
   attacks in a time window, so truncation can silently drop whole attack
   classes. Fixed with seeded random sampling.
   Regression test: `test_large_files_are_sampled_randomly_not_truncated`.

### Feature-reliance audit

In CIC-IDS2017 each attack targets a specific service, so `Destination Port`
can act as a shortcut that will not generalise. Retraining with that feature
zeroed out:

| Macro-F1 with port | Macro-F1 without port | Drop |
|---|---|---|
| 0.9981 | 0.9973 | 0.0008 |

The model does **not** lean on the port; behavioural features (`PSH Flag Count`,
`Total Fwd Packets`, `ACK Flag Count`, `Flow Packets/s`) carry the decision.

### Cross-domain compatibility — measured, not assumed

The feature *schema* is identical across the three sources (all 27 names match,
verified by `test_*_adapter_produces_full_schema`). The feature *distributions*
are not, and this was measured on replayed real packets:

| Real traffic | Correct answer | NetHawk said | Verdict |
|---|---|---|---|
| 900-packet SYN flood | attack | **DDoS, risk 74 HIGH** | correct |
| 18-port SYN scan | attack | **Port Scan, risk 58–60** | correct |
| Benign HTTPS conversation | normal | Web Attack, 0.54–0.67 conf | **false positive** |
| Benign DNS exchange | normal | Port Scan, 0.60 conf | **false positive** |
| Benign HTTP on loopback (live) | normal | **Normal, risk 0** | correct |
| Benign HTTPS on en0 (live) | normal | **Normal, 0.55 conf** | correct |

**Conclusion to state in the viva:** attack patterns transfer well; benign
traffic transfers unevenly, with false positives on short encrypted and UDP
flows and noticeably lower confidence (~0.5) on real traffic than on demo data
(~1.0). The cause is that the model is trained on synthetic flow statistics,
not on CICFlowMeter features from real captures. This is a genuine measured
limitation, not a hypothetical one.

## 7. Status summary

### Verified end to end (evidence above)

- Demo pipeline with full escalation ladder, risk scoring, simulated response, SQLite logging
- PCAP replay through the real Scapy dissection path
- **Live packet capture on loopback and on the real Wi-Fi interface (en0)**
- Dashboard: cards, alerts, history table, detail panel, controls, replay, clear, export, idempotent close
- SQLite persistence across all four tables and across restarts
- Cold-start reproducibility from an empty working tree
- Model training, evaluation, cross-validation, persistence, demo-data flagging
- Clean shutdown with no leaked threads
- Graceful LIVE→DEMO degradation

### Implemented but not verified on real data

- **Training on genuine CIC-IDS2017.** The loader is verified against CSVs that
  reproduce the real files' quirks (padded headers, `Infinity`/`NaN`,
  latin-1 labels, extra columns) — but the real 220 MB dataset is not present on
  this machine, so no real-data metrics exist. Blocked on the download (§8).
- **802.11 / monitor-mode capture.** Not implemented, deliberately. Monitor mode
  is detected and reported; nothing depends on it.
- **Real enforcement.** Deliberately absent. Every response is `[SIMULATED]`.

### Not implemented

- PyInstaller packaging (claimed on deck slide 9 — see `docs/PROPOSAL_ALIGNMENT.md`)
- AWID/AWID3 integration (future work; the adapter seam exists)
- Rogue-AP / evil-twin / deauthentication detection (needs 802.11 capture + AWID3)

## 8. Manual steps still required

1. **To report real intrusion-detection metrics**, download CIC-IDS2017
   (`MachineLearningCSV.zip`, ~220 MB, requires accepting UNB's terms at
   <https://www.unb.ca/cic/datasets/ids-2017.html>), unzip, copy the
   `*.pcap_ISCX.csv` files into `data/cicids2017/`, then:
   ```bash
   python3 scripts/train_model.py && python3 scripts/evaluate_model.py --cv 5 --audit-port
   ```
   I could not do this: it needs an account and terms acceptance.
2. **To confirm live capture on your Mac after a reboot**, run
   `python3 scripts/check_capture.py`. If it reports unavailable, either run
   NetHawk with `sudo`, or reinstall Wireshark's ChmodBPF helper.
3. **Correct the presentation** using `docs/PROPOSAL_ALIGNMENT.md` (8 wording
   fixes; the 802.11-frame and PyInstaller claims are the important ones).
4. **Optional:** replace the mock dashboard screenshot on deck slide 11 with a
   real one from the running app.
