# NetHawk — submission checklist

Status as of **20 October 2026**. Tick the manual items before you submit.

---

## 1. Repository contents

| Item | Status | Where |
|------|--------|-------|
| Source code, modular by layer | ✅ | `src/nethawk/` (14 modules) |
| Single-command entry point | ✅ | `app.py` |
| Scripts: train, evaluate, prepare data, build sample capture, capture diagnostic, terminal demo | ✅ | `scripts/` (6 scripts) |
| Automated tests | ✅ | `tests/` — **110 passing** |
| Dependency manifest | ✅ | `requirements.txt` |
| Test configuration | ✅ | `pytest.ini` |
| Version control | ✅ | git repository with commit history |
| `.gitignore` excludes datasets, DB, models, logs, reports | ✅ | `.gitignore` |
| README: overview, architecture, install, run, modes, dataset, ML, features, risk, response, schema, testing, limitations, future work, troubleshooting | ✅ | `README.md` (18 sections) |
| Architecture documentation | ✅ | `docs/architecture.md` |
| Demo script | ✅ | `docs/demo.md` |
| Viva preparation | ✅ | `docs/viva.md` (27 Q&As) |
| Verification report | ✅ | `docs/TESTING.md` |
| Proposal-vs-code audit | ✅ | `docs/PROPOSAL_ALIGNMENT.md` |
| Dataset setup instructions | ✅ | `data/README.md` |
| Reproducibility: works from an empty tree | ✅ | verified cold start, `docs/TESTING.md` §2 |

## 2. Functional requirements from the proposal

| Requirement | Status |
|-------------|--------|
| Packet capture | ✅ verified (live on `lo0` + `en0`, and PCAP replay) |
| Traffic preprocessing | ✅ |
| Feature extraction (3 adapters, one schema) | ✅ |
| ML detection (Random Forest) | ✅ |
| Attack classification (8 categories) | ✅ |
| Risk scoring (explainable, 0–100) | ✅ |
| Decision engine (LOW/MEDIUM/HIGH policy) | ✅ |
| Alert + controlled response | ✅ simulated only, labelled everywhere |
| SQLite logging (events, devices, system_status, blocklist) | ✅ |
| Desktop dashboard (cards, alerts, history, detail, controls) | ✅ |
| Real-time updates without freezing the GUI | ✅ queue + worker threads |
| Reports | ✅ `Export Report` / `utils/report.py` |
| Graceful degradation when capture is unavailable | ✅ tested |
| 802.11 / monitor-mode frame analysis | ❌ not implemented (deliberate) |
| PyInstaller packaging | ❌ not implemented |
| Training on real CIC-IDS2017 | ⛔ blocked — dataset not downloaded |

## 3. Things you must do manually

- [ ] **Correct the presentation deck** using `docs/PROPOSAL_ALIGNMENT.md`.
      The two that matter: slide 5/6 say "802.11 frames" (we analyse IP/TCP/UDP
      flows) and slide 9 lists PyInstaller (not implemented).
- [ ] **Decide on real-data training.** To report genuine metrics, download
      CIC-IDS2017 (~220 MB, needs accepting UNB's terms), place the CSVs in
      `data/cicids2017/`, then run:
      ```bash
      python3 scripts/train_model.py
      python3 scripts/evaluate_model.py --cv 5 --audit-port
      ```
      If you do not do this, say "trained on our synthetic demo dataset" in the
      presentation. Do **not** present 0.998 as an intrusion-detection result.
- [ ] **Re-run `python3 scripts/check_capture.py`** on the demo machine on the
      day (BPF permissions can change after a reboot).
- [ ] **Replace the mock dashboard screenshot** on deck slide 11 with a real one.
- [ ] **Rehearse the demo once** end to end from `docs/demo.md` (≈5 minutes).
- [ ] **Clear the database** right before presenting: click **Clear Demo Data**
      or run `python3 scripts/run_demo.py --fresh`.

## 4. Five-minute pre-demo smoke test

```bash
cd nethawk
python3 -m pytest                       # expect 110 passed
python3 scripts/check_capture.py        # know whether live mode will work today
python3 scripts/make_sample_pcap.py     # ensure the sample capture exists
python3 app.py --replay                 # expect 981 packets, 24 flows, one DDoS
python3 app.py                          # dashboard: Start → Run Security Simulation
```

## 5. Claims you may make

* A complete, working IDS pipeline from packet capture to dashboard, verified
  end to end on three traffic sources.
* Live packet capture verified on this machine (quote `docs/TESTING.md` §4c).
* Real Scapy packet dissection demonstrated on any machine via replay mode.
* An explainable risk score whose arithmetic is shown for every event.
* A leakage-resistant dataset pipeline, with two real bugs found and fixed
  during the audit, each covered by a regression test.
* 110 automated tests covering every layer.

## 6. Claims you may NOT make

* ❌ "99.8% accurate at detecting intrusions" — those are demo-data numbers.
* ❌ "We detect Wi-Fi attacks / deauthentication / evil twin / rogue APs."
* ❌ "CIC-IDS2017 is a Wi-Fi dataset" — it is not; AWID/AWID3 are.
* ❌ "We capture and analyse 802.11 frames" — IP/TCP/UDP only, no monitor mode.
* ❌ "The system blocks attackers" — the response is simulated.
* ❌ "We tested it by attacking a network" — traffic was generated locally.
* ❌ "It is packaged as a standalone executable" — not yet.
