# NetHawk

**AI-Powered Real-Time Wi-Fi Intrusion Detection & Automated Response System**
Computer Networks course project · MVP implementation

NetHawk is a standalone desktop application that watches network traffic,
extracts flow features, classifies traffic with a machine-learning model,
scores the risk of each detection, applies a controlled response policy, logs
everything to a local SQLite database, and presents it all in a dark-themed
monitoring console.

Everything runs locally. No cloud services, no server database, no network is
attacked or modified.

---

## 1. Project overview

```
Traffic (generated demo flows | live captured packets)
   -> Packet capture / traffic replay
   -> Traffic preprocessing
   -> Feature extraction        (27 CIC-IDS2017-style flow features)
   -> ML detection              (Random Forest, scikit-learn)
   -> Attack classification     (canonical category)
   -> Risk scoring              (transparent 0-100 formula)
   -> Decision engine           (LOW / MEDIUM / HIGH policy)
   -> Alert + controlled response (SIMULATED)
   -> SQLite logging
   -> Desktop dashboard
```

The system has **three traffic sources**:

| Mode | Traffic source | Requirements | Purpose |
|------|----------------|--------------|---------|
| **DEMO** (default) | Locally generated synthetic flows | None — works on any laptop | Classroom demonstration, development, testing |
| **REPLAY** | Real packets read from a `.pcap` file | None | Demonstrating the **real** Scapy packet-parsing path with no privileges |
| **LIVE** | Real packets captured from an interface | Capture privileges (see §8) | Analysing actual traffic on the machine |

LIVE mode **automatically falls back to DEMO mode** with a clear on-screen
message if packet capture is not permitted, so the demonstration can never fail
because of privileges or hardware.

Verification status of each path is recorded in
[docs/TESTING.md](docs/TESTING.md) — all three are verified working on the
development Mac.

---

## 2. Architecture

```
NETWORK LAYER        Wi-Fi / Ethernet interface, IP-TCP/UDP traffic
                             |
CAPTURE + AI/ML      capture/live.py   -> flows.py (flow assembly)
LAYER                capture/demo.py   -> controlled demo traffic
                     preprocessing/clean.py
                     features/adapters.py  (Dataset | Live | Demo adapters)
                     ml/predictor.py       (Random Forest inference)
                     detection/classifier.py (label -> category)
                             |
DECISION LAYER       risk/scoring.py       (0-100 risk score + reason)
                     response/engine.py    (policy -> simulated response)
                             |
APPLICATION LAYER    database/db.py        (SQLite: events/devices/status/blocklist)
                     dashboard/app.py      (CustomTkinter console)
                     utils/report.py       (text reports)
```

`src/nethawk/engine.py` is the orchestrator that wires these together and runs
them on background threads.

Full detail: [docs/architecture.md](docs/architecture.md).
Verification evidence: [docs/TESTING.md](docs/TESTING.md).
Demo script: [docs/demo.md](docs/demo.md). Viva prep: [docs/viva.md](docs/viva.md).

---

## 3. Technologies

| Component | Technology | Why |
|-----------|-----------|-----|
| Language | Python 3.10+ | One language for capture, ML and GUI |
| Packet capture | Scapy | Reads live frames, dissects IP/TCP/UDP |
| Data handling | pandas, numpy | Cleaning and feature tables |
| ML | scikit-learn, Random Forest | Strong tabular baseline, explainable in a viva |
| Persistence | SQLite (`sqlite3`, stdlib) | Embedded, no server, single file |
| GUI | CustomTkinter (+ ttk.Treeview) | Native-feeling dark desktop app |
| Model storage | joblib | Standard scikit-learn persistence |
| Tests | pytest | 110 tests over the whole pipeline |

---

## 4. Installation

```bash
cd nethawk
python3 -m pip install -r requirements.txt
```

macOS note: Tkinter ships with the standard python.org and Anaconda builds. If
`import tkinter` fails on a Homebrew Python, install `python-tk`.

---

## 5. Running the project

```bash
python3 app.py
```

That single command opens the dashboard, trains a model automatically if none
exists, creates the SQLite database, and starts DEMO monitoring.

Other entry points:

```bash
python3 app.py --mode demo            # explicit demo mode (default)
python3 app.py --replay               # replay the bundled capture file (real packets)
python3 app.py --replay my.pcap       # replay your own capture file
python3 app.py --mode live            # live packet capture (falls back to demo)
python3 app.py --mode live --iface en0 --filter "tcp port 443"
python3 app.py --no-autostart         # open the dashboard without monitoring
python3 app.py --headless --simulate  # full pipeline in the terminal, no GUI
python3 scripts/run_demo.py           # scripted terminal demo + printed report
python3 scripts/check_capture.py      # can this machine capture packets?
python3 scripts/evaluate_model.py --cv 5 --audit-port
```

---

## 6. Demo mode

Demo mode generates traffic locally — **nothing is transmitted on any network**.

1. Launch `python3 app.py`. The header shows `MODE: DEMO`.
2. Background traffic (mostly benign) starts flowing into the table.
3. Click **RUN SECURITY SIMULATION**.
4. A scripted attack sequence is generated from a single "attacker" host:
   port scan → FTP brute force → DoS flood → DDoS flood.
5. For each record the pipeline runs end to end and the dashboard shows the
   attack type, confidence, risk score, risk level, response, and a full
   explanation in the detail panel.

Step-by-step demonstration script: [docs/demo.md](docs/demo.md).

---

## 7. Replay mode — the real packet path without privileges

```bash
python3 scripts/make_sample_pcap.py   # build the sample capture (nothing is sent)
python3 app.py --replay               # analyse it
```

Replay reads frames from a capture file with Scapy's own
`sniff(offline=...)`, so it runs **exactly** the code LIVE mode runs: real
packet dissection, real flow assembly, real feature extraction. The only
difference is where the frames come from. It needs no privileges at all, which
makes it the reliable way to show the real packet pipeline in a classroom.

The dashboard has a **Replay Sample PCAP** button for the same thing.

The bundled sample capture is built by `scripts/make_sample_pcap.py`, which
crafts packets in memory and writes them straight to disk — it opens no socket
and transmits nothing. It contains benign HTTPS and DNS conversations, an
18-port SYN scan and a 900-packet SYN flood. Measured result: 981 packets →
24 flows, flood detected as **DDoS at risk 74 (HIGH)**, scan detected as
**Port Scan**, plus false positives on the benign flows (honest numbers in
[docs/TESTING.md](docs/TESTING.md) §4b and §6).

---

## 8. Live mode

First, check whether this machine can capture at all:

```bash
python3 scripts/check_capture.py
```

Then start it:

```bash
python3 app.py --mode live                                  # if capture is permitted
python3 app.py --mode live --iface en0 --filter "tcp port 443"
sudo $(which python3) app.py --mode live                    # if it is not
```

Live mode uses Scapy's `AsyncSniffer`, groups packets into bidirectional flows
by 5-tuple, flushes each flow after 5 idle seconds, aggregates micro-flow
storms (§11), and feeds the features to the same model.

**Privileges.** Raw capture is privileged on every OS:

| OS | What is needed |
|----|----------------|
| macOS | Read access to `/dev/bpf*`. Either run with `sudo`, **or** install Wireshark, which installs a `ChmodBPF` helper and adds you to the `access_bpf` group — then no `sudo` is needed. |
| Linux | `sudo`, or `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)` |
| Windows | Npcap installed, run from an elevated prompt |

On the development Mac, live capture **is verified working without `sudo`**
because Wireshark's ChmodBPF helper is installed (evidence in
[docs/TESTING.md](docs/TESTING.md) §4c). If that is not the case on your
machine, `check_capture.py` prints the exact `sudo` command to use.

* **802.11 monitor mode is not required and not used.** NetHawk analyses
  IP/TCP/UDP flows from whatever interface is available. Monitor mode is
  detected and reported, but no feature depends on it, and NetHawk does not
  enable it.
* **Choose the interface and a filter.** `--iface` picks the interface
  (`route -n get default` shows which one carries your traffic) and `--filter`
  takes a BPF expression. Narrowing the filter is good practice: an unfiltered
  capture sees every packet on the segment.
* **Mind the address family.** macOS often prefers IPv6, so an IPv4-only filter
  such as `host 104.20.23.154` can legitimately capture zero packets while the
  connection succeeds over IPv6. Use the hostname (libpcap expands it to all
  its addresses) or include both.
* Use the **Check Live Capture** button in the app to probe at any time.
* If capture is unavailable, the engine says why and continues in DEMO mode.

---

## 9. Dataset setup

NetHawk trains on **CIC-IDS2017** when the CSVs are present, and on a bundled
**synthetic demo dataset** when they are not. Both use the same 27-feature
schema. See [data/README.md](data/README.md) for download and setup steps.

```bash
python3 scripts/prepare_dataset.py              # report what is available
python3 scripts/prepare_dataset.py --make-demo  # regenerate the demo dataset
```

CIC-IDS2017 is a labelled **network** intrusion dataset — it is *not*
802.11-specific. The Wi-Fi-specific equivalents are AWID/AWID3; the feature
layer is modular so an AWID3 adapter can be added later.

---

## 10. ML pipeline

```
load CSVs (random sample if huge) -> normalise column names -> coerce numeric
          -> replace Inf/NaN -> drop duplicates WITHIN and ACROSS files
          -> normalise labels to canonical categories
          -> drop classes with <10 samples -> stratified 75/25 split
          -> RandomForestClassifier(n_estimators=200, class_weight=balanced_subsample)
          -> evaluate (multiclass + derived binary) -> joblib.dump
```

Two leakage guards are deliberate, and both fix bugs found during the audit:

* **De-duplication across files, not just within them.** A flow present in two
  CIC-IDS2017 CSVs could otherwise land in both the train and the test split.
  The number of rows removed is reported by the loader.
* **Random sampling instead of head-truncation.** Reading the first *N* rows of
  a time-ordered CSV can drop an entire attack class (measured: 1 class kept
  instead of 7 on a label-ordered file). Sampling is seeded, so it is
  reproducible.

Two outputs come from one model: the multiclass **attack category**, and the
binary **NORMAL / ATTACK** answer derived from it (so they can never disagree).

```bash
python3 scripts/train_model.py             # real data if present, else demo data
python3 scripts/train_model.py --demo      # force the demo dataset
python3 scripts/train_model.py --data-dir /path/to/MachineLearningCVE
```

Training writes `models/nethawk_rf.joblib` and `models/metrics.json`. The
metrics file records `data_source` and a `caveat` describing exactly what the
numbers mean.

For a full evaluation — class distribution, per-class precision/recall/F1,
macro-F1, confusion matrix, cross-validation and a feature-reliance audit:

```bash
python3 scripts/evaluate_model.py --cv 5 --audit-port
```

> **Current model in this repository was trained on SYNTHETIC DEMO DATA.**
> Its reported scores (≈0.998 accuracy) measure how well the model separates
> the *demo generator's* own classes. They are **not** experimental results on
> real traffic and must not be presented as such. Install CIC-IDS2017 and
> retrain to obtain real-data metrics.

---

## 11. Feature pipeline

27 flow features using CIC-IDS2017 column names: `Destination Port`,
`Flow Duration`, forward/backward packet and byte counts and means,
`Flow Bytes/s`, `Flow Packets/s`, flow and directional IAT statistics, packet
length min/max/mean/std, the six TCP flag counts, `Down/Up Ratio`,
`Average Packet Size`, `Init_Win_bytes_forward`.

Three adapters implement one interface, `extract_features(record)`:

| Adapter | Input | Used by |
|---------|-------|---------|
| `DatasetFeatureAdapter` | a CSV row | training, offline evaluation |
| `DemoTrafficFeatureAdapter` | a generated demo flow | DEMO mode, simulation |
| `LiveTrafficFeatureAdapter` | a `Flow` assembled from captured packets | LIVE mode |

**Honest caveat:** live features are computed by NetHawk's own flow assembler
following the CIC-IDS2017 *definitions*; they are not produced by CICFlowMeter.
A model trained on CIC-IDS2017 and applied to live traffic is therefore doing
cross-domain inference, which is a measured limitation (see §16 and
docs/TESTING.md §6).

### Micro-flow aggregation

A SYN flood uses a fresh source port for every packet, so strict 5-tuple
accounting turns 900 flood packets into 900 one-packet flows — each looking
like a single stray probe, with the packet *rate* that defines a flood lost
entirely. NetHawk therefore merges storms of tiny flows that share
`(source, destination, protocol, destination port)` into one record.

Grouping by destination **port** is what keeps the two reconnaissance patterns
apart:

* a **flood** sends hundreds of micro-flows to **one** port → merged, high rate → DoS/DDoS
* a **port scan** sends one or two micro-flows per port across **many** ports →
  each group stays below the threshold → left alone → still looks like a scan

Measured on the sample capture: 981 packets → 24 flows, the flood correctly
detected as DDoS (risk 74) and the scan still detected as Port Scan. Ordinary
conversations are never merged (only groups of ≥5 flows of ≤2 packets each).


---

## 12. Risk scoring

```
risk = 0.50 × severity(category)          # 0-100 table, per attack category
     + 0.30 × (model confidence × 100)
     + 0.20 × traffic intensity           # log-scaled packets/s and bytes/s
```

* Bounded 0-100; `Normal` is forced to 0.
* Intensity is damped for flows with fewer than 10 packets, because a rate
  computed over one or two packets is not a sustained load.
* Severity table: DDoS 95, DoS 85, Botnet 80, Web Attack 70, Brute Force 70,
  Port Scan 55, Other Suspicious 45, Normal 0.

| Score | Level |
|-------|-------|
| 0–39 | LOW |
| 40–69 | MEDIUM |
| 70–100 | HIGH |

Every event stores the full arithmetic, shown in the detail panel:

```
severity(DDoS)=95 x 0.50 = 47.5 | confidence=99.8 x 0.30 = 29.9
| intensity=87.4 x 0.20 = 17.5 => risk 95/100 (HIGH)
```

---

---

## 13. Response policy

| Risk | Action | What actually happens |
|------|--------|----------------------|
| LOW | `MONITOR` | Event logged |
| MEDIUM | `WARN` | Event logged, dashboard alert, source flagged `SUSPICIOUS` |
| HIGH | `BLOCK` | Event logged, dashboard alert, source added to a **simulated** blocklist and marked `BLOCKED (SIM)` |

**Safety.** `DecisionEngine.enforcement_enabled` is `False` and no code path
sets it to `True`. There is no firewall backend, no deauthentication and no
packet injection. Every response is stored with `simulated = 1` and rendered as
`[SIMULATED]`; the dashboard footer permanently states
*"RESPONSES ARE SIMULATED — NO REAL NETWORK ACTION"*.

---

## 14. Database schema

SQLite at `database/nethawk.db` (override with `NETHAWK_DB_PATH`).

**events** — `id, timestamp, source, destination, protocol, prediction,
attack_type, confidence, risk_score, risk_level, response, simulated, mode,
explanation, features_json`

**devices** — `id, identifier, first_seen, last_seen, packets, threat_count,
status` (`TRUSTED` / `SUSPICIOUS` / `BLOCKED (SIM)`)

**system_status** — `id, timestamp, mode, monitoring, packets_seen,
events_logged, note`

**blocklist** — `id, identifier, added_at, reason, simulated`

Inspect it directly:

```bash
sqlite3 database/nethawk.db "SELECT timestamp, source, attack_type, risk_score, risk_level, response FROM events ORDER BY id DESC LIMIT 10;"
```

---

## 15. Testing

```bash
python3 -m pytest
```

**110 tests**, all passing, covering label normalisation, risk scoring and
banding, all three feature adapters, flow assembly and direction, micro-flow
aggregation, real Scapy packet dissection via PCAP replay, IPv6 handling,
database CRUD and aggregates, dataset cleaning and the two leakage guards,
model training/persistence/metadata, the demo attack generator, the full engine
pipeline, the LIVE→DEMO fallback, clean shutdown, CLI parsing, and a dashboard
suite that drives the real widgets.

The full verification report — every command run, its real output, what is
verified, what is unverified and what is blocked — is in
[docs/TESTING.md](docs/TESTING.md).

---

## 16. Limitations

1. **The bundled model is trained on synthetic demo data.** Its metrics are not
   real-world intrusion-detection results. Real metrics require CIC-IDS2017,
   which is not present on the development machine.
2. **CIC-IDS2017 is not an 802.11 dataset.** NetHawk therefore detects *network
   layer* intrusions (DoS, DDoS, scans, brute force, botnet, web attacks) — not
   Wi-Fi-specific attacks such as deauthentication or evil twin. Those need
   AWID3 plus a monitor-mode capture path.
3. **Cross-domain accuracy is measurably uneven**, and the numbers are
   published rather than hidden. On replayed real packets the flood and the
   scan were detected correctly, but benign HTTPS and DNS flows produced
   **false positives** (Web Attack 0.54–0.67, Port Scan 0.60), and confidence
   on real traffic is ~0.5 versus ~1.0 on demo data. Cause: NetHawk's flow
   assembler follows the CIC-IDS2017 *definitions* but is not CICFlowMeter, and
   the model is trained on synthetic statistics. See
   [docs/TESTING.md](docs/TESTING.md) §6.
4. **No 802.11 frame parsing.** Monitor mode is detected but not used and never
   enabled; the MVP analyses IP/TCP/UDP flows. No SSID, BSSID or MAC-layer
   fields are read — devices are identified by IP address.
5. **Responses are simulated.** No enforcement backend exists, and no code path
   enables one.
6. **Live mode needs capture privileges.** Verified working on the development
   Mac without `sudo` (Wireshark's ChmodBPF helper); elsewhere it needs `sudo`,
   and falls back to DEMO mode when denied.
7. **Single-host, single-user.** No distributed sensors, no alert forwarding.
8. **Demo traffic is generated by the same code that produced the training
   data**, so demo-mode accuracy is optimistic by construction. This is why
   replay and live mode matter: they are the honest tests.
9. **No PyInstaller packaging yet.** The app runs from source.

---

## 17. Future work

* Integrate **AWID3** with an `AwidFeatureAdapter` for real 802.11 attacks
  (deauthentication, disassociation, evil twin, KRACK).
* Parse 802.11 management frames from a monitor-mode adapter.
* Replace the flow assembler with genuine CICFlowMeter-compatible extraction.
* Add an anomaly-detection model (Isolation Forest / autoencoder) alongside the
  supervised classifier, for unknown-attack coverage.
* Optional real enforcement behind an explicit opt-in (e.g. `pf`/`iptables`
  rules) with confirmation and an audit trail.
* Package with PyInstaller into a single distributable app.
* Alert forwarding (email / webhook) and scheduled PDF reporting.

---

## 18. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ModuleNotFoundError: customtkinter` (or scapy, sklearn…) | dependencies not installed | `python3 -m pip install -r requirements.txt` |
| `ModuleNotFoundError: tkinter` | Homebrew Python without Tk | use the python.org or Anaconda build, or `brew install python-tk` |
| Dashboard does not open, app prints "Could not load the desktop dashboard" | no display / no Tk | it falls back to the headless demo automatically; use `python3 scripts/run_demo.py` |
| `Permission denied: could not open /dev/bpf0` | live capture is privileged | `python3 scripts/check_capture.py` prints the exact `sudo` command; or install Wireshark (ChmodBPF); or use `--replay` / DEMO mode |
| LIVE mode starts but **0 packets** are captured | wrong interface, or an IPv4-only filter while the traffic is IPv6 | check `route -n get default` for the interface; use the hostname in `--filter`, or include both addresses; or drop `--filter` |
| `No CIC-IDS2017 CSV files found` | dataset not installed | see [data/README.md](data/README.md), or train on demo data: `python3 scripts/train_model.py --demo` |
| `Dataset is missing required feature columns` | the CSVs are not CIC-IDS2017 flow exports | use the `MachineLearningCSV` / `MachineLearningCVE` files, not the raw PCAPs |
| `Sample capture missing` when clicking Replay | sample `.pcap` not generated | `python3 scripts/make_sample_pcap.py` |
| Model badge says `DEMO DATA` after installing the dataset | model not retrained | `python3 scripts/train_model.py` |
| Dashboard is empty on launch | monitoring not started, or data was cleared | click **Start Monitoring**, then **RUN SECURITY SIMULATION** |
| Want a clean board before presenting | old events in SQLite | click **Clear Demo Data**, or `python3 scripts/run_demo.py --fresh` |

---

## Project structure

```
nethawk/
├── app.py                  # entry point (GUI + headless)
├── requirements.txt
├── pytest.ini
├── data/
│   ├── README.md           # dataset setup (CIC-IDS2017 + demo)
│   ├── cicids2017/         # real CSVs go here
│   └── demo/               # generated demo dataset + sample_traffic.pcap
├── models/                 # nethawk_rf.joblib + metrics.json
├── database/               # nethawk.db
├── docs/
│   ├── architecture.md
│   ├── demo.md
│   ├── viva.md
│   ├── TESTING.md              # verification report (what is proven, what is not)
│   ├── PROPOSAL_ALIGNMENT.md   # deck claims vs implementation
│   └── SUBMISSION_CHECKLIST.md
├── scripts/
│   ├── train_model.py
│   ├── evaluate_model.py       # per-class metrics, CV, feature audit
│   ├── prepare_dataset.py
│   ├── make_sample_pcap.py     # builds the sample capture (offline)
│   ├── check_capture.py        # live-capture diagnostic
│   └── run_demo.py
├── src/nethawk/
│   ├── config.py  schema.py  engine.py
│   ├── capture/   (live.py, replay.py, demo.py, flows.py)
│   ├── preprocessing/clean.py
│   ├── features/adapters.py
│   ├── datasets/  (loader.py, synthetic.py)
│   ├── ml/        (model.py, predictor.py)
│   ├── detection/classifier.py
│   ├── risk/scoring.py
│   ├── response/engine.py
│   ├── database/db.py
│   ├── dashboard/ (app.py, theme.py)
│   └── utils/     (report.py, logging.py)
└── tests/                  # 110 pytest tests
```

---

*NetHawk is a college Computer Networks project, not a production security
product. It performs no offensive action against any network.*
