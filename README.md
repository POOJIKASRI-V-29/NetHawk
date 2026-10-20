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

The system has **two modes**:

| Mode | Traffic source | Requirements | Purpose |
|------|----------------|--------------|---------|
| **DEMO** (default) | Locally generated synthetic flows | None — works on any laptop | Classroom demonstration, development, testing |
| **LIVE** | Real packets captured with Scapy | Root/admin privileges | Analysing actual traffic on the machine's interface |

LIVE mode **automatically falls back to DEMO mode** with a clear on-screen
message if packet capture is not permitted, so the demonstration can never fail
because of privileges or hardware.

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
| Tests | pytest | 85 tests over the whole pipeline |

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
sudo python3 app.py --mode live       # live packet capture (falls back to demo)
python3 app.py --no-autostart         # open the dashboard without monitoring
python3 app.py --headless --simulate  # full pipeline in the terminal, no GUI
python3 scripts/run_demo.py           # scripted terminal demo + printed report
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

## 7. Live mode

```bash
sudo $(which python3) app.py --mode live
```

Live mode uses Scapy's `AsyncSniffer`, groups packets into bidirectional flows
by 5-tuple, flushes each flow after 5 idle seconds, and feeds the extracted
features to the same model.

* Raw capture needs elevated privileges on every OS (macOS: `/dev/bpf*` is
  root-owned; Linux: `sudo` or `CAP_NET_RAW`; Windows: Npcap + elevated shell).
* **802.11 monitor mode is not required.** NetHawk analyses IP/TCP/UDP flows
  from whatever interface is available. If a monitor-mode adapter is present it
  is reported, but no feature depends on it.
* Use the **Check Live Capture** button to probe availability at any time.
* If capture is unavailable, the engine says why and continues in DEMO mode.

---

## 8. Dataset setup

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

## 9. ML pipeline

```
load CSVs -> normalise column names -> coerce numeric -> replace Inf/NaN
          -> drop duplicates -> normalise labels to canonical categories
          -> drop classes with <10 samples -> stratified 75/25 split
          -> RandomForestClassifier(n_estimators=200, class_weight=balanced_subsample)
          -> evaluate (multiclass + derived binary) -> joblib.dump
```

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

> **Current model in this repository was trained on SYNTHETIC DEMO DATA.**
> Its reported scores (≈0.998 accuracy) measure how well the model separates
> the *demo generator's* own classes. They are **not** experimental results on
> real traffic and must not be presented as such. Install CIC-IDS2017 and
> retrain to obtain real-data metrics.

---

## 10. Feature pipeline

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
cross-domain inference, which is a known limitation (see §15).

---

## 11. Risk scoring

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

## 12. Response policy

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

## 13. Database schema

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

## 14. Testing

```bash
python3 -m pytest
```

85 tests covering label normalisation, risk scoring and banding, all three
feature adapters, flow assembly and direction, database CRUD and aggregates,
model training/persistence/metadata, the demo attack generator, the full engine
pipeline, the LIVE→DEMO fallback, and a dashboard smoke test that drives the
real widgets.

---

## 15. Limitations

1. **The bundled model is trained on synthetic demo data.** Its metrics are not
   real-world intrusion-detection results. Real metrics require CIC-IDS2017.
2. **CIC-IDS2017 is not an 802.11 dataset.** NetHawk therefore detects *network
   layer* intrusions (DoS, DDoS, scans, brute force, botnet, web attacks) — not
   Wi-Fi-specific attacks such as deauthentication or evil twin. Those need
   AWID3 plus a monitor-mode capture path.
3. **Live features ≠ CICFlowMeter features.** NetHawk's flow assembler follows
   the same definitions but is an independent implementation; cross-domain
   inference degrades accuracy.
4. **No 802.11 frame parsing.** Monitor mode is detected but not used; the MVP
   analyses IP/TCP/UDP flows.
5. **Responses are simulated.** No enforcement backend exists.
6. **Live mode needs root**, which the demo environment may not have.
7. **Single-host, single-user.** No distributed sensors, no alert forwarding.
8. **Demo traffic is generated by the same process that trained the model**, so
   demo-mode accuracy is optimistic by construction.

---

## 16. Future work

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

## Project structure

```
nethawk/
├── app.py                  # entry point (GUI + headless)
├── requirements.txt
├── pytest.ini
├── data/
│   ├── README.md           # dataset setup (CIC-IDS2017 + demo)
│   ├── cicids2017/         # real CSVs go here
│   └── demo/               # generated synthetic demo dataset
├── models/                 # nethawk_rf.joblib + metrics.json
├── database/               # nethawk.db
├── docs/
│   ├── architecture.md
│   ├── demo.md
│   └── viva.md
├── scripts/
│   ├── train_model.py
│   ├── prepare_dataset.py
│   └── run_demo.py
├── src/nethawk/
│   ├── config.py  schema.py  engine.py
│   ├── capture/   (live.py, demo.py, flows.py)
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
└── tests/                  # 85 pytest tests
```

---

*NetHawk is a college Computer Networks project, not a production security
product. It performs no offensive action against any network.*
