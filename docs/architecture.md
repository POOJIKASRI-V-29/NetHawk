# NetHawk — architecture

## 1. Layered view (matches the project proposal)

```
┌─ NETWORK LAYER ───────────────────────────────────────────────┐
│  Wi-Fi / Ethernet interface · IP · TCP/UDP traffic            │
└───────────────────────────────┬───────────────────────────────┘
                                │
┌─ CAPTURE + AI/ML LAYER ───────▼───────────────────────────────┐
│  capture/live.py      AsyncSniffer -> packets                 │
│  capture/flows.py     packets -> bidirectional flows          │
│  capture/demo.py      controlled synthetic traffic (DEMO)     │
│  preprocessing/clean.py   column normalisation, Inf/NaN fix   │
│  features/adapters.py     Dataset | Live | Demo -> 27 features│
│  ml/predictor.py          Random Forest inference             │
│  detection/classifier.py  raw label -> canonical category     │
└───────────────────────────────┬───────────────────────────────┘
                                │
┌─ DECISION LAYER ──────────────▼───────────────────────────────┐
│  risk/scoring.py     deterministic 0-100 score + explanation  │
│  response/engine.py  LOW/MEDIUM/HIGH policy -> SIMULATED act. │
└───────────────────────────────┬───────────────────────────────┘
                                │
┌─ APPLICATION LAYER ───────────▼───────────────────────────────┐
│  database/db.py    events · devices · system_status · blocklist│
│  dashboard/app.py  cards · alerts · history · detail panel    │
│  utils/report.py   text security report                       │
└───────────────────────────────────────────────────────────────┘
```

`src/nethawk/engine.py` (`NetHawkEngine`) is the orchestrator: it owns the
database, the predictor, the decision engine and the traffic sources, and runs
`process_record()` for every unit of traffic.

## 2. The detection loop

`NetHawkEngine.process_record()` performs exactly seven steps:

| # | Step | Code |
|---|------|------|
| 1 | Feature extraction | `LiveTrafficFeatureAdapter` / `DemoTrafficFeatureAdapter` |
| 2 | ML detection | `Predictor.predict()` → label + probabilities |
| 3 | Attack classification | `normalize_label()` → canonical category, `to_binary()` |
| 4 | Risk scoring | `score_event()` → score, level, explanation, components |
| 5 | Decision | `DecisionEngine.decide()` → action + rationale |
| 6 | Response + logging | `DecisionEngine.execute()`, `Database.insert_event()`, `upsert_device()` |
| 7 | UI notification | message pushed onto `engine.messages` queue |

## 3. Threading model

```
Tk main thread          background threads
──────────────          ──────────────────────────────────────────
dashboard/app.py        nethawk-demo-monitor    (demo traffic loop)
  after(200ms)          nethawk-simulation      (security simulation)
  _drain_queue()  <───  nethawk-flow-flusher    (live flow expiry)
                        scapy AsyncSniffer      (packet capture)
                              │
                        queue.Queue (thread-safe)
```

The GUI never performs capture or inference; it only drains a queue every
200 ms and repaints. That is why the window stays responsive.

Each SQLite operation opens its own short-lived connection, so no connection is
shared across threads.

## 4. Feature contract

`src/nethawk/schema.py` defines the single source of truth: 27 features using
CIC-IDS2017 column names. Everything downstream — training, inference, live
capture, demo generation, tests — imports `FEATURE_NAMES` from that one place.

Adding a new traffic source means writing one adapter class that returns a dict
keyed by `FEATURE_NAMES`. Nothing else changes.

```
DatasetFeatureAdapter  ─┐
DemoTrafficFeatureAdapter ─┼─> dict[FEATURE_NAMES] ─> vector_from_dict() ─> model
LiveTrafficFeatureAdapter ─┘
```

### Live flow assembly

`FlowTable` groups packets by a direction-independent key
(`sorted((src,sport),(dst,dport))`, protocol), so both directions of a
conversation land in one flow. The **first packet observed defines the forward
direction**, matching CICFlowMeter's convention. A flow is flushed after
`LIVE_FLOW_TIMEOUT` (default 5 s) of inactivity and converted to features.

**Caveat, stated plainly:** these features follow the CIC-IDS2017 *definitions*
but are computed by NetHawk's own assembler, not CICFlowMeter. Applying a
CIC-IDS2017-trained model to them is cross-domain inference.

## 5. Why the classification layer is separate from the model

The model predicts whatever label strings its training data used
(`DoS Hulk`, `FTP-Patator`, `Web Attack – Brute Force`, …). Those differ
between CIC-IDS2017, CSE-CIC-IDS2018 and AWID3.
`detection/classifier.py` normalises them into eight stable categories, so the
risk table, the response policy, the database and the UI never have to know
which dataset trained the model.

## 6. Mode selection and fallback

```
start_monitoring("LIVE")
   └─ capture_available()                 probe: can we actually sniff?
        ├─ yes -> LiveCapture.start() -> LIVE mode
        └─ no  -> notice("LIVE unavailable: <reason>")
                  notice("Falling back to DEMO mode. <platform hint>")
                  -> DEMO mode
```

The probe result is surfaced verbatim in the dashboard footer, so a
demonstration on a machine without root still starts and explains itself.

## 7. Configuration

`src/nethawk/config.py` derives every path from the project root. Overrides:

| Variable | Meaning |
|----------|---------|
| `NETHAWK_DATA_DIR` | data directory |
| `NETHAWK_CICIDS_DIR` | where CIC-IDS2017 CSVs live |
| `NETHAWK_MODELS_DIR` | model output directory |
| `NETHAWK_DB_PATH` | SQLite file |
| `NETHAWK_DEMO_INTERVAL` | seconds between demo events (default 1.5) |
| `NETHAWK_FLOW_TIMEOUT` | live flow idle timeout (default 5.0) |
| `NETHAWK_ALERT_MIN_RISK` | minimum risk shown in Recent Alerts (default 40) |

No absolute paths are hardcoded anywhere.

## 8. Roadmap mapping (proposal → implementation)

| Proposal phase | Status in this MVP |
|----------------|--------------------|
| 1. Network monitoring | Implemented — Scapy capture with privilege detection and fallback |
| 2. Feature extraction | Implemented — 27-feature schema, three adapters |
| 3. Dataset preparation | Implemented — CIC-IDS2017 loader + cleaning + bundled demo dataset |
| 4. ML model | Implemented — Random Forest, trained, evaluated, persisted |
| 5. Live prediction | Implemented — flows → features → prediction in LIVE mode (needs root) |
| 6. Desktop application | Implemented — CustomTkinter console |
| 7. Response + logging | Implemented — policy engine + SQLite (responses simulated) |
| 8. Testing + packaging | Testing implemented (85 tests); PyInstaller packaging is future work |
