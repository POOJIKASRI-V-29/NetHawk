# NetHawk — demonstration script

Total time: about 4 minutes. Everything below works offline, with no root
privileges, and transmits nothing on any network.

## Before the review (once)

```bash
cd nethawk
python3 -m pip install -r requirements.txt
python3 -m pytest          # expect: 85 passed
python3 scripts/train_model.py
```

Optional clean slate right before presenting:

```bash
python3 -c "import sys; sys.path.insert(0,'src'); from nethawk.database.db import Database; Database().clear_all()"
```

(or just click **Clear Demo Data** in the app).

---

## The demonstration

### Step 1 — Launch (15 s)

```bash
python3 app.py
```

Point out the header: **NETWORK STATUS: MONITORING**, **MODE: DEMO**,
**MODEL: DEMO DATA**.

> Say: "NetHawk starts in demo mode, which generates traffic locally. The
> model badge shows it was trained on the bundled synthetic dataset, not on
> CIC-IDS2017 — the moment we install the real CSVs and retrain, that badge
> changes."

### Step 2 — Background monitoring (30 s)

Benign events appear in **ATTACK HISTORY** roughly every 1.5 s: prediction
`NORMAL`, attack type `Normal`, risk `0`, action `MONITOR`. Occasionally a
low-level suspicious flow appears.

> Say: "Each row is one flow that went through the complete pipeline —
> feature extraction, Random Forest prediction, classification, risk scoring
> and the response policy — and was written to SQLite."

### Step 3 — Run the security simulation (60 s)

Click the red **RUN SECURITY SIMULATION** button.

A scripted sequence from a single attacker host runs in escalating order:

| Stage | Generated traffic | Detected as | Typical risk | Response |
|-------|-------------------|-------------|--------------|----------|
| 1 | Port scan ×3 | Port Scan | ≈ 59–64 MEDIUM | WARN + flag suspicious |
| 2 | FTP brute force ×2 | Brute Force | ≈ 72 HIGH | ALERT + BLOCK (simulated) |
| 3 | DoS flood ×2 | DoS | ≈ 87–91 HIGH | ALERT + BLOCK (simulated) |
| 4 | DDoS flood ×2 | DDoS | ≈ 95–98 HIGH | ALERT + BLOCK (simulated) |

(Exact numbers vary run to run — the traffic is randomly generated.)

Watch live: **Recent Alerts** fills with colour-coded entries, **Threat Count**
climbs, **Network Risk** moves LOW → MEDIUM → HIGH, the risk bar fills red.

> Say: "This is a controlled local generator. No packets are transmitted, no
> real host is touched. The footer states that every response is simulated."

### Step 4 — Inspect one detection (60 s)

Click a **DDoS** row. The **EVENT DETAIL** panel shows:

* source, destination, protocol, mode, event id
* prediction `ATTACK`, attack type `DDoS`, confidence, plain-English meaning
* the model's top class probabilities
* the **risk arithmetic**:
  `severity(DDoS)=95 x 0.50 = 47.5 | confidence=99.8 x 0.30 = 29.9 | intensity=87.4 x 0.20 = 17.5 => risk 95/100 (HIGH)`
* the response action, what was applied, and why
* the key features that drove it (`Flow Packets/s`, `Total Fwd Packets`, …)

> Say: "Nothing here is a black box — the risk number is a weighted sum of
> three bounded terms, and we can read every one of them off the screen."

### Step 5 — Show the persistence (30 s)

In a terminal:

```bash
sqlite3 database/nethawk.db "SELECT timestamp, source, attack_type, risk_score, risk_level, response FROM events ORDER BY id DESC LIMIT 8;"
sqlite3 database/nethawk.db "SELECT * FROM blocklist;"
sqlite3 database/nethawk.db "SELECT identifier, status, packets, threat_count FROM devices;"
```

Or click **Export Report** in the app and open the file it names in
`reports/`.

### Step 6 — Show the live-mode handling (30 s)

Click **Check Live Capture**. On a machine without root the footer shows:

```
Permission denied: could not open /dev/bpf0 ... | macOS: LIVE mode needs sudo
```

> Say: "Live capture is implemented with Scapy, but raw capture needs root on
> every OS. Instead of crashing, NetHawk detects this, explains it, and stays
> in demo mode — which is exactly the graceful-degradation requirement."

If you *can* run as root, demonstrate it:

```bash
sudo $(which python3) app.py --mode live
```

Then open a browser or run `curl https://example.com` to create traffic, and
watch real flows appear in the table with `MODE: LIVE`.

---

## Backup plan (if the GUI misbehaves)

Run the terminal version, which prints the entire pipeline and a full report:

```bash
python3 scripts/run_demo.py --fresh
```

---

## What to say if asked "is this real?"

* The **pipeline** is real: real Random Forest, real feature extraction, real
  SQLite, real Scapy capture code.
* The **training data for the shipped model** is synthetic demo data, so the
  accuracy figures are demo figures, not experimental results.
* The **responses** are simulated — no network is modified.
* **Live capture** works but needs root, and it analyses IP/TCP/UDP flows, not
  802.11 frames.
