# NetHawk — demonstration script

**Total time: about 6 minutes**, timed per step below. Everything except the
optional live-capture step works **fully offline**, needs **no privileges**, and
**transmits nothing** on any network.

| Step | What it shows | Time |
|------|---------------|------|
| 0 | Clean start | 20 s |
| 1 | Launch, mode and provenance badges | 15 s |
| 2 | Background monitoring | 30 s |
| 3 | Security simulation — the escalation ladder | 60 s |
| 4 | One detection in full, with the risk arithmetic | 60 s |
| 4b | **Real packets** via PCAP replay | 45 s |
| 5 | Persisted events in SQLite | 30 s |
| 6 | Live capture (optional, needs permissions) | 45 s |
| 7 | Honest limitations | 30 s |

## Before the review (once)

```bash
cd nethawk
python3 -m pip install -r requirements.txt
python3 -m pytest          # expect: 156 passed
python3 scripts/train_model.py
python3 scripts/make_sample_pcap.py    # builds the sample capture for replay mode
python3 scripts/check_capture.py       # confirms whether live mode will work
```

Optional clean slate right before presenting:

```bash
python3 -c "import sys; sys.path.insert(0,'src'); from nethawk.database.db import Database; Database().clear_all()"
```

(or just click **Clear Demo Data** in the app).

---

## Step 0 — Clean start (20 s)

```bash
cd nethawk
python3 scripts/run_demo.py --fresh --duration 1 --step-delay 0
```

That empties the database and confirms the pipeline runs. Then close it and
launch the app for the demonstration proper.

If you prefer a single command that does everything from an empty state:

```bash
python3 app.py
```

It generates the demo dataset, trains the model and creates the database on
first run if any of them are missing.

## The demonstration

### Step 1 — Launch (15 s)

```bash
python3 app.py
```

Point out the header: **NETWORK STATUS: MONITORING**, **MODE: DEMO**,
**MODEL: DEMO DATA**. All three are live readings, not labels — the MODEL badge
reads `DEMO DATA` because `models/metrics.json` records
`data_source: DEMO_SYNTHETIC`, and it would read `CIC-IDS2017` after retraining
on the real dataset.

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

### Step 4b — Show it on REAL packets (45 s)  ← strongest part of the demo

Click **Replay Sample PCAP**.

NetHawk now reads a real capture file with Scapy and runs the *same* packet
path live mode uses — dissection, flow assembly, feature extraction — with no
privileges required.

Expected (measured): **981 packets parsed → 24 flows**, with
`MODE: REPLAY` on the rows:

| In the capture file | NetHawk says | Risk |
|---|---|---|
| 900-packet SYN flood to port 80 | **DDoS** | **74 HIGH** |
| SYN scan across 18 ports | **Port Scan** ×21 | 58–60 MEDIUM |
| 2 benign HTTPS conversations | Web Attack (*false positive*) | 63–67 MEDIUM |
| 4 benign DNS exchanges | Port Scan (*false positive*) | 48 MEDIUM |

> Say: "These are real packets, parsed by Scapy. The flood and the scan are
> detected correctly. The two benign HTTPS flows are false positives, and we
> report that honestly — it is the cost of training on synthetic flow
> statistics rather than CICFlowMeter features from real captures. Fixing it
> means training on the real dataset."

Being upfront about the false positives is worth more marks than hiding them.
If asked why the flood collapsed into one row, explain the micro-flow
aggregation (viva Q24).

### Step 5 — Show the persistence (30 s)

In a terminal:

```bash
sqlite3 database/nethawk.db "SELECT timestamp, source, attack_type, risk_score, risk_level, response FROM events ORDER BY id DESC LIMIT 8;"
sqlite3 database/nethawk.db "SELECT * FROM blocklist;"
sqlite3 database/nethawk.db "SELECT identifier, status, packets, threat_count FROM devices;"
```

Or click **Export Report** in the app and open the file it names in
`reports/`.

### Step 6 — Show LIVE capture (45 s)

Click **Check Live Capture** first. On this Mac it reports that capture **is**
available (Wireshark's ChmodBPF helper is installed), so demonstrate it:

```bash
python3 app.py --mode live --iface en0
```

Then create some traffic yourself — load a page in a browser, or run
`curl https://example.com` — and watch real flows appear with `MODE: LIVE`.
Benign browsing should come out as `Normal`, risk 0.

A fully local version, if you would rather not touch the network at all:

```bash
# terminal 1
python3 -m http.server 8077 --bind 127.0.0.1
# terminal 2
python3 app.py --headless --mode live --duration 20 --iface lo0 --filter "tcp port 8077"
# terminal 3
curl http://127.0.0.1:8077/ ; curl http://127.0.0.1:8077/
```

Measured result of exactly this: 84 packets captured, 6 flows analysed, all
`NORMAL`, stored with `mode=LIVE`.

**If `Check Live Capture` reports unavailable** (e.g. on a different machine, or
after a reboot without the ChmodBPF helper), that is also a good demo moment:

> Say: "Raw capture is privileged on every OS. Instead of crashing, NetHawk
> detects it, explains why, and continues in demo mode — and replay mode still
> proves the real packet path works without any privileges."

Then run `sudo $(which python3) app.py --mode live` if you want live capture
anyway.

**Two things to know before demonstrating live mode:**

* Pick the right interface — `route -n get default` shows which one carries
  your traffic (`en0` here).
* macOS often prefers **IPv6**. An IPv4-only filter such as
  `--filter "host 104.20.23.154"` can capture zero packets while the page loads
  fine over IPv6. Use the hostname, or no filter, if you are unsure.

---

### Step 7 — State the limitations yourself (30 s)

Say these before you are asked; it is worth more than being caught:

1. The shipped model is trained on **our own synthetic dataset**, so the 0.998
   figure measures the generator, not real intrusion detection.
2. NetHawk analyses **IP/TCP/UDP flows** captured from a Wi-Fi interface — not
   802.11 frames. No deauthentication, evil-twin or rogue-AP detection.
3. Every response is **simulated**; no network is modified.
4. On real replayed packets there are **false positives** on benign HTTPS and
   DNS, which we report in `docs/TESTING.md` rather than tuning away.

---

## Backup plans

**If the GUI misbehaves** — the terminal path runs the identical pipeline and
prints every stage plus a report:

```bash
python3 scripts/run_demo.py --fresh
```

**If live capture is unavailable** — replay still demonstrates real packet
parsing with no privileges:

```bash
python3 app.py --replay
```

**If Python or the dependencies misbehave on the demo machine** — use the
packaged build, which carries its own interpreter and libraries:

```bash
./dist/NetHawk/NetHawk
./dist/NetHawk/NetHawk --replay
```

Build it beforehand with `pyinstaller packaging/nethawk.spec --noconfirm`.
Note the bundle is unsigned: on a Mac that did not build it, right-click →
Open the first time.

**If you need to show where data lives:**

```bash
python3 app.py --paths
```

---

## What to say if asked "is this real?"

* The **pipeline** is real: real Random Forest, real feature extraction, real
  SQLite, real Scapy capture — and live capture is **verified working** on this
  machine (84 packets on loopback, 66 on `en0`; see `docs/TESTING.md` §4c).
* The **training data for the shipped model** is synthetic demo data, so the
  accuracy figures are demo figures, **not** experimental results.
* The **responses** are simulated — no network is ever modified.
* Capture analyses **IP/TCP/UDP flows**, not 802.11 frames. No monitor mode, no
  SSID/BSSID, so no rogue-AP or deauthentication detection.
* The **false positives in replay mode are real** and we report them.

## Honest one-liner if you only get one sentence

> "NetHawk is a working end-to-end IDS pipeline — capture, features, Random
> Forest, risk scoring, policy response, SQLite, dashboard — verified on
> generated traffic, on replayed real packets and on live captured packets; the
> shipped model is trained on our own synthetic dataset, so the accuracy
> numbers are demo numbers, and the responses are simulated."
