# NetHawk — viva questions and answers

Concise answers you can say out loud, each tied to where it lives in the code.

---

### 1. What is an IDS?

An **Intrusion Detection System** monitors network traffic or host activity for
signs of malicious behaviour and raises alerts. It observes and reports; it
does not necessarily stop the traffic. NetHawk is a network-based IDS with an
added controlled response layer.

### 2. IDS vs IPS?

An **IDS** detects and alerts (passive, out-of-band). An **IPS** sits inline and
actively blocks or drops malicious traffic. NetHawk is an **IDS with a simulated
IPS-style response**: the decision engine produces block actions, but
`DecisionEngine.enforcement_enabled` is `False`, so the action is recorded and
displayed as `[SIMULATED]` rather than enforced. Making it a real IPS would mean
wiring that action to `pf`/`iptables` — deliberately out of scope for a course
project.

### 3. Signature-based vs anomaly-based detection?

* **Signature-based** (Snort, Suricata): matches traffic against known attack
  patterns. Precise on known attacks, blind to new ones, needs constant rule
  updates.
* **Anomaly/behaviour-based**: learns what traffic normally looks like and flags
  deviations. Can catch unfamiliar behaviour, but produces more false positives.

NetHawk is **ML-based on flow features** — supervised, so it learns the
statistical signature of each attack *class* rather than a fixed byte pattern.
It generalises better than string signatures but still only to attack families
present in its training data.

### 4. Why machine learning?

Wireless and network traffic changes constantly, and writing a rule for every
attack variant does not scale. An ML model reads *statistical* traffic
characteristics — packet rate, flow duration, packet-size distribution, TCP flag
mix — and separates classes from those, so small variations of an attack still
land in the right class. It also gives a confidence value, which NetHawk feeds
into the risk score.

### 5. Why Random Forest?

* Strong baseline on **tabular** data, which is exactly what flow features are.
* Handles mixed feature scales without normalisation, and is robust to outliers
  (the rate columns span several orders of magnitude).
* Gives **feature importances**, so the decision is explainable in a viva.
* Gives calibrated-enough `predict_proba` values for the confidence term.
* Fast: 200 trees train in about a second on the demo data, and inference is
  sub-millisecond, so it keeps up with live flows.
* Far easier to justify than a deep model on a dataset of this size.

### 6. What is CIC-IDS2017?

A labelled network intrusion-detection dataset from the Canadian Institute for
Cybersecurity (University of New Brunswick), covering five days of traffic with
benign activity plus DoS, DDoS, port scan, brute force (FTP/SSH), botnet, web
attacks and infiltration. It is distributed as PCAPs and as CSVs of **flow
features** extracted with CICFlowMeter — roughly 80 features per flow.

### 7. Why is CIC-IDS2017 not an 802.11 / Wi-Fi dataset?

Because it was captured on a wired-style testbed and its features describe
**IP/TCP/UDP flows** — ports, flow duration, packet rates, TCP flags. It
contains no 802.11 management or control frames, no beacons, no
deauthentication frames, no BSSID/SSID fields. So a CIC-IDS2017 model can detect
*network-layer* intrusions carried over Wi-Fi, but it cannot detect
Wi-Fi-specific link-layer attacks. We state this explicitly rather than
claiming Wi-Fi attack detection we do not have.

### 8. What are AWID and AWID3?

Public **802.11-specific** intrusion-detection datasets.
**AWID** (Kolias et al., IEEE Communications Surveys & Tutorials, 2016) contains
frame-level features for attacks such as deauthentication, injection and
impersonation. **AWID3** (Chatzoglou et al., IEEE Access, 2021) extends this to
attacks against 802.11 *enterprise* networks (WPA2-Enterprise, including
KRACK-era and higher-layer attacks). Integrating AWID3 is the natural next step
for NetHawk: it needs one new feature adapter and extra label rules — the ML,
risk, decision, database and dashboard layers are unchanged.

### 9. What features are used?

27 flow features, using CIC-IDS2017 column names (`src/nethawk/schema.py`):

* identity/context: `Destination Port`, `Init_Win_bytes_forward`
* volume: total forward/backward packets and bytes, and their means
* timing: `Flow Duration`, `Flow IAT Mean/Std`, `Fwd/Bwd IAT Mean`
* rates: `Flow Bytes/s`, `Flow Packets/s`
* size distribution: min/max/mean/std packet length, `Average Packet Size`
* TCP behaviour: FIN, SYN, RST, PSH, ACK, URG flag counts
* directionality: `Down/Up Ratio`

They were chosen because each one is computable **both** from the dataset CSVs
**and** from packets we can capture live — that is what lets one model serve
both modes. On the demo model, the highest-importance features are
`PSH Flag Count`, `Total Fwd Packets`, `ACK Flag Count` and `Flow Packets/s`.

### 10. How does packet capture work?

A network interface normally passes only frames addressed to the host. Capture
tools ask the OS for a raw feed of everything the interface sees, through the
kernel capture layer — **BPF** on macOS/BSD (`/dev/bpf*`), `AF_PACKET` on Linux,
Npcap on Windows. Those devices are privileged, which is why live capture needs
`sudo`. NetHawk uses Scapy's `AsyncSniffer`, parses each packet's IP and TCP/UDP
layers, and groups packets into bidirectional flows (`capture/flows.py`); a flow
is analysed once it has been idle for 5 seconds.

**Monitor mode** goes one step further: it puts a Wi-Fi adapter into a state
where it captures raw 802.11 frames from all nearby traffic, not just decrypted
IP packets for the associated network. NetHawk detects monitor mode but does not
require it, does not use it and never enables it.

**Status on our machine:** live capture is verified working. Measured: 84
packets captured on loopback and 66 packets on the Wi-Fi interface `en0`,
assembled into flows, classified `NORMAL` with risk 0 and stored with
`mode=LIVE`. It runs without `sudo` because Wireshark's ChmodBPF helper is
installed and the account is in the `access_bpf` group; on a machine without
that, NetHawk needs `sudo` and falls back to DEMO mode if denied.

### 11. What is Scapy?

A Python packet-manipulation library: it can sniff, dissect, craft and send
packets across many protocols. NetHawk uses only the **passive** parts —
`AsyncSniffer`, interface enumeration, and layer parsing (`IP`, `TCP`, `UDP`).
NetHawk never uses Scapy to transmit anything.

### 12. How is the risk score calculated?

A deterministic weighted sum of three bounded terms (`risk/scoring.py`):

```
risk = 0.50 × severity(category)      # fixed table: DDoS 95, DoS 85, Botnet 80,
                                      # Web Attack 70, Brute Force 70,
                                      # Port Scan 55, Other 45, Normal 0
     + 0.30 × (confidence × 100)      # the model's own certainty
     + 0.20 × traffic intensity       # log-scaled packets/s and bytes/s
```

Each term is 0–100, so the result is 0–100. `Normal` is forced to 0. Intensity
is damped for flows with fewer than 10 packets, because a rate measured over one
or two packets is not a sustained load — without that, a 2-packet port-scan flow
would look like a flood. Bands: 0–39 LOW, 40–69 MEDIUM, 70–100 HIGH. Every event
stores the full arithmetic and the dashboard displays it.

**Why weighted this way:** severity dominates because what the attack *is*
matters most; confidence prevents an uncertain guess from triggering a high-risk
response; intensity separates a probe from a flood of the same class.

### 13. How does the response policy work?

`response/engine.py` maps the risk level onto an action:

| Level | Action | Effect |
|-------|--------|--------|
| LOW | MONITOR | log only |
| MEDIUM | WARN | log + dashboard alert + source marked `SUSPICIOUS` |
| HIGH | BLOCK | log + dashboard alert + source added to a **simulated** blocklist, marked `BLOCKED (SIM)` |

Every response is stored with `simulated = 1` and shown with a `[SIMULATED]`
tag, and the dashboard footer permanently states that no real network action is
taken. This is a deliberate safety decision for a classroom project.

### 14. Why SQLite?

It is embedded — a single file, no server, no configuration, no credentials —
which matches the "standalone desktop application" goal. It is in the Python
standard library, it survives restarts, it supports the SQL aggregates the
dashboard needs, and the whole project stays portable (copy the folder, keep
your history). MySQL or MongoDB would add a service to install and run for no
benefit at this scale.

### 15. Why local processing?

* **Privacy**: traffic metadata never leaves the machine.
* **Latency**: detection happens in milliseconds with no network round-trip.
* **Availability**: it still works on an isolated or offline network — which is
  where an IDS is often needed most.
* **Cost/simplicity**: no cloud account, no API keys, no deployment.

### 16. What happens if live capture is unavailable?

`capture_available()` probes capture *before* monitoring starts. If it fails,
the engine posts the exact reason plus a platform-specific hint and starts DEMO
mode instead. The application never crashes and the demonstration always runs.
This is tested (`tests/test_pipeline.py::test_live_mode_falls_back_to_demo_without_privileges`).

There is also a middle option: **replay mode** reads real packets from a
`.pcap` file through the same Scapy dissection path, so the real packet
pipeline can be demonstrated even with no privileges at all.

### 17. How is the model evaluated?

A stratified 75/25 train/test split, then on the held-out test set:
multiclass accuracy and macro-F1, a per-class precision/recall report, a
confusion matrix, and derived binary NORMAL-vs-ATTACK accuracy, precision,
recall and F1. Everything is written to `models/metrics.json` together with the
data source and a caveat sentence.

**Important honesty point:** the model shipped in this repository was trained on
the bundled **synthetic demo dataset**, so its ≈0.998 accuracy measures
separation of the demo generator's own classes. It is **not** an experimental
result on real traffic. Real numbers require downloading CIC-IDS2017 and
re-running `scripts/train_model.py`.

*Macro-F1 is reported because the classes are imbalanced — benign traffic is
3× any attack class, so plain accuracy would flatter the model.*

We also run 5-fold stratified cross-validation (demo data: macro-F1
0.9982 ± 0.0004) so the result does not rest on one lucky split, and a
feature-reliance audit that retrains with `Destination Port` zeroed out
(macro-F1 drops only 0.0008, so the model is using behaviour, not the port).
Both come from `python3 scripts/evaluate_model.py --cv 5 --audit-port`.

### 18. What are the limitations?

1. The shipped model is trained on synthetic demo data; its metrics are demo
   metrics.
2. CIC-IDS2017 is not 802.11-specific, so NetHawk detects network-layer
   intrusions, not Wi-Fi link-layer attacks such as deauthentication.
3. **Cross-domain accuracy is uneven, and we measured it.** On replayed real
   packets the SYN flood was correctly detected as DDoS (risk 74) and the port
   scan as Port Scan, but benign HTTPS and DNS flows were false-positived
   (Web Attack 0.54–0.67; Port Scan 0.60), and confidence on real traffic is
   around 0.5 versus around 1.0 on demo data. Cause: our flow assembler
   follows the CIC-IDS2017 definitions but is not CICFlowMeter, and the model
   is trained on synthetic statistics.
4. No 802.11 frame parsing; monitor mode is detected but unused. No SSID,
   BSSID or MAC-layer fields are read — devices are keyed by IP address.
5. Responses are simulated — there is no enforcement backend.
6. Live mode requires capture privileges (verified working on our Mac without
   `sudo`; elsewhere it needs `sudo`).
7. Supervised only: a genuinely novel attack may be missed or land in
   "Other Suspicious".
8. Single host, single user; no distributed sensors or alert forwarding.
9. No PyInstaller packaging yet — the deck lists it, the code does not have it.

### 19. What is a flow, and why analyse flows instead of packets?

A **flow** is all packets exchanged between the same pair of endpoints
(source IP+port, destination IP+port, protocol) within a time window. One packet
on its own says very little; an attack shows up in *aggregate* behaviour —
hundreds of tiny SYN packets to different ports, or a sustained 8000 packets/s
stream. Flow features capture that behaviour, which is why CIC-IDS2017 and
NetHawk both work at flow level.

### 20. What is the difference between your two modes?

DEMO mode generates flows locally from a labelled synthetic generator — it needs
no privileges, no dataset and no network, and it drives the classroom
demonstration. LIVE mode captures real packets with Scapy, assembles real flows
and analyses those. **Both use the identical model, risk scorer, decision engine,
database and dashboard** — only the first stage of the pipeline differs, which is
exactly what the adapter layer is for.

### 21. Is anything attacked during your demonstration?

No. The "Run Security Simulation" button calls a local generator that produces
feature vectors describing attack-like traffic. Nothing is transmitted, no host
is contacted, and no real or third-party network is involved.

### 22. What would you do next?

Integrate AWID3 for genuine 802.11 attack detection, add 802.11 frame parsing
from a monitor-mode adapter, add an unsupervised anomaly detector alongside the
classifier for unknown attacks, and package the app with PyInstaller.

### 23. You have three traffic sources. Why not just one?

Because each answers a different question, and only one of them can be relied
on in a classroom:

* **DEMO** — locally generated flows. No privileges, no dataset, no network.
  This is what guarantees the demonstration runs.
* **REPLAY** — real packets read from a `.pcap` with Scapy's
  `sniff(offline=...)`. This proves the *real* packet path works — dissection,
  flow assembly, feature extraction — without needing capture privileges.
* **LIVE** — real packets captured from an interface. This is the production
  path, and it needs privileges.

All three feed the identical model, risk scorer, decision engine, database and
dashboard. Only the first stage differs, which is exactly what the adapter
layer is for. Demo mode alone would be unconvincing (the generator also
produced the training data); replay and live are the honest tests.

### 24. A SYN flood opens a new source port per packet. Doesn't that break flow-based detection?

Yes, and handling it is a real design decision in NetHawk. With strict 5-tuple
accounting, 900 flood packets become 900 separate one-packet flows: each looks
like one stray probe and the packet *rate* that defines a flood disappears.

So before analysis NetHawk merges storms of tiny flows that share
`(source, destination, protocol, destination port)`. Grouping by destination
**port** is the key, because it separates the two reconnaissance patterns:

* a flood sends hundreds of micro-flows to **one** port → merged into one
  high-rate record → DoS/DDoS
* a scan sends one or two micro-flows per port across **many** ports → each
  group stays below the threshold → left alone → still looks like a scan

Only groups of at least five flows of at most two packets each are merged, so
ordinary conversations are untouched. Measured on our sample capture: 981
packets → 24 flows, flood detected as DDoS at risk 74, scan still detected as
Port Scan.

### 25. How do you know your evaluation isn't leaking test data into training?

We found and fixed two leakage problems during the audit, and both now have
regression tests:

1. **Cross-file duplicates.** Each CSV was de-duplicated on its own, but
   CIC-IDS2017 ships eight files and a flow present in two of them survived
   into the combined frame — so the same row could appear in both the train and
   the test split. We now de-duplicate after concatenation and report how many
   rows were removed.
2. **Biased sampling.** Large files were truncated with `nrows=N`, which keeps
   only the *first* N rows. The CSVs are time-ordered and each day's attacks are
   clustered, so truncation can drop whole classes: on a label-ordered test file
   head-truncation kept **1** class while random sampling kept **7**. Sampling is
   now random and seeded.

We also use a stratified split, report macro-F1 because of the 3:1 imbalance,
and cross-validate.

### 26. Why does the risk score damp the rate for tiny flows?

Because a rate measured over one or two packets is not a load. A single-packet
flow lasting 200 microseconds reports hundreds of thousands of packets per
second — we have seen 1,000,000 pkt/s on a one-packet scan flow in the replay
output. Without damping, every stray probe would score like a flood. So the
intensity term is scaled by `packets / 10` until a flow has at least ten
packets. The scan then scores MEDIUM (around 59) on category and confidence,
while a genuine 900-packet flood scores HIGH (around 74–98).

### 27. What would make the biggest difference if you continued this project?

Training on real data, in two steps. First CIC-IDS2017, to get honest
network-intrusion metrics instead of demo-generator metrics. Then AWID3 with a
monitor-mode capture path, which is what would let NetHawk genuinely detect
Wi-Fi link-layer attacks such as deauthentication and evil twin — the thing the
project title promises and the current MVP does not do. The adapter seam for
that already exists; nothing else in the pipeline would need to change.
