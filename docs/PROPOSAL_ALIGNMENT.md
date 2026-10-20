# Proposal vs. implementation — accuracy audit

Audited against the 13-slide NetHawk deck (`NetHawk.pptx` / `NetHawk.pdf`,
dated 6 Sep 2026) on 20 Oct 2026. The two files carry the same 13 slides.

Purpose: find every claim in the deck that the code does **not** support, so the
presentation can be corrected before submission. Nothing here invents team
details or results; it only compares the deck's wording to the repository.

Legend: **OK** = implemented and verified · **PARTIAL** = implemented but the
wording overstates it · **MISSING** = claimed but not implemented.

---

## Claims that need the wording changed

| # | Slide | Deck says | Reality | Fix the wording to |
|---|-------|-----------|---------|--------------------|
| 1 | 05 Proposed System, step 01 | "LIVE WI-FI TRAFFIC — **802.11 frames** on the monitored WLAN" | **PARTIAL.** Capture is at IP/TCP/UDP level on the Wi-Fi interface. No 802.11 frame parsing, no monitor mode. | "Live traffic on the Wi-Fi interface (IP/TCP/UDP flows)" |
| 2 | 05 Proposed System, header | "A single local pipeline from **live 802.11 traffic** to a stored security event" | **PARTIAL**, same reason. | "from live network traffic on the Wi-Fi interface" |
| 3 | 06 Architecture, network layer | "Wi-Fi Network · 802.11 Traffic — **frames · MAC · SSID · BSSID**" | **MISSING.** NetHawk never reads SSID, BSSID or 802.11 MAC-layer fields. Devices are identified by **IP address**. | "Wi-Fi network · IP/TCP/UDP traffic — addresses · ports · flow statistics" |
| 4 | 01 Introduction (graphic) | "AP rogue?" implies rogue-AP detection | **MISSING.** No rogue-AP, evil-twin or deauthentication detection. | Remove the rogue-AP cue, or label it "future work (needs AWID3 + monitor mode)" |
| 5 | 07 Novelty | "**Real-time Wi-Fi monitoring**" | **PARTIAL.** Real-time monitoring of traffic *on* a Wi-Fi interface — not of 802.11 link-layer activity. | "Real-time monitoring of traffic on the Wi-Fi interface" |
| 6 | 09 Technology stack | "**PyInstaller** — Packaging — bundles everything into one executable app" | **MISSING.** No PyInstaller spec, no packaging step. The app runs from source. | Move PyInstaller to the roadmap as not-yet-done, or delete the row |
| 7 | 09 Technology stack | "**CustomTkinter / PyQt** — Desktop GUI" | **PARTIAL.** CustomTkinter only (plus `ttk.Treeview` for the table). PyQt is unused. | "CustomTkinter (with ttk.Treeview for the history table)" |
| 8 | 10 Roadmap, phase 8 | "Testing + **Packaging** — validate & package standalone app" | **PARTIAL.** Testing is done (110 tests). Packaging is not. | Mark phase 8 as "Testing complete; packaging pending" |

## Claims the implementation supports

| Slide | Claim | Status |
|-------|-------|--------|
| 05 / 08 | Packet capture → feature extraction → ML detection → classification → risk score → decision engine → alert/response → local logging | **OK** — all seven stages implemented; see `docs/TESTING.md` |
| 06 | Four-layer architecture (network / capture+ML / decision / application) | **OK** — mirrored by the package layout |
| 07 | Feature-based ML analysis, attack classification, risk scoring, controlled response, local event logging, standalone desktop deployment, unified dashboard | **OK** |
| 07 | "The novelty lies in the specific integration and workflow — not in any single tool" | **OK** and accurate; keep this framing |
| 09 | Python, Scapy, pandas, scikit-learn, Random Forest, SQLite | **OK** — all actually used |
| 10 | Roadmap phases 1–7 | **OK** |
| 11 | "Expected output — mock values shown to illustrate the interface. **Not experimental results; no real attacks detected yet**" | **OK** — and now improvable: the dashboard shows real detections from replayed and live traffic. Replace the mock with a real screenshot, and keep a caveat that the model is demo-trained. |
| 12 | References [1]–[6] | **OK** — Snort, Zeek/Bro, Suricata, Kismet, AWID, AWID3 are all correctly cited and relevant |

## Claims to **add**, because the code does more than the deck promises

1. **PCAP replay mode** — a third traffic source that runs real Scapy packet
   dissection from a capture file with no privileges. Worth a slide: it is how
   the real packet path is demonstrated on any laptop.
2. **Graceful mode degradation** — LIVE falls back to DEMO with the reason shown.
3. **Micro-flow aggregation** — the design decision that makes SYN floods
   detectable under 5-tuple accounting (see `docs/viva.md` Q24).
4. **Explainable risk arithmetic** — every event stores the full weighted sum.
5. **Leakage-resistant dataset handling** — cross-file de-duplication and random
   sampling instead of head-truncation (both were real bugs, now fixed and tested).

## Things to say carefully in the viva

* The shipped model is trained on **synthetic demo data**. Say so before anyone
  asks. The ≈0.998 figures are demo-generator separability, not experimental
  intrusion-detection results.
* CIC-IDS2017 is **not** an 802.11 dataset. The deck's slide 3 already lists
  AWID/AWID3 correctly — use that to explain the gap, not to imply coverage.
* Responses are **simulated**. No network is ever modified.
* Live capture **is** verified on the development Mac (see `docs/TESTING.md`),
  but what it analyses is IP/TCP/UDP flows, not 802.11 frames.
