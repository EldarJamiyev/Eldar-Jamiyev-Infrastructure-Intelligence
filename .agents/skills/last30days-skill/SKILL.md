---
name: last30days-skill
description: Multi-source temporal timeline synthesis and changelog aggregation. Identifies recent infrastructural shifts, config mutations, and deployment events to pinpoint root causes.
license: MIT
---

# Last30Days Skill — Temporal Timeline Synthesis & Incident Timeline Reconstruction

This skill focuses on temporal retrospection and timeline synthesis. When diagnosing complex, cascading network failures, looking only at current instant telemetry misses the initiating trigger ("Patient Zero"). This skill reconstructs the chronological sequence of configuration mutations, firmware updates, and metric drift leading up to the failure.

---

## ⏱️ Timeline Synthesis Methodology

```
[ T-30 Days: Baseline SLA Established ]
           │
           ▼
[ T-7 Days: Minor Config / Routing Table Shift ]
           │
           ▼
[ T-2 Hours: CUSUM Changepoint Detected (Packet Loss +0.4%) ]
           │
           ▼
[ T-0: Cascading Failover & Full Link Outage ]
```

---

## 🛠️ Key Temporal Analysis Steps

1. **Git & Policy History Ingestion**:
   - Inspects `policies/desired-infrastructure-state.json` and git commit logs for recent changes.
2. **CUSUM Changepoint Alignment**:
   - Matches statistical changepoints (Page's Cumulative Sum) against historical events.
3. **Chronological Deduplication**:
   - Orders all host restarts, DHCP lease changes, and interface flaps into a single monotonic timeline.

---

## 💻 EJII Integration: Patient Zero Reconstruction

In EJII, this skill feeds the **Telemetry DVR Time-Machine & Snapshot Diff Engine (`src/systems/telemetry-dvr-timemachine.ts`)**:
- Replays network state frame-by-frame across a circular buffer.
- Compares topology snapshots at $T_0$ vs $T_{-30\text{min}}$ to highlight which switch or interface failed first.
