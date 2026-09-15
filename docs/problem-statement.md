# Problem Statement — D2: Threat Intelligence Correlation & Alert Prioritisation Assistant

**Track:** Defense & Aerospace | **Priority:** Critical Now

---

## The Challenge

Modern defense and aerospace operations generate an overwhelming volume of digital signals. A typical Tier-1 Security Operations Centre (SOC) attached to a defense installation may receive **10,000–100,000 alerts per day** from disparate systems, each speaking a different language:

| Source | Format | Volume | Examples |
|---|---|---|---|
| SIEM systems | JSON/CEF event logs | 1,000s/hour | Brute-force, lateral movement, privilege escalation |
| Satellite feeds | Proprietary binary → JSON metadata | 100s/hour | Signal anomalies, orbital deviations, jamming signatures |
| Cyber sensors | CSV/CEF (IDS/IPS signatures) | 10,000s/hour | Known CVE exploits, C2 beacon patterns, anomalous traffic |
| Intelligence reports | OSINT JSON bulletins | 10s/hour | Actor profiles, TTP updates, campaign advisories |

### Core Problems

**1. Volume overload — humans cannot scale.**
No analyst team can read 50,000 alerts and produce timely assessments. Alert fatigue causes genuine threats to be missed. Studies show analysts in overloaded environments miss 44% of significant incidents within the first hour of a shift.

**2. Format heterogeneity — correlation is manual.**
A SIEM alert and an OSINT bulletin describing the same adversary campaign look completely different. Without automated correlation, an analyst must mentally link these across four separate dashboards. This is slow, error-prone, and nearly impossible at speed.

**3. False positive overload — resources are wasted.**
Industry benchmarks put SIEM false-positive rates between 40–80%. Every minute an analyst spends chasing a false positive is a minute not spent on a real threat. Worse, organizations that chase too many false positives begin to ignore alert categories entirely ("alert fatigue"), creating systemic blind spots.

**4. No structure for commander decisions — BLUF is essential.**
Commanders cannot read raw technical logs. Military doctrine mandates BLUF (Bottom Line Up Front) format: the key judgment, confidence level, and recommended action — immediately, in plain language. No commercial SIEM product produces BLUF output.

**5. ATT&CK blindness — tactical context is absent.**
Raw alerts do not map to adversary behavior frameworks. Without MITRE ATT&CK technique identification, defenders cannot understand *what the adversary is trying to do* (initial access, lateral movement, exfiltration) — they can only see individual events.

---

## The Stakes

In the Defense & Aerospace domain, a missed genuine threat does not mean a data breach recoverable in days. It can mean:

- Loss of a classified satellite communications link
- Undetected adversary intrusion into a command-and-control network
- Exfiltration of mission-critical intelligence

**Speed and accuracy are not nice-to-haves — they are mission-critical requirements.**

---

## What a Solution Must Do

To be operationally viable, a solution must:

1. **Ingest all source formats** without requiring format-specific analyst intervention
2. **Automatically correlate** alerts describing the same incident across sources (without manual tagging)
3. **Separate genuine threats from false positives** at scale, reducing analyst workload by ≥70%
4. **Provide tactical context** via MITRE ATT&CK technique mapping
5. **Produce BLUF output** in seconds, not hours — formatted for commander consumption
6. **Rank and prioritise** so the highest-risk incidents are always at the top of the queue
