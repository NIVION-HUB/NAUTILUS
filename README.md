# NAUTILUS: Financial Crime Infrastructure & Money-Trail Analysis System

[![Track](https://img.shields.io/badge/Track-PS05%20Financial%20Crime%20Analytics-0A2540?style=for-the-badge)](https://github.com)
[![Architecture](https://img.shields.io/badge/Architecture-Local--First%20%7C%20Zero--External--API-1E88E5?style=for-the-badge)](https://github.com)
[![Legal Framework](https://img.shields.io/badge/Compliance-Sec%2091%20%26%20102%20CrPC%20%7C%20BNSS-43A047?style=for-the-badge)](https://github.com)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)

> **Networked Analysis & Unified Transaction Intelligence Linking Unified Systems (NAUTILUS)**  
> An integrated forensic investigation platform that ingests multi-format bank statements, traces suspected mule-account transactions hop-by-hop from a victim UTR, correlates digital cyber infrastructure (domains, IPs, SSL certificates, passive DNS), and auto-generates court-ready Section 91 & Section 102 CrPC statutory notices and evidence dossiers.

---

![NAUTILUS Architecture](NAUTILUS_Architecture_Flowchart.png)

---

## 📌 Executive Summary & Problem Context

Modern cyber-enabled financial fraud in India (e.g., loan app scams, task-based investment fraud, fake job portals, and APK malware) exploits two distinct planes simultaneously:
1. **Layered Financial Rails:** Stolen money is rapidly channeled through networks of rented or compromised "mule" bank accounts, split into fractions, layered across banks, and liquidated at ATMs within minutes.
2. **Disposable Digital Infrastructure:** Fraudsters deploy disposable domains, fast-flux DNS configurations, bulletproof VPS hosting, and anonymized VPNs/proxies to deceive victims and hide communication channels.

### The Operational Challenge for Law Enforcement
Investigating Officers (IOs) in cyber crime police stations receive bank statements in non-standard PDF/Excel formats and digital indicators from various sources. Analyzing them independently creates blind spots, slows down asset freezing during the critical **"Golden Hour"**, and leads to defective statutory information requests that get rejected by telecom and hosting providers.

**NAUTILUS eliminates this silo.** It unifies heterogeneous banking files and digital footprints into a **Unified Heterogeneous Entity Graph (UHEG)**, enabling automated fund tracing, explainable mule profiling, cross-case syndicate attribution, and legally sound evidence export.

---

## 🎯 Key System Innovations & Force-Multipliers

### 1. Indian Payment Narration Deconstruction Engine
Bank statements in India contain cluttered, non-standard narration strings. NAUTILUS applies deterministic pattern matching to dissect raw narrations into structured forensic parameters:
* **Payment Modalities:** Auto-classifies `UPI/P2P`, `UPI/P2M`, `IMPS-P2A`, `NEFT`, `RTGS`, and `ATM-WDL`.
* **Third-Party Providers:** Identifies handles (`@paytm`, `@ybl`, `@okhdfcbank`, `@ibl`, PhonePe, Google Pay, Cred, BharatPe).
* **12-Digit RRN / UTR Retrieval:** Extracts transaction reference numbers directly from dense strings.
* **ATM Terminal Dissection:** Parses physical cash-out terminals and locations (e.g., `ATM-WDL/S1AC001/JAIPUR-MALVIYA NAGAR`).

### 2. Transaction Topology Engine (TTE) & 8 Risk Primitives
Instead of treating accounts in isolation, the TTE mathematically analyzes graph-theoretic fund flow patterns across **8 explainable risk primitives**:
1. **Velocity Spike:** Rapid in-and-out fund transit within a 24-hour window (inflow followed by immediate outflow).
2. **Layering Depth:** Directed hop count from victim UTR to downstream terminal accounts.
3. **Counterparty Entropy:** Shannon entropy of sender accounts (detects collection funnels for multiple victims).
4. **Fan-In Funneling:** Ratio of credits from unrelated senders to bulk debit transfers or ATM cashouts (> 10:1).
5. **Repeated Counterparty Nexus:** Identifies hidden convergence points across seemingly unconnected cases.
6. **Round-Figure Clustering:** Chi-squared goodness-of-fit test detecting abnormal concentration at ₹10k, ₹50k, ₹1L milestones.
7. **Dormancy Break:** Sudden activation (> 10x prior volume within 48h) after > 90 days of inactivity.
8. **Structuring Signature:** Disproportionate credits placed just below statutory thresholds (e.g., ₹49,999 to evade ₹50,000 PAN rules).

### 3. Explainable Mule Role Taxonomy
Replaces ambiguous risk percentages with legally explainable operational roles:
* `[COLLECTOR MULE]` (Tier 1): Directly receives victim funds; exhibits near-zero balance retention and immediate dispersal.
* `[LAYERING MULE]` (Tier 2): Splits round-figure amounts across multiple downstream accounts to break the audit trail.
* `[AGGREGATOR / FUNNEL MULE]` (Tier 2/3): Collects small credits from multiple accounts into a consolidated balance.
* `[TERMINAL CASHOUT NODE]` (Tier 3/4): Physical exit point (ATM cash withdrawal, merchant POS swipe, P2P settlement).

### 4. "Golden Hour" Debit Freeze Triage Matrix
Asset recovery requires rapid action. NAUTILUS evaluates **Retained Balance**, **Transit Velocity**, and **Hop Distance** to rank accounts by immediate recovery probability:
* `[PRIORITY 1 - URGENT FREEZE]`: Holds ₹4,20,000 balance, zero outbound debits in last 3 hours — 92% recovery probability.
* `[PRIORITY 2 - ACTIVE MONITOR]`: Layering active; ₹1,10,000 in transit across 2 hops.
* `[PRIORITY 4 - EXHAUSTED]`: Balance ₹150; ₹2,00,000 liquidated via ATM cash withdrawal.

### 5. Hybrid Domain & IP Intelligence (Zero Active Probing)
* **Mode A (Live Passive OSINT):** Queries authoritative RDAP/WHOIS, resolves DNS records (A, AAAA, MX, NS, TXT, CNAME), queries Certificate Transparency (CT) logs (`crt.sh`) for subdomains, and enriches IPs with ASN, ISP, and VPN/Proxy flags.
* **Mode B (Air-Gapped Reference):** Ingests offline GeoLite2, ASN delegation tables, and pre-packaged evidence files with automated 2.5s timeout fallback.
* **Strict Constraint:** Zero active port scanning or server probing (no Nmap, no exploit fuzzing).

### 6. Dynamic IP & Carrier-Grade NAT (CGNAT) Alignment
Mobile fraudsters share public IPv4 addresses across thousands of cellular subscribers. NAUTILUS enforces exact **UTC Timestamp + Public IP + Source Port** mapping, ensuring statutory notices issued to telecom operators (Airtel, Jio, Vi) uniquely identify the specific subscriber session.

### 7. Dual-Badge Evidentiary Classification
* 🟢 **`[PRIMARY EVIDENCE / COURT ADMISSIBLE]`**: Core Banking CBS UTR rows, certified account statements with SHA-256 integrity hashes, and CT log Merkle proofs (meets Section 65B Indian Evidence Act / Section 63 BSA criteria).
* 🟡 **`[INVESTIGATIVE LEAD / INDICATIVE]`**: IP Geolocation, Hosting Provider ASN, Reverse DNS (PTR), and WHOIS Privacy records. (Clearly flagged: *Requires Section 91 CrPC notice to establish physical suspect identity*).

---

## 🏗️ System Architecture & Workflow

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                                 PRESENTATION LAYER                                        │
│  ┌────────────────────────┐  ┌────────────────────────┐  ┌─────────────────────────────┐  │
│  │ Interactive Money-Trail│  │ Bipartite Infrastructure│ │ Multi-Modal Entity Explorer │  │
│  │ Graph (Seeded by UTR)  │  │ Map (Domains ↔ IPs)    │  │ & Unified Case Timeline     │  │
│  └────────────────────────┘  └────────────────────────┘  └─────────────────────────────┘  │
│  ┌────────────────────────┐  ┌────────────────────────┐  ┌─────────────────────────────┐  │
│  │ Freeze Priority Matrix │  │ Multi-Party Notice Pack│  │ Court-Ready Case Dossier    │  │
│  │ (Golden Hour Triage)   │  │ (Sec 91/102 CrPC/BNSS) │  │ (PDF/Excel + SHA-256 Chain) │  │
│  └────────────────────────┘  └────────────────────────┘  └─────────────────────────────┘  │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│                             CORRELATION ENGINE (THE "BRAIN")                              │
│  ┌────────────────────────┐  ┌────────────────────────┐  ┌─────────────────────────────┐  │
│  │ Transaction Topology   │  │ Infrastructure DNA     │  │ Temporal Correlation Engine │  │
│  │ Engine (8 Primitives)  │  │ Engine (12 Signals)    │  │ (Clock Skew + CGNAT Align)  │  │
│  └────────────────────────┘  └────────────────────────┘  └─────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                  UNIFIED HETEROGENEOUS ENTITY GRAPH (UHEG)                          │  │
│  │    Victim UTR ↔ Mule Accounts ↔ UPI IDs ↔ Phone Numbers ↔ Domains ↔ IPs ↔ ASNs      │  │
│  └─────────────────────────────────────────────────────────────────────────────────────┘  │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│                                 NORMALIZATION LAYER                                       │
│  ┌────────────────────────┐  ┌────────────────────────┐  ┌─────────────────────────────┐  │
│  │ Bank Statement Parser  │  │ Hybrid Domain/IP Engine│  │ Case Evidence Vault &       │  │
│  │ (Layout-Free PDF/Excel)│  │ (Passive OSINT/Offline)│  │ Hash-Chained Audit Trail    │  │
│  └────────────────────────┘  └────────────────────────┘  └─────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Scalability & Real-Time Production Upgrade Blueprint

A common misconception is that massive datasets require real-time streaming architectures. In law enforcement forensics, **high-performance batch processing is mathematically optimal**:
* **Seeded $k$-Hop Graph Traversal:** Avoids computing useless all-to-all graphs across millions of rows. NAUTILUS performs directed traversal starting strictly from the victim's UTR, touching only the relevant mule sub-graph in sub-second time ($O(k)$ complexity).
* **64-bit Risk DNA In-Memory Compression:** The behavioral fingerprints of **1,000,000 bank accounts occupy only 8 MB of RAM**, enabling instant cross-case similarity checks in CPU registers.

### Decoupled Adapter Architecture (Upgrade Bridge)
The core analytical engines consume standardized `UnifiedTransaction` objects without depending on file formats:
* **Today (Forensic MVP):** Ingests PDF/Excel/CSV statements via the Bank Statement Parser (BSP).
* **Tomorrow (Live Production):** Connects to a **Kafka Event Consumer** or **CBS Webhook** pushing live transaction messages into the exact same pipeline with **zero refactoring of the correlation engines**.

---

## ⚖️ Legal Framework & Statutory Notice Automation

NAUTILUS produces legally compliant, pre-filled notices ready for signature by the Investigating Officer:

| Recipient Entity | Statutory Section | Technical Parameters Required | Purpose |
| :--- | :--- | :--- | :--- |
| **Beneficiary Banks** | Sec 91 & 102 CrPC (Sec 94 & 106 BNSS) | Account No, IFSC, Victim UTR, Defrauded Amount, Timestamp | Account Opening KYC, mandate form, IPDR login logs, and **Immediate Debit Freeze** |
| **Domain Registrars** | Sec 91 CrPC (Sec 94 BNSS) | Domain Name, Creation Date, WHOIS Registrant ID | Subscriber identity, payment gateway transaction IDs, and registration IP |
| **Cloud / VPS Providers** | Sec 91 CrPC (Sec 94 BNSS) | Server IP, Subnet, Timestamp Window | Virtual server access logs, SSH login IPs, and billing account profiles |
| **Telecom ISPs** | Sec 91 CrPC (Sec 94 BNSS) | Public IP, **Source Port**, UTC Timestamp with Offset | Carrier-Grade NAT (CGNAT) subscriber mapping to Customer Acquisition Form (CAF) |

### Mandatory Legal Disclaimer
> *`LEGAL NOTICE: Geolocation, ASN, and hosting provider attribution represent network routing infrastructure and datacenter facilities. They are indicative investigative leads and do NOT constitute legal proof of a physical suspect's identity or physical location.`*

---

## 📋 Standardized Final Investigation Report Template

The platform automatically generates a comprehensive forensic report structured into standard evidentiary sections:
* **Part I:** Incident Reference & FIR Case Intake
* **Part II:** Victim Loss & Primary Defrauded UTR
* **Part III:** Chronological Money-Trail & Layered Hop Ledger
* **Part IV:** Digital Infrastructure & Cyber Footprint Dossier
* **Part V:** Cross-Case Syndicate Linkage Matrix
* **Part VI:** Statutory Notices Dispatched (Annexures A to D)
* **Part VII:** Mandatory Forensic Certification under Section 65B Indian Evidence Act (Section 63 BSA)

---

## 🚀 Quickstart & Installation

### Prerequisites
* Python 3.10 or higher
* Recommended: Virtual environment

### Installation
```bash
# Clone the repository
git clone https://github.com/your-username/nautilus-forensics.git
cd nautilus-forensics

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install core dependencies
pip install -r requirements.txt
```

### Core Dependencies
```txt
pdfplumber>=0.10.0      # Layout-free PDF statement extraction
openpyxl>=3.1.0         # Excel statement parsing
pandas>=2.0.0           # Tabular data manipulation
dnspython>=2.4.0        # Passive DNS record resolution
python-docx>=1.1.0      # Word dossier report generation
```

### Basic Usage Example
```python
from nautilus.core.parsers.bsp import PDFStatementParser
from nautilus.core.engines.tte import TransactionTopologyEngine
from pathlib import Path

# 1. Parse bank statements
parser = PDFStatementParser()
statement = parser.parse(Path("data/sample/mule_account_statement.pdf"), account_id="ACC_98765", bank_name="State Bank of India")

# 2. Run Topology Engine
engine = TransactionTopologyEngine({"ACC_98765": statement})
risk_dna = engine.compute_risk_dna("ACC_98765")

print(f"Risk Tier: {risk_dna.risk_tier_label}")
print(f"Triggered Primitives: {[p.name for p in risk_dna.triggered_primitives]}")

# 3. Trace Money Trail from Victim UTR
money_trail = engine.trace_money_trail(victim_utr="SBIN000123456789")
print(f"Total Hops: {len(money_trail.hops)} | Layering Depth: {money_trail.layering_depth}")
```

---

## 🏆 Hackathon PS05 Scope Compliance Matrix

| PS05 Evaluation Parameter | Status | Implementation Detail |
| :--- | :---: | :--- |
| **Bank-Statement Ingestion** | ✅ Must Have | Universal layout-free parser for PDF, Excel, and CSV into `UTS v1` schema. |
| **Mule-Account Analysis** | ✅ Must Have | 8 explainable risk primitives, 64-bit Risk DNA, and 4-tier mule role taxonomy. |
| **Money-Trail Visualization** | ✅ Must Have | Directed interactive fund graph seeded from victim UTR with smart tier collapsing. |
| **Domain & IP Lookups** | ✅ Must Have | Passive WHOIS/RDAP, DNS, CT log subdomains, and IP ASN attribution with offline fallback. |
| **Cross-Case Linking** | 🌟 Good to Have | 64-bit Risk DNA and 128-bit Infra DNA similarity matching across independent FIRs. |
| **Lawful Notice Generator** | 🌟 Good to Have | Pre-drafted Section 91 & Section 102 CrPC notices with exact CGNAT Source Ports. |
| **Historical Records** | 🌟 Good to Have | Historical passive DNS tracking and Regional Internet Registry (RIR) allocation monitoring. |
| **Out-of-Scope Discipline** | 🔒 Compliant | Zero active network probing, zero unauthorized access to bank switches or private records. |

---

## 📄 License & Classification

* **Document Version:** 2.0  
* **Classification:** FOR OFFICIAL USE ONLY / HACKATHON EVALUATION  
* **Track:** Rajasthan Police Hackathon / PS05 Financial Crime Analytics
