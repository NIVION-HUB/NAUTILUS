"""
Infrastructure DNA Engine (IDE) — NAUTILUS Core Correlation Engine #2
Multi-modal infrastructure fingerprinting from local artifacts only.
"""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Optional
import re
import hashlib
import json
import ipaddress

from nautilus.core.schemas.infra_dna import (
    InfrastructureDNA, InfraSignal, InfraEvidence, INFRA_MATCH_THRESHOLDS
)


@dataclass(frozen=True, slots=True)
class DomainArtifact:
    """Parsed domain intelligence artifact."""
    domain: str
    # WHOIS
    registrar: str = ""
    reseller: str = ""
    creation_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    registrant_email: str = ""
    registrant_org: str = ""
    name_servers: tuple[str, ...] = ()
    # DNS
    a_records: tuple[str, ...] = ()
    aaaa_records: tuple[str, ...] = ()
    mx_records: tuple[str, ...] = ()
    txt_records: tuple[str, ...] = ()
    cname_records: tuple[str, ...] = ()
    ns_records: tuple[str, ...] = ()
    # SSL
    ssl_issuer: str = ""
    ssl_san: tuple[str, ...] = ()
    ssl_fingerprint: str = ""  # SHA256 of public key
    ssl_not_before: Optional[datetime] = None
    ssl_not_after: Optional[datetime] = None
    # CT Logs
    ct_entries: tuple[dict, ...] = ()
    # Subdomains
    subdomains: tuple[str, ...] = ()
    # Metadata
    source_files: tuple[str, ...] = ()
    parsed_at: datetime = field(default_factory=datetime.utcnow)


@dataclass(frozen=True, slots=True)
class IPArtifact:
    """Parsed IP intelligence artifact."""
    ip: str
    # Network
    asn: int = 0
    asn_name: str = ""
    prefix: str = ""
    country: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    hosting_provider: str = ""
    # Reverse DNS
    rdns: tuple[str, ...] = ()
    # Classification
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_hosting: bool = False
    # Metadata
    source_files: tuple[str, ...] = ()
    parsed_at: datetime = field(default_factory=datetime.utcnow)


class InfrastructureDNAEngine:
    """
    Core engine for infrastructure fingerprinting.
    Computes Infrastructure DNA from local artifacts only — zero live queries.
    """

    def __init__(self):
        self.domains: dict[str, DomainArtifact] = {}
        self.ips: dict[str, IPArtifact] = {}
        self._domain_ip_map: dict[str, set[str]] = defaultdict(set)  # domain -> IPs
        self._ip_domain_map: dict[str, set[str]] = defaultdict(set)  # IP -> domains

    def add_domain_artifact(self, artifact: DomainArtifact):
        """Add a parsed domain artifact."""
        self.domains[artifact.domain] = artifact
        # Map domain to IPs
        for ip in artifact.a_records:
            self._domain_ip_map[artifact.domain].add(ip)
            self._ip_domain_map[ip].add(artifact.domain)
        for ip in artifact.aaaa_records:
            self._domain_ip_map[artifact.domain].add(ip)
            self._ip_domain_map[ip].add(artifact.domain)

    def add_ip_artifact(self, artifact: IPArtifact):
        """Add a parsed IP artifact."""
        self.ips[artifact.ip] = artifact

    def load_from_directory(self, dir_path: str):
        """Load artifacts from JSON files in directory."""
        import os
        from pathlib import Path

        path = Path(dir_path)
        for file_path in path.glob("*.json"):
            try:
                with open(file_path) as f:
                    data = json.load(f)

                if data.get("type") == "domain":
                    artifact = DomainArtifact(
                        domain=data["domain"],
                        registrar=data.get("registrar", ""),
                        reseller=data.get("reseller", ""),
                        creation_date=datetime.fromisoformat(data["creation_date"]) if data.get("creation_date") else None,
                        expiry_date=datetime.fromisoformat(data["expiry_date"]) if data.get("expiry_date") else None,
                        registrant_email=data.get("registrant_email", ""),
                        registrant_org=data.get("registrant_org", ""),
                        name_servers=tuple(data.get("name_servers", [])),
                        a_records=tuple(data.get("a_records", [])),
                        aaaa_records=tuple(data.get("aaaa_records", [])),
                        mx_records=tuple(data.get("mx_records", [])),
                        txt_records=tuple(data.get("txt_records", [])),
                        cname_records=tuple(data.get("cname_records", [])),
                        ns_records=tuple(data.get("ns_records", [])),
                        ssl_issuer=data.get("ssl_issuer", ""),
                        ssl_san=tuple(data.get("ssl_san", [])),
                        ssl_fingerprint=data.get("ssl_fingerprint", ""),
                        ssl_not_before=datetime.fromisoformat(data["ssl_not_before"]) if data.get("ssl_not_before") else None,
                        ssl_not_after=datetime.fromisoformat(data["ssl_not_after"]) if data.get("ssl_not_after") else None,
                        ct_entries=tuple(data.get("ct_entries", [])),
                        subdomains=tuple(data.get("subdomains", [])),
                        source_files=(str(file_path),),
                    )
                    self.add_domain_artifact(artifact)

                elif data.get("type") == "ip":
                    artifact = IPArtifact(
                        ip=data["ip"],
                        asn=data.get("asn", 0),
                        asn_name=data.get("asn_name", ""),
                        prefix=data.get("prefix", ""),
                        country=data.get("country", ""),
                        region=data.get("region", ""),
                        city=data.get("city", ""),
                        isp=data.get("isp", ""),
                        hosting_provider=data.get("hosting_provider", ""),
                        rdns=tuple(data.get("rdns", [])),
                        is_vpn=data.get("is_vpn", False),
                        is_proxy=data.get("is_proxy", False),
                        is_tor=data.get("is_tor", False),
                        is_hosting=data.get("is_hosting", False),
                        source_files=(str(file_path),),
                    )
                    self.add_ip_artifact(artifact)
            except Exception as e:
                print(f"Warning: Failed to load {file_path}: {e}")

    # ==================== SIGNAL COMPUTATIONS ====================

    def compute_registrar_affinity(self, campaign_domains: list[str]) -> InfraEvidence:
        """Signal: Same registrar/reseller across multiple domains."""
        if len(campaign_domains) < 2:
            return self._empty_evidence(InfraSignal.WHOIS_REGISTRAR, "Need 2+ domains")

        registrars = []
        resellers = []

        for domain in campaign_domains:
            artifact = self.domains.get(domain)
            if artifact:
                if artifact.registrar:
                    registrars.append(artifact.registrar.lower())
                if artifact.reseller:
                    resellers.append(artifact.reseller.lower())

        if not registrars and not resellers:
            return self._empty_evidence(InfraSignal.WHOIS_REGISTRAR, "No registrar data")

        # Check for concentration
        from collections import Counter
        registrar_counts = Counter(registrars)
        reseller_counts = Counter(resellers)

        max_registrar_count = max(registrar_counts.values()) if registrar_counts else 0
        max_reseller_count = max(reseller_counts.values()) if reseller_counts else 0

        total = len(campaign_domains)
        registrar_ratio = max_registrar_count / total
        reseller_ratio = max_reseller_count / total

        score = max(registrar_ratio, reseller_ratio)

        # Bonus for exact same registrar + reseller combo
        combos = [(r, s) for r, s in zip(registrars, resellers) if r and s]
        if combos:
            combo_counts = Counter(combos)
            max_combo = max(combo_counts.values())
            combo_ratio = max_combo / len(combos)
            score = max(score, combo_ratio * 1.2)

        score = min(score, 1.0)

        dominant_registrar = registrar_counts.most_common(1)[0][0] if registrar_counts else "unknown"
        dominant_reseller = reseller_counts.most_common(1)[0][0] if reseller_counts else "unknown"

        return InfraEvidence(
            signal=InfraSignal.WHOIS_REGISTRAR,
            score=score,
            description=(
                f"Registrar affinity: {max_registrar_count}/{total} domains use '{dominant_registrar}' "
                f"({registrar_ratio:.0%}); {max_reseller_count}/{total} use reseller '{dominant_reseller}' "
                f"({reseller_ratio:.0%})"
            ),
            artifacts=tuple(campaign_domains),
            parameters={
                "total_domains": total,
                "registrar_distribution": dict(registrar_counts),
                "reseller_distribution": dict(reseller_counts),
                "dominant_registrar": dominant_registrar,
                "dominant_reseller": dominant_reseller,
            },
        )

    def compute_registration_timing(self, campaign_domains: list[str]) -> InfraEvidence:
        """Signal: Coordinated registration timing (bulk/sequential)."""
        if len(campaign_domains) < 2:
            return self._empty_evidence(InfraSignal.WHOIS_TIMESTAMP, "Need 2+ domains")

        dates = []
        for domain in campaign_domains:
            artifact = self.domains.get(domain)
            if artifact and artifact.creation_date:
                dates.append(artifact.creation_date)

        if len(dates) < 2:
            return self._empty_evidence(InfraSignal.WHOIS_TIMESTAMP, "Insufficient creation dates")

        dates.sort()

        # Check for same-day registrations
        same_day_groups = defaultdict(list)
        for i, d in enumerate(dates):
            key = d.date()
            same_day_groups[key].append(campaign_domains[i])

        max_same_day = max(len(v) for v in same_day_groups.values())
        same_day_ratio = max_same_day / len(dates)

        # Check for sequential registration (within hours)
        min_gap_hours = float('inf')
        for i in range(1, len(dates)):
            gap = (dates[i] - dates[i-1]).total_seconds() / 3600
            min_gap_hours = min(min_gap_hours, gap)

        # Score: high if bulk registration or very tight sequential
        if same_day_ratio >= 0.5:
            score = 0.9
        elif same_day_ratio >= 0.3:
            score = 0.7
        elif min_gap_hours < 1:
            score = 0.8
        elif min_gap_hours < 24:
            score = 0.5
        else:
            score = 0.2

        return InfraEvidence(
            signal=InfraSignal.WHOIS_TIMESTAMP,
            score=score,
            description=(
                f"Registration timing: {max_same_day}/{len(dates)} same-day "
                f"(ratio={same_day_ratio:.0%}); min gap={min_gap_hours:.1f}h"
            ),
            artifacts=tuple(campaign_domains),
            parameters={
                "creation_dates": [d.isoformat() for d in dates],
                "same_day_groups": {str(k): v for k, v in same_day_groups.items()},
                "min_gap_hours": min_gap_hours,
                "same_day_ratio": same_day_ratio,
            },
        )

    def compute_nameserver_overlap(self, campaign_domains: list[str]) -> InfraEvidence:
        """Signal: Shared authoritative name servers."""
        if len(campaign_domains) < 2:
            return self._empty_evidence(InfraSignal.DNS_NAMESERVERS, "Need 2+ domains")

        ns_sets = []
        for domain in campaign_domains:
            artifact = self.domains.get(domain)
            if artifact and artifact.name_servers:
                ns_sets.append(set(ns.lower() for ns in artifact.name_servers))

        if len(ns_sets) < 2:
            return self._empty_evidence(InfraSignal.DNS_NAMESERVERS, "Insufficient NS data")

        # Pairwise Jaccard similarity
        similarities = []
        for i in range(len(ns_sets)):
            for j in range(i+1, len(ns_sets)):
                inter = len(ns_sets[i] & ns_sets[j])
                union = len(ns_sets[i] | ns_sets[j])
                if union > 0:
                    similarities.append(inter / union)

        if not similarities:
            return self._empty_evidence(InfraSignal.DNS_NAMESERVERS, "No NS overlap")

        max_sim = max(similarities)
        avg_sim = sum(similarities) / len(similarities)

        # Find common NS across all
        common_ns = set.intersection(*ns_sets) if ns_sets else set()
        common_ratio = len(common_ns) / max(len(s) for s in ns_sets) if ns_sets else 0

        score = max(max_sim, common_ratio)

        return InfraEvidence(
            signal=InfraSignal.DNS_NAMESERVERS,
            score=score,
            description=(
                f"NS overlap: max Jaccard={max_sim:.2f}, avg={avg_sim:.2f}, "
                f"common across all={len(common_ns)} ({common_ratio:.0%})"
            ),
            artifacts=tuple(campaign_domains),
            parameters={
                "pairwise_similarities": similarities,
                "common_nameservers": list(common_ns),
                "domain_ns_sets": {d: list(ns) for d, ns in zip(campaign_domains, ns_sets)},
            },
        )

    def compute_dns_record_patterns(self, campaign_domains: list[str]) -> InfraEvidence:
        """Signal: Similar DNS record patterns (MX, TXT, SPF)."""
        if len(campaign_domains) < 2:
            return self._empty_evidence(InfraSignal.DNS_RECORDS, "Need 2+ domains")

        # Extract MX patterns
        mx_patterns = []
        txt_patterns = []
        spf_records = []

        for domain in campaign_domains:
            artifact = self.domains.get(domain)
            if not artifact:
                continue

            # MX pattern: normalize to provider
            mx_providers = []
            for mx in artifact.mx_records:
                mx_lower = mx.lower()
                if 'google' in mx_lower or 'googlemail' in mx_lower:
                    mx_providers.append('google')
                elif 'outlook' in mx_lower or 'office365' in mx_lower or 'protection.outlook' in mx_lower:
                    mx_providers.append('microsoft')
                elif 'zoho' in mx_lower:
                    mx_providers.append('zoho')
                elif 'proton' in mx_lower:
                    mx_providers.append('proton')
                else:
                    # Extract domain from MX
                    parts = mx_lower.split('.')
                    if len(parts) >= 2:
                        mx_providers.append('.'.join(parts[-2:]))
            mx_patterns.append(tuple(sorted(mx_providers)))

            # TXT/SPF
            for txt in artifact.txt_records:
                if txt.startswith('v=spf1'):
                    spf_records.append(txt)

        if not mx_patterns and not spf_records:
            return self._empty_evidence(InfraSignal.DNS_RECORDS, "No MX/SPF data")

        # Score based on pattern consistency
        mx_consistency = 0.0
        if mx_patterns:
            mx_counter = Counter(mx_patterns)
            mx_consistency = max(mx_counter.values()) / len(mx_patterns)

        spf_consistency = 0.0
        if spf_records:
            spf_counter = Counter(spf_records)
            spf_consistency = max(spf_counter.values()) / len(spf_records)

        score = max(mx_consistency, spf_consistency)

        return InfraEvidence(
            signal=InfraSignal.DNS_RECORDS,
            score=score,
            description=(
                f"DNS pattern consistency: MX={mx_consistency:.0%}, SPF={spf_consistency:.0%}"
            ),
            artifacts=tuple(campaign_domains),
            parameters={
                "mx_patterns": {d: list(p) for d, p in zip(campaign_domains, mx_patterns)},
                "spf_records": spf_records,
                "mx_consistency": mx_consistency,
                "spf_consistency": spf_consistency,
            },
        )

    def compute_ssl_certificate_links(self, campaign_domains: list[str]) -> InfraEvidence:
        """Signal: SSL certificate reuse (same key, same issuer, overlapping SANs)."""
        if len(campaign_domains) < 2:
            return self._empty_evidence(InfraSignal.SSL_CERTIFICATE, "Need 2+ domains")

        certs = []
        for domain in campaign_domains:
            artifact = self.domains.get(domain)
            if artifact and artifact.ssl_fingerprint:
                certs.append({
                    'domain': domain,
                    'fingerprint': artifact.ssl_fingerprint,
                    'issuer': artifact.ssl_issuer,
                    'san': set(artifact.ssl_san),
                })

        if len(certs) < 2:
            return self._empty_evidence(InfraSignal.SSL_CERTIFICATE, "Insufficient SSL data")

        # Check for identical fingerprints (same private key)
        fp_groups = defaultdict(list)
        for c in certs:
            fp_groups[c['fingerprint']].append(c['domain'])

        max_fp_group = max(len(v) for v in fp_groups.values())
        fp_reuse_ratio = max_fp_group / len(certs)

        # Check for same issuer
        issuer_groups = defaultdict(list)
        for c in certs:
            issuer_groups[c['issuer']].append(c['domain'])

        max_issuer_group = max(len(v) for v in issuer_groups.values())
        issuer_ratio = max_issuer_group / len(certs)

        # Check for SAN overlap
        san_overlaps = []
        for i in range(len(certs)):
            for j in range(i+1, len(certs)):
                inter = len(certs[i]['san'] & certs[j]['san'])
                union = len(certs[i]['san'] | certs[j]['san'])
                if union > 0:
                    san_overlaps.append(inter / union)

        max_san_overlap = max(san_overlaps) if san_overlaps else 0

        score = max(fp_reuse_ratio * 1.5, issuer_ratio, max_san_overlap)
        score = min(score, 1.0)

        return InfraEvidence(
            signal=InfraSignal.SSL_CERTIFICATE,
            score=score,
            description=(
                f"SSL links: key reuse={fp_reuse_ratio:.0%} (max group={max_fp_group}), "
                f"same issuer={issuer_ratio:.0%}, max SAN overlap={max_san_overlap:.0%}"
            ),
            artifacts=tuple(campaign_domains),
            parameters={
                "fingerprint_groups": {fp: domains for fp, domains in fp_groups.items() if len(domains) > 1},
                "issuer_groups": {iss: domains for iss, domains in issuer_groups.items() if len(domains) > 1},
                "max_san_overlap": max_san_overlap,
            },
        )

    def compute_ct_log_correlation(self, campaign_domains: list[str]) -> InfraEvidence:
        """Signal: Certificate Transparency log correlation."""
        if len(campaign_domains) < 2:
            return self._empty_evidence(InfraSignal.SSL_CT_LOGS, "Need 2+ domains")

        all_entries = []
        for domain in campaign_domains:
            artifact = self.domains.get(domain)
            if artifact and artifact.ct_entries:
                for entry in artifact.ct_entries:
                    entry['domain'] = domain
                    all_entries.append(entry)

        if len(all_entries) < 2:
            return self._empty_evidence(InfraSignal.SSL_CT_LOGS, "Insufficient CT entries")

        # Group by log ID
        log_groups = defaultdict(list)
        for entry in all_entries:
            log_id = entry.get('log_id', entry.get('log', 'unknown'))
            log_groups[log_id].append(entry)

        # Check for same log + close timestamps
        temporal_clusters = 0
        for log_id, entries in log_groups.items():
            if len(entries) < 2:
                continue
            entries.sort(key=lambda e: e.get('timestamp', ''))
            for i in range(1, len(entries)):
                t1 = datetime.fromisoformat(entries[i-1].get('timestamp', '').replace('Z', '+00:00'))
                t2 = datetime.fromisoformat(entries[i].get('timestamp', '').replace('Z', '+00:00'))
                if (t2 - t1).total_seconds() < 3600:  # Within 1 hour
                    temporal_clusters += 1

        # Score based on clustering
        total_pairs = sum(len(e) * (len(e) - 1) // 2 for e in log_groups.values())
        cluster_ratio = temporal_clusters / max(total_pairs, 1)
        score = min(cluster_ratio * 5, 1.0)  # Boost

        return InfraEvidence(
            signal=InfraSignal.SSL_CT_LOGS,
            score=score,
            description=(
                f"CT log correlation: {len(log_groups)} logs, {temporal_clusters} temporal clusters "
                f"(ratio={cluster_ratio:.2f})"
            ),
            artifacts=tuple(campaign_domains),
            parameters={
                "log_groups": {log: len(entries) for log, entries in log_groups.items()},
                "temporal_clusters": temporal_clusters,
                "total_entries": len(all_entries),
            },
        )

    def compute_ip_asn_hosting(self, campaign_domains: list[str]) -> InfraEvidence:
        """Signal: Shared ASN/hosting provider across domain IPs."""
        if len(campaign_domains) < 2:
            return self._empty_evidence(InfraSignal.IP_ASN, "Need 2+ domains")

        # Collect all IPs for these domains
        all_ips = set()
        for domain in campaign_domains:
            all_ips.update(self._domain_ip_map.get(domain, set()))

        if len(all_ips) < 2:
            return self._empty_evidence(InfraSignal.IP_ASN, "Insufficient IP data")

        asn_counts = defaultdict(int)
        provider_counts = defaultdict(int)

        for ip in all_ips:
            artifact = self.ips.get(ip)
            if artifact:
                if artifact.asn:
                    asn_counts[artifact.asn] += 1
                if artifact.hosting_provider:
                    provider_counts[artifact.hosting_provider] += 1
                elif artifact.isp:
                    provider_counts[artifact.isp] += 1

        max_asn = max(asn_counts.values()) if asn_counts else 0
        max_provider = max(provider_counts.values()) if provider_counts else 0

        asn_ratio = max_asn / len(all_ips)
        provider_ratio = max_provider / len(all_ips)

        score = max(asn_ratio, provider_ratio)

        dominant_asn = max(asn_counts.items(), key=lambda x: x[1])[0] if asn_counts else None
        dominant_provider = max(provider_counts.items(), key=lambda x: x[1])[0] if provider_counts else None

        return InfraEvidence(
            signal=InfraSignal.IP_ASN,
            score=score,
            description=(
                f"IP hosting affinity: ASN {dominant_asn}={asn_ratio:.0%}, "
                f"provider '{dominant_provider}'={provider_ratio:.0%} ({len(all_ips)} IPs)"
            ),
            artifacts=tuple(campaign_domains),
            parameters={
                "total_ips": len(all_ips),
                "asn_distribution": dict(asn_counts),
                "provider_distribution": dict(provider_counts),
                "dominant_asn": dominant_asn,
                "dominant_provider": dominant_provider,
            },
        )

    def compute_ip_prefix_allocation(self, campaign_domains: list[str]) -> InfraEvidence:
        """Signal: IPs from same prefix/block (VPS farm indicator)."""
        all_ips = set()
        for domain in campaign_domains:
            all_ips.update(self._domain_ip_map.get(domain, set()))

        if len(all_ips) < 2:
            return self._empty_evidence(InfraSignal.IP_PREFIX, "Insufficient IP data")

        # Group by /24 prefix (IPv4) or /48 (IPv6)
        prefix_groups = defaultdict(list)
        for ip_str in all_ips:
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.version == 4:
                    prefix = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                else:
                    prefix = str(ipaddress.ip_network(f"{ip}/48", strict=False))
                prefix_groups[prefix].append(ip_str)
            except ValueError:
                continue

        if not prefix_groups:
            return self._empty_evidence(InfraSignal.IP_PREFIX, "No valid IP prefixes")

        max_group = max(len(v) for v in prefix_groups.values())
        prefix_ratio = max_group / len(all_ips)

        # High concentration in few prefixes = VPS/hosting farm
        score = min(prefix_ratio * 2, 1.0)

        return InfraEvidence(
            signal=InfraSignal.IP_PREFIX,
            score=score,
            description=(
                f"IP prefix concentration: max {max_group}/{len(all_ips)} in one prefix "
                f"({prefix_ratio:.0%}) — {'likely VPS farm' if prefix_ratio > 0.5 else 'diverse'}"
            ),
            artifacts=tuple(campaign_domains),
            parameters={
                "total_ips": len(all_ips),
                "prefix_groups": {p: len(ips) for p, ips in prefix_groups.items()},
                "max_group_size": max_group,
                "prefix_ratio": prefix_ratio,
            },
        )

    def compute_vpn_proxy_indicators(self, campaign_domains: list[str]) -> InfraEvidence:
        """Signal: VPN/Proxy/Tor exit node indicators."""
        all_ips = set()
        for domain in campaign_domains:
            all_ips.update(self._domain_ip_map.get(domain, set()))

        if not all_ips:
            return self._empty_evidence(InfraSignal.IP_VPN_PROXY, "No IP data")

        vpn_count = 0
        proxy_count = 0
        tor_count = 0
        hosting_count = 0

        for ip in all_ips:
            artifact = self.ips.get(ip)
            if artifact:
                if artifact.is_vpn:
                    vpn_count += 1
                if artifact.is_proxy:
                    proxy_count += 1
                if artifact.is_tor:
                    tor_count += 1
                if artifact.is_hosting:
                    hosting_count += 1

        total = len(all_ips)
        anomaly_ratio = (vpn_count + proxy_count + tor_count) / total
        hosting_ratio = hosting_count / total

        # High VPN/Proxy/Tor = obfuscation; high hosting = infrastructure (not necessarily suspicious)
        score = min(anomaly_ratio * 2 + hosting_ratio * 0.5, 1.0)

        return InfraEvidence(
            signal=InfraSignal.IP_VPN_PROXY,
            score=score,
            description=(
                f"Anonymity indicators: VPN={vpn_count}/{total}, Proxy={proxy_count}/{total}, "
                f"Tor={tor_count}/{total}, Hosting={hosting_count}/{total}"
            ),
            artifacts=tuple(campaign_domains),
            parameters={
                "total_ips": total,
                "vpn_count": vpn_count,
                "proxy_count": proxy_count,
                "tor_count": tor_count,
                "hosting_count": hosting_count,
                "anomaly_ratio": anomaly_ratio,
                "hosting_ratio": hosting_ratio,
            },
        )

    def compute_subdomain_patterns(self, campaign_domains: list[str]) -> InfraEvidence:
        """Signal: Algorithmic vs human subdomain naming."""
        all_subdomains = []
        for domain in campaign_domains:
            artifact = self.domains.get(domain)
            if artifact and artifact.subdomains:
                all_subdomains.extend(artifact.subdomains)

        if len(all_subdomains) < 5:
            return self._empty_evidence(InfraSignal.SUBDOMAIN_ENUM, "Insufficient subdomains")

        # Entropy of subdomain labels
        labels = []
        for sd in all_subdomains:
            parts = sd.split('.')
            if len(parts) > 1:
                labels.append(parts[0])  # First label

        if not labels:
            return self._empty_evidence(InfraSignal.SUBDOMAIN_ENUM, "No valid labels")

        # Character-level entropy
        all_chars = "".join(labels)
        char_freq = defaultdict(int)
        for c in all_chars:
            char_freq[c] += 1

        total_chars = len(all_chars)
        entropy = -sum(
            (count / total_chars) * math.log2(count / total_chars)
            for count in char_freq.values()
        )

        max_entropy = math.log2(len(char_freq))
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0

        # High entropy = algorithmic (random-looking) = potentially automated
        # But also check for patterns like www1, www2, api-v1, etc.
        pattern_count = sum(1 for l in labels if re.match(r'^(www|api|mail|ftp|dev|test|stage|prod)\d*$', l))
        pattern_ratio = pattern_count / len(labels)

        # Score: high if algorithmic (high entropy, low pattern) OR structured (high pattern)
        algorithmic_score = normalized_entropy * (1 - pattern_ratio)
        structured_score = pattern_ratio
        score = max(algorithmic_score, structured_score)

        return InfraEvidence(
            signal=InfraSignal.SUBDOMAIN_ENUM,
            score=score,
            description=(
                f"Subdomain entropy: {normalized_entropy:.2f} (algorithmic={algorithmic_score:.2f}, "
                f"structured={structured_score:.2f}, {len(labels)} labels)"
            ),
            artifacts=tuple(campaign_domains),
            parameters={
                "total_subdomains": len(all_subdomains),
                "label_count": len(labels),
                "char_entropy": entropy,
                "normalized_entropy": normalized_entropy,
                "pattern_ratio": pattern_ratio,
                "sample_labels": labels[:20],
            },
        )

    def compute_passive_dns_history(self, campaign_domains: list[str]) -> InfraEvidence:
        """Signal: Historical DNS/IP changes (fast flux, domain hopping)."""
        # This would use passive DNS data if available
        # For now, use current DNS as proxy
        all_ips = set()
        for domain in campaign_domains:
            all_ips.update(self._domain_ip_map.get(domain, set()))

        if len(all_ips) < 2:
            return self._empty_evidence(InfraSignal.PASSIVE_DNS, "Insufficient IP data")

        # Check for many IPs per domain (fast flux indicator)
        ip_per_domain = {}
        for domain in campaign_domains:
            ips = self._domain_ip_map.get(domain, set())
            ip_per_domain[domain] = len(ips)

        avg_ips = sum(ip_per_domain.values()) / len(ip_per_domain)
        max_ips = max(ip_per_domain.values())

        # Check for shared IPs across domains (domain hopping)
        domain_per_ip = defaultdict(int)
        for domain, ips in self._domain_ip_map.items():
            for ip in ips:
                domain_per_ip[ip] += 1

        shared_ips = sum(1 for count in domain_per_ip.values() if count > 1)
        sharing_ratio = shared_ips / len(domain_per_ip) if domain_per_ip else 0

        score = min((max_ips / 10) * 0.5 + sharing_ratio * 0.5, 1.0)

        return InfraEvidence(
            signal=InfraSignal.PASSIVE_DNS,
            score=score,
            description=(
                f"DNS history proxy: avg IPs/domain={avg_ips:.1f}, max={max_ips}, "
                f"shared IPs={shared_ips}/{len(domain_per_ip)} ({sharing_ratio:.0%})"
            ),
            artifacts=tuple(campaign_domains),
            parameters={
                "ips_per_domain": ip_per_domain,
                "domains_per_ip": dict(domain_per_ip),
                "avg_ips_per_domain": avg_ips,
                "max_ips_per_domain": max_ips,
                "shared_ip_ratio": sharing_ratio,
            },
        )

    def _empty_evidence(self, signal: InfraSignal, reason: str) -> InfraEvidence:
        return InfraEvidence(
            signal=signal,
            score=0.0,
            description=reason,
            artifacts=(),
            parameters={"reason": reason},
        )

    # ==================== PUBLIC API ====================

    def compute_infrastructure_dna(
        self,
        campaign_id: str,
        campaign_domains: list[str],
        analysis_window_days: int = 30
    ) -> InfrastructureDNA:
        """Compute complete Infrastructure DNA for a campaign."""

        # Compute all signals
        signals = {
            InfraSignal.WHOIS_REGISTRAR: self.compute_registrar_affinity(campaign_domains),
            InfraSignal.WHOIS_TIMESTAMP: self.compute_registration_timing(campaign_domains),
            InfraSignal.DNS_NAMESERVERS: self.compute_nameserver_overlap(campaign_domains),
            InfraSignal.DNS_RECORDS: self.compute_dns_record_patterns(campaign_domains),
            InfraSignal.SSL_CERTIFICATE: self.compute_ssl_certificate_links(campaign_domains),
            InfraSignal.SSL_CT_LOGS: self.compute_ct_log_correlation(campaign_domains),
            InfraSignal.IP_ASN: self.compute_ip_asn_hosting(campaign_domains),
            InfraSignal.IP_PREFIX: self.compute_ip_prefix_allocation(campaign_domains),
            InfraSignal.IP_VPN_PROXY: self.compute_vpn_proxy_indicators(campaign_domains),
            InfraSignal.SUBDOMAIN_ENUM: self.compute_subdomain_patterns(campaign_domains),
            InfraSignal.PASSIVE_DNS: self.compute_passive_dns_history(campaign_domains),
        }

        signal_scores = {s: e.score for s, e in signals.items()}
        evidence_map = {s: e for s, e in signals.items() if e.score > 0}

        # Count unique indicators
        all_ips = set()
        for domain in campaign_domains:
            all_ips.update(self._domain_ip_map.get(domain, set()))
        indicator_count = len(campaign_domains) + len(all_ips)

        return InfrastructureDNA.compute(
            campaign_id=campaign_id,
            signal_scores=signal_scores,
            evidence_map=evidence_map,
            indicator_count=indicator_count,
            analysis_window_days=analysis_window_days,
        )

    def find_related_campaigns(
        self,
        campaign_id: str,
        campaign_domains: list[str],
        min_similarity: float = 0.6
    ) -> list[tuple[str, float]]:
        """Find campaigns with similar Infrastructure DNA."""
        target_dna = self.compute_infrastructure_dna(campaign_id, campaign_domains)

        # In production, this would query a database of known campaigns
        # For now, return empty - would be populated by analyst
        return []


# Convenience function
import math
from collections import Counter

def analyze_infrastructure(
    domain_artifacts: list[DomainArtifact],
    ip_artifacts: list[IPArtifact],
    campaign_id: str
) -> InfrastructureDNA:
    """Create IDE and compute Infrastructure DNA."""
    engine = InfrastructureDNAEngine()
    for artifact in domain_artifacts:
        engine.add_domain_artifact(artifact)
    for artifact in ip_artifacts:
        engine.add_ip_artifact(artifact)
    domains = [a.domain for a in domain_artifacts]
    return engine.compute_infrastructure_dna(campaign_id, domains)