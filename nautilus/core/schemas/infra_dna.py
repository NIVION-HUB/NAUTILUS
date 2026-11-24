"""
Infrastructure DNA Schema — NAUTILUS Proprietary Infrastructure Fingerprinting
128-bit fingerprint per campaign enabling cross-case infrastructure linking.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntFlag
from typing import Optional
import hashlib
import json


class InfraSignal(IntFlag):
    """Bit flags for infrastructure signal sources."""
    NONE = 0
    WHOIS_REGISTRAR = 1 << 0         # Registrar/reseller affinity
    WHOIS_TIMESTAMP = 1 << 1         # Registration/expiry patterns
    DNS_NAMESERVERS = 1 << 2         # Authoritative NS overlap
    DNS_RECORDS = 1 << 3             # A/MX/TXT/SPF patterns
    SSL_CERTIFICATE = 1 << 4         # Cert transparency, key reuse, SANs
    SSL_CT_LOGS = 1 << 5             # Certificate Transparency entries
    IP_ASN = 1 << 6                  # ASN/hosting provider
    IP_PREFIX = 1 << 7               # IP prefix/allocation patterns
    IP_GEO = 1 << 8                  # Geographic hosting patterns
    IP_VPN_PROXY = 1 << 9            # VPN/proxy/Tor indicators
    SUBDOMAIN_ENUM = 1 << 10         # Subdomain patterns/wildcards
    PASSIVE_DNS = 1 << 11            # Historical DNS/IP mappings
    # Bits 12-127 reserved


@dataclass(frozen=True, slots=True)
class InfraEvidence:
    """Explainable evidence for an infrastructure signal."""
    signal: InfraSignal
    score: float                      # 0.0-1.0 confidence
    description: str                  # Human-readable
    artifacts: tuple[str, ...]        # Source artifact references
    parameters: dict                  # Raw computation parameters

    def to_dict(self) -> dict:
        return {
            "signal": self.signal.name,
            "score": self.score,
            "description": self.description,
            "artifacts": list(self.artifacts),
            "parameters": self.parameters,
        }


@dataclass(frozen=True, slots=True)
class InfrastructureDNA:
    """
    128-bit Infrastructure DNA fingerprint.

    Structure (128 bits across 4 x 32-bit words):
    - Word 0 (bits 0-31):   Signal flags (12 bits) + Version (4 bits) + Reserved (16 bits)
    - Word 1 (bits 32-63):  Registrar/WHOIS profile (16 bits) + DNS profile (16 bits)
    - Word 2 (bits 64-95):  SSL/Cert profile (16 bits) + IP/Hosting profile (16 bits)
    - Word 3 (bits 96-127): Subdomain/Passive profile (16 bits) + Campaign ID hash (16 bits)
    """
    fingerprint: tuple[int, int, int, int]  # 4 x 32-bit = 128-bit
    campaign_id: str                        # Analyst-assigned or auto-generated
    computed_at: datetime
    evidence: tuple[InfraEvidence, ...] = ()
    indicator_count: int = 0                # Domains + IPs analyzed
    analysis_window_days: int = 30

    VERSION = 1

    @classmethod
    def compute(
        cls,
        campaign_id: str,
        signal_scores: dict[InfraSignal, float],
        evidence_map: dict[InfraSignal, InfraEvidence],
        indicator_count: int = 0,
        analysis_window_days: int = 30,
    ) -> InfrastructureDNA:
        """Construct Infrastructure DNA from computed signal scores."""

        # Word 0: Signal flags + version
        word0 = 0
        for signal, score in signal_scores.items():
            if score > 0.4:  # Threshold for "present"
                word0 |= int(signal)
        word0 |= (cls.VERSION & 0xF) << 28

        # Word 1: Registrar (16) + DNS (16)
        registrar_score = signal_scores.get(InfraSignal.WHOIS_REGISTRAR, 0)
        timestamp_score = signal_scores.get(InfraSignal.WHOIS_TIMESTAMP, 0)
        registrar_profile = int(((registrar_score + timestamp_score) / 2) * 65535)

        ns_score = signal_scores.get(InfraSignal.DNS_NAMESERVERS, 0)
        records_score = signal_scores.get(InfraSignal.DNS_RECORDS, 0)
        dns_profile = int(((ns_score + records_score) / 2) * 65535)

        word1 = (registrar_profile & 0xFFFF) | ((dns_profile & 0xFFFF) << 16)

        # Word 2: SSL (16) + IP (16)
        ssl_cert_score = signal_scores.get(InfraSignal.SSL_CERTIFICATE, 0)
        ssl_ct_score = signal_scores.get(InfraSignal.SSL_CT_LOGS, 0)
        ssl_profile = int(((ssl_cert_score + ssl_ct_score) / 2) * 65535)

        ip_asn_score = signal_scores.get(InfraSignal.IP_ASN, 0)
        ip_prefix_score = signal_scores.get(InfraSignal.IP_PREFIX, 0)
        ip_geo_score = signal_scores.get(InfraSignal.IP_GEO, 0)
        ip_vpn_score = signal_scores.get(InfraSignal.IP_VPN_PROXY, 0)
        ip_profile = int(((ip_asn_score + ip_prefix_score + ip_geo_score + ip_vpn_score) / 4) * 65535)

        word2 = (ssl_profile & 0xFFFF) | ((ip_profile & 0xFFFF) << 16)

        # Word 3: Subdomain (16) + Campaign hash (16)
        subdomain_score = signal_scores.get(InfraSignal.SUBDOMAIN_ENUM, 0)
        passive_score = signal_scores.get(InfraSignal.PASSIVE_DNS, 0)
        subdomain_profile = int(((subdomain_score + passive_score) / 2) * 65535)

        campaign_hash = int(hashlib.md5(campaign_id.encode()).hexdigest()[:4], 16)

        word3 = (subdomain_profile & 0xFFFF) | ((campaign_hash & 0xFFFF) << 16)

        return cls(
            fingerprint=(word0, word1, word2, word3),
            campaign_id=campaign_id,
            computed_at=datetime.utcnow(),
            evidence=tuple(evidence_map.values()),
            indicator_count=indicator_count,
            analysis_window_days=analysis_window_days,
        )

    @property
    def present_signals(self) -> list[InfraSignal]:
        flags = self.fingerprint[0] & 0xFFF  # Lower 12 bits
        return [s for s in InfraSignal if s != InfraSignal.NONE and (flags & int(s))]

    @property
    def registrar_profile(self) -> float:
        return (self.fingerprint[1] & 0xFFFF) / 65535.0

    @property
    def dns_profile(self) -> float:
        return (self.fingerprint[1] >> 16) & 0xFFFF / 65535.0

    @property
    def ssl_profile(self) -> float:
        return (self.fingerprint[2] & 0xFFFF) / 65535.0

    @property
    def ip_profile(self) -> float:
        return (self.fingerprint[2] >> 16) & 0xFFFF / 65535.0

    @property
    def subdomain_profile(self) -> float:
        return (self.fingerprint[3] & 0xFFFF) / 65535.0

    def similarity(self, other: InfrastructureDNA) -> float:
        """Compute infrastructure similarity (0-1)."""
        # Signal overlap (Jaccard on present signals)
        signals_self = set(self.present_signals)
        signals_other = set(other.present_signals)
        if not signals_self and not signals_other:
            signal_sim = 1.0
        else:
            signal_sim = len(signals_self & signals_other) / len(signals_self | signals_other)

        # Profile vector cosine similarity
        profiles_self = [
            self.registrar_profile, self.dns_profile, self.ssl_profile,
            self.ip_profile, self.subdomain_profile
        ]
        profiles_other = [
            other.registrar_profile, other.dns_profile, other.ssl_profile,
            other.ip_profile, other.subdomain_profile
        ]

        dot = sum(a * b for a, b in zip(profiles_self, profiles_other))
        norm_self = sum(a * a for a in profiles_self) ** 0.5
        norm_other = sum(b * b for b in profiles_other) ** 0.5
        profile_sim = dot / (norm_self * norm_other) if norm_self and norm_other else 0.0

        return 0.5 * signal_sim + 0.5 * profile_sim

    def to_hex(self) -> str:
        """128-bit fingerprint as 32-char hex string."""
        return "".join(f"{w:08X}" for w in self.fingerprint)

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.to_hex(),
            "fingerprint_words": [f"0x{w:08X}" for w in self.fingerprint],
            "campaign_id": self.campaign_id,
            "computed_at": self.computed_at.isoformat(),
            "present_signals": [s.name for s in self.present_signals],
            "profile_scores": {
                "registrar": self.registrar_profile,
                "dns": self.dns_profile,
                "ssl": self.ssl_profile,
                "ip_hosting": self.ip_profile,
                "subdomain": self.subdomain_profile,
            },
            "evidence": [e.to_dict() for e in self.evidence],
            "indicator_count": self.indicator_count,
            "analysis_window_days": self.analysis_window_days,
            "version": self.VERSION,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)


# Matching thresholds for cross-case infrastructure linking
INFRA_MATCH_THRESHOLDS = {
    "identical": 0.95,      # Same infrastructure, same operator
    "strong": 0.80,         # Same operator, evolved infrastructure
    "moderate": 0.60,       # Shared hosting/registrar, likely same actor
    "weak": 0.40,           # Coincidental overlap possible
}