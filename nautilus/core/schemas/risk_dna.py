"""
Risk DNA Schema — NAUTILUS Proprietary Risk Fingerprinting
64-bit fingerprint per account enabling cross-case matching without PII.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import IntFlag
from typing import Optional
import hashlib
import json


class RiskPrimitive(IntFlag):
    """Bit flags for the 6 core risk primitives — composable, auditable."""
    NONE = 0
    VELOCITY_SPIKE = 1 << 0          # Rapid in-out transfers
    LAYERING_DEPTH = 1 << 1          # Multi-hop fund movement
    COUNTERPARTY_ENTROPY = 1 << 2    # Unusually diverse sender base
    ROUND_FIGURE_CLUSTERING = 1 << 3 # Psychological threshold clustering
    DORMANCY_BREAK = 1 << 4          # Sudden activation after inactivity
    STRUCTURING_SIGNATURE = 1 << 5   # Near-threshold amount avoidance
    # Bits 6-63 reserved for future primitives

    @classmethod
    def all_primitives(cls) -> list[RiskPrimitive]:
        return [
            cls.VELOCITY_SPIKE,
            cls.LAYERING_DEPTH,
            cls.COUNTERPARTY_ENTROPY,
            cls.ROUND_FIGURE_CLUSTERING,
            cls.DORMANCY_BREAK,
            cls.STRUCTURING_SIGNATURE,
        ]

    @classmethod
    def from_flags(cls, flags: int) -> list[RiskPrimitive]:
        return [p for p in cls.all_primitives() if flags & p]


@dataclass(frozen=True, slots=True)
class PrimitiveEvidence:
    """Explainable evidence for a triggered primitive — court-ready."""
    primitive: RiskPrimitive
    score: float                      # 0.0-1.0, normalized risk contribution
    percentile: float                 # Peer percentile (0-100)
    description: str                  # Human-readable explanation
    supporting_txn_ids: tuple[str, ...]  # Transaction IDs triggering this
    parameters: dict                  # Raw computation parameters for audit

    def to_dict(self) -> dict:
        return {
            "primitive": self.primitive.name,
            "score": self.score,
            "percentile": self.percentile,
            "description": self.description,
            "supporting_txn_ids": list(self.supporting_txn_ids),
            "parameters": self.parameters,
        }


@dataclass(frozen=True, slots=True)
class RiskDNA:
    """
    64-bit Risk DNA fingerprint — the core innovation.

    Structure (64 bits):
    - Bits 0-5:   Primitive flags (6 bits)
    - Bits 6-13:  Risk tier (0-255)
    - Bits 14-21: Velocity score (0-255)
    - Bits 22-29: Layering score (0-255)
    - Bits 30-37: Entropy score (0-255)
    - Bits 38-45: Round-figure score (0-255)
    - Bits 46-53: Dormancy score (0-255)
    - Bits 54-61: Structuring score (0-255)
    - Bits 62-63: Version (2 bits)
    """
    fingerprint: int                  # 64-bit integer
    account_id: str                   # Hashed account identifier
    computed_at: datetime
    evidence: tuple[PrimitiveEvidence, ...] = ()
    peer_group: str = "ALL"           # Peer group for percentile computation
    total_transactions: int = 0
    analysis_window_days: int = 90

    # Version for forward compatibility
    VERSION = 1

    @classmethod
    def compute(
        cls,
        account_id: str,
        primitive_scores: dict[RiskPrimitive, float],
        peer_percentiles: dict[RiskPrimitive, float],
        evidence_map: dict[RiskPrimitive, PrimitiveEvidence],
        peer_group: str = "ALL",
        total_transactions: int = 0,
        analysis_window_days: int = 90,
    ) -> RiskDNA:
        """Construct RiskDNA from computed primitive scores."""
        # Build fingerprint
        fp = 0

        # Primitive flags (bits 0-5)
        for prim, score in primitive_scores.items():
            if score > 0.5:  # Threshold for "triggered"
                fp |= int(prim)

        # Risk tier (bits 6-13): composite score 0-255
        composite = sum(primitive_scores.values()) / len(RiskPrimitive.all_primitives())
        risk_tier = int(composite * 255)
        fp |= (risk_tier & 0xFF) << 6

        # Individual scores (bits 14-61, 8 bits each)
        score_bits = [
            ("velocity", primitive_scores.get(RiskPrimitive.VELOCITY_SPIKE, 0)),
            ("layering", primitive_scores.get(RiskPrimitive.LAYERING_DEPTH, 0)),
            ("entropy", primitive_scores.get(RiskPrimitive.COUNTERPARTY_ENTROPY, 0)),
            ("round_figure", primitive_scores.get(RiskPrimitive.ROUND_FIGURE_CLUSTERING, 0)),
            ("dormancy", primitive_scores.get(RiskPrimitive.DORMANCY_BREAK, 0)),
            ("structuring", primitive_scores.get(RiskPrimitive.STRUCTURING_SIGNATURE, 0)),
        ]
        for i, (_, score) in enumerate(score_bits):
            fp |= (int(score * 255) & 0xFF) << (14 + i * 8)

        # Version (bits 62-63)
        fp |= (cls.VERSION & 0x3) << 62

        return cls(
            fingerprint=fp,
            account_id=account_id,
            computed_at=datetime.utcnow(),
            evidence=tuple(evidence_map.values()),
            peer_group=peer_group,
            total_transactions=total_transactions,
            analysis_window_days=analysis_window_days,
        )

    @property
    def triggered_primitives(self) -> list[RiskPrimitive]:
        return RiskPrimitive.from_flags(self.fingerprint & 0x3F)

    @property
    def risk_tier(self) -> int:
        return (self.fingerprint >> 6) & 0xFF

    @property
    def risk_tier_label(self) -> str:
        tier = self.risk_tier
        if tier >= 200: return "CRITICAL"
        if tier >= 150: return "HIGH"
        if tier >= 100: return "ELEVATED"
        if tier >= 50: return "MODERATE"
        return "LOW"

    def get_primitive_score(self, primitive: RiskPrimitive) -> float:
        """Extract 0-1 score for a specific primitive."""
        bit_positions = {
            RiskPrimitive.VELOCITY_SPIKE: 14,
            RiskPrimitive.LAYERING_DEPTH: 22,
            RiskPrimitive.COUNTERPARTY_ENTROPY: 30,
            RiskPrimitive.ROUND_FIGURE_CLUSTERING: 38,
            RiskPrimitive.DORMANCY_BREAK: 46,
            RiskPrimitive.STRUCTURING_SIGNATURE: 54,
        }
        pos = bit_positions.get(primitive)
        if pos is None:
            return 0.0
        return ((self.fingerprint >> pos) & 0xFF) / 255.0

    def similarity(self, other: RiskDNA) -> float:
        """Compute similarity with another RiskDNA (0-1)."""
        # Compare primitive flags
        flags_self = self.fingerprint & 0x3F
        flags_other = other.fingerprint & 0x3F
        flag_similarity = bin(flags_self & flags_other).count("1") / max(
            bin(flags_self | flags_other).count("1"), 1
        )

        # Compare score profiles (cosine similarity on 6-dim vector)
        scores_self = [self.get_primitive_score(p) for p in RiskPrimitive.all_primitives()]
        scores_other = [other.get_primitive_score(p) for p in RiskPrimitive.all_primitives()]

        dot = sum(a * b for a, b in zip(scores_self, scores_other))
        norm_self = sum(a * a for a in scores_self) ** 0.5
        norm_other = sum(b * b for b in scores_other) ** 0.5
        score_similarity = dot / (norm_self * norm_other) if norm_self and norm_other else 0.0

        return 0.4 * flag_similarity + 0.6 * score_similarity

    def to_dict(self) -> dict:
        return {
            "fingerprint": f"0x{self.fingerprint:016X}",
            "fingerprint_decimal": self.fingerprint,
            "account_id": self.account_id,
            "computed_at": self.computed_at.isoformat(),
            "risk_tier": self.risk_tier,
            "risk_tier_label": self.risk_tier_label,
            "triggered_primitives": [p.name for p in self.triggered_primitives],
            "primitive_scores": {
                p.name: self.get_primitive_score(p) for p in RiskPrimitive.all_primitives()
            },
            "evidence": [e.to_dict() for e in self.evidence],
            "peer_group": self.peer_group,
            "total_transactions": self.total_transactions,
            "analysis_window_days": self.analysis_window_days,
            "version": self.VERSION,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)

    @classmethod
    def from_fingerprint(cls, fingerprint: int, account_id: str) -> RiskDNA:
        """Reconstruct minimal RiskDNA from fingerprint alone (for matching)."""
        return cls(
            fingerprint=fingerprint,
            account_id=account_id,
            computed_at=datetime.utcnow(),
        )


# Matching thresholds for cross-case linking
MATCH_THRESHOLDS = {
    "exact": 1.0,           # Identical fingerprint
    "strong": 0.85,         # Same campaign / actor
    "moderate": 0.65,       # Similar MO
    "weak": 0.45,           # Possible connection
}