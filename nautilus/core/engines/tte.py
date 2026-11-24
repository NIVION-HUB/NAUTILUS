"""
Transaction Topology Engine (TTE) — NAUTILUS Core Correlation Engine #1
Graph-theoretic fund flow analysis with explainable risk primitives.
"""
from __future__ import annotations
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional
import math
import hashlib

from nautilus.core.schemas.uts import UnifiedTransaction, AccountStatement
from nautilus.core.schemas.risk_dna import RiskDNA, RiskPrimitive, PrimitiveEvidence, MATCH_THRESHOLDS


@dataclass(frozen=True, slots=True)
class FundHop:
    """Single hop in fund movement chain."""
    from_account: str
    to_account: str
    amount: Decimal
    timestamp_utc: datetime
    utr: Optional[str]
    hop_number: int
    txn_id: str


@dataclass(frozen=True, slots=True)
class MoneyTrail:
    """Complete fund trail from victim UTR to terminal withdrawal."""
    victim_utr: str
    hops: tuple[FundHop, ...]
    terminal_accounts: tuple[str, ...]
    total_amount: Decimal
    layering_depth: int
    duration_hours: float
    risk_dna_matches: dict[str, RiskDNA]  # account_id -> RiskDNA


class TransactionTopologyEngine:
    """
    Core engine for fund flow topology analysis.
    Computes 6 explainable risk primitives per account.
    """

    # Configuration (tunable per deployment)
    VELOCITY_WINDOW_HOURS = 24
    VELOCITY_SPIKE_THRESHOLD = 3.0  # Standard deviations
    LAYERING_MAX_HOPS = 10
    ENTROPY_WINDOW_DAYS = 7
    ROUND_FIGURE_THRESHOLDS = [1000, 5000, 10000, 25000, 50000, 100000, 250000, 500000, 1000000]
    ROUND_FIGURE_EPSILON = 0.01  # 1% of threshold
    DORMANCY_LOOKBACK_DAYS = 90
    DORMANCY_BURST_MULTIPLIER = 10
    STRUCTURING_THRESHOLDS = [50000, 100000, 200000, 500000, 1000000]  # Reporting thresholds
    STRUCTURING_EPSILON_RATIO = 0.02  # Within 2% of threshold

    def __init__(self, statements: dict[str, AccountStatement]):
        """
        Initialize with parsed statements.

        Args:
            statements: Dict of account_id -> AccountStatement
        """
        self.statements = statements
        self._account_txns: dict[str, list[UnifiedTransaction]] = {
            acc_id: list(stmt.transactions) for acc_id, stmt in statements.items()
        }
        self._txn_index: dict[str, UnifiedTransaction] = {}
        self._counterparty_index: dict[str, set[str]] = defaultdict(set)  # counterparty_fp -> account_ids
        self._utr_index: dict[str, list[UnifiedTransaction]] = defaultdict(list)
        self._build_indexes()

    def _build_indexes(self):
        """Build lookup indexes for fast correlation."""
        for acc_id, txns in self._account_txns.items():
            for txn in txns:
                self._txn_index[txn.txn_id] = txn
                if txn.utr:
                    self._utr_index[txn.utr].append(txn)
                cp_fp = txn.counterparty.fingerprint()
                if cp_fp:
                    self._counterparty_index[cp_fp].add(acc_id)

    # ==================== RISK PRIMITIVE COMPUTATIONS ====================

    def compute_velocity_spike(self, account_id: str) -> PrimitiveEvidence:
        """
        Primitive 1: Velocity Spike
        Rapid in-out transfers within time window.
        """
        txns = self._account_txns.get(account_id, [])
        if len(txns) < 3:
            return self._empty_evidence(RiskPrimitive.VELOCITY_SPIKE, "Insufficient transactions")

        # Sort by timestamp
        txns_sorted = sorted(txns, key=lambda t: t.timestamp_utc)

        # Sliding window: count txns in each window
        window = timedelta(hours=self.VELOCITY_WINDOW_HOURS)
        velocities = []

        for i, txn in enumerate(txns_sorted):
            window_end = txn.timestamp_utc + window
            count = sum(1 for t in txns_sorted[i:] if t.timestamp_utc <= window_end)
            velocities.append(count)

        if not velocities:
            return self._empty_evidence(RiskPrimitive.VELOCITY_SPIKE, "No velocity data")

        mean_vel = sum(velocities) / len(velocities)
        std_vel = math.sqrt(sum((v - mean_vel) ** 2 for v in velocities) / len(velocities))

        max_vel = max(velocities)
        z_score = (max_vel - mean_vel) / std_vel if std_vel > 0 else 0

        # Score: normalized z-score (capped)
        score = min(z_score / self.VELOCITY_SPIKE_THRESHOLD, 1.0) if z_score > 0 else 0.0

        # Percentile (simplified - in production use peer group)
        percentile = min(99.0, 50 + z_score * 15) if z_score > 0 else 50.0

        # Find supporting transactions
        max_idx = velocities.index(max_vel)
        window_end = txns_sorted[max_idx].timestamp_utc + window
        supporting = [
            t.txn_id for t in txns_sorted[max_idx:]
            if t.timestamp_utc <= window_end
        ]

        return PrimitiveEvidence(
            primitive=RiskPrimitive.VELOCITY_SPIKE,
            score=score,
            percentile=percentile,
            description=(
                f"Account processed {max_vel} transactions in {self.VELOCITY_WINDOW_HOURS}h "
                f"(μ={mean_vel:.1f}, σ={std_vel:.1f}, z={z_score:.2f})"
            ),
            supporting_txn_ids=tuple(supporting),
            parameters={
                "window_hours": self.VELOCITY_WINDOW_HOURS,
                "max_velocity": max_vel,
                "mean_velocity": mean_vel,
                "std_velocity": std_vel,
                "z_score": z_score,
            },
        )

    def compute_layering_depth(self, account_id: str, victim_utr: Optional[str] = None) -> PrimitiveEvidence:
        """
        Primitive 2: Layering Depth
        Shortest path from victim UTR (or any entry) to cash-out.
        """
        txns = self._account_txns.get(account_id, [])
        if not txns:
            return self._empty_evidence(RiskPrimitive.LAYERING_DEPTH, "No transactions")

        # Build fund flow graph from this account's perspective
        # We trace where money came from and where it went

        credits = [t for t in txns if t.is_credit]
        debits = [t for t in txns if not t.is_credit]

        if not credits or not debits:
            return self._empty_evidence(RiskPrimitive.LAYERING_DEPTH, "No credit/debit pairs")

        # For each credit, find nearest subsequent debit (simplified layering)
        layering_depths = []

        for credit in credits:
            # Find debits after this credit
            subsequent_debits = [d for d in debits if d.timestamp_utc > credit.timestamp_utc]
            if subsequent_debits:
                # Depth = number of distinct counterparties in path
                # Simplified: just count hops from this credit to exit
                depth = self._trace_fund_path(credit, subsequent_debits, set(), 0)
                layering_depths.append(depth)

        if not layering_depths:
            return self._empty_evidence(RiskPrimitive.LAYERING_DEPTH, "No fund paths traced")

        max_depth = max(layering_depths)
        avg_depth = sum(layering_depths) / len(layering_depths)

        # Score based on max depth (normalized to max hops)
        score = min(max_depth / self.LAYERING_MAX_HOPS, 1.0)
        percentile = min(99.0, score * 100)

        supporting = [c.txn_id for c in credits[:5]]  # Top 5 credits

        return PrimitiveEvidence(
            primitive=RiskPrimitive.LAYERING_DEPTH,
            score=score,
            percentile=percentile,
            description=(
                f"Maximum fund layering depth: {max_depth} hops "
                f"(avg: {avg_depth:.1f}, paths analyzed: {len(layering_depths)})"
            ),
            supporting_txn_ids=tuple(supporting),
            parameters={
                "max_depth": max_depth,
                "avg_depth": avg_depth,
                "paths_analyzed": len(layering_depths),
                "max_hops_config": self.LAYERING_MAX_HOPS,
            },
        )

    def _trace_fund_path(
        self,
        start_txn: UnifiedTransaction,
        candidate_debits: list[UnifiedTransaction],
        visited: set[str],
        depth: int
    ) -> int:
        """Recursively trace fund movement (simplified)."""
        if depth >= self.LAYERING_MAX_HOPS:
            return depth

        # Find debit that could match this credit (amount proximity + time)
        best_match = None
        best_score = 0

        for debit in candidate_debits:
            if debit.txn_id in visited:
                continue
            # Score based on amount similarity and time proximity
            amount_ratio = min(start_txn.abs_amount, debit.abs_amount) / max(start_txn.abs_amount, debit.abs_amount)
            time_diff = (debit.timestamp_utc - start_txn.timestamp_utc).total_seconds() / 3600
            time_score = 1 / (1 + time_diff / 24)  # Decay over 24h
            score = amount_ratio * 0.7 + time_score * 0.3

            if score > best_score:
                best_score = score
                best_match = debit

        if best_match and best_score > 0.3:
            visited.add(best_match.txn_id)
            # Continue tracing from this debit's counterparty
            # (In full implementation, would cross-reference other accounts)
            return self._trace_fund_path(best_match, candidate_debits, visited, depth + 1)

        return depth

    def compute_counterparty_entropy(self, account_id: str) -> PrimitiveEvidence:
        """
        Primitive 3: Counterparty Entropy
        Shannon entropy of unique senders per time window.
        """
        txns = self._account_txns.get(account_id, [])
        credits = [t for t in txns if t.is_credit]

        if len(credits) < 5:
            return self._empty_evidence(RiskPrimitive.COUNTERPARTY_ENTROPY, "Insufficient credit transactions")

        # Group by time windows
        window = timedelta(days=self.ENTROPY_WINDOW_DAYS)
        credits_sorted = sorted(credits, key=lambda t: t.timestamp_utc)

        window_entropies = []

        for i, txn in enumerate(credits_sorted):
            window_end = txn.timestamp_utc + window
            window_txns = [t for t in credits_sorted[i:] if t.timestamp_utc <= window_end]

            if len(window_txns) < 3:
                continue

            # Count unique counterparties
            cp_counts = defaultdict(int)
            for t in window_txns:
                cp_fp = t.counterparty.fingerprint()
                if cp_fp:
                    cp_counts[cp_fp] += 1

            if len(cp_counts) < 2:
                continue

            # Shannon entropy
            total = sum(cp_counts.values())
            entropy = -sum(
                (count / total) * math.log2(count / total)
                for count in cp_counts.values()
            )

            # Normalize by max possible entropy (log2 of unique counterparties)
            max_entropy = math.log2(len(cp_counts))
            normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0

            window_entropies.append(normalized_entropy)

        if not window_entropies:
            return self._empty_evidence(RiskPrimitive.COUNTERPARTY_ENTROPY, "No valid entropy windows")

        max_entropy = max(window_entropies)
        avg_entropy = sum(window_entropies) / len(window_entropies)

        # High entropy = many diverse senders = potential mule recruitment
        score = max_entropy
        percentile = min(99.0, score * 100)

        return PrimitiveEvidence(
            primitive=RiskPrimitive.COUNTERPARTY_ENTROPY,
            score=score,
            percentile=percentile,
            description=(
                f"Max counterparty entropy: {max_entropy:.3f} "
                f"(avg: {avg_entropy:.3f}, windows: {len(window_entropies)})"
            ),
            supporting_txn_ids=tuple(t.txn_id for t in credits_sorted[:10]),
            parameters={
                "window_days": self.ENTROPY_WINDOW_DAYS,
                "max_entropy": max_entropy,
                "avg_entropy": avg_entropy,
                "windows_analyzed": len(window_entropies),
            },
        )

    def compute_round_figure_clustering(self, account_id: str) -> PrimitiveEvidence:
        """
        Primitive 4: Round Figure Clustering
        Chi-squared test for concentration at psychological thresholds.
        """
        txns = self._account_txns.get(account_id, [])
        if len(txns) < 10:
            return self._empty_evidence(RiskPrimitive.ROUND_FIGURE_CLUSTERING, "Insufficient transactions")

        amounts = [float(t.abs_amount) for t in txns]

        # Count transactions near each threshold
        observed = []
        expected = []

        for threshold in self.ROUND_FIGURE_THRESHOLDS:
            epsilon = threshold * self.ROUND_FIGURE_EPSILON
            count = sum(1 for a in amounts if abs(a - threshold) <= epsilon)
            observed.append(count)
            # Expected: uniform distribution across range
            range_width = max(amounts) - min(amounts) if max(amounts) > min(amounts) else 1
            exp = len(amounts) * (2 * epsilon) / range_width
            expected.append(max(exp, 0.5))  # Avoid division by zero

        # Chi-squared statistic
        chi2 = sum((o - e) ** 2 / e for o, e in zip(observed, expected))

        # Degrees of freedom = number of thresholds - 1
        df = len(self.ROUND_FIGURE_THRESHOLDS) - 1

        # p-value approximation (simplified)
        # For df=8, chi2 > 15.5 is p<0.05, > 20.1 is p<0.01
        if chi2 > 20:
            score = 0.9
        elif chi2 > 15.5:
            score = 0.7
        elif chi2 > 10:
            score = 0.5
        else:
            score = chi2 / 20  # Linear below significance

        percentile = min(99.0, score * 100)

        # Find supporting transactions
        supporting = []
        for txn in txns:
            for threshold in self.ROUND_FIGURE_THRESHOLDS:
                epsilon = threshold * self.ROUND_FIGURE_EPSILON
                if abs(float(txn.abs_amount) - threshold) <= epsilon:
                    supporting.append(txn.txn_id)
                    break

        return PrimitiveEvidence(
            primitive=RiskPrimitive.ROUND_FIGURE_CLUSTERING,
            score=score,
            percentile=percentile,
            description=(
                f"Round-figure clustering χ²={chi2:.1f} (df={df}, "
                f"{'significant' if chi2 > 15.5 else 'not significant'})"
            ),
            supporting_txn_ids=tuple(supporting),
            parameters={
                "chi2_statistic": chi2,
                "degrees_of_freedom": df,
                "thresholds_tested": self.ROUND_FIGURE_THRESHOLDS,
                "epsilon_ratio": self.ROUND_FIGURE_EPSILON,
                "observed_counts": observed,
                "expected_counts": expected,
            },
        )

    def compute_dormancy_break(self, account_id: str) -> PrimitiveEvidence:
        """
        Primitive 5: Dormancy Break
        Zero activity → sudden high-volume burst.
        """
        txns = self._account_txns.get(account_id, [])
        if len(txns) < 5:
            return self._empty_evidence(RiskPrimitive.DORMANCY_BREAK, "Insufficient transaction history")

        txns_sorted = sorted(txns, key=lambda t: t.timestamp_utc)

        # Find gaps between transactions
        gaps = []
        for i in range(1, len(txns_sorted)):
            gap_days = (txns_sorted[i].timestamp_utc - txns_sorted[i-1].timestamp_utc).days
            gaps.append((gap_days, i))  # (gap_days, index_of_second_txn)

        if not gaps:
            return self._empty_evidence(RiskPrimitive.DORMANCY_BREAK, "No gaps found")

        max_gap, gap_idx = max(gaps, key=lambda x: x[0])

        if max_gap < self.DORMANCY_LOOKBACK_DAYS:
            return self._empty_evidence(
                RiskPrimitive.DORMANCY_BREAK,
                f"Max gap {max_gap}d < dormancy threshold {self.DORMANCY_LOOKBACK_DAYS}d"
            )

        # Analyze activity after the gap
        post_gap_txns = txns_sorted[gap_idx:]
        pre_gap_txns = txns_sorted[:gap_idx]

        if not pre_gap_txns or not post_gap_txns:
            return self._empty_evidence(RiskPrimitive.DORMANCY_BREAK, "Insufficient pre/post gap data")

        # Compare transaction rates
        pre_span_days = (pre_gap_txns[-1].timestamp_utc - pre_gap_txns[0].timestamp_utc).days or 1
        post_span_days = (post_gap_txns[-1].timestamp_utc - post_gap_txns[0].timestamp_utc).days or 1

        pre_rate = len(pre_gap_txns) / pre_span_days
        post_rate = len(post_gap_txns) / post_span_days

        rate_ratio = post_rate / pre_rate if pre_rate > 0 else float('inf')

        if rate_ratio < self.DORMANCY_BURST_MULTIPLIER:
            return self._empty_evidence(
                RiskPrimitive.DORMANCY_BREAK,
                f"Post-gap rate ratio {rate_ratio:.1f}x < threshold {self.DORMANCY_BURST_MULTIPLIER}x"
            )

        score = min(math.log(rate_ratio) / math.log(self.DORMANCY_BURST_MULTIPLIER * 10), 1.0)
        percentile = min(99.0, 50 + math.log10(rate_ratio) * 20)

        supporting = tuple(t.txn_id for t in post_gap_txns[:20])

        return PrimitiveEvidence(
            primitive=RiskPrimitive.DORMANCY_BREAK,
            score=score,
            percentile=percentile,
            description=(
                f"Dormancy break: {max_gap}d gap → {rate_ratio:.1f}x activity increase "
                f"({len(pre_gap_txns)} txns/{pre_span_days}d → {len(post_gap_txns)} txns/{post_span_days}d)"
            ),
            supporting_txn_ids=supporting,
            parameters={
                "max_gap_days": max_gap,
                "pre_gap_txns": len(pre_gap_txns),
                "post_gap_txns": len(post_gap_txns),
                "pre_rate_per_day": pre_rate,
                "post_rate_per_day": post_rate,
                "rate_ratio": rate_ratio,
                "dormancy_threshold_days": self.DORMANCY_LOOKBACK_DAYS,
                "burst_multiplier": self.DORMANCY_BURST_MULTIPLIER,
            },
        )

    def compute_structuring_signature(self, account_id: str) -> PrimitiveEvidence:
        """
        Primitive 6: Structuring Signature
        Repeated near-threshold amounts avoiding reporting limits.
        """
        txns = self._account_txns.get(account_id, [])
        credits = [t for t in txns if t.is_credit]

        if len(credits) < 5:
            return self._empty_evidence(RiskPrimitive.STRUCTURING_SIGNATURE, "Insufficient credit transactions")

        amounts = [float(t.abs_amount) for t in credits]

        # Check each reporting threshold
        near_threshold_counts = []
        total_checked = 0

        for threshold in self.STRUCTURING_THRESHOLDS:
            epsilon = threshold * self.STRUCTURING_EPSILON_RATIO
            count = sum(1 for a in amounts if threshold - epsilon <= a < threshold)
            near_threshold_counts.append(count)
            total_checked += count

        structuring_ratio = total_checked / len(credits) if credits else 0

        # Score: ratio of near-threshold transactions
        if structuring_ratio > 0.3:
            score = min(structuring_ratio / 0.5, 1.0)  # Cap at 50%
        elif structuring_ratio > 0.15:
            score = structuring_ratio / 0.3 * 0.6
        else:
            score = structuring_ratio / 0.15 * 0.3

        percentile = min(99.0, score * 100)

        # Supporting transactions
        supporting = []
        for txn in credits:
            for threshold in self.STRUCTURING_THRESHOLDS:
                epsilon = threshold * self.STRUCTURING_EPSILON_RATIO
                if threshold - epsilon <= float(txn.abs_amount) < threshold:
                    supporting.append(txn.txn_id)
                    break

        return PrimitiveEvidence(
            primitive=RiskPrimitive.STRUCTURING_SIGNATURE,
            score=score,
            percentile=percentile,
            description=(
                f"Structuring signature: {structuring_ratio:.1%} of credits "
                f"within {self.STRUCTURING_EPSILON_RATIO:.0%} of reporting thresholds "
                f"({total_checked}/{len(credits)} transactions)"
            ),
            supporting_txn_ids=tuple(supporting),
            parameters={
                "structuring_ratio": structuring_ratio,
                "thresholds": self.STRUCTURING_THRESHOLDS,
                "epsilon_ratio": self.STRUCTURING_EPSILON_RATIO,
                "near_threshold_counts": near_threshold_counts,
                "total_credits": len(credits),
            },
        )

    def _empty_evidence(self, primitive: RiskPrimitive, reason: str) -> PrimitiveEvidence:
        return PrimitiveEvidence(
            primitive=primitive,
            score=0.0,
            percentile=0.0,
            description=reason,
            supporting_txn_ids=(),
            parameters={"reason": reason},
        )

    # ==================== PUBLIC API ====================

    def compute_risk_dna(self, account_id: str, peer_group: str = "ALL") -> RiskDNA:
        """Compute complete Risk DNA for an account."""
        primitives = [
            self.compute_velocity_spike(account_id),
            self.compute_layering_depth(account_id),
            self.compute_counterparty_entropy(account_id),
            self.compute_round_figure_clustering(account_id),
            self.compute_dormancy_break(account_id),
            self.compute_structuring_signature(account_id),
        ]

        primitive_scores = {e.primitive: e.score for e in primitives}
        peer_percentiles = {e.primitive: e.percentile for e in primitives}
        evidence_map = {e.primitive: e for e in primitives}

        total_txns = len(self._account_txns.get(account_id, []))

        return RiskDNA.compute(
            account_id=account_id,
            primitive_scores=primitive_scores,
            peer_percentiles=peer_percentiles,
            evidence_map=evidence_map,
            peer_group=peer_group,
            total_transactions=total_txns,
        )

    def trace_money_trail(self, victim_utr: str) -> Optional[MoneyTrail]:
        """
        Trace fund movement from victim UTR through the network.
        Returns complete hop-by-hop trail.
        """
        # Find victim transaction
        victim_txns = self._utr_index.get(victim_utr, [])
        if not victim_txns:
            return None

        victim_txn = victim_txns[0]
        victim_account = None

        # Find which account this UTR belongs to
        for acc_id, txns in self._account_txns.items():
            if any(t.utr == victim_utr for t in txns):
                victim_account = acc_id
                break

        if not victim_account:
            return None

        # BFS trace from victim transaction
        hops = []
        visited_txns = set()
        queue = deque([(victim_txn, victim_account, 0)])

        terminal_accounts = set()

        while queue and len(hops) < self.LAYERING_MAX_HOPS:
            current_txn, current_account, hop_num = queue.popleft()

            if current_txn.txn_id in visited_txns:
                continue
            visited_txns.add(current_txn.txn_id)

            # Find debits from this account after this credit
            account_txns = self._account_txns.get(current_account, [])
            subsequent_debits = [
                t for t in account_txns
                if not t.is_credit and t.timestamp_utc > current_txn.timestamp_utc
                and t.txn_id not in visited_txns
            ]

            if not subsequent_debits:
                # Terminal - cash out or end of trail
                terminal_accounts.add(current_account)
                continue

            # Follow each debit (simplified: follow largest)
            for debit in sorted(subsequent_debits, key=lambda x: x.abs_amount, reverse=True)[:3]:
                hop = FundHop(
                    from_account=current_account,
                    to_account=debit.counterparty.fingerprint() or "UNKNOWN",
                    amount=debit.abs_amount,
                    timestamp_utc=debit.timestamp_utc,
                    utr=debit.utr,
                    hop_number=hop_num + 1,
                    txn_id=debit.txn_id,
                )
                hops.append(hop)

                # Find the recipient account in our dataset
                recipient_account = None
                for acc_id, txns in self._account_txns.items():
                    if any(t.utr == debit.utr for t in txns if t.is_credit):
                        recipient_account = acc_id
                        break

                if recipient_account:
                    queue.append((debit, recipient_account, hop_num + 1))
                else:
                    terminal_accounts.add(debit.counterparty.fingerprint() or "EXTERNAL")

        if not hops:
            return None

        # Compute risk DNA for all accounts in trail
        risk_dna_matches = {}
        for hop in hops:
            if hop.from_account not in risk_dna_matches:
                risk_dna_matches[hop.from_account] = self.compute_risk_dna(hop.from_account)
            if hop.to_account not in risk_dna_matches and hop.to_account != "UNKNOWN":
                risk_dna_matches[hop.to_account] = self.compute_risk_dna(hop.to_account)

        total_amount = sum(h.amount for h in hops)
        duration = (hops[-1].timestamp_utc - hops[0].timestamp_utc).total_seconds() / 3600
        layering_depth = max(h.hop_number for h in hops)

        return MoneyTrail(
            victim_utr=victim_utr,
            hops=tuple(hops),
            terminal_accounts=tuple(terminal_accounts),
            total_amount=total_amount,
            layering_depth=layering_depth,
            duration_hours=duration,
            risk_dna_matches=risk_dna_matches,
        )

    def find_related_accounts(self, account_id: str, min_similarity: float = 0.65) -> list[tuple[str, float]]:
        """Find accounts with similar Risk DNA (cross-case linking)."""
        target_dna = self.compute_risk_dna(account_id)
        related = []

        for other_id in self._account_txns:
            if other_id == account_id:
                continue
            other_dna = self.compute_risk_dna(other_id)
            similarity = target_dna.similarity(other_dna)
            if similarity >= min_similarity:
                related.append((other_id, similarity))

        related.sort(key=lambda x: x[1], reverse=True)
        return related


# Convenience function
def analyze_statements(statements: dict[str, AccountStatement]) -> TransactionTopologyEngine:
    """Create TTE and compute Risk DNA for all accounts."""
    engine = TransactionTopologyEngine(statements)
    return engine