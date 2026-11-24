"""
Temporal Correlation Engine (TCorE) — NAUTILUS Core Correlation Engine #3
Unified temporal canvas with clock skew calibration and confidence intervals.
"""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional
import math
import statistics


@dataclass(frozen=True, slots=True)
class TemporalEvent:
    """A single event on the unified timeline."""
    event_id: str
    event_type: str                    # TRANSACTION, DNS_CHANGE, SSL_ISSUE, DOMAIN_REG, WHOIS_UPDATE, etc.
    timestamp_utc: datetime            # Normalized to UTC
    timestamp_raw: str                 # Original timestamp string
    source: str                        # Source system: BANK_CBS, WHOIS, DNS_PASSIVE, CT_LOG, EMAIL_HEADER
    confidence_interval_seconds: float # ± seconds uncertainty
    clock_skew_correction: float = 0.0 # Applied correction (seconds)
    timezone_source: str = "UTC"       # Original timezone
    # Event-specific data
    account_id: str = ""
    utr: str = ""
    amount: Decimal = Decimal('0')
    domain: str = ""
    ip: str = ""
    metadata: dict = field(default_factory=dict)

    @property
    def timestamp_min(self) -> datetime:
        """Earliest possible time (lower bound)."""
        return self.timestamp_utc - timedelta(seconds=self.confidence_interval_seconds)

    @property
    def timestamp_max(self) -> datetime:
        """Latest possible time (upper bound)."""
        return self.timestamp_utc + timedelta(seconds=self.confidence_interval_seconds)

    def overlaps(self, other: TemporalEvent) -> bool:
        """Check if confidence intervals overlap."""
        return self.timestamp_min <= other.timestamp_max and other.timestamp_min <= self.timestamp_max

    def time_gap_to(self, other: TemporalEvent) -> timedelta:
        """Gap between this event and another (positive = other is later)."""
        return other.timestamp_utc - self.timestamp_utc


@dataclass(frozen=True, slots=True)
class ClockSkewProfile:
    """Calibrated clock skew for a data source."""
    source: str
    sample_count: int
    mean_offset_seconds: float
    std_offset_seconds: float
    calibration_events: tuple[str, ...]  # Event IDs used for calibration
    last_calibrated: datetime
    is_reliable: bool = True


@dataclass(frozen=True, slots=True)
class TemporalCorrelation:
    """A correlation between events across sources."""
    event_a: TemporalEvent
    event_b: TemporalEvent
    gap_seconds: float
    gap_category: str                    # IMMEDIATE, MINUTES, HOURS, DAYS
    confidence: float                    # 0-1 based on interval overlap
    correlation_type: str                # CAUSAL, SEQUENTIAL, CONCURRENT, ANOMALOUS
    description: str


class TemporalCorrelationEngine:
    """
    Unified temporal analysis with clock skew calibration.
    Normalizes all timestamps to UTC with confidence intervals.
    """

    # Source-specific default confidence intervals (seconds)
    SOURCE_CONFIDENCE = {
        'BANK_CBS': 0,           # Core banking - authoritative
        'BANK_STATEMENT': 0,     # Statement export - authoritative
        'ATM': 30,               # ATM clock drift
        'WHOIS': 0,              # Authoritative registry
        'RDAP': 0,               # Authoritative
        'DNS_PASSIVE': 300,      # Passive DNS polling interval (5 min)
        'DNS_ZONE': 60,          # Zone transfer timestamp
        'CT_LOG': 1,             # Merkle tree timestamp
        'SSL_CERT': 60,          # Cert notBefore/notAfter precision
        'EMAIL_HEADER': 60,      # MTA clock skew
        'FIREWALL_LOG': 1,       # Syslog precision
        'PROXY_LOG': 5,          # Proxy access log
        'VPN_LOG': 5,            # VPN session log
        'MANUAL': 3600,          # Human-reported (1 hour)
    }

    # Source timezones (default assumptions)
    SOURCE_TIMEZONES = {
        'BANK_CBS': '+05:30',    # IST
        'BANK_STATEMENT': '+05:30',
        'ATM': '+05:30',
        'WHOIS': 'UTC',
        'RDAP': 'UTC',
        'DNS_PASSIVE': 'UTC',
        'DNS_ZONE': 'UTC',
        'CT_LOG': 'UTC',
        'SSL_CERT': 'UTC',
        'EMAIL_HEADER': 'UTC',   # Usually UTC in headers
        'FIREWALL_LOG': 'UTC',
        'PROXY_LOG': 'UTC',
        'VPN_LOG': 'UTC',
        'MANUAL': '+05:30',      # Assume IST if not specified
    }

    def __init__(self):
        self.events: list[TemporalEvent] = []
        self.skew_profiles: dict[str, ClockSkewProfile] = {}
        self._event_index: dict[str, TemporalEvent] = {}

    def add_event(self, event: TemporalEvent):
        """Add an event to the timeline."""
        self.events.append(event)
        self._event_index[event.event_id] = event

    def add_events(self, events: list[TemporalEvent]):
        """Add multiple events."""
        for event in events:
            self.add_event(event)

    def load_from_transactions(self, transactions: list, account_id: str):
        """Load events from UnifiedTransaction objects."""
        for txn in transactions:
            # Determine confidence based on channel
            confidence = self.SOURCE_CONFIDENCE.get('BANK_STATEMENT', 0)

            event = TemporalEvent(
                event_id=txn.txn_id,
                event_type='TRANSACTION',
                timestamp_utc=txn.timestamp_utc,
                timestamp_raw=txn.timestamp_raw,
                source='BANK_STATEMENT',
                confidence_interval_seconds=confidence,
                timezone_source=txn.tz_offset,
                account_id=account_id,
                utr=txn.utr or "",
                amount=txn.amount,
                metadata={
                    'counterparty': txn.counterparty.name,
                    'narration': txn.narration,
                    'channel': txn.channel.value,
                },
            )
            self.add_event(event)

    def load_from_domain_artifacts(self, artifacts: list):
        """Load events from DomainArtifact objects."""
        for artifact in artifacts:
            # Domain registration
            if artifact.creation_date:
                event = TemporalEvent(
                    event_id=f"REG_{artifact.domain}",
                    event_type='DOMAIN_REGISTRATION',
                    timestamp_utc=artifact.creation_date,
                    timestamp_raw=artifact.creation_date.isoformat(),
                    source='WHOIS',
                    confidence_interval_seconds=self.SOURCE_CONFIDENCE['WHOIS'],
                    timezone_source='UTC',
                    domain=artifact.domain,
                    metadata={'registrar': artifact.registrar, 'event': 'creation'},
                )
                self.add_event(event)

            # SSL certificate issuance
            if artifact.ssl_not_before:
                event = TemporalEvent(
                    event_id=f"SSL_{artifact.domain}",
                    event_type='SSL_CERT_ISSUE',
                    timestamp_utc=artifact.ssl_not_before,
                    timestamp_raw=artifact.ssl_not_before.isoformat(),
                    source='SSL_CERT',
                    confidence_interval_seconds=self.SOURCE_CONFIDENCE['SSL_CERT'],
                    timezone_source='UTC',
                    domain=artifact.domain,
                    metadata={'issuer': artifact.ssl_issuer, 'san': list(artifact.ssl_san)},
                )
                self.add_event(event)

            # CT log entries
            for ct_entry in artifact.ct_entries:
                ts_str = ct_entry.get('timestamp', '')
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                        event = TemporalEvent(
                            event_id=f"CT_{artifact.domain}_{ct_entry.get('log_id', 'unknown')}",
                            event_type='CT_LOG_ENTRY',
                            timestamp_utc=ts,
                            timestamp_raw=ts_str,
                            source='CT_LOG',
                            confidence_interval_seconds=self.SOURCE_CONFIDENCE['CT_LOG'],
                            timezone_source='UTC',
                            domain=artifact.domain,
                            metadata=ct_entry,
                        )
                        self.add_event(event)
                    except Exception:
                        pass

    def load_from_ip_artifacts(self, artifacts: list):
        """Load events from IPArtifact objects (limited temporal data)."""
        # IP artifacts typically don't have timestamps unless from passive DNS
        pass

    # ==================== CLOCK SKEW CALIBRATION ====================

    def calibrate_clock_skew(
        self,
        source_a: str,
        source_b: str,
        known_synchronous_events: list[tuple[str, str]]
    ) -> ClockSkewProfile:
        """
        Calibrate clock skew between two sources using known synchronous events.

        Args:
            source_a: First source name
            source_b: Second source name
            known_synchronous_events: List of (event_id_a, event_id_b) pairs known to be simultaneous

        Returns:
            ClockSkewProfile for source_b relative to source_a
        """
        offsets = []
        used_events = []

        for event_id_a, event_id_b in known_synchronous_events:
            event_a = self._event_index.get(event_id_a)
            event_b = self._event_index.get(event_id_b)

            if not event_a or not event_b:
                continue
            if event_a.source != source_a or event_b.source != source_b:
                continue

            # Offset = time_b - time_a (positive = b is ahead)
            offset = (event_b.timestamp_utc - event_a.timestamp_utc).total_seconds()
            offsets.append(offset)
            used_events.extend([event_id_a, event_id_b])

        if len(offsets) < 2:
            # Insufficient data - return default
            return ClockSkewProfile(
                source=source_b,
                sample_count=len(offsets),
                mean_offset_seconds=0.0,
                std_offset_seconds=0.0,
                calibration_events=tuple(used_events),
                last_calibrated=datetime.utcnow(),
                is_reliable=False,
            )

        mean_offset = statistics.mean(offsets)
        std_offset = statistics.stdev(offsets) if len(offsets) > 1 else 0.0

        profile = ClockSkewProfile(
            source=source_b,
            sample_count=len(offsets),
            mean_offset_seconds=mean_offset,
            std_offset_seconds=std_offset,
            calibration_events=tuple(used_events),
            last_calibrated=datetime.utcnow(),
            is_reliable=std_offset < 60,  # Reliable if std < 1 minute
        )

        self.skew_profiles[f"{source_a}->{source_b}"] = profile

        # Apply correction to source_b events
        self._apply_skew_correction(source_b, mean_offset)

        return profile

    def _apply_skew_correction(self, source: str, offset_seconds: float):
        """Apply clock skew correction to all events from a source."""
        for event in self.events:
            if event.source == source:
                # Create corrected event (immutable, so replace)
                corrected = TemporalEvent(
                    event_id=event.event_id,
                    event_type=event.event_type,
                    timestamp_utc=event.timestamp_utc - timedelta(seconds=offset_seconds),
                    timestamp_raw=event.timestamp_raw,
                    source=event.source,
                    confidence_interval_seconds=event.confidence_interval_seconds,
                    clock_skew_correction=offset_seconds,
                    timezone_source=event.timezone_source,
                    account_id=event.account_id,
                    utr=event.utr,
                    amount=event.amount,
                    domain=event.domain,
                    ip=event.ip,
                    metadata=event.metadata,
                )
                # Replace in list
                idx = self.events.index(event)
                self.events[idx] = corrected
                self._event_index[event.event_id] = corrected

    def auto_calibrate(self) -> dict[str, ClockSkewProfile]:
        """
        Automatic clock skew calibration using UTR as ground truth.
        UTR appears in both sender and receiver bank statements.
        """
        # Group transactions by UTR
        utr_events = defaultdict(list)
        for event in self.events:
            if event.event_type == 'TRANSACTION' and event.utr:
                utr_events[event.utr].append(event)

        profiles = {}

        # For each UTR with multiple events, calibrate
        for utr, events in utr_events.items():
            if len(events) < 2:
                continue

            # Group by source
            by_source = defaultdict(list)
            for e in events:
                by_source[e.source].append(e)

            # Find pairs of sources
            sources = list(by_source.keys())
            for i in range(len(sources)):
                for j in range(i+1, len(sources)):
                    src_a, src_b = sources[i], sources[j]
                    events_a = by_source[src_a]
                    events_b = by_source[src_b]

                    # Pair events (simplest: first with first)
                    for e_a, e_b in zip(events_a, events_b):
                        pair = (e_a.event_id, e_b.event_id)
                        profile = self.calibrate_clock_skew(src_a, src_b, [pair])
                        profiles[f"{src_a}->{src_b}"] = profile

        return profiles

    # ==================== TEMPORAL CORRELATION ====================

    def find_correlations(
        self,
        max_gap_hours: float = 72,
        min_confidence: float = 0.3
    ) -> list[TemporalCorrelation]:
        """
        Find temporal correlations between events across all sources.
        """
        correlations = []

        # Sort events by timestamp
        sorted_events = sorted(self.events, key=lambda e: e.timestamp_utc)

        # Window-based correlation detection
        for i, event_a in enumerate(sorted_events):
            # Look forward within max gap
            for event_b in sorted_events[i+1:]:
                gap = (event_b.timestamp_utc - event_a.timestamp_utc).total_seconds()

                if gap > max_gap_hours * 3600:
                    break  # Events are sorted, so no more within window

                if gap < 0:
                    continue

                # Compute confidence based on interval overlap
                confidence = self._compute_overlap_confidence(event_a, event_b)

                if confidence < min_confidence:
                    continue

                # Categorize gap
                if gap < 60:
                    gap_category = "IMMEDIATE"
                elif gap < 3600:
                    gap_category = "MINUTES"
                elif gap < 86400:
                    gap_category = "HOURS"
                else:
                    gap_category = "DAYS"

                # Determine correlation type
                corr_type = self._classify_correlation(event_a, event_b, gap)

                # Generate description
                description = self._generate_correlation_description(event_a, event_b, gap, corr_type)

                correlations.append(TemporalCorrelation(
                    event_a=event_a,
                    event_b=event_b,
                    gap_seconds=gap,
                    gap_category=gap_category,
                    confidence=confidence,
                    correlation_type=corr_type,
                    description=description,
                ))

        # Sort by confidence descending
        correlations.sort(key=lambda c: c.confidence, reverse=True)
        return correlations

    def _compute_overlap_confidence(self, event_a: TemporalEvent, event_b: TemporalEvent) -> float:
        """Compute confidence based on confidence interval overlap."""
        # If intervals overlap, high confidence
        if event_a.overlaps(event_b):
            return 0.9

        # Otherwise, confidence decays with gap relative to combined uncertainty
        gap = abs((event_b.timestamp_utc - event_a.timestamp_utc).total_seconds())
        combined_uncertainty = event_a.confidence_interval_seconds + event_b.confidence_interval_seconds

        if combined_uncertainty == 0:
            return 0.5  # No uncertainty info

        # Exponential decay
        return math.exp(-gap / (combined_uncertainty * 2))

    def _classify_correlation(
        self,
        event_a: TemporalEvent,
        event_b: TemporalEvent,
        gap_seconds: float
    ) -> str:
        """Classify the type of temporal correlation."""

        # Same UTR = causal (fund movement)
        if event_a.utr and event_a.utr == event_b.utr:
            return "CAUSAL"

        # Same account, sequential transactions
        if event_a.account_id and event_a.account_id == event_b.account_id:
            if event_a.event_type == 'TRANSACTION' and event_b.event_type == 'TRANSACTION':
                return "SEQUENTIAL"

        # Domain registration → SSL cert → DNS appearance = causal chain
        if event_a.event_type == 'DOMAIN_REGISTRATION' and event_b.event_type in ('SSL_CERT_ISSUE', 'DNS_CHANGE'):
            return "CAUSAL"

        if event_a.event_type == 'SSL_CERT_ISSUE' and event_b.event_type == 'DNS_CHANGE':
            return "CAUSAL"

        # Phishing email → victim transaction
        if event_a.event_type == 'PHISHING_EMAIL' and event_b.event_type == 'TRANSACTION':
            if gap_seconds < 86400:  # Within 24h
                return "CAUSAL"

        # Concurrent (overlapping intervals)
        if event_a.overlaps(event_b):
            return "CONCURRENT"

        return "ANOMALOUS"

    def _generate_correlation_description(
        self,
        event_a: TemporalEvent,
        event_b: TemporalEvent,
        gap_seconds: float,
        corr_type: str
    ) -> str:
        """Generate human-readable correlation description."""
        gap_str = self._format_gap(gap_seconds)

        type_descriptions = {
            "CAUSAL": "likely causal link",
            "SEQUENTIAL": "sequential activity",
            "CONCURRENT": "concurrent events",
            "ANOMALOUS": "temporal proximity (review needed)",
        }

        desc = type_descriptions.get(corr_type, "correlated")

        # Add specifics
        details = []
        if event_a.utr and event_a.utr == event_b.utr:
            details.append(f"same UTR ({event_a.utr[:8]}...)")
        if event_a.account_id and event_a.account_id == event_b.account_id:
            details.append(f"same account ({event_a.account_id})")
        if event_a.domain and event_a.domain == event_b.domain:
            details.append(f"same domain ({event_a.domain})")
        if event_a.ip and event_a.ip == event_b.ip:
            details.append(f"same IP ({event_a.ip})")

        detail_str = f" [{', '.join(details)}]" if details else ""

        return f"{event_a.event_type} → {event_b.event_type} ({gap_str}) = {desc}{detail_str}"

    def _format_gap(self, seconds: float) -> str:
        """Format time gap human-readably."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        elif seconds < 86400:
            return f"{seconds/3600:.1f}h"
        else:
            return f"{seconds/86400:.1f}d"

    # ==================== TIMELINE QUERIES ====================

    def get_timeline(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        event_types: Optional[list[str]] = None,
        sources: Optional[list[str]] = None,
        account_id: Optional[str] = None,
        domain: Optional[str] = None,
        utr: Optional[str] = None,
    ) -> list[TemporalEvent]:
        """Query events with filters."""
        results = self.events

        if start:
            results = [e for e in results if e.timestamp_utc >= start]
        if end:
            results = [e for e in results if e.timestamp_utc <= end]
        if event_types:
            results = [e for e in results if e.event_type in event_types]
        if sources:
            results = [e for e in results if e.source in sources]
        if account_id:
            results = [e for e in results if e.account_id == account_id]
        if domain:
            results = [e for e in results if e.domain == domain]
        if utr:
            results = [e for e in results if e.utr == utr]

        return sorted(results, key=lambda e: e.timestamp_utc)

    def get_event_chain(self, seed_event_id: str, max_hops: int = 5, max_gap_hours: float = 24) -> list[TemporalEvent]:
        """Build causal chain from a seed event."""
        seed = self._event_index.get(seed_event_id)
        if not seed:
            return []

        chain = [seed]
        current = seed

        for _ in range(max_hops):
            # Find next event with causal correlation
            correlations = self.find_correlations(max_gap_hours=max_gap_hours)
            next_event = None

            for corr in correlations:
                if corr.event_a.event_id == current.event_id and corr.correlation_type == "CAUSAL":
                    next_event = corr.event_b
                    break

            if not next_event or next_event in chain:
                break

            chain.append(next_event)
            current = next_event

        return chain

    def export_timeline_json(self, events: Optional[list[TemporalEvent]] = None) -> str:
        """Export timeline as JSON for visualization."""
        import json

        events = events or self.events
        sorted_events = sorted(events, key=lambda e: e.timestamp_utc)

        data = {
            "generated_at": datetime.utcnow().isoformat(),
            "event_count": len(sorted_events),
            "time_range": {
                "start": sorted_events[0].timestamp_utc.isoformat() if sorted_events else None,
                "end": sorted_events[-1].timestamp_utc.isoformat() if sorted_events else None,
            },
            "events": [
                {
                    "id": e.event_id,
                    "type": e.event_type,
                    "time": e.timestamp_utc.isoformat(),
                    "time_raw": e.timestamp_raw,
                    "source": e.source,
                    "confidence_interval": e.confidence_interval_seconds,
                    "skew_correction": e.clock_skew_correction,
                    "account": e.account_id,
                    "utr": e.utr,
                    "amount": str(e.amount) if e.amount else None,
                    "domain": e.domain,
                    "ip": e.ip,
                    "metadata": e.metadata,
                }
                for e in sorted_events
            ],
        }

        return json.dumps(data, indent=2)


# Convenience function
def build_unified_timeline(
    transactions_by_account: dict[str, list],
    domain_artifacts: list = None,
    ip_artifacts: list = None,
) -> TemporalCorrelationEngine:
    """Build unified timeline from all data sources."""
    engine = TemporalCorrelationEngine()

    # Load transactions
    for account_id, txns in transactions_by_account.items():
        engine.load_from_transactions(txns, account_id)

    # Load domain artifacts
    if domain_artifacts:
        engine.load_from_domain_artifacts(domain_artifacts)

    # Auto-calibrate using UTRs
    engine.auto_calibrate()

    return engine