"""
Unified Transaction Schema (UTS v1) — NAUTILUS Core Data Model
Bank-agnostic, forensically sound, serialization-ready.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Optional
import hashlib
import json


class Channel(str, Enum):
    """Transaction channel classification."""
    NET_BANKING = "NET_BANKING"
    MOBILE_BANKING = "MOBILE_BANKING"
    UPI = "UPI"
    ATM = "ATM"
    BRANCH = "BRANCH"
    CARD = "CARD"
    IMPS = "IMPS"
    NEFT = "NEFT"
    RTGS = "RTGS"
    AUTO_DEBIT = "AUTO_DEBIT"
    INTEREST = "INTEREST"
    CHARGES = "CHARGES"
    UNKNOWN = "UNKNOWN"


class TransactionType(str, Enum):
    """High-level transaction type."""
    CREDIT = "CREDIT"
    DEBIT = "DEBIT"


@dataclass(frozen=True, slots=True)
class Counterparty:
    """Counterparty in a transaction — minimally identifying, forensically useful."""
    name: str
    account_last4: str = ""
    ifsc: str = ""
    upi_id: str = ""
    bank_name: str = ""

    def fingerprint(self) -> str:
        """Stable hash for cross-statement counterparty linking (no PII)."""
        parts = [
            self.name.strip().upper(),
            self.account_last4[-4:] if self.account_last4 else "",
            self.ifsc.strip().upper(),
            self.upi_id.strip().lower(),
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "account_last4": self.account_last4,
            "ifsc": self.ifsc,
            "upi_id": self.upi_id,
            "bank_name": self.bank_name,
            "fingerprint": self.fingerprint(),
        }


@dataclass(frozen=True, slots=True)
class UnifiedTransaction:
    """
    Universal transaction record — the atomic unit of NAUTILUS analysis.
    Every field traceable to source artifact.
    """
    # Core identifiers
    txn_id: str                    # Bank's internal transaction ID
    utr: Optional[str] = None      # Unique Transaction Reference (RBI)

    # Temporal (all normalized to UTC, original TZ preserved)
    timestamp_utc: datetime        # Normalized timestamp
    timestamp_raw: str             # Original string from statement
    tz_offset: str = "+05:30"      # Original timezone (default IST)

    # Financial
    amount: Decimal                # Signed: +credit, -debit
    balance: Decimal               # Running balance after transaction
    currency: str = "INR"

    # Counterparty & narration
    counterparty: Counterparty = field(default_factory=lambda: Counterparty(name=""))
    narration: str = ""            # Raw narration text
    narration_tags: tuple = ()     # Parsed: ("NEFT", "INWARD", "SALARY")

    # Classification
    channel: Channel = Channel.UNKNOWN
    txn_type: TransactionType = TransactionType.CREDIT

    # Metadata & provenance
    source_file: str = ""          # Originating statement file
    source_row: int = -1           # Row/line in source
    source_hash: str = ""          # SHA256 of source row for integrity
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        # Validate amount sign matches type
        if self.txn_type == TransactionType.CREDIT and self.amount < 0:
            object.__setattr__(self, 'amount', abs(self.amount))
        elif self.txn_type == TransactionType.DEBIT and self.amount > 0:
            object.__setattr__(self, 'amount', -abs(self.amount))

    @property
    def is_credit(self) -> bool:
        return self.amount > 0

    @property
    def abs_amount(self) -> Decimal:
        return abs(self.amount)

    def to_dict(self) -> dict:
        return {
            "txn_id": self.txn_id,
            "utr": self.utr,
            "timestamp_utc": self.timestamp_utc.isoformat(),
            "timestamp_raw": self.timestamp_raw,
            "tz_offset": self.tz_offset,
            "amount": str(self.amount),
            "balance": str(self.balance),
            "currency": self.currency,
            "counterparty": self.counterparty.to_dict(),
            "narration": self.narration,
            "narration_tags": list(self.narration_tags),
            "channel": self.channel.value,
            "txn_type": self.txn_type.value,
            "source_file": self.source_file,
            "source_row": self.source_row,
            "source_hash": self.source_hash,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> UnifiedTransaction:
        cp_data = data.get("counterparty", {})
        counterparty = Counterparty(
            name=cp_data.get("name", ""),
            account_last4=cp_data.get("account_last4", ""),
            ifsc=cp_data.get("ifsc", ""),
            upi_id=cp_data.get("upi_id", ""),
            bank_name=cp_data.get("bank_name", ""),
        )
        return cls(
            txn_id=data["txn_id"],
            utr=data.get("utr"),
            timestamp_utc=datetime.fromisoformat(data["timestamp_utc"]),
            timestamp_raw=data["timestamp_raw"],
            tz_offset=data.get("tz_offset", "+05:30"),
            amount=Decimal(data["amount"]),
            balance=Decimal(data["balance"]),
            currency=data.get("currency", "INR"),
            counterparty=counterparty,
            narration=data.get("narration", ""),
            narration_tags=tuple(data.get("narration_tags", [])),
            channel=Channel(data.get("channel", "UNKNOWN")),
            txn_type=TransactionType(data.get("txn_type", "CREDIT")),
            source_file=data.get("source_file", ""),
            source_row=data.get("source_row", -1),
            source_hash=data.get("source_hash", ""),
            metadata=data.get("metadata", {}),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str) -> UnifiedTransaction:
        return cls.from_dict(json.loads(json_str))


@dataclass(frozen=True, slots=True)
class AccountStatement:
    """Container for a single account's parsed statements."""
    account_id: str                # Hashed/account mask
    bank_name: str
    account_type: str              # SAVINGS, CURRENT, etc.
    currency: str = "INR"
    transactions: tuple[UnifiedTransaction, ...] = ()
    source_files: tuple[str, ...] = ()
    parse_timestamp: datetime = field(default_factory=datetime.utcnow)
    parser_version: str = "1.0.0"

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "bank_name": self.bank_name,
            "account_type": self.account_type,
            "currency": self.currency,
            "transactions": [t.to_dict() for t in self.transactions],
            "source_files": list(self.source_files),
            "parse_timestamp": self.parse_timestamp.isoformat(),
            "parser_version": self.parser_version,
        }


# UTS Version for compatibility tracking
UTS_VERSION = "1.0.0"
SCHEMA_HASH = hashlib.sha256(UTS_VERSION.encode()).hexdigest()[:8]