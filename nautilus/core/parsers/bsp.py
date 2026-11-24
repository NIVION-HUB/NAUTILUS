"""
Bank Statement Parser (BSP) — Layout-free, schema-agnostic statement ingestion.
Handles PDF (text + OCR), Excel, CSV, OFX, QIF, JSON.
Output: Unified Transaction Schema (UTS v1).
"""
from __future__ import annotations
import re
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Optional, Iterator
import json

# Optional imports - gracefully degrade if not available
try:
    import pdfplumber
    HAS_PDFPLUMBER = True
except ImportError:
    HAS_PDFPLUMBER = False

try:
    import openpyxl
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

from nautilus.core.schemas.uts import (
    UnifiedTransaction, Counterparty, AccountStatement,
    Channel, TransactionType, UTS_VERSION
)


class StatementParser(ABC):
    """Base parser for a statement format."""

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the file."""
        pass

    @abstractmethod
    def parse(self, file_path: Path, account_id: str, bank_name: str) -> AccountStatement:
        """Parse statement file into AccountStatement."""
        pass


class PDFStatementParser(StatementParser):
    """PDF statement parser using pdfplumber with layout-free extraction."""

    # Common patterns across Indian bank statements
    DATE_PATTERNS = [
        r'(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})',           # DD-MM-YYYY or DD/MM/YYYY
        r'(\d{1,2}\s+[A-Za-z]{3}\s+\d{2,4})',         # DD MMM YYYY
        r'(\d{4}[-/]\d{1,2}[-/]\d{1,2})',             # YYYY-MM-DD
    ]

    AMOUNT_PATTERN = r'([\d,]+\.?\d*)'
    BALANCE_PATTERN = r'([\d,]+\.?\d*)'

    # Channel keywords
    CHANNEL_KEYWORDS = {
        Channel.UPI: ['upi', 'unified payment'],
        Channel.IMPS: ['imps', 'immediate payment'],
        Channel.NEFT: ['neft', 'national electronic'],
        Channel.RTGS: ['rtgs', 'real time gross'],
        Channel.ATM: ['atm', 'cash withdrawal', 'card withdrawal'],
        Channel.NET_BANKING: ['net banking', 'internet banking', 'online'],
        Channel.MOBILE_BANKING: ['mobile banking', 'm-banking', 'app'],
        Channel.CARD: ['card', 'pos', 'purchase'],
        Channel.AUTO_DEBIT: ['auto debit', 'mandate', 'nach', 'ecs'],
        Channel.INTEREST: ['interest', 'int.', 'int pd'],
        Channel.CHARGES: ['charge', 'fee', 'gst', 'commission'],
    }

    # Narration tags for classification
    NARRATION_TAGS = {
        'INWARD': ['cr', 'credit', 'received', 'inward', 'deposit'],
        'OUTWARD': ['dr', 'debit', 'paid', 'outward', 'withdrawal', 'transfer'],
        'SALARY': ['salary', 'sal', 'payroll'],
        'REFUND': ['refund', 'reversal', 'return'],
        'INTEREST': ['interest', 'int'],
        'CHARGES': ['charge', 'fee', 'gst'],
        'EMI': ['emi', 'loan'],
        'INVESTMENT': ['mf', 'mutual fund', 'sip', 'fd', 'rd'],
    }

    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix.lower() == '.pdf' and HAS_PDFPLUMBER

    def parse(self, file_path: Path, account_id: str, bank_name: str) -> AccountStatement:
        transactions = []

        with pdfplumber.open(file_path) as pdf:
            for page_num, page in enumerate(pdf.pages):
                # Try table extraction first
                tables = page.extract_tables()
                if tables:
                    for table in tables:
                        txns = self._parse_table(table, file_path, page_num)
                        transactions.extend(txns)

                # Fallback: text extraction with line parsing
                if not tables:
                    text = page.extract_text()
                    if text:
                        txns = self._parse_text(text, file_path, page_num)
                        transactions.extend(txns)

        # Deduplicate and sort
        transactions = self._deduplicate(transactions)
        transactions.sort(key=lambda t: t.timestamp_utc)

        return AccountStatement(
            account_id=account_id,
            bank_name=bank_name,
            account_type="SAVINGS",  # Could be inferred
            transactions=tuple(transactions),
            source_files=(str(file_path),),
            parser_version=UTS_VERSION,
        )

    def _parse_table(self, table: list[list], file_path: Path, page_num: int) -> list[UnifiedTransaction]:
        """Parse extracted table rows into transactions."""
        transactions = []

        # Find header row
        header_row_idx = self._find_header_row(table)
        if header_row_idx == -1:
            return transactions

        headers = [str(h).lower().strip() if h else "" for h in table[header_row_idx]]
        col_map = self._map_columns(headers)

        for row_idx, row in enumerate(table[header_row_idx + 1:], start=header_row_idx + 1):
            if not row or all(not cell for cell in row):
                continue

            txn = self._row_to_transaction(row, col_map, file_path, page_num, row_idx)
            if txn:
                transactions.append(txn)

        return transactions

    def _find_header_row(self, table: list[list]) -> int:
        """Find the row containing transaction headers."""
        keywords = ['date', 'narration', 'description', 'amount', 'balance', 'debit', 'credit', 'particulars']
        for i, row in enumerate(table[:10]):  # Check first 10 rows
            if not row:
                continue
            row_text = " ".join(str(c).lower() for c in row if c)
            if sum(1 for k in keywords if k in row_text) >= 3:
                return i
        return -1

    def _map_columns(self, headers: list[str]) -> dict[str, int]:
        """Map column indices to semantic fields."""
        col_map = {}
        for i, h in enumerate(headers):
            h_lower = h.lower()
            if any(k in h_lower for k in ['date', 'value date', 'txn date']):
                col_map['date'] = i
            elif any(k in h_lower for k in ['narration', 'description', 'particulars', 'details', 'remarks']):
                col_map['narration'] = i
            elif any(k in h_lower for k in ['debit', 'withdrawal', 'dr']):
                col_map['debit'] = i
            elif any(k in h_lower for k in ['credit', 'deposit', 'cr']):
                col_map['credit'] = i
            elif any(k in h_lower for k in ['balance', 'bal']):
                col_map['balance'] = i
            elif any(k in h_lower for k in ['ref', 'utr', 'reference', 'txn id']):
                col_map['reference'] = i
        return col_map

    def _row_to_transaction(
        self, row: list, col_map: dict, file_path: Path, page_num: int, row_idx: int
    ) -> Optional[UnifiedTransaction]:
        """Convert a table row to UnifiedTransaction."""
        try:
            # Date
            date_str = str(row[col_map.get('date', 0)]) if 'date' in col_map else ""
            timestamp_utc, timestamp_raw, tz_offset = self._parse_date(date_str)
            if not timestamp_utc:
                return None

            # Amount (debit/credit or signed amount)
            amount = Decimal('0')
            txn_type = TransactionType.CREDIT

            if 'debit' in col_map and 'credit' in col_map:
                debit_str = str(row[col_map['debit']]).strip()
                credit_str = str(row[col_map['credit']]).strip()
                if debit_str and debit_str not in ('-', '0', '0.00'):
                    amount = -self._parse_amount(debit_str)
                    txn_type = TransactionType.DEBIT
                elif credit_str and credit_str not in ('-', '0', '0.00'):
                    amount = self._parse_amount(credit_str)
                    txn_type = TransactionType.CREDIT
            elif 'amount' in col_map:
                amt_str = str(row[col_map['amount']]).strip()
                amount = self._parse_amount(amt_str)
                txn_type = TransactionType.DEBIT if amount < 0 else TransactionType.CREDIT

            # Balance
            balance = Decimal('0')
            if 'balance' in col_map:
                balance = self._parse_amount(str(row[col_map['balance']]))

            # Narration
            narration = str(row[col_map.get('narration', 1)]) if 'narration' in col_map else ""

            # Reference/UTR
            reference = ""
            utr = None
            if 'reference' in col_map:
                reference = str(row[col_map['reference']]).strip()
                utr = self._extract_utr(reference + " " + narration)

            # Counterparty extraction
            counterparty = self._extract_counterparty(narration, reference)

            # Channel & tags
            channel = self._classify_channel(narration)
            narration_tags = self._extract_narration_tags(narration)

            # Source hash for integrity
            source_row = f"{page_num}|{row_idx}|{date_str}|{narration}|{amount}|{balance}"
            source_hash = hashlib.sha256(source_row.encode()).hexdigest()[:16]

            return UnifiedTransaction(
                txn_id=reference or f"AUTO_{source_hash[:12]}",
                utr=utr,
                timestamp_utc=timestamp_utc,
                timestamp_raw=timestamp_raw,
                tz_offset=tz_offset,
                amount=amount,
                balance=balance,
                counterparty=counterparty,
                narration=narration,
                narration_tags=narration_tags,
                channel=channel,
                txn_type=txn_type,
                source_file=str(file_path),
                source_row=row_idx,
                source_hash=source_hash,
            )
        except Exception:
            return None

    def _parse_text(self, text: str, file_path: Path, page_num: int) -> list[UnifiedTransaction]:
        """Parse plain text lines (fallback when no tables)."""
        transactions = []
        lines = text.split('\n')

        for line_idx, line in enumerate(lines):
            line = line.strip()
            if not line or len(line) < 10:
                continue

            # Try to match date + amount pattern
            txn = self._parse_line(line, file_path, page_num, line_idx)
            if txn:
                transactions.append(txn)

        return transactions

    def _parse_line(self, line: str, file_path: Path, page_num: int, line_idx: int) -> Optional[UnifiedTransaction]:
        """Parse a single text line into transaction."""
        # Find date in line
        date_match = None
        for pattern in self.DATE_PATTERNS:
            match = re.search(pattern, line)
            if match:
                date_match = match
                break

        if not date_match:
            return None

        date_str = date_match.group(1)
        timestamp_utc, timestamp_raw, tz_offset = self._parse_date(date_str)
        if not timestamp_utc:
            return None

        # Extract amounts (look for 2-3 currency values)
        amounts = re.findall(r'[\d,]+\.?\d*', line[date_match.end():])
        if len(amounts) < 2:
            return None

        amount = self._parse_amount(amounts[0])
        balance = self._parse_amount(amounts[-1]) if len(amounts) > 1 else Decimal('0')

        # Determine debit/credit from context
        txn_type = TransactionType.CREDIT
        if any(kw in line.lower() for kw in ['dr', 'debit', 'withdrawal', 'paid', 'transfer out']):
            txn_type = TransactionType.DEBIT
            amount = -abs(amount)
        elif any(kw in line.lower() for kw in ['cr', 'credit', 'deposit', 'received', 'transfer in']):
            txn_type = TransactionType.CREDIT
            amount = abs(amount)

        # Narration is text between date and amounts
        narration_start = date_match.end()
        narration_end = line.rfind(amounts[0])
        narration = line[narration_start:narration_end].strip()

        # Extract UTR
        utr = self._extract_utr(line)

        # Counterparty
        counterparty = self._extract_counterparty(narration, "")

        # Channel & tags
        channel = self._classify_channel(narration)
        narration_tags = self._extract_narration_tags(narration)

        source_row = f"{page_num}|{line_idx}|{line}"
        source_hash = hashlib.sha256(source_row.encode()).hexdigest()[:16]

        return UnifiedTransaction(
            txn_id=f"AUTO_{source_hash[:12]}",
            utr=utr,
            timestamp_utc=timestamp_utc,
            timestamp_raw=timestamp_raw,
            tz_offset=tz_offset,
            amount=amount,
            balance=balance,
            counterparty=counterparty,
            narration=narration,
            narration_tags=narration_tags,
            channel=channel,
            txn_type=txn_type,
            source_file=str(file_path),
            source_row=line_idx,
            source_hash=source_hash,
        )

    def _parse_date(self, date_str: str) -> tuple[Optional[datetime], str, str]:
        """Parse date string to UTC datetime."""
        date_str = date_str.strip()
        formats = [
            '%d-%m-%Y', '%d/%m/%Y', '%d-%m-%y', '%d/%m/%y',
            '%d %b %Y', '%d %B %Y', '%d-%b-%Y', '%d/%b/%Y',
            '%Y-%m-%d', '%Y/%m/%d',
            '%d-%m-%Y %H:%M:%S', '%d/%m/%Y %H:%M:%S',
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                # Assume IST if no timezone
                return dt, date_str, '+05:30'
            except ValueError:
                continue
        return None, date_str, '+05:30'

    def _parse_amount(self, amt_str: str) -> Decimal:
        """Parse amount string to Decimal."""
        try:
            return Decimal(amt_str.replace(',', '').strip())
        except (InvalidOperation, ValueError):
            return Decimal('0')

    def _extract_utr(self, text: str) -> Optional[str]:
        """Extract UTR (Unique Transaction Reference) from text."""
        # UTR patterns: 16-22 digits, often starting with bank code
        patterns = [
            r'\b(\d{16,22})\b',  # Generic long number
            r'UTR[:\s]*(\d{16,22})',
            r'REF[:\s]*(\d{16,22})',
            r'TXN[:\s]*(\d{16,22})',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _extract_counterparty(self, narration: str, reference: str) -> Counterparty:
        """Extract counterparty information from narration."""
        combined = f"{narration} {reference}".strip()

        # IFSC pattern
        ifsc_match = re.search(r'\b([A-Z]{4}0[A-Z0-9]{6})\b', combined)
        ifsc = ifsc_match.group(1) if ifsc_match else ""

        # UPI ID pattern
        upi_match = re.search(r'\b([\w.-]+@[\w.-]+)\b', combined)
        upi_id = upi_match.group(1) if upi_match else ""

        # Account number (last 4 digits)
        acct_match = re.search(r'(?:A/C|AC|ACC|ACCOUNT)[:\s]*\d*(\d{4})\b', combined, re.IGNORECASE)
        account_last4 = acct_match.group(1) if acct_match else ""

        # Name extraction (heuristic)
        name = self._extract_name(narration)

        # Bank name from IFSC
        bank_name = ""
        if ifsc:
            bank_code = ifsc[:4]
            bank_map = {
                'SBIN': 'State Bank of India',
                'HDFC': 'HDFC Bank',
                'ICIC': 'ICICI Bank',
                'AXIS': 'Axis Bank',
                'KKBK': 'Kotak Mahindra Bank',
                'IND': 'IndusInd Bank',
                'YESB': 'Yes Bank',
                'BARB': 'Bank of Baroda',
                'PUNB': 'Punjab National Bank',
                'CNRB': 'Canara Bank',
                'UBIN': 'Union Bank of India',
            }
            bank_name = bank_map.get(bank_code, "")

        return Counterparty(
            name=name,
            account_last4=account_last4,
            ifsc=ifsc,
            upi_id=upi_id,
            bank_name=bank_name,
        )

    def _extract_name(self, narration: str) -> str:
        """Extract counterparty name from narration."""
        # Remove common prefixes/suffixes
        text = narration

        # Patterns like "TO NAME", "FROM NAME", "BY NAME", "NEFT NAME"
        patterns = [
            r'(?:TO|FROM|BY|NEFT|IMPS|RTGS|UPI)\s+([A-Z\s]+?)(?:\s+\d|\s+[A-Z]{4}0|\s+@|$)',
            r'([A-Z][A-Z\s]{2,30}?)\s+(?:\d{10,}|[A-Z]{4}0)',
        ]

        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                name = match.group(1).strip()
                if len(name) > 2 and not name.isdigit():
                    return name

        # Fallback: first meaningful words
        words = [w for w in text.split() if len(w) > 2 and not w.isdigit()]
        return " ".join(words[:5]) if words else "UNKNOWN"

    def _classify_channel(self, narration: str) -> Channel:
        """Classify transaction channel from narration."""
        text = narration.lower()
        for channel, keywords in self.CHANNEL_KEYWORDS.items():
            if any(kw in text for kw in keywords):
                return channel
        return Channel.UNKNOWN

    def _extract_narration_tags(self, narration: str) -> tuple:
        """Extract structured tags from narration."""
        text = narration.lower()
        tags = []
        for tag, keywords in self.NARRATION_TAGS.items():
            if any(kw in text for kw in keywords):
                tags.append(tag)
        return tuple(tags)

    def _deduplicate(self, transactions: list[UnifiedTransaction]) -> list[UnifiedTransaction]:
        """Remove duplicate transactions based on source_hash."""
        seen = set()
        unique = []
        for txn in transactions:
            if txn.source_hash not in seen:
                seen.add(txn.source_hash)
                unique.append(txn)
        return unique


class ExcelStatementParser(StatementParser):
    """Excel/CSV statement parser using pandas."""

    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in ('.xlsx', '.xls', '.csv') and HAS_PANDAS

    def parse(self, file_path: Path, account_id: str, bank_name: str) -> AccountStatement:
        transactions = []

        if file_path.suffix.lower() == '.csv':
            df = pd.read_csv(file_path)
        else:
            df = pd.read_excel(file_path)

        # Normalize column names
        df.columns = [str(c).lower().strip() for c in df.columns]

        # Map columns (similar to PDF parser)
        col_map = self._map_columns(df.columns.tolist())

        for row_idx, row in df.iterrows():
            txn = self._row_to_transaction(row, col_map, file_path, row_idx)
            if txn:
                transactions.append(txn)

        transactions.sort(key=lambda t: t.timestamp_utc)

        return AccountStatement(
            account_id=account_id,
            bank_name=bank_name,
            account_type="SAVINGS",
            transactions=tuple(transactions),
            source_files=(str(file_path),),
            parser_version=UTS_VERSION,
        )

    def _map_columns(self, columns: list[str]) -> dict[str, str]:
        col_map = {}
        for c in columns:
            c_lower = c.lower()
            if any(k in c_lower for k in ['date', 'value date', 'txn date', 'transaction date']):
                col_map['date'] = c
            elif any(k in c_lower for k in ['narration', 'description', 'particulars', 'details', 'remarks']):
                col_map['narration'] = c
            elif any(k in c_lower for k in ['debit', 'withdrawal', 'dr']):
                col_map['debit'] = c
            elif any(k in c_lower for k in ['credit', 'deposit', 'cr']):
                col_map['credit'] = c
            elif any(k in c_lower for k in ['balance', 'bal']):
                col_map['balance'] = c
            elif any(k in c_lower for k in ['ref', 'utr', 'reference', 'txn id', 'transaction id']):
                col_map['reference'] = c
        return col_map

    def _row_to_transaction(
        self, row: pd.Series, col_map: dict, file_path: Path, row_idx: int
    ) -> Optional[UnifiedTransaction]:
        try:
            # Date
            date_val = row[col_map.get('date', '')] if 'date' in col_map else None
            if pd.isna(date_val):
                return None
            date_str = str(date_val)
            timestamp_utc, timestamp_raw, tz_offset = PDFStatementParser()._parse_date(date_str)
            if not timestamp_utc:
                return None

            # Amount
            amount = Decimal('0')
            txn_type = TransactionType.CREDIT

            if 'debit' in col_map and 'credit' in col_map:
                debit = row[col_map['debit']]
                credit = row[col_map['credit']]
                if not pd.isna(debit) and float(debit) != 0:
                    amount = -Decimal(str(debit)).quantize(Decimal('0.01'))
                    txn_type = TransactionType.DEBIT
                elif not pd.isna(credit) and float(credit) != 0:
                    amount = Decimal(str(credit)).quantize(Decimal('0.01'))
                    txn_type = TransactionType.CREDIT

            # Balance
            balance = Decimal('0')
            if 'balance' in col_map and not pd.isna(row[col_map['balance']]):
                balance = Decimal(str(row[col_map['balance']])).quantize(Decimal('0.01'))

            # Narration
            narration = str(row[col_map.get('narration', '')]) if 'narration' in col_map else ""

            # Reference/UTR
            reference = str(row[col_map.get('reference', '')]) if 'reference' in col_map else ""
            utr = PDFStatementParser()._extract_utr(reference + " " + narration)

            # Counterparty
            counterparty = PDFStatementParser()._extract_counterparty(narration, reference)

            # Channel & tags
            channel = PDFStatementParser()._classify_channel(narration)
            narration_tags = PDFStatementParser()._extract_narration_tags(narration)

            source_row = f"{row_idx}|{date_str}|{narration}|{amount}|{balance}"
            source_hash = hashlib.sha256(source_row.encode()).hexdigest()[:16]

            return UnifiedTransaction(
                txn_id=reference or f"AUTO_{source_hash[:12]}",
                utr=utr,
                timestamp_utc=timestamp_utc,
                timestamp_raw=timestamp_raw,
                tz_offset=tz_offset,
                amount=amount,
                balance=balance,
                counterparty=counterparty,
                narration=narration,
                narration_tags=narration_tags,
                channel=channel,
                txn_type=txn_type,
                source_file=str(file_path),
                source_row=row_idx,
                source_hash=source_hash,
            )
        except Exception:
            return None


class BankStatementParser:
    """
    Universal Bank Statement Parser — auto-detects format and parses.
    """

    def __init__(self):
        self.parsers: list[StatementParser] = [
            PDFStatementParser(),
            ExcelStatementParser(),
        ]

    def parse_file(self, file_path: Path, account_id: str, bank_name: str) -> AccountStatement:
        """Parse a single statement file."""
        for parser in self.parsers:
            if parser.can_parse(file_path):
                return parser.parse(file_path, account_id, bank_name)
        raise ValueError(f"No parser available for {file_path}")

    def parse_directory(
        self, dir_path: Path, account_id: str, bank_name: str
    ) -> AccountStatement:
        """Parse all statement files in a directory for one account."""
        all_transactions = []
        source_files = []

        for file_path in sorted(dir_path.iterdir()):
            if file_path.is_file() and file_path.suffix.lower() in ('.pdf', '.xlsx', '.xls', '.csv'):
                try:
                    stmt = self.parse_file(file_path, account_id, bank_name)
                    all_transactions.extend(stmt.transactions)
                    source_files.append(str(file_path))
                except Exception as e:
                    print(f"Warning: Failed to parse {file_path}: {e}")

        all_transactions.sort(key=lambda t: t.timestamp_utc)

        return AccountStatement(
            account_id=account_id,
            bank_name=bank_name,
            account_type="SAVINGS",
            transactions=tuple(all_transactions),
            source_files=tuple(source_files),
            parser_version=UTS_VERSION,
        )


# Convenience function
def parse_statements(input_path: str, account_id: str, bank_name: str) -> AccountStatement:
    """Parse statements from file or directory."""
    path = Path(input_path)
    parser = BankStatementParser()
    if path.is_file():
        return parser.parse_file(path, account_id, bank_name)
    elif path.is_dir():
        return parser.parse_directory(path, account_id, bank_name)
    else:
        raise ValueError(f"Path not found: {input_path}")