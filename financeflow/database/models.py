"""SQLAlchemy ORM models for FinanceFlow."""

from __future__ import annotations

import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship

from financeflow.config import DATABASE_URL


class Base(DeclarativeBase):
    pass


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_number: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    owner_name: Mapped[str] = mapped_column(String(100), nullable=False)
    balance: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    account_type: Mapped[str] = mapped_column(String(20), nullable=False)  # checking/savings/investment
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )

    transactions: Mapped[list[Transaction]] = relationship(
        "Transaction", back_populates="account", cascade="all, delete-orphan"
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "account_number": self.account_number,
            "owner_name": self.owner_name,
            "balance": self.balance,
            "account_type": self.account_type,
            "is_active": self.is_active,
        }


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("accounts.id"), nullable=False)
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False)
    tx_type: Mapped[str] = mapped_column(String(20), nullable=False)  # debit/credit
    merchant: Mapped[Optional[str]] = mapped_column(String(100))
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow
    )

    account: Mapped[Account] = relationship("Account", back_populates="transactions")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "account_id": self.account_id,
            "amount": self.amount,
            "description": self.description,
            "tx_type": self.tx_type,
            "merchant": self.merchant,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class Customer(Base):
    """Synthetic customer table with obviously-fake PII for scanner demo purposes.

    All PII here is synthetic and non-real:
    - SSNs use the 000-xx-xxxx format (area 000 is never assigned by SSA).
    - Emails use the .example RFC-reserved TLD.
    - Phone numbers use the 555-010x prefix (entertainment use only per NANP).
    - Names are clearly fictional.
    These are formatted to trigger Presidio pattern detectors for demo purposes
    while being obviously non-real to any human reviewer.
    """

    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("accounts.id"), nullable=False)
    full_name: Mapped[str] = mapped_column(String(100), nullable=False)
    # SSN format: 000-xx-xxxx — area 000 is NEVER assigned (synthetic only)
    ssn: Mapped[str] = mapped_column(String(11), nullable=False)
    # .example TLD is RFC-reserved and not a real domain
    email: Mapped[str] = mapped_column(String(150), nullable=False)
    # 555-010x prefix = NANP entertainment/fake-use reservation
    phone: Mapped[str] = mapped_column(String(20), nullable=False)
    address: Mapped[str] = mapped_column(String(255), nullable=False)
    date_of_birth: Mapped[str] = mapped_column(String(10), nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "account_id": self.account_id,
            "full_name": self.full_name,
            "ssn": self.ssn,
            "email": self.email,
            "phone": self.phone,
            "address": self.address,
            "date_of_birth": self.date_of_birth,
        }


# ── Engine + Session factory ──────────────────────────────────────────────────

_engine = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
    return _engine


def get_session() -> Session:
    from sqlalchemy.orm import sessionmaker

    engine = get_engine()
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return SessionLocal()
