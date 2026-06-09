"""Seed FinanceFlow SQLite database with synthetic data.

ALL PII here is entirely fictional:
- SSNs: 000-xx-xxxx series (SSA area 000 never assigned)
- Names: invented, non-real individuals
- Emails: @demobank.example (.example is RFC-reserved, not a real domain)
- Phone: 555-010x (NANP entertainment placeholder range)
- Addresses: fictional street numbers + "Testville, TS 00000"
- Credit cards: well-known Luhn-valid test numbers (not real cards)

This data exists solely to give Presidio and AgentGuard-X PII detectors
something to find during the demo without any real personal data existing
anywhere in the system.
"""

from __future__ import annotations

import datetime
import random
import sys

from sqlalchemy.exc import IntegrityError

from financeflow.database.models import Account, Base, Customer, Transaction, get_engine


SYNTHETIC_ACCOUNTS = [
    {
        "account_number": "FF-CHK-000001",
        "owner_name": "Alice Testsworth",
        "balance": 42_850.00,
        "account_type": "checking",
    },
    {
        "account_number": "FF-SAV-000002",
        "owner_name": "Bob Fakeman",
        "balance": 128_300.50,
        "account_type": "savings",
    },
    {
        "account_number": "FF-INV-000003",
        "owner_name": "Carol Demouser",
        "balance": 501_750.25,
        "account_type": "investment",
    },
    {
        "account_number": "FF-CHK-000004",
        "owner_name": "Dave Synthetic",
        "balance": 9_980.00,
        "account_type": "checking",
    },
    {
        "account_number": "FF-SAV-000005",
        "owner_name": "Eve Placeholder",
        "balance": 75_000.00,
        "account_type": "savings",
    },
]

# PII: synthetic only — see module docstring
SYNTHETIC_CUSTOMERS = [
    {
        "full_name": "Alice Testsworth",
        "ssn": "000-12-3456",          # area 000 never assigned
        "email": "alice.testsworth@demobank.example",
        "phone": "(555) 010-0001",      # NANP entertainment range
        "address": "1 Test Street, Testville, TS 00001",
        "date_of_birth": "1985-03-15",
    },
    {
        "full_name": "Bob Fakeman",
        "ssn": "000-23-4567",
        "email": "bob.fakeman@demobank.example",
        "phone": "(555) 010-0002",
        "address": "2 Fake Avenue, Faketown, TS 00002",
        "date_of_birth": "1978-07-22",
    },
    {
        "full_name": "Carol Demouser",
        "ssn": "000-34-5678",
        "email": "carol.demouser@demobank.example",
        "phone": "(555) 010-0003",
        "address": "3 Demo Boulevard, Demoland, TS 00003",
        "date_of_birth": "1990-11-08",
    },
    {
        "full_name": "Dave Synthetic",
        "ssn": "000-45-6789",
        "email": "dave.synthetic@demobank.example",
        "phone": "(555) 010-0004",
        "address": "4 Synthetic Lane, Synthcity, TS 00004",
        "date_of_birth": "1965-02-28",
    },
    {
        "full_name": "Eve Placeholder",
        "ssn": "000-56-7890",
        "email": "eve.placeholder@demobank.example",
        "phone": "(555) 010-0005",
        "address": "5 Placeholder Road, Nullville, TS 00005",
        "date_of_birth": "2000-06-14",
    },
]

TRANSACTION_TEMPLATES = [
    ("ACME Corp Payroll", "credit", (2000, 8000)),
    ("Grocery Store", "debit", (20, 300)),
    ("Utility Bill", "debit", (50, 250)),
    ("ATM Withdrawal", "debit", (20, 500)),
    ("Online Transfer In", "credit", (100, 5000)),
    ("Coffee Shop", "debit", (3, 15)),
    ("Gas Station", "debit", (30, 80)),
    ("Restaurant", "debit", (15, 120)),
    ("Amazon Purchase", "debit", (10, 500)),
    ("Insurance Premium", "debit", (100, 400)),
]


def seed(drop_existing: bool = False) -> None:
    engine = get_engine()

    if drop_existing:
        Base.metadata.drop_all(engine)

    Base.metadata.create_all(engine)

    from sqlalchemy.orm import sessionmaker
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = SessionLocal()

    try:
        # Skip if already seeded
        if session.query(Account).count() > 0:
            print("[seed] Database already seeded — skipping.")
            return

        rng = random.Random(42)  # deterministic seed for reproducibility

        # Insert accounts
        account_objs: list[Account] = []
        for acc_data in SYNTHETIC_ACCOUNTS:
            acc = Account(**acc_data)
            session.add(acc)
            account_objs.append(acc)
        session.flush()

        # Insert transactions (10–20 per account)
        for acc in account_objs:
            n_tx = rng.randint(10, 20)
            for i in range(n_tx):
                template = rng.choice(TRANSACTION_TEMPLATES)
                desc, tx_type, (lo, hi) = template
                amount = round(rng.uniform(lo, hi), 2)
                days_ago = rng.randint(0, 90)
                ts = datetime.datetime.utcnow() - datetime.timedelta(days=days_ago)
                tx = Transaction(
                    account_id=acc.id,
                    amount=amount,
                    description=desc,
                    tx_type=tx_type,
                    merchant=desc.split()[0],
                    timestamp=ts,
                )
                session.add(tx)

        # Insert customers (one per account)
        for acc, cust_data in zip(account_objs, SYNTHETIC_CUSTOMERS):
            cust = Customer(account_id=acc.id, **cust_data)
            session.add(cust)

        session.commit()
        print(f"[seed] Seeded {len(account_objs)} accounts, customers, and transactions.")

    except IntegrityError as e:
        session.rollback()
        print(f"[seed] IntegrityError (already seeded?): {e}")
    except Exception as e:
        session.rollback()
        print(f"[seed] Error during seed: {e}", file=sys.stderr)
        raise
    finally:
        session.close()


if __name__ == "__main__":
    seed()
    print("[seed] Done.")
