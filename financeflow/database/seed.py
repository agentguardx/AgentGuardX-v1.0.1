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
    {"account_number": "FF-CHK-000001", "owner_name": "Alice Testsworth",
     "balance": 6_480_500.00, "account_type": "checking"},
    {"account_number": "FF-SAV-000002", "owner_name": "Bob Fakeman",
     "balance": 8_120_750.50, "account_type": "savings"},
    {"account_number": "FF-INV-000003", "owner_name": "Carol Demouser",
     "balance": 11_905_300.25, "account_type": "investment"},
    {"account_number": "FF-CHK-000004", "owner_name": "Dave Synthetic",
     "balance": 5_870_900.00, "account_type": "checking"},
    {"account_number": "FF-SAV-000005", "owner_name": "Eve Placeholder",
     "balance": 7_640_000.00, "account_type": "savings"},
    {"account_number": "FF-INV-000006", "owner_name": "Frank Mockton",
     "balance": 13_410_250.75, "account_type": "investment"},
    {"account_number": "FF-CHK-000007", "owner_name": "Grace Dummond",
     "balance": 6_150_600.00, "account_type": "checking"},
    {"account_number": "FF-SAV-000008", "owner_name": "Henry Sampleman",
     "balance": 9_780_400.50, "account_type": "savings"},
    {"account_number": "FF-INV-000009", "owner_name": "Iris Faketon",
     "balance": 12_050_900.00, "account_type": "investment"},
    {"account_number": "FF-CHK-000010", "owner_name": "Jack Testerson",
     "balance": 5_330_150.25, "account_type": "checking"},
    {"account_number": "FF-SAV-000011", "owner_name": "Karen Stubfield",
     "balance": 7_905_300.00, "account_type": "savings"},
    {"account_number": "FF-INV-000012", "owner_name": "Leo Mockingbird",
     "balance": 14_220_800.75, "account_type": "investment"},
    {"account_number": "FF-CHK-000013", "owner_name": "Mona Fixture",
     "balance": 5_640_500.00, "account_type": "checking"},
    {"account_number": "FF-SAV-000014", "owner_name": "Nate Phantomly",
     "balance": 8_350_900.50, "account_type": "savings"},
    {"account_number": "FF-INV-000015", "owner_name": "Olivia Sampleton",
     "balance": 10_770_300.00, "account_type": "investment"},
    {"account_number": "FF-CHK-000016", "owner_name": "Peter Dummigan",
     "balance": 6_910_250.25, "account_type": "checking"},
    {"account_number": "FF-SAV-000017", "owner_name": "Quinn Falsworth",
     "balance": 9_120_600.00, "account_type": "savings"},
    {"account_number": "FF-INV-000018", "owner_name": "Rita Synthwood",
     "balance": 12_980_400.75, "account_type": "investment"},
    {"account_number": "FF-CHK-000019", "owner_name": "Sam Testacre",
     "balance": 5_510_900.00, "account_type": "checking"},
    {"account_number": "FF-SAV-000020", "owner_name": "Tina Mockerly",
     "balance": 7_280_150.50, "account_type": "savings"},
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
    {
        "full_name": "Frank Mockton",
        "ssn": "000-67-8901",
        "email": "frank.mockton@demobank.example",
        "phone": "(555) 010-0006",
        "address": "6 Mock Court, Sampleton, TS 00006",
        "date_of_birth": "1982-09-30",
    },
    {
        "full_name": "Grace Dummond",
        "ssn": "000-78-9012",
        "email": "grace.dummond@demobank.example",
        "phone": "(555) 010-0007",
        "address": "7 Dummy Drive, Fixtureville, TS 00007",
        "date_of_birth": "1995-12-05",
    },
    {
        "full_name": "Henry Sampleman",
        "ssn": "000-89-0123",
        "email": "henry.sampleman@demobank.example",
        "phone": "(555) 010-0008",
        "address": "8 Sample Street, Mockford, TS 00008",
        "date_of_birth": "1970-04-18",
    },
    {
        "full_name": "Iris Faketon",
        "ssn": "000-90-1234",
        "email": "iris.faketon@demobank.example",
        "phone": "(555) 010-0009",
        "address": "9 Faux Avenue, Testburg, TS 00009",
        "date_of_birth": "1988-08-08",
    },
    {
        "full_name": "Jack Testerson",
        "ssn": "000-01-2345",
        "email": "jack.testerson@demobank.example",
        "phone": "(555) 010-0010",
        "address": "10 Tester Lane, Dummytown, TS 00010",
        "date_of_birth": "1992-01-22",
    },
    {
        "full_name": "Karen Stubfield",
        "ssn": "000-11-2233",
        "email": "karen.stubfield@demobank.example",
        "phone": "(555) 010-0011",
        "address": "11 Stub Street, Mocktown, TS 00011",
        "date_of_birth": "1983-05-19",
    },
    {
        "full_name": "Leo Mockingbird",
        "ssn": "000-22-3344",
        "email": "leo.mockingbird@demobank.example",
        "phone": "(555) 010-0012",
        "address": "12 Mocking Way, Fauxburg, TS 00012",
        "date_of_birth": "1976-10-03",
    },
    {
        "full_name": "Mona Fixture",
        "ssn": "000-33-4455",
        "email": "mona.fixture@demobank.example",
        "phone": "(555) 010-0013",
        "address": "13 Fixture Court, Testville, TS 00013",
        "date_of_birth": "1991-07-27",
    },
    {
        "full_name": "Nate Phantomly",
        "ssn": "000-44-5566",
        "email": "nate.phantomly@demobank.example",
        "phone": "(555) 010-0014",
        "address": "14 Phantom Road, Nullville, TS 00014",
        "date_of_birth": "1968-12-11",
    },
    {
        "full_name": "Olivia Sampleton",
        "ssn": "000-55-6677",
        "email": "olivia.sampleton@demobank.example",
        "phone": "(555) 010-0015",
        "address": "15 Sample Avenue, Demoland, TS 00015",
        "date_of_birth": "1994-02-09",
    },
    {
        "full_name": "Peter Dummigan",
        "ssn": "000-66-7788",
        "email": "peter.dummigan@demobank.example",
        "phone": "(555) 010-0016",
        "address": "16 Dummy Drive, Synthcity, TS 00016",
        "date_of_birth": "1980-08-23",
    },
    {
        "full_name": "Quinn Falsworth",
        "ssn": "000-77-8899",
        "email": "quinn.falsworth@demobank.example",
        "phone": "(555) 010-0017",
        "address": "17 False Lane, Sampleton, TS 00017",
        "date_of_birth": "1987-04-01",
    },
    {
        "full_name": "Rita Synthwood",
        "ssn": "000-88-9900",
        "email": "rita.synthwood@demobank.example",
        "phone": "(555) 010-0018",
        "address": "18 Synth Boulevard, Fixtureville, TS 00018",
        "date_of_birth": "1973-11-16",
    },
    {
        "full_name": "Sam Testacre",
        "ssn": "000-99-0011",
        "email": "sam.testacre@demobank.example",
        "phone": "(555) 010-0019",
        "address": "19 Testacre Trail, Mockford, TS 00019",
        "date_of_birth": "1996-09-12",
    },
    {
        "full_name": "Tina Mockerly",
        "ssn": "000-10-1122",
        "email": "tina.mockerly@demobank.example",
        "phone": "(555) 010-0020",
        "address": "20 Mockerly Mews, Testburg, TS 00020",
        "date_of_birth": "1989-06-30",
    },
]

TRANSACTION_TEMPLATES = [
    # High-value credits (these are multi-million-dollar accounts)
    ("Wire Transfer In", "credit", (50_000, 750_000)),
    ("Investment Dividend", "credit", (10_000, 180_000)),
    ("Real Estate Settlement", "credit", (200_000, 1_500_000)),
    ("Bond Maturity", "credit", (50_000, 400_000)),
    ("Quarterly Bonus", "credit", (25_000, 150_000)),
    ("ACME Corp Payroll", "credit", (8_000, 25_000)),
    # High-value debits
    ("Stock Purchase", "debit", (20_000, 500_000)),
    ("Online Transfer Out", "debit", (5_000, 300_000)),
    ("Luxury Purchase", "debit", (10_000, 250_000)),
    ("Property Tax", "debit", (5_000, 60_000)),
    ("Charitable Donation", "debit", (5_000, 100_000)),
    ("Mortgage Payment", "debit", (8_000, 45_000)),
    ("Wealth Management Fee", "debit", (2_000, 25_000)),
    ("Insurance Premium", "debit", (1_000, 15_000)),
    # Everyday activity for a lively feed
    ("Restaurant", "debit", (100, 3_000)),
    ("Utility Bill", "debit", (200, 2_000)),
    ("Online Purchase", "debit", (50, 5_000)),
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

        # Insert transactions (25–45 per account, spread over ~6 months)
        for acc in account_objs:
            n_tx = rng.randint(25, 45)
            for i in range(n_tx):
                template = rng.choice(TRANSACTION_TEMPLATES)
                desc, tx_type, (lo, hi) = template
                amount = round(rng.uniform(lo, hi), 2)
                days_ago = rng.randint(0, 180)
                ts = datetime.datetime.utcnow() - datetime.timedelta(
                    days=days_ago, hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
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
