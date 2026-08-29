"""Transactionally read-only operational readiness preflight for bootstrap."""

from __future__ import annotations

import os

from sqlalchemy import create_engine, inspect, text


PHASE8_HEAD = "d9a137b5e6f7"
SECURITY_TABLES = (
    "security_users",
    "security_organisations",
    "security_organisation_memberships",
    "security_entitlement_snapshots",
    "security_audit_events",
)
REQUIRED_TRIGGERS = {
    ("security_entitlement_snapshots", "trg_security_entitlement_snapshots_append_only"),
    ("security_audit_events", "trg_security_audit_events_append_only"),
}


def main() -> None:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            connection.execute(text("SET TRANSACTION READ ONLY"))
            if connection.scalar(text("SHOW transaction_read_only")) != "on":
                raise AssertionError("operational preflight transaction is not read-only")
            schema = connection.scalar(text("SELECT current_schema()"))
            if schema != "public":
                raise AssertionError("operational bootstrap preflight must target the public schema")
            revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
            if revision != PHASE8_HEAD:
                raise AssertionError(f"operational bootstrap preflight expected {PHASE8_HEAD}; found {revision}")
            tables = set(inspect(connection).get_table_names(schema="public"))
            missing_tables = set(SECURITY_TABLES) - tables
            if missing_tables:
                raise AssertionError(f"operational security tables are missing: {sorted(missing_tables)}")
            trigger_rows = set(
                connection.execute(
                    text(
                        "SELECT c.relname,t.tgname FROM pg_trigger t "
                        "JOIN pg_class c ON c.oid=t.tgrelid "
                        "JOIN pg_namespace n ON n.oid=c.relnamespace "
                        "WHERE n.nspname='public' AND NOT t.tgisinternal"
                    )
                ).tuples()
            )
            missing_triggers = REQUIRED_TRIGGERS - trigger_rows
            if missing_triggers:
                raise AssertionError(f"operational append-only triggers are missing: {sorted(missing_triggers)}")
            counts = {
                table: connection.scalar(text(f'SELECT count(*) FROM "{table}"'))
                for table in SECURITY_TABLES
            }
            occupied = {table: count for table, count in counts.items() if count != 0}
            if occupied:
                raise AssertionError(f"operational security domain is not empty: {occupied}")
        print("Operational schema: public")
        print(f"Migration revision: {PHASE8_HEAD}")
        print("Transaction mode: read-only verified")
        print("Security tables: 5 verified")
        print("Append-only triggers: entitlement and audit verified")
        print("Security domain rows: exactly 0 across all 5 tables")
        print("Bootstrap readiness snapshot: accepted")
        print("Execution safety: atomic executor will recheck emptiness at execution time")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
