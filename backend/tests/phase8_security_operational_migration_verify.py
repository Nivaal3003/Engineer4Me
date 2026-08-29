"""Read-only preflight and postflight checks for the operational Phase 8 migration."""

from __future__ import annotations

import argparse
import os

from sqlalchemy import create_engine, inspect, text


PRE_PHASE8_REVISION = "b7f110e3d2a1"
FOUNDATION_REVISION = "c8f123a4d5e6"
PHASE8_HEAD = "d9a137b5e6f7"
SECURITY_TABLES = {
    "security_users",
    "security_organisations",
    "security_organisation_memberships",
    "security_entitlement_snapshots",
    "security_audit_events",
}
TRIGGERS = {
    ("security_entitlement_snapshots", "trg_security_entitlement_snapshots_append_only"),
    ("security_audit_events", "trg_security_audit_events_append_only"),
}


def revision(connection) -> str:
    value = connection.scalar(text("SELECT version_num FROM alembic_version"))
    if not isinstance(value, str):
        raise AssertionError("operational migration revision is unavailable")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("status", "preflight", "foundation", "postflight"))
    args = parser.parse_args()
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            schema = connection.scalar(text("SELECT current_schema()"))
            if schema != "public":
                raise AssertionError(f"operational schema must be public; found {schema!r}")
            current = revision(connection)
            tables = set(inspect(connection).get_table_names(schema="public"))
            present = SECURITY_TABLES & tables
            if args.mode == "status":
                print("Operational schema: public")
                print(f"Current revision: {current}")
                print(f"Security tables present: {len(present)}")
                return
            if args.mode == "preflight":
                if current != PRE_PHASE8_REVISION:
                    raise AssertionError(f"operational preflight expected {PRE_PHASE8_REVISION}; found {current}")
                if present:
                    raise AssertionError(f"Phase 8 security tables already exist before migration: {sorted(present)}")
                print("Operational schema: public")
                print(f"Preflight revision: {current}")
                print("Phase 8 security tables before upgrade: none")
                print("Preflight: accepted")
                return
            if args.mode == "foundation":
                expected = SECURITY_TABLES - {"security_audit_events"}
                if current != FOUNDATION_REVISION:
                    raise AssertionError(f"operational foundation expected {FOUNDATION_REVISION}; found {current}")
                if present != expected:
                    raise AssertionError(f"operational foundation table set is invalid: {sorted(present)}")
                trigger_count = connection.scalar(
                    text(
                        "SELECT count(*) FROM pg_trigger t "
                        "JOIN pg_class c ON c.oid=t.tgrelid "
                        "JOIN pg_namespace n ON n.oid=c.relnamespace "
                        "WHERE n.nspname='public' "
                        "AND c.relname='security_entitlement_snapshots' "
                        "AND t.tgname='trg_security_entitlement_snapshots_append_only' "
                        "AND NOT t.tgisinternal"
                    )
                )
                if trigger_count != 1:
                    raise AssertionError("operational foundation entitlement trigger is missing")
                print("Operational schema: public")
                print(f"Foundation revision: {current}")
                print("Foundation security tables: 4 verified")
                print("Entitlement append-only trigger: verified")
                print("Foundation recovery state: accepted")
                return
            if current != PHASE8_HEAD:
                raise AssertionError(f"operational postflight expected {PHASE8_HEAD}; found {current}")
            missing = SECURITY_TABLES - tables
            if missing:
                raise AssertionError(f"Phase 8 security tables are missing: {sorted(missing)}")
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
            missing_triggers = TRIGGERS - trigger_rows
            if missing_triggers:
                raise AssertionError(f"Phase 8 append-only triggers are missing: {sorted(missing_triggers)}")
            print("Operational schema: public")
            print(f"Postflight revision: {current}")
            print("Security tables: 5 verified")
            print("Append-only triggers: entitlement and audit verified")
            print("Security seed rows created by verifier: none")
            print("Postflight: accepted")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
