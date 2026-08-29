"""Focused SQLAlchemy tests for Phase 8 security persistence models."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.models.security_identity import ImmutableSecurityRecordError, SecurityEntitlementSnapshot, SecurityOrganisation, SecurityOrganisationMembership, SecurityUser


NOW = datetime(2026, 8, 5, 21, 0, tzinfo=UTC)
TABLES = (SecurityUser.__table__, SecurityOrganisation.__table__, SecurityOrganisationMembership.__table__, SecurityEntitlementSnapshot.__table__)


@pytest.fixture
def session():
    engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record):
        cursor = connection.cursor(); cursor.execute("PRAGMA foreign_keys=ON"); cursor.close()
    Base.metadata.create_all(engine, tables=TABLES)
    value = Session(engine)
    try:
        yield value
    finally:
        value.close(); engine.dispose()


def user(**overrides):
    values = dict(id=uuid4(), email="engineer@example.com", display_name="Engineer", status="active", issuer="engineer4me", subject=str(uuid4()), created_at=NOW, updated_at=NOW)
    values.update(overrides); return SecurityUser(**values)


def organisation(**overrides):
    values = dict(id=uuid4(), slug="plant-team", name="Plant Team", status="active", created_at=NOW, updated_at=NOW)
    values.update(overrides); return SecurityOrganisation(**values)


def persist_identity(session):
    account=user(); org=organisation(); session.add_all((account,org)); session.flush(); return account,org


def test_persists_user_organisation_and_active_membership(session):
    account,org=persist_identity(session)
    membership=SecurityOrganisationMembership(id=uuid4(), user_id=account.id, organisation_id=org.id, role="engineer", status="active", joined_at=NOW, created_at=NOW, updated_at=NOW)
    session.add(membership); session.commit()
    assert session.scalar(select(SecurityOrganisationMembership)).role == "engineer"


@pytest.mark.parametrize("field,value", [("email","UPPER@example.com"),("status","unknown"),("display_name"," ")])
def test_user_database_constraints_fail_closed(session,field,value):
    account=user(**{field:value}); session.add(account)
    with pytest.raises(IntegrityError): session.commit()


def test_issuer_subject_identity_is_unique(session):
    first=user(); second=user(email="other@example.com", issuer=first.issuer, subject=first.subject); session.add_all((first,second))
    with pytest.raises(IntegrityError): session.commit()


def test_email_is_case_insensitively_unique(session):
    session.add_all((user(email="engineer@example.com"),user(email="ENGINEER@example.com")))
    with pytest.raises(IntegrityError): session.commit()


def test_organisation_slug_is_case_insensitively_unique(session):
    session.add_all((organisation(slug="plant-team"),organisation(slug="PLANT-TEAM")))
    with pytest.raises(IntegrityError): session.commit()


def test_membership_is_unique_per_user_and_organisation(session):
    account,org=persist_identity(session)
    common=dict(user_id=account.id,organisation_id=org.id,role="engineer",status="active",joined_at=NOW,created_at=NOW,updated_at=NOW)
    session.add_all((SecurityOrganisationMembership(id=uuid4(),**common),SecurityOrganisationMembership(id=uuid4(),**common)))
    with pytest.raises(IntegrityError): session.commit()


@pytest.mark.parametrize("status,joined_at", [("active",None),("invited",NOW),("suspended",NOW),("revoked",NOW)])
def test_membership_joined_state_is_enforced(session,status,joined_at):
    account,org=persist_identity(session); session.add(SecurityOrganisationMembership(id=uuid4(),user_id=account.id,organisation_id=org.id,role="engineer",status=status,joined_at=joined_at,created_at=NOW,updated_at=NOW))
    with pytest.raises(IntegrityError): session.commit()


def entitlement(org_id,**overrides):
    values=dict(id=uuid4(),organisation_id=org_id,sequence_number=1,plan_id="controlled-plan",subscription_status="active",features=["engineering_calculations"],quotas=[{"kind":"monthly_calculation_runs","limit":10}],effective_at=NOW,expires_at=NOW+timedelta(days=30),source_reference="trusted subscription record",created_at=NOW)
    values.update(overrides); return SecurityEntitlementSnapshot(**values)


def test_entitlement_snapshot_persists_json(session):
    org=organisation(); session.add(org); session.flush(); value=entitlement(org.id); session.add(value); session.commit(); stored=session.get(SecurityEntitlementSnapshot,value.id); assert stored.features == ["engineering_calculations"]; assert stored.quotas[0]["limit"] == 10


def test_entitlement_sequence_is_unique_per_organisation(session):
    org=organisation(); session.add(org); session.flush(); session.add_all((entitlement(org.id),entitlement(org.id)))
    with pytest.raises(IntegrityError): session.commit()


def test_entitlement_time_window_is_enforced(session):
    org=organisation(); session.add(org); session.flush(); session.add(entitlement(org.id,expires_at=NOW))
    with pytest.raises(IntegrityError): session.commit()


def test_entitlement_update_is_rejected_by_orm(session):
    org=organisation(); session.add(org); session.flush(); value=entitlement(org.id); session.add(value); session.commit(); value.plan_id="forged-plan"
    with pytest.raises(ImmutableSecurityRecordError): session.commit()


def test_entitlement_delete_is_rejected_by_orm(session):
    org=organisation(); session.add(org); session.flush(); value=entitlement(org.id); session.add(value); session.commit(); session.delete(value)
    with pytest.raises(ImmutableSecurityRecordError): session.commit()


def test_foreign_keys_reject_orphan_membership_and_entitlement(session):
    session.add(SecurityOrganisationMembership(id=uuid4(),user_id=uuid4(),organisation_id=uuid4(),role="engineer",status="active",joined_at=NOW,created_at=NOW,updated_at=NOW))
    with pytest.raises(IntegrityError): session.commit()
