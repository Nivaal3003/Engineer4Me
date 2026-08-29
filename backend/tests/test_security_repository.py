"""Focused tenant and entitlement repository tests."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.models.security_identity import SecurityEntitlementSnapshot, SecurityOrganisation, SecurityOrganisationMembership, SecurityUser
from app.repositories.security_repository import SecurityPersistenceConflictError, SecurityRepository
from app.security.entitlements import ControlledFeature, OrganisationEntitlementSnapshot, QuotaGrant, QuotaKind, SubscriptionStatus
from app.security.identity_models import IdentityStatus, MembershipStatus, OrganisationRole


NOW = datetime(2026, 8, 5, 22, 0, tzinfo=UTC)
TABLES=(SecurityUser.__table__,SecurityOrganisation.__table__,SecurityOrganisationMembership.__table__,SecurityEntitlementSnapshot.__table__)


@pytest.fixture
def repository():
    engine=create_engine("sqlite+pysqlite:///:memory:",connect_args={"check_same_thread":False},poolclass=StaticPool)
    @event.listens_for(engine,"connect")
    def foreign_keys(connection,_record):
        cursor=connection.cursor();cursor.execute("PRAGMA foreign_keys=ON");cursor.close()
    Base.metadata.create_all(engine,tables=TABLES);session=Session(engine)
    try: yield SecurityRepository(session),session
    finally: session.close();engine.dispose()


def user(**overrides):
    values=dict(id=uuid4(),email="engineer@example.com",display_name="Engineer",status="active",issuer="engineer4me",subject=str(uuid4()),created_at=NOW,updated_at=NOW);values.update(overrides);return SecurityUser(**values)


def organisation(**overrides):
    values=dict(id=uuid4(),slug="plant-team",name="Plant Team",status="active",created_at=NOW,updated_at=NOW);values.update(overrides);return SecurityOrganisation(**values)


def seeded(repository):
    repo,session=repository;account=repo.add_user(user());org=repo.add_organisation(organisation());membership=repo.add_membership(SecurityOrganisationMembership(id=uuid4(),user_id=account.id,organisation_id=org.id,role="engineer",status="active",joined_at=NOW,created_at=NOW,updated_at=NOW));session.commit();return repo,session,account,org,membership


def entitlement(org_id, *, snapshot_id=None, plan_id="controlled-plan", status=SubscriptionStatus.ACTIVE, effective_at=NOW-timedelta(days=1), expires_at=NOW+timedelta(days=30)):
    return OrganisationEntitlementSnapshot(snapshot_id=snapshot_id or uuid4(),organisation_id=org_id,plan_id=plan_id,subscription_status=status,features=(ControlledFeature.ENGINEERING_CALCULATIONS,),quotas=(QuotaGrant(kind=QuotaKind.MONTHLY_CALCULATION_RUNS,limit=10),),effective_at=effective_at,expires_at=expires_at,source_reference="trusted subscription record")


def test_external_identity_lookup_is_exact(repository):
    repo,session,account,_,_=seeded(repository)
    assert repo.user_by_external_identity(issuer=account.issuer,subject=account.subject).id == account.id
    assert repo.user_by_external_identity(issuer="other",subject=account.subject) is None


def test_membership_lookup_requires_both_user_and_organisation(repository):
    repo,_,account,org,membership=seeded(repository)
    assert repo.membership(user_id=account.id,organisation_id=org.id).id == membership.id
    assert repo.membership(user_id=account.id,organisation_id=uuid4()) is None
    assert repo.membership(user_id=uuid4(),organisation_id=org.id) is None


def test_active_membership_returns_typed_contract(repository):
    repo,_,account,org,membership=seeded(repository);result=repo.active_membership_contract(user_id=account.id,organisation_id=org.id)
    assert result.membership_id == membership.id
    assert result.status is MembershipStatus.ACTIVE
    assert result.role is OrganisationRole.ENGINEER


@pytest.mark.parametrize("status",["invited","suspended","revoked"])
def test_inactive_membership_fails_closed(repository,status):
    repo,session=repository;account=repo.add_user(user());org=repo.add_organisation(organisation());repo.add_membership(SecurityOrganisationMembership(id=uuid4(),user_id=account.id,organisation_id=org.id,role="engineer",status=status,joined_at=None,created_at=NOW,updated_at=NOW));session.commit()
    assert repo.active_membership_contract(user_id=account.id,organisation_id=org.id) is None


def test_duplicate_external_identity_translates_conflict(repository):
    repo,_=repository;first=user();repo.add_user(first)
    with pytest.raises(SecurityPersistenceConflictError): repo.add_user(user(email="other@example.com",issuer=first.issuer,subject=first.subject))


def test_duplicate_membership_translates_conflict(repository):
    repo,_,account,org,_=seeded(repository);common=dict(user_id=account.id,organisation_id=org.id,role="read_only",status="active",joined_at=NOW,created_at=NOW,updated_at=NOW)
    with pytest.raises(SecurityPersistenceConflictError): repo.add_membership(SecurityOrganisationMembership(id=uuid4(),**common))


def test_entitlement_append_assigns_monotonic_sequence(repository):
    repo,session,_,org,_=seeded(repository);first=repo.append_entitlement(entitlement(org.id));second=repo.append_entitlement(entitlement(org.id,plan_id="controlled-plan-v2"));session.commit()
    assert first.sequence_number == 1
    assert second.sequence_number == 2


def test_current_entitlement_returns_latest_effective_snapshot(repository):
    repo,session,_,org,_=seeded(repository);repo.append_entitlement(entitlement(org.id,plan_id="old-plan"));repo.append_entitlement(entitlement(org.id,plan_id="new-plan"));session.commit()
    assert repo.current_entitlement(organisation_id=org.id,effective_at=NOW).plan_id == "new-plan"


def test_current_entitlement_does_not_cross_tenants(repository):
    repo,session,_,org,_=seeded(repository);repo.append_entitlement(entitlement(org.id));session.commit()
    assert repo.current_entitlement(organisation_id=uuid4(),effective_at=NOW) is None


def test_future_and_expired_entitlements_are_not_current(repository):
    repo,session,_,org,_=seeded(repository);repo.append_entitlement(entitlement(org.id,effective_at=NOW+timedelta(days=1),expires_at=NOW+timedelta(days=2)));session.commit()
    assert repo.current_entitlement(organisation_id=org.id,effective_at=NOW) is None


def test_entitlement_round_trip_preserves_features_and_quotas(repository):
    repo,session,_,org,_=seeded(repository);source=entitlement(org.id);repo.append_entitlement(source);session.commit();result=repo.current_entitlement(organisation_id=org.id,effective_at=NOW)
    assert result.features == source.features
    assert result.quotas == source.quotas


def test_identity_status_is_typed_and_missing_identity_returns_none(repository):
    repo,_,account,_,_=seeded(repository)
    assert repo.identity_status(account.id) is IdentityStatus.ACTIVE
    assert repo.identity_status(uuid4()) is None
