"""Isolated PostgreSQL proof for the reviewed authenticated access boundary."""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar
from uuid import UUID, uuid4, uuid5

import jwt
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.api.analyzers import (
    ANALYZER_APPLICATION_ASSESSMENT_PATH,
    ANALYZER_CATALOGUE_PATH,
    get_analyzer_application_service,
)
from app.db.database import get_db
from app.engineering.design.analyzer_workflow_models import (
    ANALYZER_DESIGN_CASE_EXAMPLES,
)
from app.main import app as pre_activation_app
from app.main import create_reviewed_secured_application
from app.security.access_dependency import ORGANISATION_HEADER_NAME
from app.security.bootstrap_models import SecurityBootstrapCommand
from app.security.entitlements import (
    ControlledFeature,
    OrganisationEntitlementSnapshot,
    SubscriptionStatus,
)
from app.security.identity_models import OrganisationRole
from app.services.security_bootstrap_executor import (
    TransactionalSecurityBootstrapExecutor,
)


BACKEND_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATTERN = re.compile(r"\Ae4m_phase8_step170_[0-9a-f]{32}\Z")
SECURITY_TABLES = (
    "security_users",
    "security_organisations",
    "security_organisation_memberships",
    "security_entitlement_snapshots",
    "security_audit_events",
)
PHASE8_HEAD = "d9a137b5e6f7"
PHASE8_BASE = "b7f110e3d2a1"
ISSUER = "https://identity.step170.invalid"
AUDIENCE = "engineer4me-step170-probe"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"
KEY_ID = "step170-rs256-key"
OWNER_SUBJECT = "synthetic-owner-subject-step170"
UNKNOWN_SUBJECT = "synthetic-unknown-subject-step170"
OWNER_TOKEN_ID = "provider-session:step170:owner"
UNKNOWN_TOKEN_ID = "provider-session:step170:unknown"
ATTACKER_TOKEN_ID = "provider-session:step170:attacker"
SESSION_ID_NAMESPACE = UUID("a7a4ea3e-9aff-5e98-8ed7-9af4bff9eaf8")


def quoted_identifier(value: str) -> str:
    if SCHEMA_PATTERN.fullmatch(value) is None:
        raise ValueError("temporary schema name is outside the controlled pattern")
    return '"' + value + '"'


def alembic_config(connection) -> Config:
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.attributes["connection"] = connection
    config.attributes["configure_logger"] = False
    return config


def public_snapshot(engine) -> tuple[str, tuple[int, ...]]:
    with engine.connect() as connection:
        connection.exec_driver_sql(
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
        )
        revision = connection.scalar(
            text("SELECT version_num FROM public.alembic_version")
        )
        counts = tuple(
            connection.scalar(text(f'SELECT count(*) FROM public."{table}"'))
            for table in SECURITY_TABLES
        )
    return str(revision), counts


def isolated_counts(engine, *, expected_schema: str) -> dict[str, int]:
    with engine.connect() as connection:
        if connection.scalar(text("SELECT current_schema()")) != expected_schema:
            raise AssertionError("isolated verification escaped the temporary schema")
        return {
            table: int(connection.scalar(text(f'SELECT count(*) FROM "{table}"')))
            for table in SECURITY_TABLES
        }


def route_state(application) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            id(route),
            getattr(route, "path", None),
            tuple(sorted(getattr(route, "methods", ()) or ())),
            id(getattr(route, "endpoint", None)),
            id(getattr(route, "dependant", None)),
            tuple(id(item) for item in getattr(route, "dependencies", ())),
        )
        for route in application.routes
    )


def expected_session_id(*, subject: str, token_id: str) -> UUID:
    name = f"{len(ISSUER)}:{ISSUER}{len(subject)}:{subject}{token_id}"
    return uuid5(SESSION_ID_NAMESPACE, name)


class TrackingSession(Session):
    instances: ClassVar[list["TrackingSession"]] = []

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.commit_calls = 0
        self.rollback_calls = 0
        self.close_calls = 0
        type(self).instances.append(self)

    def commit(self) -> None:
        self.commit_calls += 1
        super().commit()

    def rollback(self) -> None:
        self.rollback_calls += 1
        super().rollback()

    def close(self) -> None:
        self.close_calls += 1
        super().close()


class AccessTrackingSession(TrackingSession):
    instances: ClassVar[list[TrackingSession]] = []


class AuditTrackingSession(TrackingSession):
    instances: ClassVar[list[TrackingSession]] = []
    fail_next_commit: ClassVar[bool] = False

    def commit(self) -> None:
        if type(self).fail_next_commit:
            type(self).fail_next_commit = False
            self.commit_calls += 1
            raise SQLAlchemyError("synthetic isolated audit commit failure")
        super().commit()


class FakeHTTPSResponse:
    status = 200
    headers = {"Content-Type": "application/jwk-set+json"}

    def __init__(self, body: bytes) -> None:
        self._body = body

    def geturl(self) -> str:
        return JWKS_URL

    def read(self, amount: int = -1) -> bytes:
        return self._body if amount < 0 else self._body[:amount]

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        return None


def signed_token(
    *,
    private_key,
    subject: str,
    token_id: str,
    issued_at: datetime,
) -> str:
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": subject,
            "jti": token_id,
            "iat": issued_at,
            "exp": issued_at + timedelta(minutes=10),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )


def request_headers(token: str, organisation_id: UUID) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        ORGANISATION_HEADER_NAME: str(organisation_id),
    }


def assert_unauthorized(response) -> None:
    if response.status_code != 401:
        raise AssertionError(f"credential failure returned {response.status_code}")
    if response.json() != {"detail": "Authentication required."}:
        raise AssertionError("credential failure response was not uniform")
    if response.headers.get("www-authenticate") != "Bearer":
        raise AssertionError("credential failure omitted the Bearer challenge")


def assert_denied(response) -> None:
    if response.status_code != 403 or response.json() != {"detail": "Access denied."}:
        raise AssertionError("access denial was not uniform")


def main() -> None:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")

    schema = f"e4m_phase8_step170_{uuid4().hex}"
    quoted = quoted_identifier(schema)
    administration_engine = create_engine(database_url, pool_pre_ping=True)
    isolated_engine = None
    created = False
    public_before = None

    try:
        public_before = public_snapshot(administration_engine)
        if public_before != (PHASE8_HEAD, (0, 0, 0, 0, 0)):
            raise AssertionError(
                "operational public security state is not the accepted empty head"
            )
        with administration_engine.connect() as connection:
            connection.execute(text(f"CREATE SCHEMA {quoted}"))
            connection.commit()
            created = True
            connection.execute(text(f"SET search_path TO {quoted}"))
            connection.commit()
            command.upgrade(alembic_config(connection), "head")
            revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
            if revision != PHASE8_HEAD:
                raise AssertionError(f"unexpected isolated migration head: {revision}")

        isolated_engine = create_engine(database_url, pool_pre_ping=True)

        @event.listens_for(isolated_engine, "connect", insert=True)
        def set_isolated_search_path(dbapi_connection, connection_record) -> None:
            del connection_record
            previous_autocommit = dbapi_connection.autocommit
            try:
                dbapi_connection.autocommit = True
                with dbapi_connection.cursor() as cursor:
                    cursor.execute(f"SET search_path TO {quoted}")
            finally:
                dbapi_connection.autocommit = previous_autocommit

        if isolated_counts(
            isolated_engine,
            expected_schema=schema,
        ) != {table: 0 for table in SECURITY_TABLES}:
            raise AssertionError("isolated security domain was not empty before bootstrap")

        AccessTrackingSession.instances.clear()
        AuditTrackingSession.instances.clear()
        AuditTrackingSession.fail_next_commit = False
        access_maker = sessionmaker(
            bind=isolated_engine,
            class_=AccessTrackingSession,
            expire_on_commit=False,
        )
        audit_maker = sessionmaker(
            bind=isolated_engine,
            class_=AuditTrackingSession,
            expire_on_commit=False,
        )

        def isolated_access_session() -> Session:
            session = access_maker()
            try:
                if session.scalar(text("SELECT current_schema()")) != schema:
                    raise AssertionError("access session escaped the temporary schema")
            except BaseException:
                session.close()
                raise
            return session

        def isolated_audit_session() -> Session:
            session = audit_maker()
            try:
                if session.scalar(text("SELECT current_schema()")) != schema:
                    raise AssertionError("audit session escaped the temporary schema")
            except BaseException:
                session.close()
                raise
            return session

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(
            private_key.public_key(),
            as_dict=True,
        )
        public_jwk.update({"kid": KEY_ID, "alg": "RS256", "use": "sig"})
        jwks_body = json.dumps(
            {"keys": [public_jwk]},
            separators=(",", ":"),
        ).encode("utf-8")
        jwks_calls: list[tuple[str, float]] = []

        def open_url(request, timeout: float):
            jwks_calls.append((request.full_url, timeout))
            return FakeHTTPSResponse(jwks_body)

        pre_activation_routes = route_state(pre_activation_app)
        pre_activation_openapi = pre_activation_app.openapi_schema
        application = create_reviewed_secured_application(
            environment={
                "E4M_AUTH_ISSUER": ISSUER,
                "E4M_AUTH_AUDIENCE": AUDIENCE,
                "E4M_AUTH_JWKS_URL": JWKS_URL,
                "E4M_AUTH_ALGORITHMS": "RS256",
            },
            access_session_factory=isolated_access_session,
            audit_session_factory=isolated_audit_session,
            open_url=open_url,
        )
        composition = application.state.security_composition
        if (
            len(composition.manifest.registrations) != 93
            or len(composition.manifest.protected_registrations()) != 91
            or len(composition.manifest.public_registrations()) != 2
        ):
            raise AssertionError("secured application manifest is not exact")
        if jwks_calls or AccessTrackingSession.instances or AuditTrackingSession.instances:
            raise AssertionError("secured application construction performed eager I/O")
        if route_state(pre_activation_app) != pre_activation_routes:
            raise AssertionError("secured factory mutated the pre-activation route surface")
        if pre_activation_app.openapi_schema is not pre_activation_openapi:
            raise AssertionError("secured factory mutated pre-activation OpenAPI state")
        if hasattr(pre_activation_app.state, "security_composition"):
            raise AssertionError("pre-activation application was activated")

        def forbidden_request_database():
            raise AssertionError("protected denial reached the operational request database")

        application.dependency_overrides[get_db] = forbidden_request_database
        analyzer_handler_calls: list[str] = []

        def tracked_analyzer_service():
            analyzer_handler_calls.append("called")
            return get_analyzer_application_service()

        application.dependency_overrides[
            get_analyzer_application_service
        ] = tracked_analyzer_service
        issued_at = datetime.now(UTC).replace(microsecond=0)
        bootstrap_id = uuid4()
        request_id = uuid4()
        user_id = uuid4()
        organisation_id = uuid4()
        membership_id = uuid4()
        entitlement_id = uuid4()
        secondary_organisation_id = uuid4()
        owner_token = signed_token(
            private_key=private_key,
            subject=OWNER_SUBJECT,
            token_id=OWNER_TOKEN_ID,
            issued_at=issued_at,
        )
        unknown_token = signed_token(
            private_key=private_key,
            subject=UNKNOWN_SUBJECT,
            token_id=UNKNOWN_TOKEN_ID,
            issued_at=issued_at,
        )
        attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        invalid_token = signed_token(
            private_key=attacker_key,
            subject=OWNER_SUBJECT,
            token_id=ATTACKER_TOKEN_ID,
            issued_at=issued_at,
        )
        observed_responses = []

        with TestClient(application, raise_server_exceptions=False) as client:
            public_responses = (
                client.get("/"),
                client.get("/health"),
                client.get("/openapi.json"),
                client.get("/docs"),
            )
            observed_responses.extend(public_responses)
            if any(response.status_code != 200 for response in public_responses):
                raise AssertionError("secured application public surface failed")
            missing = client.get(
                ANALYZER_CATALOGUE_PATH,
                headers={ORGANISATION_HEADER_NAME: str(organisation_id)},
            )
            observed_responses.append(missing)
            assert_unauthorized(missing)
            if (
                jwks_calls
                or AccessTrackingSession.instances
                or AuditTrackingSession.instances
                or analyzer_handler_calls
            ):
                raise AssertionError("pre-bootstrap public or missing-token request performed security I/O")
            if isolated_counts(
                isolated_engine,
                expected_schema=schema,
            ) != {table: 0 for table in SECURITY_TABLES}:
                raise AssertionError("pre-bootstrap requests changed the empty security domain")

            entitlement = OrganisationEntitlementSnapshot(
                snapshot_id=entitlement_id,
                organisation_id=organisation_id,
                plan_id="isolated-step170-plan",
                subscription_status=SubscriptionStatus.TRIAL,
                features=(ControlledFeature.ENGINEERING_CALCULATIONS,),
                quotas=(),
                effective_at=issued_at,
                expires_at=issued_at + timedelta(hours=1),
                source_reference="isolated Step 170 probe only",
            )
            bootstrap = SecurityBootstrapCommand(
                bootstrap_id=bootstrap_id,
                request_id=request_id,
                user_id=user_id,
                organisation_id=organisation_id,
                membership_id=membership_id,
                email="step170@example.com",
                display_name="Step 170 Synthetic Owner",
                issuer=ISSUER,
                subject=OWNER_SUBJECT,
                organisation_slug="step170-org",
                organisation_name="Step 170 Synthetic Organisation",
                initial_role=OrganisationRole.OWNER,
                activated_at=issued_at,
                entitlement=entitlement,
            )
            bootstrap_maker = sessionmaker(bind=isolated_engine, expire_on_commit=False)

            def isolated_bootstrap_session() -> Session:
                session = bootstrap_maker()
                try:
                    if session.scalar(text("SELECT current_schema()")) != schema:
                        raise AssertionError(
                            "bootstrap session escaped the temporary schema"
                        )
                except BaseException:
                    session.close()
                    raise
                return session

            receipt = TransactionalSecurityBootstrapExecutor(
                isolated_bootstrap_session
            ).execute(bootstrap)
            if (
                receipt.bootstrap_id != bootstrap_id
                or receipt.user_id != user_id
                or receipt.organisation_id != organisation_id
                or receipt.entitlement_snapshot_id != entitlement_id
            ):
                raise AssertionError("synthetic bootstrap receipt lost correlation")
            if isolated_counts(
                isolated_engine,
                expected_schema=schema,
            ) != {table: 1 for table in SECURITY_TABLES}:
                raise AssertionError("synthetic bootstrap did not commit exactly five records")

            with isolated_engine.begin() as connection:
                if connection.scalar(text("SELECT current_schema()")) != schema:
                    raise AssertionError("secondary organisation insert escaped temporary schema")
                connection.execute(
                    text(
                        "INSERT INTO security_organisations (id,slug,name,status) "
                        "VALUES (:id,'step170-secondary','Step 170 Secondary Organisation','active')"
                    ),
                    {"id": secondary_organisation_id},
                )

            invalid = client.get(
                ANALYZER_CATALOGUE_PATH,
                headers=request_headers(invalid_token, organisation_id),
            )
            observed_responses.append(invalid)
            assert_unauthorized(invalid)
            if (
                len(jwks_calls) != 1
                or AccessTrackingSession.instances
                or AuditTrackingSession.instances
                or analyzer_handler_calls
            ):
                raise AssertionError("invalid signature crossed the credential boundary")
            if isolated_counts(
                isolated_engine,
                expected_schema=schema,
            )["security_audit_events"] != 1:
                raise AssertionError("credential failure created an access audit event")

            unknown = client.get(
                ANALYZER_CATALOGUE_PATH,
                headers=request_headers(unknown_token, organisation_id),
            )
            observed_responses.append(unknown)
            assert_denied(unknown)
            if analyzer_handler_calls:
                raise AssertionError("unknown identity denial reached the route handler")

            allowed_catalogue = client.get(
                ANALYZER_CATALOGUE_PATH,
                headers=request_headers(owner_token, organisation_id),
            )
            observed_responses.append(allowed_catalogue)
            if allowed_catalogue.status_code != 200 or len(allowed_catalogue.json()) != 21:
                raise AssertionError("owner RBAC catalogue access did not execute")
            if len(analyzer_handler_calls) != 1:
                raise AssertionError("allowed catalogue route did not execute exactly once")

            unowned_organisation = client.get(
                ANALYZER_CATALOGUE_PATH,
                headers=request_headers(owner_token, secondary_organisation_id),
            )
            observed_responses.append(unowned_organisation)
            assert_denied(unowned_organisation)
            if len(analyzer_handler_calls) != 1:
                raise AssertionError("unowned organisation denial reached the route handler")

            denied_entitlement = client.get(
                "/api/v1/designs",
                headers=request_headers(owner_token, organisation_id),
            )
            observed_responses.append(denied_entitlement)
            assert_denied(denied_entitlement)

            assessment = client.post(
                ANALYZER_APPLICATION_ASSESSMENT_PATH,
                headers=request_headers(owner_token, organisation_id),
                json=ANALYZER_DESIGN_CASE_EXAMPLES[0].request.model_dump(mode="json"),
            )
            observed_responses.append(assessment)
            if assessment.status_code != 200 or "assessment" not in assessment.json():
                raise AssertionError("entitlement-backed analyzer route did not execute")
            if len(analyzer_handler_calls) != 2:
                raise AssertionError("allowed analyzer route did not execute exactly once")

            access_audit_count = isolated_counts(
                isolated_engine,
                expected_schema=schema,
            )["security_audit_events"]
            if access_audit_count != 6:
                raise AssertionError("completed access decisions were not durably audited")

            handler_calls: list[str] = []

            def forbidden_analyzer_service():
                handler_calls.append("called")
                raise AssertionError("route handler executed before durable audit commit")

            application.dependency_overrides[
                get_analyzer_application_service
            ] = forbidden_analyzer_service
            AuditTrackingSession.fail_next_commit = True
            audit_outage = client.get(
                ANALYZER_CATALOGUE_PATH,
                headers=request_headers(owner_token, organisation_id),
            )
            observed_responses.append(audit_outage)
            if audit_outage.status_code != 500 or audit_outage.text != "Internal Server Error":
                raise AssertionError("audit commit failure did not fail closed generically")
            if handler_calls:
                raise AssertionError("audit failure allowed protected route execution")
            if isolated_counts(
                isolated_engine,
                expected_schema=schema,
            )["security_audit_events"] != access_audit_count:
                raise AssertionError("failed audit transaction left a persisted event")
            del application.dependency_overrides[get_analyzer_application_service]

        application.dependency_overrides.clear()
        response_material = "\n".join(
            response.text + json.dumps(dict(response.headers), sort_keys=True)
            for response in observed_responses
        )
        for sensitive_value in (
            OWNER_SUBJECT,
            UNKNOWN_SUBJECT,
            OWNER_TOKEN_ID,
            UNKNOWN_TOKEN_ID,
            ATTACKER_TOKEN_ID,
            owner_token,
            unknown_token,
            invalid_token,
        ):
            if sensitive_value in response_material:
                raise AssertionError("raw identity or credential content entered a response")
        if jwks_calls != [(JWKS_URL, 5.0)]:
            raise AssertionError(f"bounded JWKS cache behavior drifted: {jwks_calls}")
        if len(AccessTrackingSession.instances) != 6:
            raise AssertionError("access decisions did not use six fresh read sessions")
        if any(
            item.commit_calls != 0
            or item.rollback_calls != 1
            or item.close_calls != 1
            for item in AccessTrackingSession.instances
        ):
            raise AssertionError("access read sessions were not rollback-only and closed")
        if len(AuditTrackingSession.instances) != 6:
            raise AssertionError("access decisions did not use six isolated audit sessions")
        successful_audits = AuditTrackingSession.instances[:-1]
        failed_audit = AuditTrackingSession.instances[-1]
        if any(
            item.commit_calls != 1
            or item.rollback_calls != 0
            or item.close_calls != 1
            for item in successful_audits
        ):
            raise AssertionError("durable audit sessions did not commit and close exactly")
        if (
            failed_audit.commit_calls != 1
            or failed_audit.rollback_calls != 1
            or failed_audit.close_calls != 1
        ):
            raise AssertionError("failed audit session did not roll back and close")

        with isolated_engine.connect() as verification:
            counts = {
                table: int(verification.scalar(text(f'SELECT count(*) FROM "{table}"')))
                for table in SECURITY_TABLES
            }
            if counts != {
                "security_users": 1,
                "security_organisations": 2,
                "security_organisation_memberships": 1,
                "security_entitlement_snapshots": 1,
                "security_audit_events": 6,
            }:
                raise AssertionError(f"isolated final row counts are invalid: {counts}")
            access_rows = verification.execute(
                text(
                    "SELECT event_type,outcome,reason_code,request_id,actor_user_id,"
                    "organisation_id,session_id,permission,resource_kind,resource_id,context "
                    "FROM security_audit_events WHERE event_type IN ('access_allowed','access_denied')"
                )
            ).mappings().all()
            persisted_audit_document = str(
                verification.scalar(
                    text(
                        "SELECT coalesce(jsonb_agg(to_jsonb(event)), '[]'::jsonb)::text "
                        "FROM security_audit_events AS event"
                    )
                )
            )
            persisted_identities = verification.execute(
                text("SELECT id,issuer,subject FROM security_users ORDER BY id")
            ).mappings().all()

        if len(access_rows) != 5 or len({row["request_id"] for row in access_rows}) != 5:
            raise AssertionError("access audit request correlation is incomplete")
        owner_session = expected_session_id(
            subject=OWNER_SUBJECT,
            token_id=OWNER_TOKEN_ID,
        )
        unknown_session = expected_session_id(
            subject=UNKNOWN_SUBJECT,
            token_id=UNKNOWN_TOKEN_ID,
        )
        owner_rows = [row for row in access_rows if row["actor_user_id"] == user_id]
        unknown_rows = [row for row in access_rows if row["actor_user_id"] is None]
        if len(owner_rows) != 4 or {row["session_id"] for row in owner_rows} != {owner_session}:
            raise AssertionError("owner audit session correlation is invalid")
        if len(unknown_rows) != 1 or unknown_rows[0]["session_id"] != unknown_session:
            raise AssertionError("unknown identity audit session correlation is invalid")
        if owner_session == unknown_session:
            raise AssertionError("distinct verified token subjects shared audit correlation")
        if [dict(row) for row in persisted_identities] != [
            {"id": user_id, "issuer": ISSUER, "subject": OWNER_SUBJECT}
        ]:
            raise AssertionError("synthetic bootstrap identity persistence drifted")
        for sensitive_value in (
            OWNER_SUBJECT,
            UNKNOWN_SUBJECT,
            OWNER_TOKEN_ID,
            UNKNOWN_TOKEN_ID,
            ATTACKER_TOKEN_ID,
            owner_token,
            unknown_token,
            invalid_token,
        ):
            if sensitive_value in persisted_audit_document:
                raise AssertionError("raw identity or credential content entered audit persistence")

        expected_rows = {
            (
                "access_denied",
                "denied",
                "identity_not_found",
                None,
                organisation_id,
                "engineering:read",
                "calculation",
                None,
                json.dumps({}, sort_keys=True),
            ),
            (
                "access_allowed",
                "succeeded",
                "allowed",
                user_id,
                organisation_id,
                "engineering:read",
                "calculation",
                None,
                json.dumps(
                    {"decision_reason": "allowed", "policy_version": "1.0.0"},
                    sort_keys=True,
                ),
            ),
            (
                "access_denied",
                "denied",
                "authorization_denied",
                user_id,
                secondary_organisation_id,
                "engineering:read",
                "calculation",
                None,
                json.dumps(
                    {
                        "decision_reason": "membership_not_found",
                        "policy_version": "1.0.0",
                    },
                    sort_keys=True,
                ),
            ),
            (
                "access_denied",
                "denied",
                "entitlement_denied",
                user_id,
                organisation_id,
                "engineering:read",
                "engineering_case",
                None,
                json.dumps(
                    {
                        "decision_reason": "allowed",
                        "entitlement_plan": "isolated-step170-plan",
                        "entitlement_reason": "feature_not_granted",
                        "policy_version": "1.0.0",
                    },
                    sort_keys=True,
                ),
            ),
            (
                "access_allowed",
                "succeeded",
                "allowed",
                user_id,
                organisation_id,
                "engineering:execute",
                "calculation",
                None,
                json.dumps(
                    {
                        "decision_reason": "allowed",
                        "entitlement_plan": "isolated-step170-plan",
                        "entitlement_reason": "allowed",
                        "policy_version": "1.0.0",
                    },
                    sort_keys=True,
                ),
            ),
        }
        actual_rows = {
            (
                row["event_type"],
                row["outcome"],
                row["reason_code"],
                row["actor_user_id"],
                row["organisation_id"],
                row["permission"],
                row["resource_kind"],
                row["resource_id"],
                json.dumps(dict(row["context"]), sort_keys=True),
            )
            for row in access_rows
        }
        if actual_rows != expected_rows:
            raise AssertionError("persisted full-stack access audit contracts drifted")
        if route_state(pre_activation_app) != pre_activation_routes:
            raise AssertionError("full-stack proof mutated the pre-activation route surface")
        if pre_activation_app.openapi_schema is not pre_activation_openapi:
            raise AssertionError("full-stack proof mutated pre-activation OpenAPI state")
        if hasattr(pre_activation_app.state, "security_composition"):
            raise AssertionError("full-stack proof activated the operational application")

        isolated_engine.dispose()
        isolated_engine = None
        with administration_engine.connect() as connection:
            connection.execute(text(f"SET search_path TO {quoted}"))
            connection.commit()
            command.downgrade(alembic_config(connection), PHASE8_BASE)
            if connection.scalar(text("SELECT version_num FROM alembic_version")) != PHASE8_BASE:
                raise AssertionError("isolated downgrade did not reach the Phase 8 base")
            remaining = set(inspect(connection).get_table_names(schema=schema))
            if set(SECURITY_TABLES) & remaining:
                raise AssertionError("security tables remained after isolated downgrade")
            function_count = connection.scalar(
                text(
                    "SELECT count(*) FROM pg_proc AS procedure "
                    "JOIN pg_namespace AS namespace "
                    "ON namespace.oid=procedure.pronamespace "
                    "WHERE namespace.nspname=:schema AND procedure.proname IN "
                    "('phase8_reject_entitlement_snapshot_mutation',"
                    "'phase8_reject_security_audit_mutation')"
                ),
                {"schema": schema},
            )
            if function_count != 0:
                raise AssertionError("Phase 8 trigger functions remained after downgrade")

        print(f"Temporary schema: {schema}")
        print(f"Upgrade head: {PHASE8_HEAD}")
        print("Secured application: 93 exact bindings; 91 protected and 2 public")
        print("Synthetic bootstrap: owner, membership, entitlement, and audit committed")
        print("Credential boundary: missing and invalid tokens rejected before access I/O")
        print("Access decisions: owner allowed; unknown identity, unowned organisation, and missing feature denied")
        print("Entitlement-backed analyzer execution: passed")
        print("Durable access audits: 5 exact correlated events verified")
        print("Session isolation: access rollback-only; audit commit-or-rollback verified")
        print("Audit outage: generic fail-closed response; protected handler not executed")
        print(f"Downgrade target: {PHASE8_BASE} verified")
    finally:
        if isolated_engine is not None:
            isolated_engine.dispose()
        try:
            if created:
                with administration_engine.begin() as cleanup:
                    cleanup.execute(text(f"DROP SCHEMA IF EXISTS {quoted} CASCADE"))
            with administration_engine.connect() as verification:
                schema_count = verification.scalar(
                    text(
                        "SELECT count(*) FROM information_schema.schemata "
                        "WHERE schema_name=:schema"
                    ),
                    {"schema": schema},
                )
            public_after = public_snapshot(administration_engine)
            if schema_count != 0:
                raise AssertionError("temporary schema cleanup was incomplete")
            if public_before is not None and public_after != public_before:
                raise AssertionError(
                    "operational public security state changed during isolated proof"
                )
        finally:
            administration_engine.dispose()

    print("Temporary schema cleanup: complete")
    print("Operational public schema: exact revision and empty security rows unchanged")
    print("Operational app.main activation: not performed")


if __name__ == "__main__":
    main()
