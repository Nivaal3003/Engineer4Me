import hashlib
import hmac
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import FastAPI

from app.api.analyzers import AnalyzerRequestBodyLimitMiddleware
from app.api.analyzers import router as analyzer_router
from app.api.calculations import CalculationRequestBodyLimitMiddleware
from app.api.calculations import router as calculation_router
from app.api.control_valves import ControlValveRequestBodyLimitMiddleware
from app.api.control_valves import router as control_valve_router
from app.api.dp_flow import DPFlowRequestBodyLimitMiddleware
from app.api.dp_flow import router as dp_flow_router
from app.api.designs import DesignRequestBodyLimitMiddleware
from app.api.designs import router as design_router
from app.api.datasheets import router as datasheet_router
from app.api.filesystem_document_execution_api import (
    router as filesystem_document_execution_router,
)
from app.api.filesystem_document_upload_api import (
    router as filesystem_document_upload_router,
)
from app.api.ingestion import router as ingestion_router
from app.api.knowledge import router as knowledge_router
from app.api.level_applications import (
    LevelApplicationRequestBodyLimitMiddleware,
)
from app.api.level_applications import router as level_application_router
from app.api.manufacturers import router as manufacturer_router
from app.api.measurements import router as measurement_router
from app.api.pressure_relief import PressureReliefRequestBodyLimitMiddleware
from app.api.pressure_relief import router as pressure_relief_router
from app.api.product_families import router as product_family_router
from app.api.products import router as product_router
from app.api.protocol import router as protocol_router
from app.api.selections import router as selection_router
from app.repositories.security_audit_writer import AuditSessionFactory
from app.security.authentication_jwks_readiness import SHA256_PATTERN
from app.security.authentication_readiness_document import (
    AuthenticationReadinessPreview,
    render_authentication_readiness_preview,
)
from app.security.authentication_token_readiness import (
    authentication_identity_sha256,
)
from app.security.jwks_http_loader import OpenURL
from app.security.security_application_activation_readiness import (
    OperationalApplicationActivationReadinessDocumentError,
    load_operational_application_activation_readiness_receipt,
)
from app.security.security_bootstrap_operational_postflight import (
    OperationalSecurityBootstrapPostflightReceipt,
)
from app.security.security_application import compose_reviewed_application_security
from app.services.security_access_reader import AccessSessionFactory

APPLICATION_VERSION = "0.10.0"
OPERATIONAL_ACTIVATION_READINESS_MAXIMUM_AGE_SECONDS = 30
OPERATIONAL_ACTIVATION_READINESS_FUTURE_SKEW_SECONDS = 30


class OperationalSecuredApplicationActivationError(RuntimeError):
    """Sanitized rejection before a bootstrap-confirmed application is built."""


@dataclass(frozen=True, slots=True)
class OperationalSecuredApplicationActivationReceipt:
    """Privacy-minimised in-memory evidence for one secured application build."""

    configuration_sha256: str
    execution_receipt_sha256: str
    bootstrap_document_sha256: str
    user_id: UUID
    organisation_id: UUID
    route_bindings: int
    protected_bindings: int
    public_bindings: int
    bootstrap_verified: bool = True
    activation_ready: bool = True

    def __post_init__(self) -> None:
        if (
            type(self.configuration_sha256) is not str
            or SHA256_PATTERN.fullmatch(self.configuration_sha256) is None
            or type(self.execution_receipt_sha256) is not str
            or SHA256_PATTERN.fullmatch(self.execution_receipt_sha256) is None
            or type(self.bootstrap_document_sha256) is not str
            or SHA256_PATTERN.fullmatch(self.bootstrap_document_sha256) is None
            or type(self.user_id) is not UUID
            or type(self.organisation_id) is not UUID
            or self.route_bindings != 93
            or self.protected_bindings != 91
            or self.public_bindings != 2
            or self.bootstrap_verified is not True
            or self.activation_ready is not True
        ):
            raise ValueError("operational secured application receipt is invalid")


@dataclass(frozen=True, slots=True)
class OperationalReadinessConfirmedApplicationReceipt:
    """Privacy-minimised evidence for one readiness-bound app construction."""

    activation_readiness_sha256: str
    postflight_receipt_sha256: str
    configuration_sha256: str
    jwks_document_sha256: str
    bootstrap_document_sha256: str
    issuer_sha256: str
    user_id: UUID
    organisation_id: UUID
    entitlement_snapshot_id: UUID
    readiness_checked_at: datetime
    construction_checked_at: datetime
    route_bindings: int
    protected_bindings: int
    public_bindings: int
    readiness_bound: bool = True
    application_constructed: bool = True
    deployment_cutover_performed: bool = False

    def __post_init__(self) -> None:
        hashes = (
            self.activation_readiness_sha256,
            self.postflight_receipt_sha256,
            self.configuration_sha256,
            self.jwks_document_sha256,
            self.bootstrap_document_sha256,
            self.issuer_sha256,
        )
        identifiers = (
            self.user_id,
            self.organisation_id,
            self.entitlement_snapshot_id,
        )
        timestamps = (
            self.readiness_checked_at,
            self.construction_checked_at,
        )
        if all(
            isinstance(value, datetime)
            and value.tzinfo is not None
            and value.utcoffset() is not None
            for value in timestamps
        ):
            age = self.construction_checked_at.astimezone(
                UTC
            ) - self.readiness_checked_at.astimezone(UTC)
        else:
            age = None
        if (
            any(
                type(value) is not str
                or SHA256_PATTERN.fullmatch(value) is None
                for value in hashes
            )
            or any(type(value) is not UUID for value in identifiers)
            or len(set(identifiers)) != len(identifiers)
            or any(
                not isinstance(value, datetime)
                or value.tzinfo is None
                or value.utcoffset() is None
                for value in timestamps
            )
            or age is None
            or age
            < -timedelta(
                seconds=OPERATIONAL_ACTIVATION_READINESS_FUTURE_SKEW_SECONDS
            )
            or age
            > timedelta(
                seconds=OPERATIONAL_ACTIVATION_READINESS_MAXIMUM_AGE_SECONDS
            )
            or self.route_bindings != 93
            or self.protected_bindings != 91
            or self.public_bindings != 2
            or self.readiness_bound is not True
            or self.application_constructed is not True
            or self.deployment_cutover_performed is not False
        ):
            raise ValueError(
                "operational readiness-confirmed application receipt is invalid"
            )


def root() -> dict[str, str]:
    return {
        "application": "Engineer4Me",
        "status": "running",
        "version": APPLICATION_VERSION,
    }


def health() -> dict[str, str]:
    return {
        "status": "healthy",
    }


def _create_application_shell() -> FastAPI:
    application = FastAPI(
        title="Engineer4Me API",
        version=APPLICATION_VERSION,
        description=(
            "Vendor-neutral engineering knowledge platform for process instrumentation."
        ),
    )
    application.add_middleware(CalculationRequestBodyLimitMiddleware)
    application.add_middleware(LevelApplicationRequestBodyLimitMiddleware)
    application.add_middleware(DPFlowRequestBodyLimitMiddleware)
    application.add_middleware(ControlValveRequestBodyLimitMiddleware)
    application.add_middleware(PressureReliefRequestBodyLimitMiddleware)
    application.add_middleware(AnalyzerRequestBodyLimitMiddleware)
    application.add_middleware(DesignRequestBodyLimitMiddleware)
    application.add_api_route("/", root, methods=["GET"], tags=["System"])
    application.add_api_route("/health", health, methods=["GET"], tags=["System"])
    return application


def create_reviewed_secured_application(
    *,
    environment: Mapping[str, str],
    access_session_factory: AccessSessionFactory,
    audit_session_factory: AuditSessionFactory,
    open_url: OpenURL | None = None,
) -> FastAPI:
    """Build the complete reviewed application from explicit deployment inputs."""

    application = _create_application_shell()
    composition = compose_reviewed_application_security(
        application,
        environment=environment,
        access_session_factory=access_session_factory,
        audit_session_factory=audit_session_factory,
        open_url=open_url,
    )
    application.state.security_composition = composition
    return application


def _environment_from_authentication_readiness(
    readiness: AuthenticationReadinessPreview,
) -> dict[str, str]:
    """Revalidate and translate one public readiness preview exactly once."""

    render_authentication_readiness_preview(readiness)
    environment = {
        "E4M_AUTH_ISSUER": readiness.issuer,
        "E4M_AUTH_AUDIENCE": readiness.audience,
        "E4M_AUTH_JWKS_URL": readiness.jwks_url,
        "E4M_AUTH_ALGORITHMS": ",".join(readiness.algorithms),
        "E4M_AUTH_TOKEN_IDENTIFIER_CLAIM": readiness.token_identifier_claim,
        "E4M_AUTH_TOKEN_PROFILE": readiness.token_profile,
        "E4M_AUTH_CLOCK_SKEW_SECONDS": str(readiness.clock_skew_seconds),
        "E4M_AUTH_MAXIMUM_TOKEN_AGE_SECONDS": str(
            readiness.maximum_token_age_seconds
        ),
        "E4M_AUTH_JWKS_CACHE_SECONDS": str(readiness.jwks_cache_seconds),
        "E4M_AUTH_JWKS_MAXIMUM_KEYS": str(readiness.jwks_maximum_keys),
        "E4M_AUTH_JWKS_TIMEOUT_SECONDS": str(
            readiness.jwks_timeout_seconds
        ),
        "E4M_AUTH_JWKS_MAXIMUM_RESPONSE_BYTES": str(
            readiness.jwks_maximum_response_bytes
        ),
    }
    if readiness.microsoft_entra_tenant_id is not None:
        environment["E4M_AUTH_MICROSOFT_ENTRA_TENANT_ID"] = (
            readiness.microsoft_entra_tenant_id
        )
    if readiness.microsoft_entra_api_application_id is not None:
        environment["E4M_AUTH_MICROSOFT_ENTRA_API_APPLICATION_ID"] = (
            readiness.microsoft_entra_api_application_id
        )
    if readiness.microsoft_entra_required_delegated_scope is not None:
        environment["E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_DELEGATED_SCOPE"] = (
            readiness.microsoft_entra_required_delegated_scope
        )
    if readiness.microsoft_entra_calling_client_application_id is not None:
        environment["E4M_AUTH_MICROSOFT_ENTRA_CALLING_CLIENT_APPLICATION_ID"] = (
            readiness.microsoft_entra_calling_client_application_id
        )
    if readiness.microsoft_entra_required_azpacr is not None:
        environment["E4M_AUTH_MICROSOFT_ENTRA_REQUIRED_AZPACR"] = (
            readiness.microsoft_entra_required_azpacr
        )
    return environment


def create_bootstrap_confirmed_secured_application(
    *,
    authentication_readiness: AuthenticationReadinessPreview,
    bootstrap_postflight: OperationalSecurityBootstrapPostflightReceipt,
    access_session_factory: AccessSessionFactory,
    audit_session_factory: AuditSessionFactory,
    open_url: OpenURL | None = None,
) -> FastAPI:
    """Build the reviewed secured surface only after exact bootstrap evidence."""

    if (
        type(bootstrap_postflight)
        is not OperationalSecurityBootstrapPostflightReceipt
    ):
        raise TypeError("operational bootstrap postflight receipt is required")
    try:
        environment = _environment_from_authentication_readiness(
            authentication_readiness
        )
    except (TypeError, ValueError):
        raise OperationalSecuredApplicationActivationError(
            "operational authentication readiness is invalid"
        ) from None
    if not hmac.compare_digest(
        authentication_readiness.configuration_sha256,
        bootstrap_postflight.configuration_sha256,
    ):
        raise OperationalSecuredApplicationActivationError(
            "operational authentication and bootstrap evidence do not match"
        )

    application = create_reviewed_secured_application(
        environment=environment,
        access_session_factory=access_session_factory,
        audit_session_factory=audit_session_factory,
        open_url=open_url,
    )
    manifest = application.state.security_composition.manifest
    activation = OperationalSecuredApplicationActivationReceipt(
        configuration_sha256=bootstrap_postflight.configuration_sha256,
        execution_receipt_sha256=(
            bootstrap_postflight.execution_receipt_sha256
        ),
        bootstrap_document_sha256=(
            bootstrap_postflight.bootstrap_document_sha256
        ),
        user_id=bootstrap_postflight.user_id,
        organisation_id=bootstrap_postflight.organisation_id,
        route_bindings=len(manifest.registrations),
        protected_bindings=len(manifest.protected_registrations()),
        public_bindings=len(manifest.public_registrations()),
    )
    application.state.security_activation = activation
    return application


def _activation_construction_time(
    clock: Callable[[], datetime],
) -> datetime:
    try:
        value = clock()
    except Exception:
        raise OperationalSecuredApplicationActivationError(
            "operational activation construction time is unavailable"
        ) from None
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise OperationalSecuredApplicationActivationError(
            "operational activation construction time is invalid"
        )
    return value.astimezone(UTC)


def create_readiness_confirmed_secured_application(
    *,
    authentication_readiness: AuthenticationReadinessPreview,
    activation_readiness_document: bytes,
    approved_activation_readiness_sha256: str,
    access_session_factory: AccessSessionFactory,
    audit_session_factory: AuditSessionFactory,
    open_url: OpenURL | None = None,
    clock: Callable[[], datetime],
) -> FastAPI:
    """Build one separate secured app from exact fresh readiness evidence."""

    if (
        type(approved_activation_readiness_sha256) is not str
        or SHA256_PATTERN.fullmatch(approved_activation_readiness_sha256) is None
    ):
        raise OperationalSecuredApplicationActivationError(
            "approved activation readiness digest is invalid"
        )
    if type(activation_readiness_document) is not bytes:
        raise TypeError("operational activation readiness document must be bytes")
    if not callable(access_session_factory):
        raise TypeError("operational access session factory must be callable")
    if not callable(audit_session_factory):
        raise TypeError("operational audit session factory must be callable")
    if open_url is not None and not callable(open_url):
        raise TypeError("operational JWKS transport must be callable")
    if not callable(clock):
        raise TypeError("operational activation construction clock is required")

    actual = hashlib.sha256(activation_readiness_document).hexdigest()
    if not hmac.compare_digest(
        actual,
        approved_activation_readiness_sha256,
    ):
        raise OperationalSecuredApplicationActivationError(
            "operational activation readiness does not match approval"
        )
    try:
        readiness = load_operational_application_activation_readiness_receipt(
            activation_readiness_document
        )
    except OperationalApplicationActivationReadinessDocumentError:
        raise OperationalSecuredApplicationActivationError(
            "operational activation readiness evidence is invalid"
        ) from None

    construction_checked_at = _activation_construction_time(clock)
    readiness_checked_at = readiness.checked_at.astimezone(UTC)
    age = construction_checked_at - readiness_checked_at
    if (
        age
        < -timedelta(
            seconds=OPERATIONAL_ACTIVATION_READINESS_FUTURE_SKEW_SECONDS
        )
        or age
        > timedelta(seconds=OPERATIONAL_ACTIVATION_READINESS_MAXIMUM_AGE_SECONDS)
    ):
        raise OperationalSecuredApplicationActivationError(
            "operational activation readiness is not current"
        )

    try:
        environment = _environment_from_authentication_readiness(
            authentication_readiness
        )
    except (TypeError, ValueError):
        raise OperationalSecuredApplicationActivationError(
            "operational authentication readiness is invalid"
        ) from None
    if not hmac.compare_digest(
        authentication_readiness.configuration_sha256,
        readiness.configuration_sha256,
    ):
        raise OperationalSecuredApplicationActivationError(
            "operational authentication and activation evidence do not match"
        )
    issuer_sha256 = authentication_identity_sha256(
        authentication_readiness.issuer
    )
    if not hmac.compare_digest(issuer_sha256, readiness.issuer_sha256):
        raise OperationalSecuredApplicationActivationError(
            "operational authentication identity evidence does not match"
        )

    application = create_reviewed_secured_application(
        environment=environment,
        access_session_factory=access_session_factory,
        audit_session_factory=audit_session_factory,
        open_url=open_url,
    )
    manifest = application.state.security_composition.manifest
    application.state.security_activation = (
        OperationalReadinessConfirmedApplicationReceipt(
            activation_readiness_sha256=actual,
            postflight_receipt_sha256=(
                readiness.postflight_receipt_sha256
            ),
            configuration_sha256=readiness.configuration_sha256,
            jwks_document_sha256=readiness.jwks_document_sha256,
            bootstrap_document_sha256=readiness.bootstrap_document_sha256,
            issuer_sha256=readiness.issuer_sha256,
            user_id=readiness.user_id,
            organisation_id=readiness.organisation_id,
            entitlement_snapshot_id=readiness.entitlement_snapshot_id,
            readiness_checked_at=readiness_checked_at,
            construction_checked_at=construction_checked_at,
            route_bindings=len(manifest.registrations),
            protected_bindings=len(manifest.protected_registrations()),
            public_bindings=len(manifest.public_registrations()),
        )
    )
    return application


def _register_pre_activation_routes(application: FastAPI) -> None:
    """Preserve the accepted application until operational activation is reviewed."""

    for router in (
        manufacturer_router,
        measurement_router,
        protocol_router,
        product_family_router,
        product_router,
        selection_router,
        knowledge_router,
        ingestion_router,
        filesystem_document_upload_router,
        filesystem_document_execution_router,
        calculation_router,
        level_application_router,
        dp_flow_router,
        control_valve_router,
        pressure_relief_router,
        analyzer_router,
        design_router,
        datasheet_router,
    ):
        application.include_router(router, prefix="/api/v1")


app = _create_application_shell()
_register_pre_activation_routes(app)


__all__ = [
    "APPLICATION_VERSION",
    "OPERATIONAL_ACTIVATION_READINESS_FUTURE_SKEW_SECONDS",
    "OPERATIONAL_ACTIVATION_READINESS_MAXIMUM_AGE_SECONDS",
    "OperationalReadinessConfirmedApplicationReceipt",
    "OperationalSecuredApplicationActivationError",
    "OperationalSecuredApplicationActivationReceipt",
    "app",
    "create_bootstrap_confirmed_secured_application",
    "create_readiness_confirmed_secured_application",
    "create_reviewed_secured_application",
    "health",
    "root",
]
