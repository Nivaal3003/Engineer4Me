"""Format-scoped audited access for the controlled datasheet export route."""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import Depends, Header, HTTPException, Path, status

from app.security.access_dependency import ORGANISATION_HEADER_NAME
from app.security.authentication_availability import AvailabilityAwareAuthenticationDependency
from app.security.authorization import ResourceKind
from app.security.entitlements import ControlledFeature
from app.security.identity_models import Permission
from app.security.route_policy import RouteAccessScope, RouteHTTPMethod, RouteSecurityPolicy
from app.services.security_access_service import SecurityAccessCommand, SecurityAccessOutcome, TrustedAuthenticationContext
from app.services.security_audit_service import AuditedSecurityAccessService


class DatasheetExportAccessFormat(StrEnum):
    JSON = "json"
    XLSX = "xlsx"


DATASHEET_EXPORT_FEATURE_BY_FORMAT = MappingProxyType(
    {
        DatasheetExportAccessFormat.JSON: ControlledFeature.DATASHEET_JSON_EXPORT,
        DatasheetExportAccessFormat.XLSX: ControlledFeature.DATASHEET_XLSX_EXPORT,
    }
)

DATASHEET_EXPORT_OPERATION_ID = "downloadDesignDatasheetRevision"
DATASHEET_EXPORT_PATH_TEMPLATE = (
    "/api/v1/designs/{design_case_id}/datasheets/{datasheet_id}/revisions/"
    "{revision_number}/exports/{export_format}"
)


class DatasheetExportAccessConfigurationError(RuntimeError):
    """Sanitized rejection for any policy other than the reviewed export route."""


RequestIDFactory = Callable[[], UUID]


def _validate_export_policy(policy: RouteSecurityPolicy) -> None:
    if not isinstance(policy, RouteSecurityPolicy):
        raise TypeError("datasheet export access requires RouteSecurityPolicy")
    if (
        policy.operation_id != DATASHEET_EXPORT_OPERATION_ID
        or policy.method is not RouteHTTPMethod.GET
        or policy.path_template != DATASHEET_EXPORT_PATH_TEMPLATE
        or policy.scope is not RouteAccessScope.ORGANISATION_HEADER
        or policy.permission is not Permission.DATASHEET_EXPORT
        or policy.resource_kind is not ResourceKind.DATASHEET
        or policy.feature is not None
    ):
        raise DatasheetExportAccessConfigurationError(
            "datasheet export access policy does not match the reviewed route"
        )


def build_audited_datasheet_export_access_dependency(
    *,
    authentication: AvailabilityAwareAuthenticationDependency,
    audited_access_service: AuditedSecurityAccessService,
    policy: RouteSecurityPolicy,
    request_id_factory: RequestIDFactory = uuid4,
):
    """Build one unregistered dependency with exact format entitlement selection."""

    if not isinstance(audited_access_service, AuditedSecurityAccessService):
        raise TypeError("audited organisation access requires AuditedSecurityAccessService")
    _validate_export_policy(policy)

    def enforce(
        export_format: Annotated[DatasheetExportAccessFormat, Path()],
        organisation_id: Annotated[UUID, Header(alias=ORGANISATION_HEADER_NAME)],
        authentication_context: TrustedAuthenticationContext = Depends(authentication),
    ) -> SecurityAccessOutcome:
        feature = DATASHEET_EXPORT_FEATURE_BY_FORMAT.get(export_format)
        if feature is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
        outcome = audited_access_service.evaluate(
            authentication_context,
            SecurityAccessCommand(
                request_id=request_id_factory(),
                organisation_id=organisation_id,
                permission=Permission.DATASHEET_EXPORT,
                resource_kind=ResourceKind.DATASHEET,
                feature=feature,
            ),
        )
        if not outcome.allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
        return outcome

    return enforce


__all__ = [
    "DATASHEET_EXPORT_FEATURE_BY_FORMAT",
    "DATASHEET_EXPORT_OPERATION_ID",
    "DATASHEET_EXPORT_PATH_TEMPLATE",
    "DatasheetExportAccessConfigurationError",
    "DatasheetExportAccessFormat",
    "build_audited_datasheet_export_access_dependency",
]
