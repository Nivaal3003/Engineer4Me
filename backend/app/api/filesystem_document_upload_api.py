"""Multipart upload API for filesystem-backed document ingestion.

This router is intentionally separate from the ingestion job lifecycle router.
It accepts untrusted multipart files, converts them into transport-neutral
``FilesystemDocumentUpload`` values, and delegates all persistent side effects
to ``FilesystemDocumentUploadService``.

The module keeps the HTTP boundary narrow:

- raw request bytes are rejected before multipart parsing can spool them;
- upload streams are passed through without reading whole files into memory;
- permanent storage limits remain authoritative in the storage adapter;
- the shared ingestion job service is reused, so uploaded jobs are immediately
  visible through the existing ingestion lifecycle endpoints;
- caller JSON metadata is bounded and decoded before storage begins;
- server-owned storage metadata always replaces conflicting caller values; and
- internal paths, checksums, and rollback details are not disclosed in errors.

``app.main`` includes this router under ``/api/v1``.
"""

from __future__ import annotations

import json
import logging
import os
import stat as stat_module
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Final

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.responses import Response
from starlette.types import Message, Receive

from app.api.ingestion import get_ingestion_job_service
from app.ingestion.filesystem_document_storage import (
    DocumentStorageContentError,
    DocumentStorageFilenameError,
    DocumentStorageTooLargeError,
    FilesystemDocumentStorage,
    FilesystemDocumentStorageConfig,
)
from app.ingestion.filesystem_document_upload_service import (
    DocumentUploadRollbackError,
    DocumentUploadStorageError,
    DocumentUploadSubmissionError,
    DocumentUploadValidationError,
    FilesystemDocumentUpload,
    FilesystemDocumentUploadService,
    FilesystemDocumentUploadServiceConfig,
)
from app.ingestion.ingestion_job_models import IngestionJob
from app.ingestion.ingestion_job_service import IngestionJobService


logger = logging.getLogger(__name__)


_UPLOAD_ROOT_ENVIRONMENT_VARIABLE: Final[str] = (
    "ENGINEER4ME_UPLOAD_ROOT"
)
_MAXIMUM_CONTENT_BYTES_ENVIRONMENT_VARIABLE: Final[str] = (
    "ENGINEER4ME_UPLOAD_MAXIMUM_CONTENT_BYTES"
)
_MAXIMUM_REQUEST_BYTES_ENVIRONMENT_VARIABLE: Final[str] = (
    "ENGINEER4ME_UPLOAD_MAXIMUM_REQUEST_BYTES"
)
_READ_CHUNK_BYTES_ENVIRONMENT_VARIABLE: Final[str] = (
    "ENGINEER4ME_UPLOAD_READ_CHUNK_BYTES"
)
_MAXIMUM_DOCUMENTS_ENVIRONMENT_VARIABLE: Final[str] = (
    "ENGINEER4ME_UPLOAD_MAXIMUM_DOCUMENTS_PER_JOB"
)
_DEFAULT_ATTEMPTS_ENVIRONMENT_VARIABLE: Final[str] = (
    "ENGINEER4ME_UPLOAD_DEFAULT_MAXIMUM_ATTEMPTS"
)

_DEFAULT_UPLOAD_ROOT: Final[Path] = Path(
    "/var/lib/engineer4me/uploads"
)
_DEFAULT_MAXIMUM_CONTENT_BYTES: Final[int] = 25 * 1024 * 1024
_DEFAULT_MAXIMUM_REQUEST_BYTES: Final[int] = 128 * 1024 * 1024
_MAXIMUM_REQUEST_BYTES_LIMIT: Final[int] = 512 * 1024 * 1024
_DEFAULT_READ_CHUNK_BYTES: Final[int] = 64 * 1024
_DEFAULT_MAXIMUM_DOCUMENTS_PER_JOB: Final[int] = 20
_DEFAULT_MAXIMUM_ATTEMPTS: Final[int] = 3

_MAXIMUM_INGESTION_DOCUMENTS: Final[int] = 1_000
_MAXIMUM_ATTEMPTS_LIMIT: Final[int] = 20
_MAXIMUM_METADATA_JSON_CHARACTERS: Final[int] = 64 * 1024
_MAXIMUM_DOCUMENT_ATTRIBUTES_JSON_CHARACTERS: Final[int] = (
    256 * 1024
)
_PRIVATE_DIRECTORY_MODE: Final[int] = 0o700
_HTTP_BAD_REQUEST: Final[int] = 400
_HTTP_CONTENT_TOO_LARGE: Final[int] = 413
_HTTP_UNPROCESSABLE_CONTENT: Final[int] = 422
_INVALID_CONTENT_LENGTH_DETAIL: Final[str] = (
    "The upload request contains an invalid Content-Length header."
)
_REQUEST_TOO_LARGE_DETAIL: Final[str] = (
    "The upload request exceeds the configured aggregate size limit."
)


class FilesystemDocumentUploadApiConfigurationError(RuntimeError):
    """Raised when trusted server upload configuration is unusable."""


class DocumentUploadRequestError(ValueError):
    """Raised when multipart form metadata is malformed or inconsistent."""


class _InvalidContentLengthError(ValueError):
    """Raised when one raw upload length header is ambiguous or malformed."""


class _RequestBodyTooLargeError(RuntimeError):
    """Raised internally before multipart parsing exceeds its byte budget."""


@dataclass(frozen=True, slots=True)
class FilesystemDocumentUploadApiConfig:
    """Validated server-side composition controls for multipart uploads."""

    storage_root_directory: Path = _DEFAULT_UPLOAD_ROOT
    maximum_content_bytes: int = _DEFAULT_MAXIMUM_CONTENT_BYTES
    maximum_request_bytes: int = _DEFAULT_MAXIMUM_REQUEST_BYTES
    read_chunk_bytes: int = _DEFAULT_READ_CHUNK_BYTES
    maximum_documents_per_job: int = (
        _DEFAULT_MAXIMUM_DOCUMENTS_PER_JOB
    )
    default_maximum_attempts: int = _DEFAULT_MAXIMUM_ATTEMPTS

    def __post_init__(self) -> None:
        """Validate trusted limits before any upload directory is created."""

        if not isinstance(
            self.storage_root_directory,
            (str, os.PathLike),
        ):
            raise TypeError(
                "storage_root_directory must be a filesystem path."
            )

        raw_root = str(self.storage_root_directory).strip()

        if not raw_root:
            raise ValueError(
                "storage_root_directory cannot be blank."
            )

        root = Path(raw_root).expanduser()

        if not root.is_absolute():
            raise ValueError(
                "storage_root_directory must be an absolute path."
            )

        _require_bounded_integer(
            self.maximum_content_bytes,
            label="maximum_content_bytes",
            minimum=1,
        )
        _require_bounded_integer(
            self.maximum_request_bytes,
            label="maximum_request_bytes",
            minimum=1,
            maximum=_MAXIMUM_REQUEST_BYTES_LIMIT,
        )
        _require_bounded_integer(
            self.read_chunk_bytes,
            label="read_chunk_bytes",
            minimum=1,
            maximum=self.maximum_content_bytes,
        )
        _require_bounded_integer(
            self.maximum_documents_per_job,
            label="maximum_documents_per_job",
            minimum=1,
            maximum=_MAXIMUM_INGESTION_DOCUMENTS,
        )
        _require_bounded_integer(
            self.default_maximum_attempts,
            label="default_maximum_attempts",
            minimum=1,
            maximum=_MAXIMUM_ATTEMPTS_LIMIT,
        )

        object.__setattr__(
            self,
            "storage_root_directory",
            root,
        )

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
    ) -> "FilesystemDocumentUploadApiConfig":
        """Build configuration from a supplied or process environment."""

        source = os.environ if environment is None else environment

        if not isinstance(source, Mapping):
            raise TypeError("environment must be a mapping.")

        root_value = source.get(
            _UPLOAD_ROOT_ENVIRONMENT_VARIABLE,
            str(_DEFAULT_UPLOAD_ROOT),
        )

        if not isinstance(root_value, str):
            raise FilesystemDocumentUploadApiConfigurationError(
                f"{_UPLOAD_ROOT_ENVIRONMENT_VARIABLE} must be a string."
            )

        return cls(
            storage_root_directory=Path(root_value),
            maximum_content_bytes=_read_environment_integer(
                source,
                name=(
                    _MAXIMUM_CONTENT_BYTES_ENVIRONMENT_VARIABLE
                ),
                default=_DEFAULT_MAXIMUM_CONTENT_BYTES,
                minimum=1,
            ),
            maximum_request_bytes=_read_environment_integer(
                source,
                name=(
                    _MAXIMUM_REQUEST_BYTES_ENVIRONMENT_VARIABLE
                ),
                default=_DEFAULT_MAXIMUM_REQUEST_BYTES,
                minimum=1,
                maximum=_MAXIMUM_REQUEST_BYTES_LIMIT,
            ),
            read_chunk_bytes=_read_environment_integer(
                source,
                name=_READ_CHUNK_BYTES_ENVIRONMENT_VARIABLE,
                default=_DEFAULT_READ_CHUNK_BYTES,
                minimum=1,
            ),
            maximum_documents_per_job=(
                _read_environment_integer(
                    source,
                    name=_MAXIMUM_DOCUMENTS_ENVIRONMENT_VARIABLE,
                    default=_DEFAULT_MAXIMUM_DOCUMENTS_PER_JOB,
                    minimum=1,
                    maximum=_MAXIMUM_INGESTION_DOCUMENTS,
                )
            ),
            default_maximum_attempts=_read_environment_integer(
                source,
                name=_DEFAULT_ATTEMPTS_ENVIRONMENT_VARIABLE,
                default=_DEFAULT_MAXIMUM_ATTEMPTS,
                minimum=1,
                maximum=_MAXIMUM_ATTEMPTS_LIMIT,
            ),
        )


@lru_cache(maxsize=1)
def get_filesystem_document_upload_api_config(
) -> FilesystemDocumentUploadApiConfig:
    """Return the process-wide environment-derived upload configuration."""

    try:
        return FilesystemDocumentUploadApiConfig.from_environment()
    except (
        FilesystemDocumentUploadApiConfigurationError,
        TypeError,
        ValueError,
    ) as error:
        raise FilesystemDocumentUploadApiConfigurationError(
            "Filesystem document upload configuration is invalid."
        ) from error


@lru_cache(maxsize=1)
def get_filesystem_document_storage() -> FilesystemDocumentStorage:
    """Return the process-wide guarded filesystem storage adapter."""

    config = get_filesystem_document_upload_api_config()
    root = _prepare_storage_root(config.storage_root_directory)

    try:
        storage_config = FilesystemDocumentStorageConfig(
            root_directory=root,
            maximum_content_bytes=config.maximum_content_bytes,
            read_chunk_bytes=config.read_chunk_bytes,
        )
        return FilesystemDocumentStorage(storage_config)
    except (OSError, TypeError, ValueError) as error:
        raise FilesystemDocumentUploadApiConfigurationError(
            "Filesystem document storage could not be configured."
        ) from error


def get_filesystem_document_upload_api_config_dependency(
) -> FilesystemDocumentUploadApiConfig:
    """Return upload configuration or one safe service response."""

    try:
        return get_filesystem_document_upload_api_config()
    except FilesystemDocumentUploadApiConfigurationError as error:
        logger.error(
            "Filesystem upload API configuration is unavailable."
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Document upload storage is unavailable.",
        ) from error


def get_filesystem_document_storage_dependency(
) -> FilesystemDocumentStorage:
    """Return guarded storage or one safe service response."""

    try:
        return get_filesystem_document_storage()
    except FilesystemDocumentUploadApiConfigurationError as error:
        logger.error(
            "Filesystem upload storage configuration is unavailable."
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Document upload storage is unavailable.",
        ) from error


def get_filesystem_document_upload_service(
    storage: Annotated[
        FilesystemDocumentStorage,
        Depends(get_filesystem_document_storage_dependency),
    ],
    job_service: Annotated[
        IngestionJobService,
        Depends(get_ingestion_job_service),
    ],
    api_config: Annotated[
        FilesystemDocumentUploadApiConfig,
        Depends(
            get_filesystem_document_upload_api_config_dependency
        ),
    ],
) -> FilesystemDocumentUploadService:
    """Compose uploads with the shared ingestion lifecycle service."""

    return FilesystemDocumentUploadService(
        storage=storage,
        job_service=job_service,
        config=FilesystemDocumentUploadServiceConfig(
            maximum_documents_per_job=(
                api_config.maximum_documents_per_job
            ),
            default_maximum_attempts=(
                api_config.default_maximum_attempts
            ),
        ),
    )


FilesystemDocumentUploadServiceDependency = Annotated[
    FilesystemDocumentUploadService,
    Depends(get_filesystem_document_upload_service),
]


class _BoundedRequestReceive:
    """Count raw ASGI request bytes before multipart parsing can spool them."""

    __slots__ = (
        "_maximum_bytes",
        "_receive",
        "_received_bytes",
    )

    def __init__(
        self,
        receive: Receive,
        *,
        maximum_bytes: int,
    ) -> None:
        """Wrap one ASGI receive callable with a strict cumulative limit."""

        if not callable(receive):
            raise TypeError("receive must be callable.")

        _require_bounded_integer(
            maximum_bytes,
            label="maximum_bytes",
            minimum=1,
            maximum=_MAXIMUM_REQUEST_BYTES_LIMIT,
        )

        self._receive = receive
        self._maximum_bytes = maximum_bytes
        self._received_bytes = 0

    @property
    def maximum_bytes(self) -> int:
        """Return the immutable raw request-body budget."""

        return self._maximum_bytes

    @property
    def received_bytes(self) -> int:
        """Return the number of accepted raw request bytes."""

        return self._received_bytes

    async def __call__(self) -> Message:
        """Return one message or fail before an oversized chunk escapes."""

        message = await self._receive()

        if message.get("type") != "http.request":
            return message

        body = message.get("body", b"")

        if not isinstance(body, bytes):
            raise RuntimeError(
                "ASGI request body chunks must be bytes."
            )

        received_bytes = self._received_bytes + len(body)

        if received_bytes > self._maximum_bytes:
            raise _RequestBodyTooLargeError(
                "Raw upload request exceeded its configured byte budget."
            )

        self._received_bytes = received_bytes
        return message


class BoundedUploadRequestRoute(APIRoute):
    """Reject oversized upload bodies before Starlette multipart parsing."""

    def get_route_handler(
        self,
    ) -> Callable[[Request], Awaitable[Response]]:
        """Wrap FastAPI's handler with declared and streamed byte limits."""

        route_handler = super().get_route_handler()

        async def bounded_route_handler(
            request: Request,
        ) -> Response:
            try:
                maximum_request_bytes = (
                    get_filesystem_document_upload_api_config()
                    .maximum_request_bytes
                )
            except (
                FilesystemDocumentUploadApiConfigurationError,
                TypeError,
                ValueError,
            ):
                logger.error(
                    "Filesystem upload request limit is unavailable."
                )
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={
                        "detail": (
                            "Document upload storage is unavailable."
                        )
                    },
                )

            try:
                declared_length = _read_declared_content_length(
                    request
                )
            except _InvalidContentLengthError:
                return JSONResponse(
                    status_code=_HTTP_BAD_REQUEST,
                    content={
                        "detail": _INVALID_CONTENT_LENGTH_DETAIL,
                    },
                )

            if (
                declared_length is not None
                and declared_length > maximum_request_bytes
            ):
                return _request_too_large_response()

            bounded_receive = _BoundedRequestReceive(
                request.receive,
                maximum_bytes=maximum_request_bytes,
            )
            bounded_request = Request(
                request.scope,
                receive=bounded_receive,
            )

            try:
                return await route_handler(bounded_request)
            except Exception as error:
                if _exception_chain_contains_request_limit(error):
                    return _request_too_large_response()

                raise

        return bounded_route_handler


def _read_declared_content_length(request: Request) -> int | None:
    """Return one strict decimal Content-Length value when supplied."""

    raw_values = [
        value.strip()
        for name, value in request.scope.get("headers", ())
        if name.lower() == b"content-length"
    ]

    if not raw_values:
        return None

    if len(raw_values) != 1:
        raise _InvalidContentLengthError(
            "Content-Length must be supplied at most once."
        )

    raw_value = raw_values[0]

    try:
        text = raw_value.decode("ascii")
    except UnicodeDecodeError as error:
        raise _InvalidContentLengthError(
            "Content-Length must contain ASCII digits."
        ) from error

    if (
        not text
        or len(text) > 20
        or not text.isdecimal()
    ):
        raise _InvalidContentLengthError(
            "Content-Length must be one non-negative decimal integer."
        )

    try:
        return int(text, 10)
    except ValueError as error:
        raise _InvalidContentLengthError(
            "Content-Length is outside its supported range."
        ) from error


def _exception_chain_contains_request_limit(
    error: BaseException,
) -> bool:
    """Return whether one exception chain contains the private limit signal."""

    pending: list[BaseException] = [error]
    visited: set[int] = set()

    while pending:
        current = pending.pop()
        identity = id(current)

        if identity in visited:
            continue

        visited.add(identity)

        if isinstance(current, _RequestBodyTooLargeError):
            return True

        if current.__cause__ is not None:
            pending.append(current.__cause__)

        if current.__context__ is not None:
            pending.append(current.__context__)

    return False


def _request_too_large_response() -> JSONResponse:
    """Return one stable response without exposing request internals."""

    return JSONResponse(
        status_code=_HTTP_CONTENT_TOO_LARGE,
        content={"detail": _REQUEST_TOO_LARGE_DETAIL},
    )


router = APIRouter(
    prefix="/ingestion",
    tags=["Document Ingestion"],
    route_class=BoundedUploadRequestRoute,
)


@router.post(
    "/uploads",
    response_model=IngestionJob,
    status_code=status.HTTP_201_CREATED,
    summary="Upload documents and create an ingestion job",
    responses={
        _HTTP_BAD_REQUEST: {
            "description": "The raw request length header is invalid.",
        },
        _HTTP_CONTENT_TOO_LARGE: {
            "description": (
                "The aggregate request or one uploaded document "
                "exceeds configured limits."
            ),
        },
        _HTTP_UNPROCESSABLE_CONTENT: {
            "description": "Upload metadata or document content is invalid.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Upload rollback could not be completed safely.",
        },
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "description": "Upload storage or job registration is unavailable.",
        },
    },
)
def upload_ingestion_documents(
    files: Annotated[
        list[UploadFile],
        File(
            description=(
                "One or more supported documents. Every file is streamed "
                "through bounded guarded storage."
            ),
        ),
    ],
    submitted_by: Annotated[
        str,
        Form(
            min_length=1,
            max_length=255,
            description="User or system identity submitting the upload.",
        ),
    ],
    service: FilesystemDocumentUploadServiceDependency,
    correlation_id: Annotated[
        str | None,
        Form(
            max_length=255,
            description="Optional caller trace or batch identifier.",
        ),
    ] = None,
    maximum_attempts: Annotated[
        int | None,
        Form(
            ge=1,
            le=_MAXIMUM_ATTEMPTS_LIMIT,
            description="Optional per-document processing attempt limit.",
        ),
    ] = None,
    metadata_json: Annotated[
        str | None,
        Form(
            max_length=_MAXIMUM_METADATA_JSON_CHARACTERS,
            description="Optional JSON object containing job metadata.",
        ),
    ] = None,
    document_attributes_json: Annotated[
        str | None,
        Form(
            max_length=(
                _MAXIMUM_DOCUMENT_ATTRIBUTES_JSON_CHARACTERS
            ),
            description=(
                "Optional JSON array of per-document attribute objects "
                "in the same order as files."
            ),
        ),
    ] = None,
) -> IngestionJob:
    """Persist multipart documents and register one pending ingestion job."""

    try:
        metadata = _decode_json_mapping(
            metadata_json,
            label="metadata_json",
        )
        document_attributes = _decode_document_attributes(
            document_attributes_json,
            expected_count=len(files),
        )
        uploads = tuple(
            FilesystemDocumentUpload(
                filename=file.filename or "",
                stream=file.file,
                media_type=file.content_type,
                attributes=document_attributes[index],
            )
            for index, file in enumerate(files)
        )

        return service.submit_uploads(
            uploads=uploads,
            submitted_by=submitted_by,
            correlation_id=correlation_id,
            metadata=metadata,
            maximum_attempts=maximum_attempts,
        )
    except Exception as error:
        _raise_upload_api_error(error)


def _raise_upload_api_error(error: Exception) -> None:
    """Translate upload-layer failures into safe HTTP responses."""

    if isinstance(
        error,
        (
            DocumentUploadRequestError,
            DocumentUploadValidationError,
        ),
    ):
        raise HTTPException(
            status_code=_HTTP_UNPROCESSABLE_CONTENT,
            detail=str(error),
        ) from error

    if isinstance(error, DocumentUploadStorageError):
        storage_error = error.__cause__

        if isinstance(storage_error, DocumentStorageTooLargeError):
            raise HTTPException(
                status_code=_HTTP_CONTENT_TOO_LARGE,
                detail=(
                    "One or more uploaded documents exceed the "
                    "configured content-size limit."
                ),
            ) from error

        if isinstance(
            storage_error,
            (
                DocumentStorageContentError,
                DocumentStorageFilenameError,
            ),
        ):
            raise HTTPException(
                status_code=_HTTP_UNPROCESSABLE_CONTENT,
                detail=(
                    "One or more uploaded documents could not be "
                    "accepted within the configured storage rules."
                ),
            ) from error

        logger.error(
            "Upload storage failed: error=%s",
            type(storage_error).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Document upload storage is unavailable.",
        ) from error

    if isinstance(error, DocumentUploadSubmissionError):
        logger.error(
            "Upload job registration failed after guarded rollback."
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "The uploaded documents could not be registered for "
                "processing."
            ),
        ) from error

    if isinstance(error, DocumentUploadRollbackError):
        logger.error(
            "Upload rollback failed: primary=%s rollback=%s count=%s",
            error.primary_error_type,
            ",".join(error.rollback_error_types),
            error.rollback_error_count,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "The upload transaction failed and requires storage "
                "reconciliation."
            ),
        ) from error

    if isinstance(
        error,
        FilesystemDocumentUploadApiConfigurationError,
    ):
        logger.error("Filesystem upload API configuration is unavailable.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Document upload storage is unavailable.",
        ) from error

    raise error


def _decode_json_mapping(
    value: str | None,
    *,
    label: str,
) -> dict[str, Any]:
    """Decode one optional bounded JSON object."""

    if value is None or not value.strip():
        return {}

    decoded = _decode_json(value, label=label)

    if not isinstance(decoded, dict):
        raise DocumentUploadRequestError(
            f"{label} must contain a JSON object."
        )

    return decoded


def _decode_document_attributes(
    value: str | None,
    *,
    expected_count: int,
) -> tuple[dict[str, Any], ...]:
    """Decode attributes whose ordering must match uploaded files."""

    if (
        isinstance(expected_count, bool)
        or not isinstance(expected_count, int)
        or expected_count < 0
    ):
        raise ValueError(
            "expected_count must be a non-negative integer."
        )

    if value is None or not value.strip():
        return tuple({} for _ in range(expected_count))

    decoded = _decode_json(
        value,
        label="document_attributes_json",
    )

    if not isinstance(decoded, list):
        raise DocumentUploadRequestError(
            "document_attributes_json must contain a JSON array."
        )

    if len(decoded) != expected_count:
        raise DocumentUploadRequestError(
            "document_attributes_json must contain exactly one object "
            "for each uploaded file."
        )

    prepared: list[dict[str, Any]] = []

    for index, item in enumerate(decoded):
        if not isinstance(item, dict):
            raise DocumentUploadRequestError(
                "document_attributes_json entries must be JSON objects; "
                f"entry {index} is invalid."
            )

        prepared.append(item)

    return tuple(prepared)


def _decode_json(value: str, *, label: str) -> Any:
    """Decode strict JSON while rejecting non-standard numeric constants."""

    try:
        return json.loads(
            value,
            parse_constant=_reject_json_constant,
        )
    except DocumentUploadRequestError:
        raise
    except (json.JSONDecodeError, ValueError, RecursionError) as error:
        raise DocumentUploadRequestError(
            f"{label} must contain valid JSON."
        ) from error


def _reject_json_constant(value: str) -> None:
    """Reject NaN and infinity tokens accepted by Python's JSON decoder."""

    raise DocumentUploadRequestError(
        f"Unsupported non-finite JSON number: {value}."
    )


def _prepare_storage_root(root: Path) -> Path:
    """Create and validate the trusted private upload root."""

    try:
        if root.exists() and root.is_symlink():
            raise FilesystemDocumentUploadApiConfigurationError(
                "Configured upload root cannot be a symbolic link."
            )

        root.mkdir(
            mode=_PRIVATE_DIRECTORY_MODE,
            parents=True,
            exist_ok=True,
        )

        if root.is_symlink() or not root.is_dir():
            raise FilesystemDocumentUploadApiConfigurationError(
                "Configured upload root is not a private directory."
            )

        if os.name == "posix":
            os.chmod(root, _PRIVATE_DIRECTORY_MODE)
            permission_bits = stat_module.S_IMODE(
                root.stat().st_mode
            )

            if permission_bits & 0o077:
                raise FilesystemDocumentUploadApiConfigurationError(
                    "Configured upload root permissions are not private."
                )

        return root.resolve(strict=True)
    except FilesystemDocumentUploadApiConfigurationError:
        raise
    except OSError as error:
        raise FilesystemDocumentUploadApiConfigurationError(
            "Configured upload root could not be prepared."
        ) from error


def _read_environment_integer(
    environment: Mapping[str, str],
    *,
    name: str,
    default: int,
    minimum: int,
    maximum: int | None = None,
) -> int:
    """Read one strict bounded integer from trusted environment data."""

    raw_value = environment.get(name)

    if raw_value is None:
        return default

    if not isinstance(raw_value, str):
        raise FilesystemDocumentUploadApiConfigurationError(
            f"{name} must be a string."
        )

    stripped = raw_value.strip()

    if not stripped:
        raise FilesystemDocumentUploadApiConfigurationError(
            f"{name} cannot be blank."
        )

    try:
        value = int(stripped, 10)
    except ValueError as error:
        raise FilesystemDocumentUploadApiConfigurationError(
            f"{name} must be an integer."
        ) from error

    try:
        _require_bounded_integer(
            value,
            label=name,
            minimum=minimum,
            maximum=maximum,
        )
    except ValueError as error:
        raise FilesystemDocumentUploadApiConfigurationError(
            f"{name} is outside its supported range."
        ) from error

    return value


def _require_bounded_integer(
    value: int,
    *,
    label: str,
    minimum: int,
    maximum: int | None = None,
) -> None:
    """Reject booleans, non-integers, and out-of-range values."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer.")

    if value < minimum:
        raise ValueError(
            f"{label} must be at least {minimum}."
        )

    if maximum is not None and value > maximum:
        raise ValueError(
            f"{label} must be no greater than {maximum}."
        )


__all__ = [
    "BoundedUploadRequestRoute",
    "DocumentUploadRequestError",
    "FilesystemDocumentUploadApiConfig",
    "FilesystemDocumentUploadApiConfigurationError",
    "FilesystemDocumentUploadServiceDependency",
    "get_filesystem_document_storage",
    "get_filesystem_document_storage_dependency",
    "get_filesystem_document_upload_api_config",
    "get_filesystem_document_upload_api_config_dependency",
    "get_filesystem_document_upload_service",
    "router",
    "upload_ingestion_documents",
]
