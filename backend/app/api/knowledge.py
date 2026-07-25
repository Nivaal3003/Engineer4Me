"""FastAPI routes for controlled engineering knowledge.

The router exposes the Engineer4Me engineering knowledge service through a
versioned REST interface.

The API supports:

- registering controlled engineering knowledge;
- revising existing knowledge;
- retrieving published and unpublished records;
- listing records and compact summaries;
- structured, text, safety, and verified-evidence searches;
- assessing publication readiness;
- retrieving revision history;
- viewing aggregate knowledge statistics;
- deleting knowledge through an administrative endpoint.

The current knowledge service uses an in-memory repository. A shared service
instance is therefore retained for the lifetime of the FastAPI process.
Future persistent repositories can be injected without changing the public
API contract.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Query
from fastapi import Response
from pydantic import BaseModel
from pydantic import Field

from app.engineering.knowledge_models import (
    EngineeringKnowledge,
    EvidenceType,
)
from app.engineering.knowledge_repository import (
    KnowledgeNotFoundError,
    KnowledgeRepository,
    KnowledgeSearchQuery,
    KnowledgeSearchResult,
)
from app.engineering.knowledge_service import (
    EngineeringKnowledgeService,
    KnowledgePublicationError,
    KnowledgeServiceError,
    KnowledgeServiceStatistics,
    KnowledgeSummary,
    KnowledgeWorkflowError,
    PublicationReadiness,
)


router = APIRouter(
    prefix="/knowledge",
    tags=["Engineering Knowledge"],
)


_knowledge_repository = KnowledgeRepository()
_knowledge_service = EngineeringKnowledgeService(_knowledge_repository)


def get_knowledge_service() -> EngineeringKnowledgeService:
    """Return the shared engineering knowledge service."""

    return _knowledge_service


KnowledgeServiceDependency = Annotated[
    EngineeringKnowledgeService,
    Depends(get_knowledge_service),
]


class KnowledgeTextSearchRequest(BaseModel):
    """Request body for general engineering knowledge text search."""

    text: str = Field(
        min_length=1,
        max_length=500,
        description="Vendor-neutral engineering search text.",
    )
    include_unpublished: bool = Field(
        default=False,
        description="Include draft and other unpublished records.",
    )
    limit: int = Field(
        default=25,
        ge=1,
        le=100,
        description="Maximum number of search results.",
    )


class KnowledgeSafetySearchRequest(BaseModel):
    """Request body for safety-prioritised engineering knowledge search."""

    text: str | None = Field(
        default=None,
        max_length=500,
        description="Optional safety-related search text.",
    )
    blocking_only: bool = Field(
        default=False,
        description=(
            "Return only guidance that blocks work until the hazard "
            "is resolved."
        ),
    )
    minimum_confidence_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Minimum acceptable confidence score.",
    )
    include_unpublished: bool = Field(
        default=False,
        description="Include draft and other unpublished records.",
    )
    limit: int = Field(
        default=25,
        ge=1,
        le=100,
        description="Maximum number of search results.",
    )


class KnowledgeVerifiedSearchRequest(BaseModel):
    """Request body for verified-evidence knowledge search."""

    text: str | None = Field(
        default=None,
        max_length=500,
        description="Optional engineering search text.",
    )
    evidence_types: list[EvidenceType] = Field(
        default_factory=list,
        description="Optional verified evidence types to include.",
    )
    minimum_confidence_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Minimum acceptable confidence score.",
    )
    include_unpublished: bool = Field(
        default=False,
        description="Include draft and other unpublished records.",
    )
    limit: int = Field(
        default=25,
        ge=1,
        le=100,
        description="Maximum number of search results.",
    )


def _raise_api_error(error: Exception) -> None:
    """Translate knowledge-layer exceptions into HTTP responses."""

    if isinstance(error, KnowledgeNotFoundError):
        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error

    if isinstance(error, KnowledgePublicationError):
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    if isinstance(error, KnowledgeWorkflowError):
        raise HTTPException(
            status_code=409,
            detail=str(error),
        ) from error

    if isinstance(error, KnowledgeServiceError):
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    if isinstance(error, ValueError):
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    raise error


@router.get(
    "/statistics",
    response_model=KnowledgeServiceStatistics,
)
def get_knowledge_statistics(
    service: KnowledgeServiceDependency,
) -> KnowledgeServiceStatistics:
    """Return aggregate statistics across all knowledge records."""

    return service.get_statistics()


@router.get(
    "/summaries",
    response_model=list[KnowledgeSummary],
)
def list_knowledge_summaries(
    service: KnowledgeServiceDependency,
    include_unpublished: bool = Query(
        default=False,
        description="Include summaries for unpublished records.",
    ),
) -> list[KnowledgeSummary]:
    """Return compact evidence, review, and safety summaries."""

    return service.list_summaries(
        include_unpublished=include_unpublished,
    )


@router.post(
    "/search",
    response_model=list[KnowledgeSearchResult],
)
def search_knowledge(
    query: KnowledgeSearchQuery,
    service: KnowledgeServiceDependency,
) -> list[KnowledgeSearchResult]:
    """Perform structured engineering knowledge search."""

    return service.search(query)


@router.post(
    "/search/text",
    response_model=list[KnowledgeSearchResult],
)
def search_knowledge_text(
    request: KnowledgeTextSearchRequest,
    service: KnowledgeServiceDependency,
) -> list[KnowledgeSearchResult]:
    """Perform general vendor-neutral text search."""

    return service.search_text(
        request.text,
        include_unpublished=request.include_unpublished,
        limit=request.limit,
    )


@router.post(
    "/search/safety",
    response_model=list[KnowledgeSearchResult],
)
def search_safety_guidance(
    request: KnowledgeSafetySearchRequest,
    service: KnowledgeServiceDependency,
) -> list[KnowledgeSearchResult]:
    """Search safety guidance using safety-priority ordering."""

    return service.search_safety_guidance(
        request.text,
        blocking_only=request.blocking_only,
        minimum_confidence_score=request.minimum_confidence_score,
        include_unpublished=request.include_unpublished,
        limit=request.limit,
    )


@router.post(
    "/search/verified",
    response_model=list[KnowledgeSearchResult],
)
def search_verified_knowledge(
    request: KnowledgeVerifiedSearchRequest,
    service: KnowledgeServiceDependency,
) -> list[KnowledgeSearchResult]:
    """Search knowledge supported by verified evidence."""

    return service.search_verified_knowledge(
        request.text,
        evidence_types=request.evidence_types,
        minimum_confidence_score=request.minimum_confidence_score,
        include_unpublished=request.include_unpublished,
        limit=request.limit,
    )


@router.post(
    "/publication-readiness",
    response_model=PublicationReadiness,
)
def assess_publication_readiness(
    knowledge: EngineeringKnowledge,
    service: KnowledgeServiceDependency,
) -> PublicationReadiness:
    """Assess a knowledge record without storing it."""

    return service.assess_publication_readiness(knowledge)


@router.get(
    "",
    response_model=list[EngineeringKnowledge],
)
def list_knowledge(
    service: KnowledgeServiceDependency,
    include_unpublished: bool = Query(
        default=False,
        description="Include draft and other unpublished records.",
    ),
) -> list[EngineeringKnowledge]:
    """List visible engineering knowledge records."""

    return service.list_knowledge(
        include_unpublished=include_unpublished,
    )


@router.post(
    "",
    response_model=EngineeringKnowledge,
    status_code=201,
)
def register_knowledge(
    knowledge: EngineeringKnowledge,
    service: KnowledgeServiceDependency,
) -> EngineeringKnowledge:
    """Register a new controlled engineering knowledge record."""

    try:
        return service.register(knowledge)
    except Exception as error:
        _raise_api_error(error)
        raise


@router.put(
    "",
    response_model=EngineeringKnowledge,
)
def upsert_knowledge(
    knowledge: EngineeringKnowledge,
    service: KnowledgeServiceDependency,
) -> EngineeringKnowledge:
    """Register or revise engineering knowledge."""

    try:
        return service.upsert(knowledge)
    except Exception as error:
        _raise_api_error(error)
        raise


@router.get(
    "/{knowledge_id}/summary",
    response_model=KnowledgeSummary,
)
def get_knowledge_summary(
    knowledge_id: str,
    service: KnowledgeServiceDependency,
    include_unpublished: bool = Query(
        default=False,
        description="Allow retrieval of an unpublished record.",
    ),
) -> KnowledgeSummary:
    """Return a compact summary for one knowledge record."""

    try:
        return service.get_summary(
            knowledge_id,
            include_unpublished=include_unpublished,
        )
    except Exception as error:
        _raise_api_error(error)
        raise


@router.get(
    "/{knowledge_id}/history",
    response_model=list[EngineeringKnowledge],
)
def get_knowledge_history(
    knowledge_id: str,
    service: KnowledgeServiceDependency,
) -> list[EngineeringKnowledge]:
    """Return prior revisions for one knowledge record."""

    try:
        service.ensure_exists(
            knowledge_id,
            include_unpublished=True,
        )
        return service.get_history(knowledge_id)
    except Exception as error:
        _raise_api_error(error)
        raise


@router.get(
    "/{knowledge_id}/publication-readiness",
    response_model=PublicationReadiness,
)
def get_publication_readiness(
    knowledge_id: str,
    service: KnowledgeServiceDependency,
    include_unpublished: bool = Query(
        default=True,
        description="Allow readiness checks for unpublished records.",
    ),
) -> PublicationReadiness:
    """Assess publication readiness for a stored knowledge record."""

    try:
        knowledge = service.get(
            knowledge_id,
            include_unpublished=include_unpublished,
        )
        return service.assess_publication_readiness(knowledge)
    except Exception as error:
        _raise_api_error(error)
        raise


@router.get(
    "/{knowledge_id}",
    response_model=EngineeringKnowledge,
)
def get_knowledge(
    knowledge_id: str,
    service: KnowledgeServiceDependency,
    include_unpublished: bool = Query(
        default=False,
        description="Allow retrieval of an unpublished record.",
    ),
) -> EngineeringKnowledge:
    """Retrieve engineering knowledge by identifier."""

    try:
        return service.get(
            knowledge_id,
            include_unpublished=include_unpublished,
        )
    except Exception as error:
        _raise_api_error(error)
        raise


@router.put(
    "/{knowledge_id}",
    response_model=EngineeringKnowledge,
)
def revise_knowledge(
    knowledge_id: str,
    knowledge: EngineeringKnowledge,
    service: KnowledgeServiceDependency,
) -> EngineeringKnowledge:
    """Store a new revision of existing engineering knowledge."""

    if knowledge.knowledge_id != knowledge_id:
        raise HTTPException(
            status_code=422,
            detail=(
                "The path knowledge identifier must match the "
                "knowledge_id in the request body."
            ),
        )

    try:
        return service.revise(knowledge)
    except Exception as error:
        _raise_api_error(error)
        raise


@router.delete(
    "/{knowledge_id}",
    status_code=204,
)
def delete_knowledge(
    knowledge_id: str,
    service: KnowledgeServiceDependency,
) -> Response:
    """Permanently delete knowledge and its revision history."""

    try:
        service.delete(knowledge_id)
    except Exception as error:
        _raise_api_error(error)
        raise

    return Response(status_code=204)