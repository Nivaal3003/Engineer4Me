"""Application service for Engineer4Me engineering knowledge.

The service provides the controlled business-logic layer between API or AI
workflows and the engineering knowledge repository.

Responsibilities include:

- registering and revising controlled engineering knowledge;
- enforcing publication-readiness requirements;
- protecting published knowledge from unsafe direct replacement;
- providing vendor-neutral structured search;
- prioritising safety-critical and stop-work guidance;
- exposing evidence, confidence, and review-readiness summaries;
- preparing the platform for future database, RAG, document-ingestion,
  fault-code, and legacy-equipment services.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from enum import StrEnum
from typing import Iterable

from pydantic import Field

from app.engineering.knowledge_models import (
    EngineeringBaseModel,
    EngineeringKnowledge,
    EvidenceType,
    KnowledgeStatus,
    ReviewDecision,
    ReviewType,
)
from app.engineering.knowledge_repository import (
    KnowledgeNotFoundError,
    KnowledgeRepository,
    KnowledgeSearchQuery,
    KnowledgeSearchResult,
    SearchSortOrder,
)


class KnowledgeServiceError(Exception):
    """Base exception raised by the engineering knowledge service."""


class KnowledgePublicationError(KnowledgeServiceError):
    """Raised when engineering knowledge is not ready for publication."""


class KnowledgeWorkflowError(KnowledgeServiceError):
    """Raised when an invalid knowledge workflow operation is requested."""


class PublicationRequirement(StrEnum):
    """Controlled requirements checked before knowledge publication."""

    PUBLISHED_STATUS = "published_status"
    TECHNICAL_REVIEW = "technical_review"
    SAFETY_REVIEW = "safety_review"
    STANDARDS_REVIEW = "standards_review"
    FINAL_APPROVAL = "final_approval"
    VERIFIED_EVIDENCE = "verified_evidence"
    CONFIDENCE_SCORE = "confidence_score"
    REVISION_METADATA = "revision_metadata"


class PublicationCheck(EngineeringBaseModel):
    """Result of one publication-readiness requirement."""

    requirement: PublicationRequirement
    passed: bool
    message: str


class PublicationReadiness(EngineeringBaseModel):
    """Publication-readiness assessment for engineering knowledge."""

    knowledge_id: str
    ready: bool
    checks: list[PublicationCheck] = Field(default_factory=list)
    failed_requirements: list[PublicationRequirement] = Field(
        default_factory=list
    )
    verified_evidence_count: int = Field(default=0, ge=0)
    approved_review_count: int = Field(default=0, ge=0)
    confidence_score: float = Field(ge=0.0, le=100.0)


class KnowledgeSummary(EngineeringBaseModel):
    """Safe summary of one controlled engineering knowledge record."""

    knowledge_id: str
    title: str
    status: KnowledgeStatus
    confidence_score: float = Field(ge=0.0, le=100.0)
    revision: str
    evidence_count: int = Field(default=0, ge=0)
    verified_evidence_count: int = Field(default=0, ge=0)
    approved_review_count: int = Field(default=0, ge=0)
    has_safety_guidance: bool = False
    blocks_work_until_resolved: bool = False


class KnowledgeServiceStatistics(EngineeringBaseModel):
    """Aggregate knowledge-service statistics."""

    total_records: int = Field(default=0, ge=0)
    published_records: int = Field(default=0, ge=0)
    unpublished_records: int = Field(default=0, ge=0)
    records_with_safety_guidance: int = Field(default=0, ge=0)
    blocking_safety_records: int = Field(default=0, ge=0)
    records_with_verified_evidence: int = Field(default=0, ge=0)
    status_counts: dict[str, int] = Field(default_factory=dict)
    evidence_type_counts: dict[str, int] = Field(default_factory=dict)


class EngineeringKnowledgeService:
    """Coordinate controlled engineering knowledge workflows."""

    _REQUIRED_REVIEW_TYPES = (
        ReviewType.TECHNICAL,
        ReviewType.SAFETY,
        ReviewType.STANDARDS,
        ReviewType.FINAL_APPROVAL,
    )

    def __init__(
        self,
        repository: KnowledgeRepository | None = None,
    ) -> None:
        """Initialise the service with an optional repository."""

        self._repository = repository or KnowledgeRepository()

    @property
    def repository(self) -> KnowledgeRepository:
        """Return the configured repository."""

        return self._repository

    def register(
        self,
        knowledge: EngineeringKnowledge,
    ) -> EngineeringKnowledge:
        """Register a new controlled engineering knowledge record.

        Published records must satisfy all service publication requirements.
        Draft records may be registered while review work is still incomplete.
        """

        if knowledge.status == KnowledgeStatus.PUBLISHED:
            self.require_publication_ready(knowledge)

        return self._repository.add(knowledge)

    def register_many(
        self,
        records: Iterable[EngineeringKnowledge],
    ) -> list[EngineeringKnowledge]:
        """Register several knowledge records in input order.

        The method validates every record before writing any of them so an
        invalid published record cannot cause a partial bulk registration.
        """

        prepared = [deepcopy(record) for record in records]

        for record in prepared:
            if record.status == KnowledgeStatus.PUBLISHED:
                self.require_publication_ready(record)

        registered: list[EngineeringKnowledge] = []

        for record in prepared:
            registered.append(self._repository.add(record))

        return registered

    def revise(
        self,
        knowledge: EngineeringKnowledge,
    ) -> EngineeringKnowledge:
        """Store a new revision of existing engineering knowledge.

        Published revisions must remain publication-ready. The repository
        enforces that the revision value changes and preserves history.
        """

        if knowledge.status == KnowledgeStatus.PUBLISHED:
            self.require_publication_ready(knowledge)

        return self._repository.update(knowledge)

    def upsert(
        self,
        knowledge: EngineeringKnowledge,
    ) -> EngineeringKnowledge:
        """Register or revise engineering knowledge."""

        if knowledge.status == KnowledgeStatus.PUBLISHED:
            self.require_publication_ready(knowledge)

        return self._repository.upsert(knowledge)

    def get(
        self,
        knowledge_id: str,
        *,
        include_unpublished: bool = False,
    ) -> EngineeringKnowledge:
        """Retrieve engineering knowledge by identifier."""

        return self._repository.get(
            knowledge_id,
            include_unpublished=include_unpublished,
        )

    def get_history(
        self,
        knowledge_id: str,
    ) -> list[EngineeringKnowledge]:
        """Retrieve prior revisions for one knowledge record."""

        return self._repository.get_history(knowledge_id)

    def list_knowledge(
        self,
        *,
        include_unpublished: bool = False,
    ) -> list[EngineeringKnowledge]:
        """List visible engineering knowledge."""

        return self._repository.list_all(
            include_unpublished=include_unpublished,
        )

    def delete(
        self,
        knowledge_id: str,
    ) -> None:
        """Delete knowledge and its revision history.

        Permanent deletion should be restricted to administrative workflows.
        Future persistent repositories can replace this with archival or
        retention-policy behaviour.
        """

        self._repository.delete(knowledge_id)

    def search(
        self,
        query: KnowledgeSearchQuery,
    ) -> list[KnowledgeSearchResult]:
        """Perform structured engineering knowledge search."""

        return self._repository.search(query)

    def search_text(
        self,
        text: str,
        *,
        include_unpublished: bool = False,
        limit: int = 25,
    ) -> list[KnowledgeSearchResult]:
        """Perform general vendor-neutral text search."""

        return self._repository.search_text(
            text,
            include_unpublished=include_unpublished,
            limit=limit,
        )

    def search_safety_guidance(
        self,
        text: str | None = None,
        *,
        blocking_only: bool = False,
        minimum_confidence_score: float = 0.0,
        include_unpublished: bool = False,
        limit: int = 25,
    ) -> list[KnowledgeSearchResult]:
        """Search safety guidance with safety-priority ordering."""

        return self._repository.search(
            KnowledgeSearchQuery(
                text=text,
                safety_guidance_required=True,
                blocking_safety_only=blocking_only,
                minimum_confidence_score=minimum_confidence_score,
                include_unpublished=include_unpublished,
                sort_order=SearchSortOrder.SAFETY_PRIORITY,
                limit=limit,
            )
        )

    def search_verified_knowledge(
        self,
        text: str | None = None,
        *,
        evidence_types: list[EvidenceType] | None = None,
        minimum_confidence_score: float = 0.0,
        include_unpublished: bool = False,
        limit: int = 25,
    ) -> list[KnowledgeSearchResult]:
        """Search knowledge supported by verified evidence."""

        return self._repository.search(
            KnowledgeSearchQuery(
                text=text,
                verified_evidence_only=True,
                evidence_types=evidence_types or [],
                minimum_confidence_score=minimum_confidence_score,
                include_unpublished=include_unpublished,
                sort_order=SearchSortOrder.CONFIDENCE,
                limit=limit,
            )
        )

    def assess_publication_readiness(
        self,
        knowledge: EngineeringKnowledge,
    ) -> PublicationReadiness:
        """Assess whether a record meets controlled publication requirements."""

        checks: list[PublicationCheck] = []

        checks.append(
            PublicationCheck(
                requirement=PublicationRequirement.PUBLISHED_STATUS,
                passed=knowledge.status == KnowledgeStatus.PUBLISHED,
                message=(
                    "Knowledge status is published."
                    if knowledge.status == KnowledgeStatus.PUBLISHED
                    else "Knowledge status must be published."
                ),
            )
        )

        approved_reviews = [
            review
            for review in knowledge.reviews
            if review.decision == ReviewDecision.APPROVED
        ]

        approved_review_types = {
            review.review_type for review in approved_reviews
        }

        review_requirements = (
            (
                ReviewType.TECHNICAL,
                PublicationRequirement.TECHNICAL_REVIEW,
                "technical",
            ),
            (
                ReviewType.SAFETY,
                PublicationRequirement.SAFETY_REVIEW,
                "safety",
            ),
            (
                ReviewType.STANDARDS,
                PublicationRequirement.STANDARDS_REVIEW,
                "standards",
            ),
            (
                ReviewType.FINAL_APPROVAL,
                PublicationRequirement.FINAL_APPROVAL,
                "final approval",
            ),
        )

        for review_type, requirement, label in review_requirements:
            passed = review_type in approved_review_types
            checks.append(
                PublicationCheck(
                    requirement=requirement,
                    passed=passed,
                    message=(
                        f"Approved {label} review is present."
                        if passed
                        else f"Approved {label} review is required."
                    ),
                )
            )

        verified_evidence_count = sum(
            item.verified for item in knowledge.evidence
        )

        checks.append(
            PublicationCheck(
                requirement=PublicationRequirement.VERIFIED_EVIDENCE,
                passed=verified_evidence_count > 0,
                message=(
                    "At least one verified evidence source is present."
                    if verified_evidence_count > 0
                    else "At least one verified evidence source is required."
                ),
            )
        )

        checks.append(
            PublicationCheck(
                requirement=PublicationRequirement.CONFIDENCE_SCORE,
                passed=knowledge.confidence_score > 0.0,
                message=(
                    "A positive confidence score is present."
                    if knowledge.confidence_score > 0.0
                    else "A positive confidence score is required."
                ),
            )
        )

        revision = knowledge.revision_metadata.revision.strip()
        created_by = knowledge.revision_metadata.created_by.strip()

        revision_metadata_valid = bool(revision and created_by)

        checks.append(
            PublicationCheck(
                requirement=PublicationRequirement.REVISION_METADATA,
                passed=revision_metadata_valid,
                message=(
                    "Revision metadata is complete."
                    if revision_metadata_valid
                    else (
                        "Revision and responsible creator are required "
                        "before publication."
                    )
                ),
            )
        )

        failed_requirements = [
            check.requirement for check in checks if not check.passed
        ]

        return PublicationReadiness(
            knowledge_id=knowledge.knowledge_id,
            ready=not failed_requirements,
            checks=checks,
            failed_requirements=failed_requirements,
            verified_evidence_count=verified_evidence_count,
            approved_review_count=len(approved_reviews),
            confidence_score=knowledge.confidence_score,
        )

    def require_publication_ready(
        self,
        knowledge: EngineeringKnowledge,
    ) -> PublicationReadiness:
        """Require knowledge to satisfy all publication controls.

        Raises:
            KnowledgePublicationError: If one or more requirements fail.
        """

        readiness = self.assess_publication_readiness(knowledge)

        if readiness.ready:
            return readiness

        failed = ", ".join(
            requirement.value
            for requirement in readiness.failed_requirements
        )

        raise KnowledgePublicationError(
            "Engineering knowledge is not ready for publication. "
            f"Knowledge ID: {knowledge.knowledge_id}. "
            f"Failed requirements: {failed}."
        )

    def get_summary(
        self,
        knowledge_id: str,
        *,
        include_unpublished: bool = False,
    ) -> KnowledgeSummary:
        """Return a compact evidence and safety summary."""

        knowledge = self.get(
            knowledge_id,
            include_unpublished=include_unpublished,
        )

        return self._build_summary(knowledge)

    def list_summaries(
        self,
        *,
        include_unpublished: bool = False,
    ) -> list[KnowledgeSummary]:
        """Return summaries for all visible records."""

        return [
            self._build_summary(record)
            for record in self.list_knowledge(
                include_unpublished=include_unpublished
            )
        ]

    def get_statistics(self) -> KnowledgeServiceStatistics:
        """Return aggregate statistics including unpublished records."""

        records = self._repository.list_all(include_unpublished=True)

        status_counts = Counter(record.status.value for record in records)

        evidence_type_counts: Counter[str] = Counter()

        for record in records:
            evidence_type_counts.update(
                evidence.evidence_type.value
                for evidence in record.evidence
            )

        published_records = sum(
            record.status == KnowledgeStatus.PUBLISHED
            for record in records
        )

        records_with_safety_guidance = sum(
            record.safety is not None for record in records
        )

        blocking_safety_records = sum(
            record.safety is not None
            and record.safety.blocks_work_until_resolved
            for record in records
        )

        records_with_verified_evidence = sum(
            any(evidence.verified for evidence in record.evidence)
            for record in records
        )

        return KnowledgeServiceStatistics(
            total_records=len(records),
            published_records=published_records,
            unpublished_records=len(records) - published_records,
            records_with_safety_guidance=records_with_safety_guidance,
            blocking_safety_records=blocking_safety_records,
            records_with_verified_evidence=records_with_verified_evidence,
            status_counts=dict(sorted(status_counts.items())),
            evidence_type_counts=dict(
                sorted(evidence_type_counts.items())
            ),
        )

    def ensure_exists(
        self,
        knowledge_id: str,
        *,
        include_unpublished: bool = False,
    ) -> None:
        """Ensure a knowledge identifier exists and is visible.

        Raises:
            KnowledgeNotFoundError: If no visible record exists.
        """

        self.get(
            knowledge_id,
            include_unpublished=include_unpublished,
        )

    @staticmethod
    def _build_summary(
        knowledge: EngineeringKnowledge,
    ) -> KnowledgeSummary:
        """Build a compact summary from a knowledge record."""

        approved_review_count = sum(
            review.decision == ReviewDecision.APPROVED
            for review in knowledge.reviews
        )

        verified_evidence_count = sum(
            evidence.verified for evidence in knowledge.evidence
        )

        return KnowledgeSummary(
            knowledge_id=knowledge.knowledge_id,
            title=knowledge.title,
            status=knowledge.status,
            confidence_score=knowledge.confidence_score,
            revision=knowledge.revision_metadata.revision,
            evidence_count=len(knowledge.evidence),
            verified_evidence_count=verified_evidence_count,
            approved_review_count=approved_review_count,
            has_safety_guidance=knowledge.safety is not None,
            blocks_work_until_resolved=(
                knowledge.safety is not None
                and knowledge.safety.blocks_work_until_resolved
            ),
        )
