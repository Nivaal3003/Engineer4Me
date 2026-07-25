"""Tests for the Engineer4Me engineering knowledge service."""

from datetime import UTC, datetime

import pytest

from app.engineering.knowledge_models import (
    EngineeringDiscipline,
    EngineeringKnowledge,
    EquipmentApplicability,
    EvidenceReference,
    EvidenceStrength,
    EvidenceType,
    KnowledgeCategory,
    KnowledgeReview,
    KnowledgeStatus,
    ReviewDecision,
    ReviewType,
    RevisionMetadata,
    SafetyGuidance,
    SafetySeverity,
)
from app.engineering.knowledge_repository import (
    KnowledgeNotFoundError,
    KnowledgeRepository,
    KnowledgeSearchQuery,
)
from app.engineering.knowledge_service import (
    EngineeringKnowledgeService,
    KnowledgePublicationError,
    PublicationRequirement,
)


def build_verified_evidence(
    evidence_id: str = "EVD-001",
    evidence_type: EvidenceType = EvidenceType.OEM_MANUAL,
) -> EvidenceReference:
    """Create verified engineering evidence."""

    return EvidenceReference(
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        title="Industrial pressure transmitter manual",
        publisher_or_owner="Example OEM",
        strength=EvidenceStrength.HIGH,
        verified=True,
        verified_by="Senior Instrumentation Engineer",
        verified_at=datetime.now(UTC),
    )


def build_approved_review(
    review_type: ReviewType,
) -> KnowledgeReview:
    """Create a completed approved engineering review."""

    return KnowledgeReview(
        review_type=review_type,
        decision=ReviewDecision.APPROVED,
        reviewer_name="Engineering Reviewer",
        reviewer_role="Lead Engineer",
        reviewed_at=datetime.now(UTC),
    )


def build_published_knowledge(
    *,
    knowledge_id: str = "KNOW-001",
    title: str = "Pressure transmitter installation",
    confidence_score: float = 85.0,
    evidence_type: EvidenceType = EvidenceType.OEM_MANUAL,
    safety: SafetyGuidance | None = None,
) -> EngineeringKnowledge:
    """Create publication-ready engineering knowledge."""

    return EngineeringKnowledge(
        knowledge_id=knowledge_id,
        title=title,
        subject="Pressure measurement",
        summary=(
            "Evidence-based guidance for pressure transmitter installation."
        ),
        detailed_guidance=(
            "Confirm process conditions, isolate the process, inspect the "
            "connection, install the transmitter, and verify operation."
        ),
        discipline=EngineeringDiscipline.INSTRUMENTATION,
        categories=[
            KnowledgeCategory.INSTALLATION,
            KnowledgeCategory.VERIFICATION,
        ],
        status=KnowledgeStatus.PUBLISHED,
        taxonomy_ids=["instrument.pressure.transmitter"],
        semantic_tags=[
            "pressure transmitter",
            "installation",
            "impulse line",
        ],
        equipment_applicability=[
            EquipmentApplicability(
                equipment_category="Process Instrumentation",
                equipment_type="Pressure Transmitter",
                measurement_principle="Piezoresistive",
                manufacturer="Example OEM",
                model_family="PX Series",
                models=["PX100", "PX200"],
                components=["sensor", "electronics module"],
            )
        ],
        safety=safety,
        evidence=[
            build_verified_evidence(
                evidence_type=evidence_type,
            )
        ],
        reviews=[
            build_approved_review(ReviewType.TECHNICAL),
            build_approved_review(ReviewType.SAFETY),
            build_approved_review(ReviewType.STANDARDS),
            build_approved_review(ReviewType.FINAL_APPROVAL),
        ],
        revision_metadata=RevisionMetadata(
            revision="1.0",
            created_by="Engineer4Me test suite",
        ),
        confidence_score=confidence_score,
    )


def build_draft_knowledge(
    *,
    knowledge_id: str = "DRAFT-001",
    title: str = "Draft troubleshooting guidance",
) -> EngineeringKnowledge:
    """Create valid draft engineering knowledge."""

    return EngineeringKnowledge(
        knowledge_id=knowledge_id,
        title=title,
        subject="Draft engineering content",
        summary="Draft guidance awaiting controlled review.",
        detailed_guidance="Draft technical guidance.",
        discipline=EngineeringDiscipline.INSTRUMENTATION,
        categories=[KnowledgeCategory.TROUBLESHOOTING],
        revision_metadata=RevisionMetadata(
            revision="1.0",
            created_by="Engineer4Me test suite",
        ),
    )


def build_blocking_safety() -> SafetyGuidance:
    """Create stop-work safety guidance."""

    return SafetyGuidance(
        safety_summary=(
            "Stop work until pressure isolation and zero-energy state "
            "are independently verified."
        ),
        severity=SafetySeverity.CRITICAL,
        blocks_work_until_resolved=True,
        required_site_risk_assessment=True,
    )


def test_service_uses_supplied_repository() -> None:
    """The configured repository should be exposed by the service."""

    repository = KnowledgeRepository()
    service = EngineeringKnowledgeService(repository)

    assert service.repository is repository


def test_service_creates_repository_when_not_supplied() -> None:
    """The service should create a repository by default."""

    service = EngineeringKnowledgeService()

    assert isinstance(service.repository, KnowledgeRepository)


def test_register_stores_publication_ready_knowledge() -> None:
    """Publication-ready knowledge should be registered."""

    service = EngineeringKnowledgeService()
    record = build_published_knowledge()

    stored = service.register(record)

    assert stored == record
    assert service.get("KNOW-001") == record


def test_register_allows_incomplete_draft() -> None:
    """Draft knowledge may be stored while reviews are incomplete."""

    service = EngineeringKnowledgeService()

    stored = service.register(build_draft_knowledge())

    assert stored.status == KnowledgeStatus.DRAFT
    assert service.get(
        "DRAFT-001",
        include_unpublished=True,
    ).status == KnowledgeStatus.DRAFT


def test_register_many_stores_records_in_input_order() -> None:
    """Bulk registration should preserve input order."""

    service = EngineeringKnowledgeService()

    records = [
        build_published_knowledge(
            knowledge_id="KNOW-001",
            title="Pressure guidance",
        ),
        build_published_knowledge(
            knowledge_id="KNOW-002",
            title="Flow guidance",
        ),
    ]

    stored = service.register_many(records)

    assert [record.knowledge_id for record in stored] == [
        "KNOW-001",
        "KNOW-002",
    ]


def test_register_many_validates_before_writing() -> None:
    """Failed bulk validation must not partially populate the repository."""

    service = EngineeringKnowledgeService()

    valid = build_published_knowledge()
    invalid = build_published_knowledge(
        knowledge_id="KNOW-002",
    )
    invalid.confidence_score = 0.0

    with pytest.raises(KnowledgePublicationError):
        service.register_many([valid, invalid])

    assert service.repository.count(include_unpublished=True) == 0


def test_publication_readiness_passes_complete_record() -> None:
    """Complete published knowledge should pass every service check."""

    service = EngineeringKnowledgeService()

    readiness = service.assess_publication_readiness(
        build_published_knowledge()
    )

    assert readiness.ready is True
    assert readiness.failed_requirements == []
    assert readiness.verified_evidence_count == 1
    assert readiness.approved_review_count == 4
    assert all(check.passed for check in readiness.checks)


def test_draft_is_not_publication_ready() -> None:
    """A draft should fail publication controls."""

    service = EngineeringKnowledgeService()

    readiness = service.assess_publication_readiness(
        build_draft_knowledge()
    )

    assert readiness.ready is False
    assert PublicationRequirement.PUBLISHED_STATUS in (
        readiness.failed_requirements
    )
    assert PublicationRequirement.TECHNICAL_REVIEW in (
        readiness.failed_requirements
    )
    assert PublicationRequirement.VERIFIED_EVIDENCE in (
        readiness.failed_requirements
    )


def test_positive_confidence_is_required_for_publication() -> None:
    """Published knowledge must have a positive confidence score."""

    service = EngineeringKnowledgeService()
    record = build_published_knowledge()
    record.confidence_score = 0.0

    readiness = service.assess_publication_readiness(record)

    assert readiness.ready is False
    assert PublicationRequirement.CONFIDENCE_SCORE in (
        readiness.failed_requirements
    )


def test_require_publication_ready_returns_assessment() -> None:
    """The publication guard should return successful readiness details."""

    service = EngineeringKnowledgeService()

    readiness = service.require_publication_ready(
        build_published_knowledge()
    )

    assert readiness.ready is True
    assert readiness.knowledge_id == "KNOW-001"


def test_require_publication_ready_raises_descriptive_error() -> None:
    """The publication guard should identify failed controls."""

    service = EngineeringKnowledgeService()

    with pytest.raises(
        KnowledgePublicationError,
        match="published_status",
    ):
        service.require_publication_ready(
            build_draft_knowledge()
        )


def test_revise_stores_new_revision_and_history() -> None:
    """The service should preserve history when revising knowledge."""

    original = build_published_knowledge()
    service = EngineeringKnowledgeService(
        KnowledgeRepository([original])
    )

    revised = original.model_copy(deep=True)
    revised.title = "Revised pressure transmitter installation"
    revised.revision_metadata.revision = "2.0"
    revised.revision_metadata.previous_revision = "1.0"
    revised.revision_metadata.updated_by = "Service Test"
    revised.revision_metadata.updated_at = datetime.now(UTC)

    stored = service.revise(revised)
    history = service.get_history("KNOW-001")

    assert stored.revision_metadata.revision == "2.0"
    assert len(history) == 1
    assert history[0].revision_metadata.revision == "1.0"


def test_upsert_registers_unknown_record() -> None:
    """Upsert should register a previously unknown knowledge record."""

    service = EngineeringKnowledgeService()

    stored = service.upsert(build_published_knowledge())

    assert stored.knowledge_id == "KNOW-001"


def test_upsert_revises_existing_record() -> None:
    """Upsert should revise an existing knowledge record."""

    original = build_published_knowledge()
    service = EngineeringKnowledgeService(
        KnowledgeRepository([original])
    )

    revised = original.model_copy(deep=True)
    revised.title = "Updated installation guidance"
    revised.revision_metadata.revision = "2.0"

    stored = service.upsert(revised)

    assert stored.revision_metadata.revision == "2.0"
    assert service.get("KNOW-001").title == (
        "Updated installation guidance"
    )


def test_list_knowledge_hides_drafts_by_default() -> None:
    """Public service listings should hide draft records."""

    service = EngineeringKnowledgeService(
        KnowledgeRepository(
            [
                build_published_knowledge(),
                build_draft_knowledge(),
            ]
        )
    )

    records = service.list_knowledge()

    assert [record.knowledge_id for record in records] == [
        "KNOW-001"
    ]


def test_list_knowledge_can_include_drafts() -> None:
    """Internal service listings may include unpublished records."""

    service = EngineeringKnowledgeService(
        KnowledgeRepository(
            [
                build_published_knowledge(),
                build_draft_knowledge(),
            ]
        )
    )

    records = service.list_knowledge(include_unpublished=True)

    assert {record.knowledge_id for record in records} == {
        "KNOW-001",
        "DRAFT-001",
    }


def test_search_delegates_structured_query() -> None:
    """Structured service search should return repository results."""

    service = EngineeringKnowledgeService(
        KnowledgeRepository([build_published_knowledge()])
    )

    results = service.search(
        KnowledgeSearchQuery(
            disciplines=[
                EngineeringDiscipline.INSTRUMENTATION
            ]
        )
    )

    assert len(results) == 1
    assert results[0].knowledge.knowledge_id == "KNOW-001"


def test_search_text_returns_matching_knowledge() -> None:
    """Text search should expose vendor-neutral repository search."""

    service = EngineeringKnowledgeService(
        KnowledgeRepository([build_published_knowledge()])
    )

    results = service.search_text("pressure transmitter")

    assert len(results) == 1
    assert results[0].relevance_score > 0


def test_search_safety_guidance_returns_safety_records_only() -> None:
    """Safety search should exclude records without safety guidance."""

    service = EngineeringKnowledgeService(
        KnowledgeRepository(
            [
                build_published_knowledge(
                    knowledge_id="SAFE-001",
                    title="Pressure isolation",
                    safety=build_blocking_safety(),
                ),
                build_published_knowledge(
                    knowledge_id="NORMAL-001",
                    title="Normal inspection",
                ),
            ]
        )
    )

    results = service.search_safety_guidance()

    assert [result.knowledge.knowledge_id for result in results] == [
        "SAFE-001"
    ]


def test_blocking_safety_search_returns_stop_work_guidance() -> None:
    """Blocking safety search should return stop-work content only."""

    warning = SafetyGuidance(
        safety_summary="Wear the required personal protective equipment.",
        severity=SafetySeverity.WARNING,
    )

    service = EngineeringKnowledgeService(
        KnowledgeRepository(
            [
                build_published_knowledge(
                    knowledge_id="BLOCK-001",
                    title="Blocking isolation guidance",
                    safety=build_blocking_safety(),
                ),
                build_published_knowledge(
                    knowledge_id="WARN-001",
                    title="Inspection warning",
                    safety=warning,
                ),
            ]
        )
    )

    results = service.search_safety_guidance(
        blocking_only=True
    )

    assert [result.knowledge.knowledge_id for result in results] == [
        "BLOCK-001"
    ]


def test_verified_search_filters_by_evidence_type() -> None:
    """Verified searches should support evidence-type filtering."""

    service = EngineeringKnowledgeService(
        KnowledgeRepository(
            [
                build_published_knowledge(
                    knowledge_id="OEM-001",
                    evidence_type=EvidenceType.OEM_MANUAL,
                ),
                build_published_knowledge(
                    knowledge_id="STD-001",
                    evidence_type=EvidenceType.INTERNATIONAL_STANDARD,
                ),
            ]
        )
    )

    results = service.search_verified_knowledge(
        evidence_types=[EvidenceType.INTERNATIONAL_STANDARD]
    )

    assert [result.knowledge.knowledge_id for result in results] == [
        "STD-001"
    ]


def test_get_summary_reports_evidence_reviews_and_safety() -> None:
    """Knowledge summaries should expose controlled trust indicators."""

    service = EngineeringKnowledgeService(
        KnowledgeRepository(
            [
                build_published_knowledge(
                    safety=build_blocking_safety()
                )
            ]
        )
    )

    summary = service.get_summary("KNOW-001")

    assert summary.evidence_count == 1
    assert summary.verified_evidence_count == 1
    assert summary.approved_review_count == 4
    assert summary.has_safety_guidance is True
    assert summary.blocks_work_until_resolved is True


def test_list_summaries_respects_visibility() -> None:
    """Summary listings should use normal publication visibility."""

    service = EngineeringKnowledgeService(
        KnowledgeRepository(
            [
                build_published_knowledge(),
                build_draft_knowledge(),
            ]
        )
    )

    public_summaries = service.list_summaries()
    all_summaries = service.list_summaries(
        include_unpublished=True
    )

    assert len(public_summaries) == 1
    assert len(all_summaries) == 2


def test_statistics_include_published_and_draft_records() -> None:
    """Statistics should include all controlled records."""

    service = EngineeringKnowledgeService(
        KnowledgeRepository(
            [
                build_published_knowledge(
                    safety=build_blocking_safety()
                ),
                build_draft_knowledge(),
            ]
        )
    )

    statistics = service.get_statistics()

    assert statistics.total_records == 2
    assert statistics.published_records == 1
    assert statistics.unpublished_records == 1
    assert statistics.records_with_safety_guidance == 1
    assert statistics.blocking_safety_records == 1
    assert statistics.records_with_verified_evidence == 1
    assert statistics.status_counts["published"] == 1
    assert statistics.status_counts["draft"] == 1
    assert statistics.evidence_type_counts["oem_manual"] == 1


def test_ensure_exists_accepts_visible_record() -> None:
    """Existence checks should pass for visible knowledge."""

    service = EngineeringKnowledgeService(
        KnowledgeRepository([build_published_knowledge()])
    )

    result = service.ensure_exists("KNOW-001")

    assert result is None


def test_ensure_exists_rejects_unknown_record() -> None:
    """Existence checks should preserve repository not-found errors."""

    service = EngineeringKnowledgeService()

    with pytest.raises(KnowledgeNotFoundError):
        service.ensure_exists("UNKNOWN")


def test_ensure_exists_respects_draft_visibility() -> None:
    """Draft existence should require explicit internal visibility."""

    service = EngineeringKnowledgeService(
        KnowledgeRepository([build_draft_knowledge()])
    )

    with pytest.raises(KnowledgeNotFoundError):
        service.ensure_exists("DRAFT-001")

    service.ensure_exists(
        "DRAFT-001",
        include_unpublished=True,
    )


def test_delete_removes_record() -> None:
    """Delete should remove the controlled knowledge record."""

    service = EngineeringKnowledgeService(
        KnowledgeRepository([build_published_knowledge()])
    )

    service.delete("KNOW-001")

    with pytest.raises(KnowledgeNotFoundError):
        service.get("KNOW-001")
