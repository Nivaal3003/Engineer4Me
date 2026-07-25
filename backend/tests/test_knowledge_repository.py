"""Tests for the Engineer4Me engineering knowledge repository."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.engineering.knowledge_models import (
    EngineeringDiscipline,
    EngineeringKnowledge,
    EnvironmentCondition,
    EnvironmentalConstraint,
    EquipmentApplicability,
    EvidenceReference,
    EvidenceStrength,
    EvidenceType,
    IndustryApplicability,
    IndustrySector,
    KnowledgeCategory,
    KnowledgeReview,
    KnowledgeStatus,
    ReviewDecision,
    ReviewType,
    RevisionMetadata,
    SafetyGuidance,
    SafetySeverity,
    StandardApplicability,
    StandardReference,
)
from app.engineering.knowledge_repository import (
    KnowledgeAlreadyExistsError,
    KnowledgeNotFoundError,
    KnowledgeRepository,
    KnowledgeRevisionError,
    KnowledgeSearchQuery,
    SearchSortOrder,
)


def build_verified_evidence(
    evidence_id: str = "EVD-001",
    evidence_type: EvidenceType = EvidenceType.OEM_MANUAL,
) -> EvidenceReference:
    """Create a valid verified evidence reference."""

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


def build_review(review_type: ReviewType) -> KnowledgeReview:
    """Create a completed approved review."""

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
    discipline: EngineeringDiscipline = EngineeringDiscipline.INSTRUMENTATION,
    confidence_score: float = 85.0,
    safety: SafetyGuidance | None = None,
) -> EngineeringKnowledge:
    """Create a valid published engineering knowledge record."""

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
        discipline=discipline,
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
        industry_applicability=[
            IndustryApplicability(
                industry=IndustrySector.MINING,
                process_area="Concentrator",
                typical_process_media=["slurry", "water"],
                typical_equipment=["pressure transmitter"],
                common_failure_modes=["blocked impulse line"],
            )
        ],
        environmental_constraints=[
            EnvironmentalConstraint(
                condition=EnvironmentCondition.HIGH_VIBRATION,
                description="Installation close to rotating equipment.",
                engineering_impact=(
                    "Vibration can loosen fittings and damage electronics."
                ),
            )
        ],
        safety=safety,
        standards=[
            StandardReference(
                organisation="IEC",
                standard_number="IEC 61511",
                title="Functional safety",
                applicability=StandardApplicability.RECOMMENDED,
            )
        ],
        evidence=[build_verified_evidence()],
        reviews=[
            build_review(ReviewType.TECHNICAL),
            build_review(ReviewType.SAFETY),
            build_review(ReviewType.STANDARDS),
            build_review(ReviewType.FINAL_APPROVAL),
        ],
        revision_metadata=RevisionMetadata(
            revision="1.0",
            created_by="Engineer4Me test suite",
        ),
        confidence_score=confidence_score,
    )


def build_draft_knowledge(
    knowledge_id: str = "DRAFT-001",
) -> EngineeringKnowledge:
    """Create a valid unpublished draft record."""

    return EngineeringKnowledge(
        knowledge_id=knowledge_id,
        title="Draft troubleshooting guidance",
        subject="Draft engineering content",
        summary="Draft guidance awaiting review.",
        detailed_guidance="Draft technical guidance.",
        discipline=EngineeringDiscipline.INSTRUMENTATION,
        categories=[KnowledgeCategory.TROUBLESHOOTING],
        revision_metadata=RevisionMetadata(
            revision="1.0",
            created_by="Engineer4Me test suite",
        ),
    )


def test_repository_adds_and_gets_published_knowledge() -> None:
    """Published knowledge should be retrievable by identifier."""

    repository = KnowledgeRepository()
    record = build_published_knowledge()

    stored = repository.add(record)
    retrieved = repository.get(record.knowledge_id)

    assert stored == record
    assert retrieved == record
    assert retrieved is not record


def test_repository_rejects_duplicate_identifier() -> None:
    """A knowledge ID cannot be added twice."""

    repository = KnowledgeRepository()
    record = build_published_knowledge()

    repository.add(record)

    with pytest.raises(
        KnowledgeAlreadyExistsError,
        match="already exists",
    ):
        repository.add(record)


def test_unpublished_record_is_hidden_by_default() -> None:
    """Draft knowledge should not be publicly retrievable."""

    repository = KnowledgeRepository([build_draft_knowledge()])

    with pytest.raises(
        KnowledgeNotFoundError,
        match="Published engineering knowledge was not found",
    ):
        repository.get("DRAFT-001")


def test_unpublished_record_can_be_retrieved_explicitly() -> None:
    """Internal callers may explicitly retrieve unpublished records."""

    repository = KnowledgeRepository([build_draft_knowledge()])

    record = repository.get(
        "DRAFT-001",
        include_unpublished=True,
    )

    assert record.status == KnowledgeStatus.DRAFT


def test_repository_returns_defensive_copies() -> None:
    """Changing a returned object must not change repository storage."""

    repository = KnowledgeRepository([build_published_knowledge()])

    retrieved = repository.get("KNOW-001")
    retrieved.title = "Changed outside repository"

    stored = repository.get("KNOW-001")

    assert stored.title == "Pressure transmitter installation"


def test_update_requires_existing_record() -> None:
    """Updating an unknown identifier should fail."""

    repository = KnowledgeRepository()

    with pytest.raises(
        KnowledgeNotFoundError,
        match="was not found",
    ):
        repository.update(build_published_knowledge())


def test_update_requires_new_revision() -> None:
    """Controlled knowledge cannot overwrite the same revision."""

    original = build_published_knowledge()
    repository = KnowledgeRepository([original])

    updated = original.model_copy(deep=True)
    updated.title = "Updated pressure transmitter installation"

    with pytest.raises(
        KnowledgeRevisionError,
        match="must use a new revision",
    ):
        repository.update(updated)


def test_update_preserves_previous_revision() -> None:
    """Updating a record should retain its previous revision."""

    original = build_published_knowledge()
    repository = KnowledgeRepository([original])

    updated = original.model_copy(deep=True)
    updated.title = "Revised pressure transmitter installation"
    updated.revision_metadata.revision = "2.0"
    updated.revision_metadata.previous_revision = "1.0"
    updated.revision_metadata.updated_by = "Repository Test"
    updated.revision_metadata.updated_at = datetime.now(UTC)

    repository.update(updated)

    current = repository.get("KNOW-001")
    history = repository.get_history("KNOW-001")

    assert current.revision_metadata.revision == "2.0"
    assert current.title == "Revised pressure transmitter installation"
    assert len(history) == 1
    assert history[0].revision_metadata.revision == "1.0"


def test_upsert_adds_new_record() -> None:
    """Upsert should add a record that does not exist."""

    repository = KnowledgeRepository()

    result = repository.upsert(build_published_knowledge())

    assert result.knowledge_id == "KNOW-001"
    assert repository.count() == 1


def test_upsert_updates_existing_record() -> None:
    """Upsert should revise a record that already exists."""

    original = build_published_knowledge()
    repository = KnowledgeRepository([original])

    updated = original.model_copy(deep=True)
    updated.revision_metadata.revision = "2.0"
    updated.title = "Updated installation guidance"

    result = repository.upsert(updated)

    assert result.revision_metadata.revision == "2.0"
    assert repository.get("KNOW-001").title == (
        "Updated installation guidance"
    )


def test_delete_removes_record_and_history() -> None:
    """Deleting a record should make it unavailable."""

    repository = KnowledgeRepository([build_published_knowledge()])

    repository.delete("KNOW-001")

    assert repository.count(include_unpublished=True) == 0

    with pytest.raises(KnowledgeNotFoundError):
        repository.get("KNOW-001")


def test_delete_unknown_record_fails() -> None:
    """Deleting an unknown identifier should raise an error."""

    repository = KnowledgeRepository()

    with pytest.raises(KnowledgeNotFoundError):
        repository.delete("UNKNOWN")


def test_count_hides_unpublished_records_by_default() -> None:
    """Public counts should include published records only."""

    repository = KnowledgeRepository(
        [
            build_published_knowledge(),
            build_draft_knowledge(),
        ]
    )

    assert repository.count() == 1
    assert repository.count(include_unpublished=True) == 2


def test_list_all_orders_records_by_title() -> None:
    """Visible records should be sorted alphabetically by title."""

    repository = KnowledgeRepository(
        [
            build_published_knowledge(
                knowledge_id="KNOW-B",
                title="Valve inspection",
            ),
            build_published_knowledge(
                knowledge_id="KNOW-A",
                title="Flowmeter installation",
            ),
        ]
    )

    records = repository.list_all()

    assert [record.knowledge_id for record in records] == [
        "KNOW-A",
        "KNOW-B",
    ]


def test_text_search_matches_title_and_tags() -> None:
    """Text search should match weighted engineering fields."""

    repository = KnowledgeRepository([build_published_knowledge()])

    results = repository.search_text("pressure transmitter")

    assert len(results) == 1
    assert results[0].knowledge.knowledge_id == "KNOW-001"
    assert results[0].relevance_score > 0
    assert "title" in results[0].matched_fields
    assert "semantic_tags" in results[0].matched_fields


def test_text_search_excludes_non_matching_records() -> None:
    """Records without matching search terms should not be returned."""

    repository = KnowledgeRepository([build_published_knowledge()])

    results = repository.search_text("gas chromatograph")

    assert results == []


def test_search_filters_by_discipline_and_category() -> None:
    """Structured discipline and category filters should be combined."""

    instrumentation = build_published_knowledge()
    electrical = build_published_knowledge(
        knowledge_id="ELEC-001",
        title="Electrical motor inspection",
        discipline=EngineeringDiscipline.ELECTRICAL,
    )

    repository = KnowledgeRepository([instrumentation, electrical])

    results = repository.search(
        KnowledgeSearchQuery(
            disciplines=[EngineeringDiscipline.INSTRUMENTATION],
            categories=[KnowledgeCategory.INSTALLATION],
        )
    )

    assert [result.knowledge.knowledge_id for result in results] == [
        "KNOW-001"
    ]


def test_search_filters_equipment_case_insensitively() -> None:
    """Equipment filters should be case-insensitive."""

    repository = KnowledgeRepository([build_published_knowledge()])

    results = repository.search(
        KnowledgeSearchQuery(
            manufacturers=["example oem"],
            model_families=["px series"],
            models=["px100"],
        )
    )

    assert len(results) == 1
    assert results[0].knowledge.knowledge_id == "KNOW-001"


def test_search_filters_by_industry_and_environment() -> None:
    """Industry and environmental filters should be applied."""

    repository = KnowledgeRepository([build_published_knowledge()])

    results = repository.search(
        KnowledgeSearchQuery(
            industries=[IndustrySector.MINING],
            environmental_conditions=[
                EnvironmentCondition.HIGH_VIBRATION
            ],
        )
    )

    assert len(results) == 1


def test_search_filters_by_standard_number() -> None:
    """Referenced engineering standards should be searchable."""

    repository = KnowledgeRepository([build_published_knowledge()])

    results = repository.search(
        KnowledgeSearchQuery(
            standard_numbers=["iec 61511"],
        )
    )

    assert len(results) == 1


def test_verified_evidence_filter_excludes_unverified_record() -> None:
    """Verified-only searches should exclude unsupported knowledge."""

    draft = build_draft_knowledge()
    draft.evidence = [
        EvidenceReference(
            evidence_id="EVD-DRAFT",
            evidence_type=EvidenceType.USER_EXPERIENCE,
            title="Unverified field report",
        )
    ]

    repository = KnowledgeRepository([draft])

    results = repository.search(
        KnowledgeSearchQuery(
            verified_evidence_only=True,
            include_unpublished=True,
        )
    )

    assert results == []


def test_blocking_safety_filter_requires_safety_guidance() -> None:
    """Blocking safety search should only return stop-work guidance."""

    blocking_safety = SafetyGuidance(
        safety_summary="Stop work until pressure isolation is verified.",
        severity=SafetySeverity.CRITICAL,
        blocks_work_until_resolved=True,
        required_site_risk_assessment=True,
    )

    repository = KnowledgeRepository(
        [
            build_published_knowledge(
                knowledge_id="SAFE-001",
                title="Pressure isolation safety",
                safety=blocking_safety,
            ),
            build_published_knowledge(
                knowledge_id="NORMAL-001",
                title="Normal transmitter inspection",
            ),
        ]
    )

    query = KnowledgeSearchQuery(blocking_safety_only=True)
    results = repository.search(query)

    assert query.safety_guidance_required is True
    assert [result.knowledge.knowledge_id for result in results] == [
        "SAFE-001"
    ]


def test_safety_priority_sort_places_blocking_record_first() -> None:
    """Stop-work safety guidance should rank before normal guidance."""

    blocking_safety = SafetyGuidance(
        safety_summary="Stop work until isolation is complete.",
        severity=SafetySeverity.CRITICAL,
        blocks_work_until_resolved=True,
        required_site_risk_assessment=True,
    )

    warning_safety = SafetyGuidance(
        safety_summary="Use caution during inspection.",
        severity=SafetySeverity.WARNING,
    )

    repository = KnowledgeRepository(
        [
            build_published_knowledge(
                knowledge_id="WARNING-001",
                title="Warning guidance",
                safety=warning_safety,
            ),
            build_published_knowledge(
                knowledge_id="BLOCK-001",
                title="Blocking guidance",
                safety=blocking_safety,
            ),
        ]
    )

    results = repository.search(
        KnowledgeSearchQuery(
            sort_order=SearchSortOrder.SAFETY_PRIORITY,
        )
    )

    assert results[0].knowledge.knowledge_id == "BLOCK-001"
    assert results[0].safety_priority > results[1].safety_priority


def test_confidence_sort_places_highest_confidence_first() -> None:
    """Confidence sorting should return the strongest record first."""

    repository = KnowledgeRepository(
        [
            build_published_knowledge(
                knowledge_id="LOW-001",
                title="Low confidence guidance",
                confidence_score=60.0,
            ),
            build_published_knowledge(
                knowledge_id="HIGH-001",
                title="High confidence guidance",
                confidence_score=95.0,
            ),
        ]
    )

    results = repository.search(
        KnowledgeSearchQuery(
            sort_order=SearchSortOrder.CONFIDENCE,
        )
    )

    assert results[0].knowledge.knowledge_id == "HIGH-001"


def test_search_limit_is_enforced() -> None:
    """Search results should respect the requested maximum."""

    repository = KnowledgeRepository(
        [
            build_published_knowledge(
                knowledge_id=f"KNOW-{index}",
                title=f"Pressure guidance {index}",
            )
            for index in range(5)
        ]
    )

    results = repository.search(
        KnowledgeSearchQuery(limit=2)
    )

    assert len(results) == 2


def test_invalid_search_limit_is_rejected() -> None:
    """Search limits outside the supported range should fail."""

    with pytest.raises(ValidationError):
        KnowledgeSearchQuery(limit=0)
