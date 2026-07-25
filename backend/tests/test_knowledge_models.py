"""Tests for the Engineer4Me engineering knowledge models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.engineering.knowledge_models import (
    EngineeringDiscipline,
    EngineeringKnowledge,
    EngineeringProcedure,
    EnvironmentCondition,
    EnvironmentalConstraint,
    EvidenceReference,
    EvidenceStrength,
    EvidenceType,
    KnowledgeCategory,
    KnowledgeReview,
    KnowledgeStatus,
    PreventiveMaintenanceTask,
    ProcedureStep,
    ReviewDecision,
    ReviewType,
    RevisionMetadata,
    SafetyGuidance,
    SafetySeverity,
)


def build_revision_metadata() -> RevisionMetadata:
    """Return valid revision metadata for knowledge model tests."""

    return RevisionMetadata(
        created_by="Engineer4Me test suite",
    )


def build_verified_evidence(
    evidence_id: str = "EVD-001",
) -> EvidenceReference:
    """Return a valid verified evidence source."""

    return EvidenceReference(
        evidence_id=evidence_id,
        evidence_type=EvidenceType.OEM_MANUAL,
        title="Pressure transmitter installation manual",
        publisher_or_owner="Example OEM",
        strength=EvidenceStrength.HIGH,
        verified=True,
        verified_by="Senior Instrumentation Engineer",
        verified_at=datetime.now(UTC),
    )


def build_approved_review(review_type: ReviewType) -> KnowledgeReview:
    """Return a completed approved knowledge review."""

    return KnowledgeReview(
        review_type=review_type,
        decision=ReviewDecision.APPROVED,
        reviewer_name="Engineering Reviewer",
        reviewer_role="Lead Engineer",
        reviewed_at=datetime.now(UTC),
    )


def build_knowledge_payload() -> dict:
    """Return the minimum valid payload for draft knowledge."""

    return {
        "knowledge_id": "KNOW-001",
        "title": "Pressure transmitter installation guidance",
        "subject": "Pressure measurement",
        "summary": "Guidance for installing industrial pressure transmitters.",
        "detailed_guidance": (
            "Verify process conditions, isolate the process, inspect the "
            "installation point, install the transmitter, reconnect impulse "
            "lines, and complete commissioning verification."
        ),
        "discipline": EngineeringDiscipline.INSTRUMENTATION,
        "categories": [
            KnowledgeCategory.INSTALLATION,
            KnowledgeCategory.VERIFICATION,
        ],
        "revision_metadata": build_revision_metadata(),
    }


def test_draft_engineering_knowledge_can_be_created() -> None:
    """A valid draft knowledge record should be accepted."""

    knowledge = EngineeringKnowledge(**build_knowledge_payload())

    assert knowledge.knowledge_id == "KNOW-001"
    assert knowledge.status == KnowledgeStatus.DRAFT
    assert knowledge.confidence_score == 50.0
    assert knowledge.evidence == []
    assert knowledge.reviews == []


def test_extra_fields_are_rejected() -> None:
    """Engineering models should reject undocumented fields."""

    payload = build_knowledge_payload()
    payload["unexpected_field"] = "not allowed"

    with pytest.raises(ValidationError, match="unexpected_field"):
        EngineeringKnowledge(**payload)


def test_verified_evidence_requires_verified_by() -> None:
    """Verified evidence must identify the person who verified it."""

    with pytest.raises(
        ValidationError,
        match="verified_by is required",
    ):
        EvidenceReference(
            evidence_id="EVD-002",
            evidence_type=EvidenceType.OEM_DATASHEET,
            title="Industrial transmitter datasheet",
            verified=True,
        )


def test_unverified_evidence_does_not_require_verifier() -> None:
    """Unverified evidence may be stored without verification metadata."""

    evidence = EvidenceReference(
        evidence_id="EVD-003",
        evidence_type=EvidenceType.FIELD_CASE_STUDY,
        title="Field installation case study",
        verified=False,
    )

    assert evidence.verified is False
    assert evidence.verified_by is None


def test_duplicate_knowledge_categories_are_rejected() -> None:
    """A knowledge record cannot contain duplicate categories."""

    payload = build_knowledge_payload()
    payload["categories"] = [
        KnowledgeCategory.INSTALLATION,
        KnowledgeCategory.INSTALLATION,
    ]

    with pytest.raises(
        ValidationError,
        match="Knowledge categories must be unique",
    ):
        EngineeringKnowledge(**payload)


def test_duplicate_evidence_ids_are_rejected() -> None:
    """Evidence identifiers must remain unique within one record."""

    payload = build_knowledge_payload()
    payload["evidence"] = [
        build_verified_evidence("EVD-DUPLICATE"),
        build_verified_evidence("EVD-DUPLICATE"),
    ]

    with pytest.raises(
        ValidationError,
        match="Evidence IDs must be unique",
    ):
        EngineeringKnowledge(**payload)


def test_environmental_minimum_cannot_exceed_maximum() -> None:
    """Environmental operating ranges must be logically ordered."""

    with pytest.raises(
        ValidationError,
        match="minimum_value cannot be greater than maximum_value",
    ):
        EnvironmentalConstraint(
            condition=EnvironmentCondition.HIGH_AMBIENT_TEMPERATURE,
            description="High-temperature outdoor installation.",
            minimum_value=80.0,
            maximum_value=60.0,
            unit="degC",
            engineering_impact=(
                "Electronics may exceed their approved temperature rating."
            ),
        )


def test_valid_environmental_range_is_accepted() -> None:
    """A correctly ordered environmental range should be accepted."""

    constraint = EnvironmentalConstraint(
        condition=EnvironmentCondition.HIGH_AMBIENT_TEMPERATURE,
        description="High-temperature outdoor installation.",
        minimum_value=40.0,
        maximum_value=60.0,
        unit="degC",
        engineering_impact=(
            "Temperature may reduce equipment life and measurement stability."
        ),
    )

    assert constraint.minimum_value == 40.0
    assert constraint.maximum_value == 60.0


def test_hold_point_requires_approval_role() -> None:
    """A formal hold point must identify its approval authority."""

    with pytest.raises(
        ValidationError,
        match="approval_role is required",
    ):
        ProcedureStep(
            step_number=1,
            title="Confirm process isolation",
            instruction="Verify that the process connection is isolated.",
            hold_point=True,
        )


def test_hold_point_with_approval_role_is_valid() -> None:
    """A hold point is valid when its approval role is supplied."""

    step = ProcedureStep(
        step_number=1,
        title="Confirm process isolation",
        instruction="Verify that the process connection is isolated.",
        hold_point=True,
        approval_role="Authorised Process Controller",
    )

    assert step.hold_point is True
    assert step.approval_role == "Authorised Process Controller"


def test_procedure_requires_unique_step_numbers() -> None:
    """Procedure step numbers must not be duplicated."""

    with pytest.raises(
        ValidationError,
        match="Procedure step numbers must be unique",
    ):
        EngineeringProcedure(
            procedure_id="PROC-001",
            title="Pressure transmitter installation",
            purpose="Install and verify a pressure transmitter.",
            steps=[
                ProcedureStep(
                    step_number=1,
                    title="Inspect equipment",
                    instruction="Inspect the transmitter for damage.",
                ),
                ProcedureStep(
                    step_number=1,
                    title="Verify model",
                    instruction="Confirm the model matches the specification.",
                ),
            ],
        )


def test_procedure_requires_at_least_one_step() -> None:
    """An engineering procedure cannot be created without steps."""

    with pytest.raises(ValidationError):
        EngineeringProcedure(
            procedure_id="PROC-002",
            title="Empty procedure",
            purpose="Demonstrate procedure validation.",
            steps=[],
        )


def test_severe_service_interval_cannot_exceed_normal_interval() -> None:
    """Severe-service maintenance must be at least as frequent as normal."""

    with pytest.raises(
        ValidationError,
        match=(
            "severe_service_interval_days cannot exceed "
            "normal_interval_days"
        ),
    ):
        PreventiveMaintenanceTask(
            task_id="PM-001",
            title="Inspect transmitter impulse lines",
            description=(
                "Inspect impulse lines for blockage, leaks, and corrosion."
            ),
            normal_interval_days=90,
            severe_service_interval_days=180,
        )


def test_valid_severe_service_interval_is_accepted() -> None:
    """A shorter severe-service interval should be accepted."""

    task = PreventiveMaintenanceTask(
        task_id="PM-002",
        title="Inspect transmitter impulse lines",
        description=(
            "Inspect impulse lines for blockage, leaks, and corrosion."
        ),
        normal_interval_days=90,
        severe_service_interval_days=30,
    )

    assert task.normal_interval_days == 90
    assert task.severe_service_interval_days == 30


def test_completed_review_requires_reviewer_name() -> None:
    """A completed review must identify the reviewer."""

    with pytest.raises(
        ValidationError,
        match="reviewer_name is required",
    ):
        KnowledgeReview(
            review_type=ReviewType.TECHNICAL,
            decision=ReviewDecision.APPROVED,
            reviewed_at=datetime.now(UTC),
        )


def test_completed_review_requires_reviewed_at() -> None:
    """A completed review must include its completion timestamp."""

    with pytest.raises(
        ValidationError,
        match="reviewed_at is required",
    ):
        KnowledgeReview(
            review_type=ReviewType.TECHNICAL,
            decision=ReviewDecision.APPROVED,
            reviewer_name="Engineering Reviewer",
        )


def test_pending_review_does_not_require_completion_details() -> None:
    """A pending review may exist before a reviewer is assigned."""

    review = KnowledgeReview(
        review_type=ReviewType.SAFETY,
        decision=ReviewDecision.PENDING,
    )

    assert review.reviewer_name is None
    assert review.reviewed_at is None


def test_approved_knowledge_requires_evidence() -> None:
    """Approved knowledge must contain supporting evidence."""

    payload = build_knowledge_payload()
    payload["status"] = KnowledgeStatus.APPROVED

    with pytest.raises(
        ValidationError,
        match="must contain evidence",
    ):
        EngineeringKnowledge(**payload)


def test_approved_knowledge_requires_verified_evidence() -> None:
    """Approved knowledge must contain at least one verified source."""

    payload = build_knowledge_payload()
    payload["status"] = KnowledgeStatus.APPROVED
    payload["evidence"] = [
        EvidenceReference(
            evidence_id="EVD-UNVERIFIED",
            evidence_type=EvidenceType.USER_EXPERIENCE,
            title="Unverified user experience",
            verified=False,
        )
    ]

    with pytest.raises(
        ValidationError,
        match="at least one verified evidence source",
    ):
        EngineeringKnowledge(**payload)


def test_approved_knowledge_does_not_require_final_reviews() -> None:
    """Approved records require evidence but not publication reviews."""

    payload = build_knowledge_payload()
    payload["status"] = KnowledgeStatus.APPROVED
    payload["evidence"] = [build_verified_evidence()]

    knowledge = EngineeringKnowledge(**payload)

    assert knowledge.status == KnowledgeStatus.APPROVED
    assert knowledge.reviews == []


def test_published_knowledge_requires_all_control_reviews() -> None:
    """Published knowledge must pass every mandatory review stage."""

    payload = build_knowledge_payload()
    payload["status"] = KnowledgeStatus.PUBLISHED
    payload["evidence"] = [build_verified_evidence()]
    payload["reviews"] = [
        build_approved_review(ReviewType.TECHNICAL),
        build_approved_review(ReviewType.SAFETY),
        build_approved_review(ReviewType.FINAL_APPROVAL),
    ]

    with pytest.raises(
        ValidationError,
        match="standards",
    ):
        EngineeringKnowledge(**payload)


def test_published_knowledge_accepts_all_required_reviews() -> None:
    """Published knowledge is valid after all required approvals."""

    payload = build_knowledge_payload()
    payload["status"] = KnowledgeStatus.PUBLISHED
    payload["evidence"] = [build_verified_evidence()]
    payload["reviews"] = [
        build_approved_review(ReviewType.TECHNICAL),
        build_approved_review(ReviewType.SAFETY),
        build_approved_review(ReviewType.STANDARDS),
        build_approved_review(ReviewType.FINAL_APPROVAL),
    ]

    knowledge = EngineeringKnowledge(**payload)

    assert knowledge.status == KnowledgeStatus.PUBLISHED
    assert len(knowledge.reviews) == 4


def test_approved_with_conditions_satisfies_review_requirement() -> None:
    """Conditional approval should count as an approved control review."""

    payload = build_knowledge_payload()
    payload["status"] = KnowledgeStatus.PUBLISHED
    payload["evidence"] = [build_verified_evidence()]
    payload["reviews"] = [
        build_approved_review(ReviewType.TECHNICAL),
        build_approved_review(ReviewType.SAFETY),
        KnowledgeReview(
            review_type=ReviewType.STANDARDS,
            decision=ReviewDecision.APPROVED_WITH_CONDITIONS,
            reviewer_name="Standards Engineer",
            reviewer_role="Compliance Specialist",
            reviewed_at=datetime.now(UTC),
            conditions=["Confirm site-specific standard before execution."],
        ),
        build_approved_review(ReviewType.FINAL_APPROVAL),
    ]

    knowledge = EngineeringKnowledge(**payload)

    assert knowledge.status == KnowledgeStatus.PUBLISHED


def test_published_blocking_safety_guidance_requires_risk_assessment() -> None:
    """Blocking safety guidance must require a site risk assessment."""

    payload = build_knowledge_payload()
    payload["status"] = KnowledgeStatus.PUBLISHED
    payload["evidence"] = [build_verified_evidence()]
    payload["reviews"] = [
        build_approved_review(ReviewType.TECHNICAL),
        build_approved_review(ReviewType.SAFETY),
        build_approved_review(ReviewType.STANDARDS),
        build_approved_review(ReviewType.FINAL_APPROVAL),
    ]
    payload["safety"] = SafetyGuidance(
        safety_summary="Do not proceed until process isolation is verified.",
        severity=SafetySeverity.CRITICAL,
        blocks_work_until_resolved=True,
        required_site_risk_assessment=False,
    )

    with pytest.raises(
        ValidationError,
        match="must require a site risk assessment",
    ):
        EngineeringKnowledge(**payload)


def test_draft_blocking_safety_guidance_can_be_recorded_for_review() -> None:
    """Draft safety content may be incomplete while still under review."""

    payload = build_knowledge_payload()
    payload["safety"] = SafetyGuidance(
        safety_summary="Potential stored process pressure exists.",
        severity=SafetySeverity.CRITICAL,
        blocks_work_until_resolved=True,
        required_site_risk_assessment=False,
    )

    knowledge = EngineeringKnowledge(**payload)

    assert knowledge.status == KnowledgeStatus.DRAFT
    assert knowledge.safety is not None
    assert knowledge.safety.blocks_work_until_resolved is True
