"""Tests for the engineering knowledge adapter."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.engineering.knowledge_adapter import (
    EngineeringKnowledgeAdapter,
    KnowledgeAdapterError,
    KnowledgeConversionStatus,
    UnsupportedKnowledgeRecordError,
)
from app.engineering.knowledge_models import (
    EngineeringDiscipline,
    EvidenceStrength,
    EvidenceType,
    KnowledgeCategory,
    KnowledgeStatus,
    SafetySeverity,
)
from app.ingestion.document_models import (
    ConfidenceLevel,
    DocumentType,
    EngineeringFactType,
    EquipmentCategory,
    ReviewStatus,
    SafetySeverity as IngestionSafetySeverity,
)
from app.ingestion.knowledge_index import (
    IndexedEngineeringValue,
    IndexedEvidence,
    KnowledgeIndexBuildResult,
    KnowledgeIndexRecord,
    KnowledgeIndexStatus,
)


@pytest.fixture
def adapter() -> EngineeringKnowledgeAdapter:
    return EngineeringKnowledgeAdapter()


@pytest.fixture
def document_id():
    return uuid4()


@pytest.fixture
def fact_id():
    return uuid4()


@pytest.fixture
def index_record(
    document_id,
    fact_id,
) -> KnowledgeIndexRecord:
    evidence_id = uuid4()

    return KnowledgeIndexRecord(
        fact_id=fact_id,
        document_id=document_id,
        title="Rosemount 3051 high pressure warning",
        statement=(
            "Isolate the process pressure before removing the transmitter."
        ),
        fact_type=EngineeringFactType.SAFETY_WARNING,
        document_type=DocumentType.USER_MANUAL,
        manufacturer="Emerson",
        brand="Rosemount",
        product_family="3051",
        product_series="3051S",
        model_numbers=["3051S2"],
        part_numbers=["03031-1234"],
        equipment_categories=[EquipmentCategory.PRESSURE_INSTRUMENT],
        standards=["IEC 61511", "IEC 60079"],
        protocols=["HART"],
        tools=["Calibrated pressure source"],
        parts=["Process seal"],
        actions=["Isolate process pressure"],
        verification_steps=["Confirm pressure is zero"],
        operating_conditions=["High pressure service"],
        prerequisites=["Approved permit to work"],
        tags=["pressure", "transmitter", "safety"],
        values=[
            IndexedEngineeringValue(
                raw_value="100 bar",
                unit="bar",
                maximum=100.0,
            )
        ],
        evidence=[
            IndexedEvidence(
                evidence_id=evidence_id,
                document_id=document_id,
                page_number=14,
                section="Safety",
                quoted_text=(
                    "Isolate the process pressure before removing the "
                    "transmitter."
                ),
                verified=True,
                extraction_confidence=0.96,
            )
        ],
        safety_severities=[IngestionSafetySeverity.WARNING],
        hazards=["Stored process pressure"],
        required_ppe=["Safety glasses"],
        isolation_requirements=["Process pressure isolation"],
        permit_requirements=["Permit to work"],
        safety_blocking=True,
        extraction_confidence=0.94,
        confidence_level=ConfidenceLevel.HIGH,
        requires_human_review=True,
        review_status=ReviewStatus.PENDING,
        status=KnowledgeIndexStatus.PENDING_REVIEW,
        searchable_text=(
            "rosemount 3051 high pressure warning isolate process pressure"
        ),
        keywords=["rosemount", "3051", "pressure", "safety"],
        identifiers=["3051s2", "030311234"],
        source_title="Rosemount 3051 Reference Manual",
        source_revision="Rev 5",
        source_document_number="00809-0100-4007",
        indexed_at=datetime(2026, 7, 26, 10, 0, tzinfo=UTC),
        index_version="1.0.0",
        attributes={
            "is_safety_related": True,
            "is_fault_related": False,
            "high_priority_fact": True,
            "verified_evidence_count": 1,
        },
    )


def test_adapter_metadata(adapter):
    assert (
        adapter.ADAPTER_NAME
        == "Engineer4Me engineering knowledge adapter"
    )
    assert adapter.ADAPTER_VERSION == "1.0.0"


def test_convert_record_returns_draft_knowledge(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert knowledge.status == KnowledgeStatus.DRAFT
    assert knowledge.title == index_record.title
    assert knowledge.detailed_guidance == index_record.statement


def test_convert_record_builds_stable_knowledge_id(
    adapter,
    index_record,
):
    first = adapter.convert_record(index_record)
    second = adapter.convert_record(index_record)

    assert first.knowledge_id == second.knowledge_id
    assert first.knowledge_id.startswith("doc-")
    assert "-fact-" in first.knowledge_id


def test_convert_record_sets_default_creator(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert (
        knowledge.revision_metadata.created_by
        == "document-ingestion"
    )


def test_convert_record_accepts_custom_creator(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(
        index_record,
        created_by="phase-5-test",
    )

    assert knowledge.revision_metadata.created_by == "phase-5-test"


def test_convert_record_rejects_blank_creator(
    adapter,
    index_record,
):
    with pytest.raises(KnowledgeAdapterError):
        adapter.convert_record(index_record, created_by="   ")


@pytest.mark.parametrize(
    "status",
    [
        KnowledgeIndexStatus.REJECTED,
        KnowledgeIndexStatus.WITHDRAWN,
    ],
)
def test_convert_record_rejects_unsupported_status(
    adapter,
    index_record,
    status,
):
    rejected = index_record.model_copy(update={"status": status})

    with pytest.raises(UnsupportedKnowledgeRecordError):
        adapter.convert_record(rejected)


def test_convert_record_maps_safety_category(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert KnowledgeCategory.SAFETY in knowledge.categories


def test_convert_record_maps_safety_discipline(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert knowledge.discipline == EngineeringDiscipline.SAFETY


def test_convert_record_builds_equipment_applicability(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert len(knowledge.equipment_applicability) == 1

    equipment = knowledge.equipment_applicability[0]

    assert equipment.equipment_category == "pressure instrument"
    assert equipment.manufacturer == "Emerson"
    assert equipment.model_family == "3051"
    assert equipment.models == ["3051S2"]
    assert equipment.components == ["Process seal"]


def test_convert_record_builds_verified_evidence(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert len(knowledge.evidence) == 1

    evidence = knowledge.evidence[0]

    assert evidence.verified is True
    assert evidence.verified_by == "document-ingestion-verification"
    assert evidence.verified_at == index_record.indexed_at
    assert evidence.document_number == "00809-0100-4007"


def test_convert_record_maps_manual_evidence_type(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert knowledge.evidence[0].evidence_type == EvidenceType.OEM_MANUAL


def test_convert_record_maps_evidence_strength(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert knowledge.evidence[0].strength == EvidenceStrength.VERY_HIGH


@pytest.mark.parametrize(
    ("confidence", "expected"),
    [
        (0.95, EvidenceStrength.VERY_HIGH),
        (0.75, EvidenceStrength.HIGH),
        (0.50, EvidenceStrength.MODERATE),
        (0.25, EvidenceStrength.LOW),
        (0.10, EvidenceStrength.VERY_LOW),
    ],
)
def test_evidence_strength_boundaries(
    adapter,
    index_record,
    confidence,
    expected,
):
    evidence = index_record.evidence[0].model_copy(
        update={"extraction_confidence": confidence}
    )

    record = index_record.model_copy(update={"evidence": [evidence]})
    knowledge = adapter.convert_record(record)

    assert knowledge.evidence[0].strength == expected


def test_convert_record_builds_standard_references(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert len(knowledge.standards) == 2
    assert knowledge.standards[0].standard_number == "IEC 61511"
    assert knowledge.standards[0].organisation == "IEC"


def test_convert_record_builds_blocking_safety_guidance(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert knowledge.safety is not None
    assert knowledge.safety.blocks_work_until_resolved is True
    assert knowledge.safety.requires_authorised_person is True
    assert knowledge.safety.required_site_risk_assessment is True
    assert knowledge.safety.severity == SafetySeverity.CRITICAL


def test_convert_record_builds_hazard_controls(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert knowledge.safety is not None
    assert len(knowledge.safety.hazards) == 1

    hazard = knowledge.safety.hazards[0]

    assert hazard.title == "Stored process pressure"
    assert hazard.severity == SafetySeverity.CRITICAL
    assert hazard.stop_work_condition is not None


def test_convert_record_builds_pre_work_checks(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert knowledge.safety is not None

    checks = knowledge.safety.pre_work_checks

    assert "Approved permit to work" in checks
    assert "Confirm required PPE: Safety glasses" in checks
    assert (
        "Confirm isolation requirement: Process pressure isolation"
        in checks
    )
    assert "Confirm permit requirement: Permit to work" in checks


def test_convert_record_builds_verification_requirements(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert len(knowledge.verification_requirements) == 1

    verification = knowledge.verification_requirements[0]

    assert verification.description == "Confirm pressure is zero"
    assert (
        verification.required_tool
        == "Calibrated pressure source"
    )
    assert verification.independent_verification_required is True


def test_convert_record_converts_confidence_to_percentage(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert knowledge.confidence_score == 94.0


def test_convert_record_explains_confidence(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert knowledge.confidence_explanation is not None
    assert "0.9400" in knowledge.confidence_explanation
    assert "high" in knowledge.confidence_explanation
    assert "pending" in knowledge.confidence_explanation
    assert "technical approval" in knowledge.confidence_explanation


def test_convert_record_adds_human_review_limitation(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert any(
        "requiring human review" in limitation
        for limitation in knowledge.limitations
    )


def test_convert_record_adds_traceability_taxonomy(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert (
        "fact-type:safety_warning"
        in knowledge.taxonomy_ids
    )
    assert (
        "document-type:user_manual"
        in knowledge.taxonomy_ids
    )
    assert (
        "equipment:pressure_instrument"
        in knowledge.taxonomy_ids
    )


def test_convert_record_adds_semantic_tags(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert "pressure" in knowledge.semantic_tags
    assert "safety_warning" in knowledge.semantic_tags
    assert "document_ingestion" in knowledge.semantic_tags
    assert "automatically_extracted" in knowledge.semantic_tags


def test_convert_record_uses_multidisciplinary_fallback(
    adapter,
    index_record,
):
    record = index_record.model_copy(
        update={
            "fact_type": EngineeringFactType.PRODUCT_FEATURE,
            "equipment_categories": [],
            "safety_severities": [],
            "hazards": [],
            "safety_blocking": False,
        }
    )

    knowledge = adapter.convert_record(record)

    assert (
        knowledge.discipline
        == EngineeringDiscipline.MULTIDISCIPLINARY
    )


def test_convert_record_maps_instrumentation_equipment(
    adapter,
    index_record,
):
    record = index_record.model_copy(
        update={
            "fact_type": EngineeringFactType.PRODUCT_FEATURE,
            "safety_severities": [],
            "hazards": [],
            "safety_blocking": False,
        }
    )

    knowledge = adapter.convert_record(record)

    assert (
        knowledge.discipline
        == EngineeringDiscipline.INSTRUMENTATION
    )


def test_convert_record_maps_fault_categories(
    adapter,
    index_record,
):
    record = index_record.model_copy(
        update={
            "fact_type": EngineeringFactType.FAULT_CODE,
            "safety_severities": [],
            "hazards": [],
            "safety_blocking": False,
        }
    )

    knowledge = adapter.convert_record(record)

    assert KnowledgeCategory.FAULT_CODE in knowledge.categories
    assert KnowledgeCategory.TROUBLESHOOTING in knowledge.categories


def test_convert_record_without_evidence_adds_limitation(
    adapter,
    index_record,
):
    record = index_record.model_copy(update={"evidence": []})

    knowledge = adapter.convert_record(record)

    assert knowledge.evidence == []
    assert any(
        "No traceable source evidence" in limitation
        for limitation in knowledge.limitations
    )


def test_convert_record_without_equipment_returns_empty_scope(
    adapter,
    index_record,
):
    record = index_record.model_copy(
        update={
            "manufacturer": None,
            "brand": None,
            "product_family": None,
            "product_series": None,
            "model_numbers": [],
            "equipment_categories": [],
        }
    )

    knowledge = adapter.convert_record(record)

    assert knowledge.equipment_applicability == []


def test_convert_record_without_safety_returns_none(
    adapter,
    index_record,
):
    record = index_record.model_copy(
        update={
            "fact_type": EngineeringFactType.PRODUCT_FEATURE,
            "safety_severities": [],
            "hazards": [],
            "safety_blocking": False,
        }
    )

    knowledge = adapter.convert_record(record)

    assert knowledge.safety is None


def test_convert_records_preserves_order(
    adapter,
    index_record,
):
    second = index_record.model_copy(
        update={
            "index_id": uuid4(),
            "fact_id": uuid4(),
            "title": "Second knowledge record",
        }
    )

    converted = adapter.convert_records([index_record, second])

    assert len(converted) == 2
    assert converted[0].title == index_record.title
    assert converted[1].title == "Second knowledge record"


def test_convert_records_skips_rejected_records(
    adapter,
    index_record,
):
    rejected = index_record.model_copy(
        update={
            "index_id": uuid4(),
            "fact_id": uuid4(),
            "status": KnowledgeIndexStatus.REJECTED,
        }
    )

    converted = adapter.convert_records([index_record, rejected])

    assert len(converted) == 1
    assert converted[0].title == index_record.title


def test_convert_build_converts_valid_records(
    adapter,
    index_record,
):
    build = KnowledgeIndexBuildResult(
        document_id=index_record.document_id,
        records=[index_record],
        index_engine="test-index",
        index_version="1.0.0",
    )

    result = adapter.convert_build(build)

    assert result.converted_count == 1
    assert result.skipped_count == 0
    assert result.failed_count == 0
    assert len(result.knowledge) == 1
    assert result.items[0].status == KnowledgeConversionStatus.CONVERTED


def test_convert_build_skips_rejected_records(
    adapter,
    index_record,
):
    rejected = index_record.model_copy(
        update={"status": KnowledgeIndexStatus.REJECTED}
    )

    build = KnowledgeIndexBuildResult(
        document_id=index_record.document_id,
        records=[rejected],
        index_engine="test-index",
        index_version="1.0.0",
    )

    result = adapter.convert_build(build)

    assert result.converted_count == 0
    assert result.skipped_count == 1
    assert result.failed_count == 0
    assert result.knowledge == []
    assert result.items[0].status == KnowledgeConversionStatus.SKIPPED
    assert result.warnings


def test_convert_build_preserves_build_warnings_and_errors(
    adapter,
    index_record,
):
    build = KnowledgeIndexBuildResult(
        document_id=index_record.document_id,
        records=[index_record],
        warnings=["source warning"],
        errors=["source error"],
        index_engine="test-index",
        index_version="1.0.0",
    )

    result = adapter.convert_build(build)

    assert "source warning" in result.warnings
    assert "source error" in result.errors


def test_convert_build_records_custom_creator(
    adapter,
    index_record,
):
    build = KnowledgeIndexBuildResult(
        document_id=index_record.document_id,
        records=[index_record],
        index_engine="test-index",
        index_version="1.0.0",
    )

    result = adapter.convert_build(
        build,
        created_by="knowledge-import",
    )

    assert (
        result.knowledge[0].revision_metadata.created_by
        == "knowledge-import"
    )


def test_conversion_result_counts_match_items(
    adapter,
    index_record,
):
    rejected = index_record.model_copy(
        update={
            "index_id": uuid4(),
            "fact_id": uuid4(),
            "status": KnowledgeIndexStatus.REJECTED,
        }
    )

    build = KnowledgeIndexBuildResult(
        document_id=index_record.document_id,
        records=[index_record, rejected],
        index_engine="test-index",
        index_version="1.0.0",
    )

    result = adapter.convert_build(build)

    assert result.converted_count == 1
    assert result.skipped_count == 1
    assert result.failed_count == 0
    assert len(result.items) == 2


def test_subject_includes_fact_type_and_product_context(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert "safety warning" in knowledge.subject
    assert "Emerson" in knowledge.subject
    assert "3051" in knowledge.subject


def test_summary_identifies_draft_origin(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert "Draft engineering knowledge extracted" in knowledge.summary
    assert "94.00%" in knowledge.summary
    assert "Human review required: yes" in knowledge.summary


def test_revision_metadata_records_source_fact(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert knowledge.revision_metadata.change_summary is not None
    assert str(index_record.fact_id) in (
        knowledge.revision_metadata.change_summary
    )
    assert adapter.ADAPTER_VERSION in (
        knowledge.revision_metadata.change_summary
    )


def test_adapter_does_not_publish_extracted_content(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert knowledge.status != KnowledgeStatus.PUBLISHED
    assert knowledge.reviews == []


def test_adapter_includes_site_control_exclusion(
    adapter,
    index_record,
):
    knowledge = adapter.convert_record(index_record)

    assert any(
        "site procedures" in exclusion
        for exclusion in knowledge.exclusions
    )

