"""Tests for ingestion-to-repository publication orchestration."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.engineering.knowledge_models import KnowledgeStatus
from app.engineering.knowledge_service import EngineeringKnowledgeService
from app.ingestion.document_models import (
    ConfidenceLevel,
    DocumentType,
    EngineeringFactType,
    ReviewStatus,
)
from app.ingestion.knowledge_index import (
    KnowledgeIndexBuildResult,
    KnowledgeIndexRecord,
    KnowledgeIndexStatus,
)
from app.ingestion.repository_publisher import (
    EngineeringKnowledgeRepositoryPublisher,
    RepositoryPublicationStatus,
    RepositoryPublisherError,
)


@pytest.fixture
def document_id():
    """Return a stable document identifier for one test."""

    return uuid4()


@pytest.fixture
def active_record(document_id):
    """Return a minimal active knowledge-index record."""

    return KnowledgeIndexRecord(
        fact_id=uuid4(),
        document_id=document_id,
        title="Pressure transmitter installation requirement",
        statement=(
            "Install the pressure transmitter in accordance with the "
            "manufacturer instructions and approved site procedures."
        ),
        fact_type=EngineeringFactType.INSTALLATION_REQUIREMENT,
        document_type=DocumentType.UNKNOWN,
        manufacturer="Example Manufacturer",
        brand="Example Brand",
        product_family="Pressure Transmitter",
        product_series="PT Series",
        model_numbers=["PT-100"],
        part_numbers=[],
        equipment_categories=[],
        standards=[],
        protocols=["HART"],
        tools=["Calibrated hand tools"],
        parts=[],
        actions=["Install the transmitter"],
        verification_steps=["Verify the installation is secure"],
        operating_conditions=[],
        prerequisites=["Approved installation procedure"],
        tags=["pressure", "transmitter", "installation"],
        values=[],
        evidence=[],
        safety_severities=[],
        hazards=[],
        required_ppe=[],
        isolation_requirements=[],
        permit_requirements=[],
        safety_blocking=False,
        extraction_confidence=0.92,
        confidence_level=ConfidenceLevel.HIGH,
        requires_human_review=False,
        review_status=ReviewStatus.PENDING,
        status=KnowledgeIndexStatus.ACTIVE,
        searchable_text=(
            "pressure transmitter installation requirement example "
            "manufacturer pt-100 hart"
        ),
        keywords=[
            "pressure",
            "transmitter",
            "installation",
            "pt-100",
            "hart",
        ],
        identifiers=["pt100"],
        source_title="Example Pressure Transmitter Manual",
        source_revision="1",
        source_document_number="DOC-PT-100",
        indexed_at=datetime(2026, 7, 27, 10, 0, tzinfo=UTC),
        index_version="1.0.0",
        attributes={
            "is_safety_related": False,
            "is_fault_related": False,
            "high_priority_fact": False,
            "verified_evidence_count": 0,
        },
    )


@pytest.fixture
def build(document_id, active_record):
    """Return an index build containing one active record."""

    return KnowledgeIndexBuildResult(
        document_id=document_id,
        records=[active_record],
        indexed_fact_count=1,
        skipped_fact_count=0,
        duplicate_fact_count=0,
        warnings=[],
        errors=[],
        index_engine="test-indexer",
        index_version="1.0.0",
    )


def test_publish_build_registers_converted_draft(build):
    """Converted index records are registered as draft knowledge."""

    service = EngineeringKnowledgeService()
    publisher = EngineeringKnowledgeRepositoryPublisher(service=service)

    result = publisher.publish_build(
        build,
        created_by="publisher-test",
    )

    assert result.successful is True
    assert result.processed_count == 1
    assert result.registered_count == 1
    assert result.skipped_count == 0
    assert result.failed_count == 0
    assert len(result.registered_knowledge_ids) == 1

    knowledge_id = result.registered_knowledge_ids[0]
    stored = service.get(
        knowledge_id,
        include_unpublished=True,
    )

    assert stored.status == KnowledgeStatus.DRAFT
    assert stored.revision_metadata.created_by == "publisher-test"
    assert stored.title == "Pressure transmitter installation requirement"


def test_publish_build_returns_registered_item(build):
    """Successful registrations produce a registered publication item."""

    publisher = EngineeringKnowledgeRepositoryPublisher()

    result = publisher.publish_build(build)

    assert len(result.items) == 1

    item = result.items[0]

    assert item.status == RepositoryPublicationStatus.REGISTERED
    assert item.fact_id == build.records[0].fact_id
    assert item.index_id == build.records[0].index_id
    assert item.knowledge_id in result.registered_knowledge_ids
    assert item.message is None


def test_publish_build_skips_rejected_record(
    document_id,
    active_record,
):
    """Rejected index records are preserved as skipped outcomes."""

    rejected = active_record.model_copy(
        update={"status": KnowledgeIndexStatus.REJECTED}
    )

    build = KnowledgeIndexBuildResult(
        document_id=document_id,
        records=[rejected],
        index_engine="test-indexer",
        index_version="1.0.0",
    )

    publisher = EngineeringKnowledgeRepositoryPublisher()
    result = publisher.publish_build(build)

    assert result.successful is True
    assert result.registered_count == 0
    assert result.skipped_count == 1
    assert result.failed_count == 0
    assert result.items[0].status == RepositoryPublicationStatus.SKIPPED
    assert result.items[0].fact_id == rejected.fact_id
    assert result.warnings


def test_publish_build_skips_withdrawn_record(
    document_id,
    active_record,
):
    """Withdrawn index records are not converted or registered."""

    withdrawn = active_record.model_copy(
        update={"status": KnowledgeIndexStatus.WITHDRAWN}
    )

    build = KnowledgeIndexBuildResult(
        document_id=document_id,
        records=[withdrawn],
        index_engine="test-indexer",
        index_version="1.0.0",
    )

    publisher = EngineeringKnowledgeRepositoryPublisher()
    result = publisher.publish_build(build)

    assert result.registered_count == 0
    assert result.skipped_count == 1
    assert result.failed_count == 0
    assert result.items[0].status == RepositoryPublicationStatus.SKIPPED


def test_repeated_build_is_idempotent_when_skip_existing_is_true(build):
    """Processing the same deterministic fact twice skips the second copy."""

    service = EngineeringKnowledgeService()
    publisher = EngineeringKnowledgeRepositoryPublisher(service=service)

    first = publisher.publish_build(build)
    second = publisher.publish_build(build)

    assert first.registered_count == 1
    assert first.skipped_count == 0
    assert first.failed_count == 0

    assert second.registered_count == 0
    assert second.skipped_count == 1
    assert second.failed_count == 0
    assert second.items[0].status == RepositoryPublicationStatus.SKIPPED
    assert "already exists" in second.items[0].message
    assert service.repository.count(include_unpublished=True) == 1


def test_duplicate_is_failure_when_skip_existing_is_false(build):
    """Duplicate identifiers fail when explicit skipping is disabled."""

    service = EngineeringKnowledgeService()
    publisher = EngineeringKnowledgeRepositoryPublisher(service=service)

    publisher.publish_build(build)

    result = publisher.publish_build(
        build,
        skip_existing=False,
    )

    assert result.successful is False
    assert result.registered_count == 0
    assert result.skipped_count == 0
    assert result.failed_count == 1
    assert result.items[0].status == RepositoryPublicationStatus.FAILED
    assert "already exists" in result.items[0].message
    assert result.errors


def test_publish_build_preserves_index_warnings_and_errors(
    document_id,
    active_record,
):
    """Build diagnostics are carried through adapter and publisher results."""

    build = KnowledgeIndexBuildResult(
        document_id=document_id,
        records=[active_record],
        warnings=["Indexer warning"],
        errors=["Indexer error"],
        index_engine="test-indexer",
        index_version="1.0.0",
    )

    publisher = EngineeringKnowledgeRepositoryPublisher()
    result = publisher.publish_build(build)

    assert "Indexer warning" in result.warnings
    assert "Indexer error" in result.errors
    assert result.conversion.warnings == ["Indexer warning"]
    assert result.conversion.errors == ["Indexer error"]


def test_publish_build_registers_valid_records_when_another_is_skipped(
    document_id,
    active_record,
):
    """One skipped record does not prevent another record being registered."""

    rejected = active_record.model_copy(
        update={
            "fact_id": uuid4(),
            "index_id": uuid4(),
            "title": "Rejected extracted requirement",
            "status": KnowledgeIndexStatus.REJECTED,
        }
    )

    build = KnowledgeIndexBuildResult(
        document_id=document_id,
        records=[rejected, active_record],
        index_engine="test-indexer",
        index_version="1.0.0",
    )

    service = EngineeringKnowledgeService()
    publisher = EngineeringKnowledgeRepositoryPublisher(service=service)

    result = publisher.publish_build(build)

    assert result.registered_count == 1
    assert result.skipped_count == 1
    assert result.failed_count == 0
    assert result.processed_count == 2
    assert service.repository.count(include_unpublished=True) == 1

    statuses = [item.status for item in result.items]

    assert statuses == [
        RepositoryPublicationStatus.SKIPPED,
        RepositoryPublicationStatus.REGISTERED,
    ]


def test_publish_build_rejects_blank_created_by(build):
    """Revision responsibility cannot be blank."""

    publisher = EngineeringKnowledgeRepositoryPublisher()

    with pytest.raises(
        RepositoryPublisherError,
        match="created_by cannot be empty",
    ):
        publisher.publish_build(
            build,
            created_by="   ",
        )


def test_publisher_exposes_injected_service_and_adapter():
    """Injected dependencies remain available for orchestration inspection."""

    service = EngineeringKnowledgeService()
    publisher = EngineeringKnowledgeRepositoryPublisher(service=service)

    assert publisher.service is service
    assert publisher.adapter is not None
