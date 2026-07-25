"""API tests for controlled Engineer4Me engineering knowledge."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.knowledge import get_knowledge_service
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
from app.engineering.knowledge_repository import KnowledgeRepository
from app.engineering.knowledge_service import (
    EngineeringKnowledgeService,
)
from app.main import app


client = TestClient(app)


@pytest.fixture
def knowledge_service() -> EngineeringKnowledgeService:
    """Provide a fresh knowledge repository for every API test."""

    service = EngineeringKnowledgeService(
        KnowledgeRepository()
    )

    app.dependency_overrides[get_knowledge_service] = (
        lambda: service
    )

    yield service

    app.dependency_overrides.pop(
        get_knowledge_service,
        None,
    )


def unique_knowledge_id(prefix: str = "KNOW") -> str:
    """Create an isolated knowledge identifier."""

    return f"{prefix}-{uuid4().hex[:10].upper()}"


def build_verified_evidence(
    evidence_id: str | None = None,
    evidence_type: EvidenceType = EvidenceType.OEM_MANUAL,
) -> EvidenceReference:
    """Create verified evidence suitable for publication."""

    return EvidenceReference(
        evidence_id=(
            evidence_id
            or f"EVD-{uuid4().hex[:10].upper()}"
        ),
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
    """Create an approved controlled engineering review."""

    return KnowledgeReview(
        review_type=review_type,
        decision=ReviewDecision.APPROVED,
        reviewer_name="Engineering Reviewer",
        reviewer_role="Lead Engineer",
        reviewed_at=datetime.now(UTC),
    )


def build_blocking_safety() -> SafetyGuidance:
    """Create critical stop-work safety guidance."""

    return SafetyGuidance(
        safety_summary=(
            "Stop work until process pressure isolation and the "
            "zero-energy state have been independently verified."
        ),
        severity=SafetySeverity.CRITICAL,
        blocks_work_until_resolved=True,
        required_site_risk_assessment=True,
    )


def build_published_knowledge(
    *,
    knowledge_id: str | None = None,
    title: str = "Pressure transmitter installation",
    evidence_type: EvidenceType = EvidenceType.OEM_MANUAL,
    confidence_score: float = 85.0,
    safety: SafetyGuidance | None = None,
) -> EngineeringKnowledge:
    """Create publication-ready engineering knowledge."""

    return EngineeringKnowledge(
        knowledge_id=(
            knowledge_id
            or unique_knowledge_id()
        ),
        title=title,
        subject="Pressure measurement",
        summary=(
            "Evidence-based guidance for pressure transmitter "
            "installation."
        ),
        detailed_guidance=(
            "Confirm process conditions, complete the site risk "
            "assessment, isolate the process, verify zero energy, "
            "inspect the connection, install the transmitter, and "
            "verify correct operation before returning the equipment "
            "to service."
        ),
        discipline=EngineeringDiscipline.INSTRUMENTATION,
        categories=[
            KnowledgeCategory.INSTALLATION,
            KnowledgeCategory.VERIFICATION,
        ],
        status=KnowledgeStatus.PUBLISHED,
        taxonomy_ids=[
            "instrument.pressure.transmitter",
        ],
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
                models=[
                    "PX100",
                    "PX200",
                ],
                components=[
                    "sensor",
                    "electronics module",
                ],
            )
        ],
        safety=safety,
        evidence=[
            build_verified_evidence(
                evidence_type=evidence_type,
            )
        ],
        reviews=[
            build_approved_review(
                ReviewType.TECHNICAL
            ),
            build_approved_review(
                ReviewType.SAFETY
            ),
            build_approved_review(
                ReviewType.STANDARDS
            ),
            build_approved_review(
                ReviewType.FINAL_APPROVAL
            ),
        ],
        revision_metadata=RevisionMetadata(
            revision="1.0",
            created_by="Engineer4Me API test suite",
        ),
        confidence_score=confidence_score,
    )


def build_draft_knowledge(
    *,
    knowledge_id: str | None = None,
    title: str = "Draft troubleshooting guidance",
) -> EngineeringKnowledge:
    """Create valid unpublished engineering knowledge."""

    return EngineeringKnowledge(
        knowledge_id=(
            knowledge_id
            or unique_knowledge_id("DRAFT")
        ),
        title=title,
        subject="Draft engineering content",
        summary="Draft guidance awaiting controlled review.",
        detailed_guidance="Draft technical guidance.",
        discipline=EngineeringDiscipline.INSTRUMENTATION,
        categories=[
            KnowledgeCategory.TROUBLESHOOTING,
        ],
        status=KnowledgeStatus.DRAFT,
        revision_metadata=RevisionMetadata(
            revision="1.0",
            created_by="Engineer4Me API test suite",
        ),
    )


def as_json(
    knowledge: EngineeringKnowledge,
) -> dict:
    """Convert a knowledge model into an API-safe JSON payload."""

    return knowledge.model_dump(mode="json")


def create_knowledge(
    knowledge: EngineeringKnowledge,
) -> dict:
    """Register knowledge through the public API."""

    response = client.post(
        "/api/v1/knowledge",
        json=as_json(knowledge),
    )

    assert response.status_code == 201, response.text

    return response.json()


def test_create_and_get_published_knowledge(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Published knowledge should be registered and retrieved."""

    record = build_published_knowledge()

    created = create_knowledge(record)

    response = client.get(
        f"/api/v1/knowledge/{record.knowledge_id}"
    )

    assert response.status_code == 200

    response_data = response.json()

    assert created["knowledge_id"] == record.knowledge_id
    assert response_data["knowledge_id"] == record.knowledge_id
    assert response_data["title"] == record.title
    assert response_data["status"] == "published"
    assert response_data["confidence_score"] == 85.0
    assert len(response_data["evidence"]) == 1
    assert len(response_data["reviews"]) == 4


def test_list_knowledge_hides_drafts_by_default(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Public list responses should exclude draft knowledge."""

    published = build_published_knowledge()
    draft = build_draft_knowledge()

    create_knowledge(published)
    create_knowledge(draft)

    response = client.get("/api/v1/knowledge")

    assert response.status_code == 200

    returned_ids = {
        item["knowledge_id"]
        for item in response.json()
    }

    assert published.knowledge_id in returned_ids
    assert draft.knowledge_id not in returned_ids


def test_list_knowledge_can_include_unpublished_records(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Internal list requests should include draft knowledge."""

    published = build_published_knowledge()
    draft = build_draft_knowledge()

    create_knowledge(published)
    create_knowledge(draft)

    response = client.get(
        "/api/v1/knowledge",
        params={
            "include_unpublished": True,
        },
    )

    assert response.status_code == 200

    returned_ids = {
        item["knowledge_id"]
        for item in response.json()
    }

    assert returned_ids == {
        published.knowledge_id,
        draft.knowledge_id,
    }


def test_draft_requires_unpublished_visibility(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Draft knowledge should be hidden unless explicitly requested."""

    draft = build_draft_knowledge()
    create_knowledge(draft)

    hidden_response = client.get(
        f"/api/v1/knowledge/{draft.knowledge_id}"
    )

    visible_response = client.get(
        f"/api/v1/knowledge/{draft.knowledge_id}",
        params={
            "include_unpublished": True,
        },
    )

    assert hidden_response.status_code == 404
    assert visible_response.status_code == 200
    assert (
        visible_response.json()["knowledge_id"]
        == draft.knowledge_id
    )


def test_missing_knowledge_returns_404(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Unknown knowledge identifiers should return HTTP 404."""

    response = client.get(
        "/api/v1/knowledge/UNKNOWN-KNOWLEDGE"
    )

    assert response.status_code == 404
    assert "UNKNOWN-KNOWLEDGE" in response.json()["detail"]


def test_text_search_returns_matching_knowledge(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Text search should return relevant engineering knowledge."""

    matching = build_published_knowledge(
        title="Pressure transmitter installation",
    )
    unrelated = build_published_knowledge(
        title="Control valve inspection",
    )
    unrelated.subject = "Control valves"
    unrelated.summary = "Guidance for inspecting control valves."
    unrelated.detailed_guidance = (
        "Inspect the valve body, actuator, positioner, and linkage."
    )
    unrelated.semantic_tags = [
        "control valve",
        "actuator",
        "positioner",
    ]

    create_knowledge(matching)
    create_knowledge(unrelated)

    response = client.post(
        "/api/v1/knowledge/search/text",
        json={
            "text": "pressure transmitter",
            "include_unpublished": False,
            "limit": 25,
        },
    )

    assert response.status_code == 200
    assert len(response.json()) >= 1

    returned_ids = [
        result["knowledge"]["knowledge_id"]
        for result in response.json()
    ]

    assert matching.knowledge_id in returned_ids


def test_structured_search_filters_by_discipline(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Structured search should accept repository search filters."""

    record = build_published_knowledge()
    create_knowledge(record)

    response = client.post(
        "/api/v1/knowledge/search",
        json={
            "disciplines": [
                "instrumentation",
            ],
        },
    )

    assert response.status_code == 200

    returned_ids = [
        result["knowledge"]["knowledge_id"]
        for result in response.json()
    ]

    assert record.knowledge_id in returned_ids


def test_safety_search_returns_blocking_guidance(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Safety search should prioritise stop-work guidance."""

    safe_record = build_published_knowledge(
        title="Pressure isolation safety",
        safety=build_blocking_safety(),
    )
    normal_record = build_published_knowledge(
        title="Routine transmitter inspection",
    )

    create_knowledge(safe_record)
    create_knowledge(normal_record)

    response = client.post(
        "/api/v1/knowledge/search/safety",
        json={
            "blocking_only": True,
            "minimum_confidence_score": 0,
            "include_unpublished": False,
            "limit": 25,
        },
    )

    assert response.status_code == 200

    returned_ids = [
        result["knowledge"]["knowledge_id"]
        for result in response.json()
    ]

    assert returned_ids == [
        safe_record.knowledge_id,
    ]


def test_verified_search_filters_evidence_type(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Verified search should filter by controlled evidence type."""

    oem_record = build_published_knowledge(
        evidence_type=EvidenceType.OEM_MANUAL,
    )
    standard_record = build_published_knowledge(
        evidence_type=EvidenceType.INTERNATIONAL_STANDARD,
    )

    create_knowledge(oem_record)
    create_knowledge(standard_record)

    response = client.post(
        "/api/v1/knowledge/search/verified",
        json={
            "evidence_types": [
                "international_standard",
            ],
            "minimum_confidence_score": 0,
            "include_unpublished": False,
            "limit": 25,
        },
    )

    assert response.status_code == 200

    returned_ids = [
        result["knowledge"]["knowledge_id"]
        for result in response.json()
    ]

    assert returned_ids == [
        standard_record.knowledge_id,
    ]


def test_publication_readiness_accepts_complete_record(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Publication-ready knowledge should pass API assessment."""

    record = build_published_knowledge()

    response = client.post(
        "/api/v1/knowledge/publication-readiness",
        json=as_json(record),
    )

    assert response.status_code == 200
    assert response.json()["ready"] is True
    assert response.json()["failed_requirements"] == []
    assert response.json()["verified_evidence_count"] == 1
    assert response.json()["approved_review_count"] == 4


def test_publication_readiness_identifies_draft_failures(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Draft readiness assessment should identify failed controls."""

    draft = build_draft_knowledge()

    response = client.post(
        "/api/v1/knowledge/publication-readiness",
        json=as_json(draft),
    )

    assert response.status_code == 200
    assert response.json()["ready"] is False

    failed_requirements = set(
        response.json()["failed_requirements"]
    )

    assert "published_status" in failed_requirements
    assert "technical_review" in failed_requirements
    assert "verified_evidence" in failed_requirements


def test_incomplete_published_record_is_rejected(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Published records that fail controls should return HTTP 422."""

    record = build_published_knowledge(
        confidence_score=0.0,
    )

    response = client.post(
        "/api/v1/knowledge",
        json=as_json(record),
    )

    assert response.status_code == 422
    assert "confidence" in response.json()["detail"].lower()


def test_get_knowledge_summary(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Summary endpoints should expose evidence and safety indicators."""

    record = build_published_knowledge(
        safety=build_blocking_safety(),
    )
    create_knowledge(record)

    response = client.get(
        f"/api/v1/knowledge/{record.knowledge_id}/summary"
    )

    assert response.status_code == 200

    summary = response.json()

    assert summary["knowledge_id"] == record.knowledge_id
    assert summary["evidence_count"] == 1
    assert summary["verified_evidence_count"] == 1
    assert summary["approved_review_count"] == 4
    assert summary["has_safety_guidance"] is True
    assert summary["blocks_work_until_resolved"] is True


def test_list_knowledge_summaries(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Summary listing should return visible knowledge summaries."""

    record = build_published_knowledge()
    create_knowledge(record)

    response = client.get(
        "/api/v1/knowledge/summaries"
    )

    assert response.status_code == 200
    assert any(
        summary["knowledge_id"] == record.knowledge_id
        for summary in response.json()
    )


def test_get_knowledge_statistics(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Statistics should include published, draft, and safety totals."""

    published = build_published_knowledge(
        safety=build_blocking_safety(),
    )
    draft = build_draft_knowledge()

    create_knowledge(published)
    create_knowledge(draft)

    response = client.get(
        "/api/v1/knowledge/statistics"
    )

    assert response.status_code == 200

    statistics = response.json()

    assert statistics["total_records"] == 2
    assert statistics["published_records"] == 1
    assert statistics["unpublished_records"] == 1
    assert statistics["records_with_safety_guidance"] == 1
    assert statistics["blocking_safety_records"] == 1
    assert statistics["records_with_verified_evidence"] == 1


def test_revise_knowledge_preserves_history(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Revising knowledge should preserve the previous revision."""

    original = build_published_knowledge()
    create_knowledge(original)

    revised = original.model_copy(deep=True)
    revised.title = "Revised pressure transmitter installation"
    revised.revision_metadata.revision = "2.0"
    revised.revision_metadata.previous_revision = "1.0"
    revised.revision_metadata.updated_by = "API Test Engineer"
    revised.revision_metadata.updated_at = datetime.now(UTC)

    revise_response = client.put(
        f"/api/v1/knowledge/{original.knowledge_id}",
        json=as_json(revised),
    )

    assert revise_response.status_code == 200
    assert (
        revise_response.json()["revision_metadata"]["revision"]
        == "2.0"
    )

    history_response = client.get(
        f"/api/v1/knowledge/{original.knowledge_id}/history"
    )

    assert history_response.status_code == 200
    assert len(history_response.json()) == 1
    assert (
        history_response.json()[0]["revision_metadata"]["revision"]
        == "1.0"
    )


def test_revision_identifier_must_match_path(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """The body identifier must match the route identifier."""

    original = build_published_knowledge()
    create_knowledge(original)

    revised = original.model_copy(deep=True)
    revised.knowledge_id = unique_knowledge_id("OTHER")
    revised.revision_metadata.revision = "2.0"

    response = client.put(
        f"/api/v1/knowledge/{original.knowledge_id}",
        json=as_json(revised),
    )

    assert response.status_code == 422
    assert "must match" in response.json()["detail"]


def test_upsert_registers_new_knowledge(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Collection PUT should register previously unknown knowledge."""

    record = build_published_knowledge()

    response = client.put(
        "/api/v1/knowledge",
        json=as_json(record),
    )

    assert response.status_code == 200
    assert response.json()["knowledge_id"] == record.knowledge_id


def test_delete_knowledge(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Deleting knowledge should make it unavailable."""

    record = build_published_knowledge()
    create_knowledge(record)

    delete_response = client.delete(
        f"/api/v1/knowledge/{record.knowledge_id}"
    )

    get_response = client.get(
        f"/api/v1/knowledge/{record.knowledge_id}"
    )

    assert delete_response.status_code == 204
    assert get_response.status_code == 404


def test_invalid_text_search_request_returns_422(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """Empty text search requests should fail validation."""

    response = client.post(
        "/api/v1/knowledge/search/text",
        json={
            "text": "",
        },
    )

    assert response.status_code == 422


def test_knowledge_routes_are_exposed_in_openapi(
    knowledge_service: EngineeringKnowledgeService,
) -> None:
    """The OpenAPI schema should expose the Knowledge API."""

    schema = app.openapi()

    required_paths = {
        "/api/v1/knowledge",
        "/api/v1/knowledge/statistics",
        "/api/v1/knowledge/summaries",
        "/api/v1/knowledge/search",
        "/api/v1/knowledge/search/text",
        "/api/v1/knowledge/search/safety",
        "/api/v1/knowledge/search/verified",
        "/api/v1/knowledge/publication-readiness",
        "/api/v1/knowledge/{knowledge_id}",
        "/api/v1/knowledge/{knowledge_id}/summary",
        "/api/v1/knowledge/{knowledge_id}/history",
        (
            "/api/v1/knowledge/"
            "{knowledge_id}/publication-readiness"
        ),
    }

    assert required_paths.issubset(
        set(schema["paths"])
    )