"""Tests for deterministic engineering knowledge indexing and search."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.ingestion.document_models import (
    ConfidenceLevel,
    DocumentRevision,
    DocumentType,
    EngineeringFactType,
    EngineeringValue,
    EquipmentCategory,
    EvidenceLocation,
    EvidenceReference,
    EvidenceType,
    ExtractedDocumentMetadata,
    ExtractedEngineeringFact,
    ProductReference,
    ReviewStatus,
    SafetyInformation,
    SafetySeverity,
)
from app.ingestion.knowledge_index import (
    EngineeringKnowledgeIndexer,
    EngineeringKnowledgeIndexSearch,
    IndexedEngineeringValue,
    KnowledgeIndexStatus,
    KnowledgeSearchFilters,
    KnowledgeSearchRequest,
    SearchMatchType,
    normalise_identifier,
    normalise_search_text,
    tokenise,
    unique_strings,
)


# ---------------------------------------------------------------------------
# Test factories
# ---------------------------------------------------------------------------


def make_metadata(
    *,
    document_id: UUID | None = None,
    manufacturer: str = "IFM",
    brand: str = "ifm electronic",
    product_family: str = "PN pressure sensors",
    product_series: str = "PN7",
    model_numbers: list[str] | None = None,
    part_numbers: list[str] | None = None,
    equipment_categories: list[EquipmentCategory] | None = None,
    document_type: DocumentType = DocumentType.USER_MANUAL,
    standards: list[str] | None = None,
    certifications: list[str] | None = None,
    keywords: list[str] | None = None,
) -> ExtractedDocumentMetadata:
    resolved_document_id = document_id or uuid4()

    return ExtractedDocumentMetadata(
        document_id=resolved_document_id,
        title="IFM PN7 Pressure Sensor Operating Instructions",
        document_type=document_type,
        revision=DocumentRevision(
            revision="Rev 3",
            document_number="80234567",
        ),
        product_reference=ProductReference(
            manufacturer=manufacturer,
            brand=brand,
            product_family=product_family,
            product_series=product_series,
            model_numbers=model_numbers or ["PN7094"],
            part_numbers=part_numbers or ["PN-7094-A"],
            equipment_categories=equipment_categories
            or [EquipmentCategory.PRESSURE_INSTRUMENT],
        ),
        standards_referenced=standards or ["IEC 61010-1"],
        hazardous_area_certifications=certifications or ["IECEx"],
        keywords=keywords or ["pressure", "sensor", "industrial"],
        metadata_confidence=0.95,
    )


def make_evidence(
    *,
    document_id: UUID,
    page_number: int = 12,
    quoted_text: str = "The rated pressure is 10 bar.",
    verified: bool = True,
) -> EvidenceReference:
    return EvidenceReference(
        document_id=document_id,
        evidence_type=EvidenceType.TEXT,
        location=EvidenceLocation(
            page_number=page_number,
            section="Technical data",
            block_id=uuid4(),
        ),
        quoted_text=quoted_text,
        extraction_confidence=0.96,
        verified=verified,
    )


def make_fact(
    *,
    document_id: UUID | None = None,
    fact_id: UUID | None = None,
    fact_type: EngineeringFactType = EngineeringFactType.SPECIFICATION,
    title: str = "Rated pressure",
    statement: str = "The rated pressure is 10 bar.",
    manufacturer: str | None = None,
    product_family: str | None = None,
    product_series: str | None = None,
    model_numbers: list[str] | None = None,
    equipment_categories: list[EquipmentCategory] | None = None,
    value: EngineeringValue | None = None,
    safety_information: list[SafetyInformation] | None = None,
    standards: list[str] | None = None,
    required_tools: list[str] | None = None,
    required_parts: list[str] | None = None,
    actions: list[str] | None = None,
    verification_steps: list[str] | None = None,
    operating_conditions: list[str] | None = None,
    prerequisites: list[str] | None = None,
    tags: list[str] | None = None,
    evidence: list[EvidenceReference] | None = None,
    extraction_confidence: float = 0.92,
    requires_human_review: bool = False,
    review_status: ReviewStatus = ReviewStatus.NOT_REQUIRED,
    attributes: dict[str, object] | None = None,
) -> ExtractedEngineeringFact:
    resolved_document_id = document_id or uuid4()

    return ExtractedEngineeringFact(
        fact_id=fact_id or uuid4(),
        document_id=resolved_document_id,
        fact_type=fact_type,
        title=title,
        statement=statement,
        manufacturer=manufacturer,
        product_family=product_family,
        product_series=product_series,
        model_numbers=model_numbers or [],
        equipment_categories=equipment_categories or [],
        value=value,
        safety_information=safety_information or [],
        standards_referenced=standards or [],
        required_tools=required_tools or [],
        required_parts=required_parts or [],
        actions=actions or [],
        verification_steps=verification_steps or [],
        operating_conditions=operating_conditions or [],
        prerequisites=prerequisites or [],
        tags=tags or [],
        evidence=evidence or [],
        extraction_confidence=extraction_confidence,
        requires_human_review=requires_human_review,
        review_status=review_status,
        attributes=attributes or {},
    )


def build_record(
    *,
    fact: ExtractedEngineeringFact | None = None,
    metadata: ExtractedDocumentMetadata | None = None,
):
    if fact is None and metadata is None:
        document_id = uuid4()
        metadata = make_metadata(document_id=document_id)
        fact = make_fact(document_id=document_id)
    elif fact is None:
        assert metadata is not None
        fact = make_fact(document_id=metadata.document_id)

    return EngineeringKnowledgeIndexer().index_fact(
        fact,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------


def test_normalise_search_text() -> None:
    result = normalise_search_text(
        "  IFM\u00a0PN7094 — Rated Pressure: 10 BAR!  "
    )

    assert result == "ifm pn7094 rated pressure: 10 bar"


def test_normalise_identifier() -> None:
    assert normalise_identifier("PN-7094/A") == "pn7094a"
    assert normalise_identifier(" E 101 ") == "e101"


def test_unique_strings_is_stable_and_case_insensitive() -> None:
    result = unique_strings(
        [
            "IFM",
            " ifm ",
            "Rosemount",
            "",
            None,
            "ROSEMOUNT",
            "Siemens",
        ]
    )

    assert result == ["IFM", "Rosemount", "Siemens"]


def test_tokenise_preserves_technical_identifiers() -> None:
    result = tokenise(
        "Use PN-7094/A with IO-Link and IEC 61010-1."
    )

    assert "pn-7094/a" in result
    assert "io-link" in result
    assert "iec" in result
    assert "61010-1" in result
    assert "with" not in result


# ---------------------------------------------------------------------------
# Indexed value validation
# ---------------------------------------------------------------------------


def test_indexed_value_rejects_invalid_range() -> None:
    with pytest.raises(ValidationError):
        IndexedEngineeringValue(
            raw_value="invalid",
            minimum=20.0,
            maximum=10.0,
        )


def test_indexed_value_accepts_valid_range() -> None:
    value = IndexedEngineeringValue(
        raw_value="0 to 10",
        unit="bar",
        minimum=0.0,
        maximum=10.0,
        nominal=5.0,
        conditions=["At 20 °C"],
    )

    assert value.unit == "bar"
    assert value.minimum == 0.0
    assert value.maximum == 10.0


# ---------------------------------------------------------------------------
# Fact indexing
# ---------------------------------------------------------------------------


def test_indexes_basic_engineering_fact() -> None:
    document_id = uuid4()
    metadata = make_metadata(document_id=document_id)
    fact = make_fact(document_id=document_id)

    record = EngineeringKnowledgeIndexer().index_fact(
        fact,
        metadata=metadata,
    )

    assert record.fact_id == fact.fact_id
    assert record.document_id == document_id
    assert record.metadata_id == metadata.metadata_id
    assert record.fact_type == EngineeringFactType.SPECIFICATION
    assert record.document_type == DocumentType.USER_MANUAL
    assert record.title == "Rated pressure"
    assert record.statement == "The rated pressure is 10 bar."


def test_fact_identity_overrides_metadata_identity() -> None:
    document_id = uuid4()
    metadata = make_metadata(
        document_id=document_id,
        manufacturer="IFM",
        product_family="PN pressure sensors",
        product_series="PN7",
    )
    fact = make_fact(
        document_id=document_id,
        manufacturer="Emerson",
        product_family="Rosemount 3051",
        product_series="3051S",
    )

    record = EngineeringKnowledgeIndexer().index_fact(
        fact,
        metadata=metadata,
    )

    assert record.manufacturer == "Emerson"
    assert record.product_family == "Rosemount 3051"
    assert record.product_series == "3051S"
    assert record.brand == "ifm electronic"


def test_metadata_identity_fills_missing_fact_fields() -> None:
    document_id = uuid4()
    metadata = make_metadata(document_id=document_id)
    fact = make_fact(document_id=document_id)

    record = EngineeringKnowledgeIndexer().index_fact(
        fact,
        metadata=metadata,
    )

    assert record.manufacturer == "IFM"
    assert record.brand == "ifm electronic"
    assert record.product_family == "PN pressure sensors"
    assert record.product_series == "PN7"
    assert record.model_numbers == ["PN7094"]
    assert record.part_numbers == ["PN-7094-A"]


def test_merges_models_and_equipment_categories_without_duplicates() -> None:
    document_id = uuid4()
    metadata = make_metadata(
        document_id=document_id,
        model_numbers=["PN7094", "PN7096"],
        equipment_categories=[
            EquipmentCategory.PRESSURE_INSTRUMENT,
            EquipmentCategory.SENSOR,
        ],
    )
    fact = make_fact(
        document_id=document_id,
        model_numbers=["PN7094", "PN7098"],
        equipment_categories=[
            EquipmentCategory.PRESSURE_INSTRUMENT,
            EquipmentCategory.TRANSMITTER,
        ],
    )

    record = EngineeringKnowledgeIndexer().index_fact(
        fact,
        metadata=metadata,
    )

    assert record.model_numbers == [
        "PN7094",
        "PN7098",
        "PN7096",
    ]
    assert record.equipment_categories == [
        EquipmentCategory.PRESSURE_INSTRUMENT,
        EquipmentCategory.TRANSMITTER,
        EquipmentCategory.SENSOR,
    ]


def test_indexes_engineering_value() -> None:
    record = build_record(
        fact=make_fact(
            value=EngineeringValue(
                value="0 to 10",
                unit="bar",
                minimum=0.0,
                maximum=10.0,
                nominal=5.0,
                tolerance=0.1,
                conditions=["At 20 °C"],
            )
        )
    )

    assert len(record.values) == 1
    assert record.values[0].raw_value == "0 to 10"
    assert record.values[0].unit == "bar"
    assert record.values[0].maximum == 10.0
    assert "bar" in record.searchable_text


def test_indexes_evidence_traceability() -> None:
    document_id = uuid4()
    evidence = make_evidence(document_id=document_id)
    metadata = make_metadata(document_id=document_id)
    fact = make_fact(
        document_id=document_id,
        evidence=[evidence],
    )

    record = EngineeringKnowledgeIndexer().index_fact(
        fact,
        metadata=metadata,
    )

    assert len(record.evidence) == 1
    assert record.evidence[0].evidence_id == evidence.evidence_id
    assert record.evidence[0].document_id == document_id
    assert record.evidence[0].page_number == 12
    assert record.evidence[0].section == "Technical data"
    assert record.evidence[0].verified is True
    assert record.verified_evidence_count == 1


def test_indexes_source_document_traceability() -> None:
    record = build_record()

    assert (
        record.source_title
        == "IFM PN7 Pressure Sensor Operating Instructions"
    )
    assert record.source_revision == "Rev 3"
    assert record.source_document_number == "80234567"
    assert normalise_identifier("80234567") in record.identifiers


def test_indexes_safety_information() -> None:
    document_id = uuid4()
    safety = SafetyInformation(
        severity=SafetySeverity.DANGER,
        hazard="Stored pressure may cause uncontrolled release.",
        consequence="Serious injury may occur.",
        required_actions=[
            "Depressurise the process before removing the sensor."
        ],
        prohibited_actions=["Do not loosen the process connection under pressure."],
        required_ppe=["Safety glasses", "Protective gloves"],
        isolation_requirements=["Close and lock the isolation valve"],
        permit_requirements=["Valid work permit"],
        escalation_required=True,
    )

    record = build_record(
        fact=make_fact(
            document_id=document_id,
            fact_type=EngineeringFactType.SAFETY_WARNING,
            title="Stored pressure hazard",
            statement="Depressurise the process before removing the sensor.",
            safety_information=[safety],
        ),
        metadata=make_metadata(document_id=document_id),
    )

    assert record.is_safety_related is True
    assert record.safety_severities == [SafetySeverity.DANGER]
    assert record.hazards == [
        "Stored pressure may cause uncontrolled release."
    ]
    assert record.required_ppe == [
        "Safety glasses",
        "Protective gloves",
    ]
    assert record.isolation_requirements == [
        "Close and lock the isolation valve"
    ]
    assert record.permit_requirements == ["Valid work permit"]
    assert record.safety_blocking is True


def test_indexes_protocol_from_statement() -> None:
    document_id = uuid4()
    record = build_record(
        fact=make_fact(
            document_id=document_id,
            fact_type=EngineeringFactType.COMMUNICATION_PROTOCOL,
            title="IO-Link communication",
            statement="The sensor supports IO-Link version 1.1.",
        ),
        metadata=make_metadata(document_id=document_id),
    )

    assert any(
        normalise_search_text(protocol) == "io-link"
        for protocol in record.protocols
    )


def test_indexes_protocol_from_attributes() -> None:
    record = build_record(
        fact=make_fact(
            attributes={
                "protocols": [
                    "HART",
                    "Modbus TCP",
                ]
            }
        )
    )

    assert "HART" in record.protocols
    assert "Modbus TCP" in record.protocols


def test_indexes_fault_code_identifier() -> None:
    document_id = uuid4()
    record = build_record(
        fact=make_fact(
            document_id=document_id,
            fact_type=EngineeringFactType.FAULT_CODE,
            title="Fault E101",
            statement="Fault E101 indicates sensor overload.",
            attributes={"fault_code": "E101"},
        ),
        metadata=make_metadata(document_id=document_id),
    )

    assert "e101" in record.identifiers
    assert record.is_fault_related is True


def test_indexes_standards_and_certifications() -> None:
    document_id = uuid4()
    metadata = make_metadata(
        document_id=document_id,
        standards=["IEC 61010-1", "ISO 9001"],
        certifications=["IECEx", "ATEX"],
    )
    fact = make_fact(
        document_id=document_id,
        standards=["IEC 61508"],
    )

    record = EngineeringKnowledgeIndexer().index_fact(
        fact,
        metadata=metadata,
    )

    assert record.standards == [
        "IEC 61508",
        "IEC 61010-1",
        "ISO 9001",
        "IECEx",
        "ATEX",
    ]


def test_index_status_active_when_review_not_required() -> None:
    record = build_record(
        fact=make_fact(
            requires_human_review=False,
            review_status=ReviewStatus.NOT_REQUIRED,
        )
    )

    assert record.status == KnowledgeIndexStatus.ACTIVE


def test_index_status_pending_review() -> None:
    record = build_record(
        fact=make_fact(
            extraction_confidence=0.60,
            requires_human_review=True,
            review_status=ReviewStatus.PENDING,
        )
    )

    assert record.status == KnowledgeIndexStatus.PENDING_REVIEW


def test_index_status_rejected() -> None:
    record = build_record(
        fact=make_fact(
            requires_human_review=True,
            review_status=ReviewStatus.REJECTED,
        )
    )

    assert record.status == KnowledgeIndexStatus.REJECTED


def test_index_fact_rejects_mismatched_metadata_document() -> None:
    fact = make_fact(document_id=uuid4())
    metadata = make_metadata(document_id=uuid4())

    with pytest.raises(
        ValueError,
        match="must reference the same document",
    ):
        EngineeringKnowledgeIndexer().index_fact(
            fact,
            metadata=metadata,
        )


# ---------------------------------------------------------------------------
# Index build result
# ---------------------------------------------------------------------------


def test_build_indexes_multiple_facts() -> None:
    document_id = uuid4()
    metadata = make_metadata(document_id=document_id)
    facts = [
        make_fact(
            document_id=document_id,
            title="Rated pressure",
        ),
        make_fact(
            document_id=document_id,
            fact_type=EngineeringFactType.MAINTENANCE_INTERVAL,
            title="Inspection interval",
            statement="Inspect the seal every 12 months.",
        ),
    ]

    result = EngineeringKnowledgeIndexer().build(
        facts,
        metadata=metadata,
    )

    assert result.document_id == document_id
    assert result.indexed_fact_count == 2
    assert result.skipped_fact_count == 0
    assert result.duplicate_fact_count == 0
    assert len(result.records) == 2
    assert result.errors == []


def test_build_skips_duplicate_fact_ids() -> None:
    document_id = uuid4()
    fact_id = uuid4()
    facts = [
        make_fact(
            document_id=document_id,
            fact_id=fact_id,
            title="First fact",
        ),
        make_fact(
            document_id=document_id,
            fact_id=fact_id,
            title="Duplicate fact",
        ),
    ]

    result = EngineeringKnowledgeIndexer().build(
        facts,
        metadata=make_metadata(document_id=document_id),
    )

    assert result.indexed_fact_count == 1
    assert result.duplicate_fact_count == 1
    assert len(result.warnings) == 1
    assert str(fact_id) in result.warnings[0]


def test_build_skips_fact_from_different_document() -> None:
    document_id = uuid4()
    other_document_id = uuid4()

    result = EngineeringKnowledgeIndexer().build(
        [
            make_fact(document_id=document_id),
            make_fact(document_id=other_document_id),
        ],
        metadata=make_metadata(document_id=document_id),
    )

    assert result.indexed_fact_count == 1
    assert result.skipped_fact_count == 1
    assert len(result.errors) == 1
    assert str(other_document_id) in result.errors[0]


def test_build_requires_metadata_or_fact() -> None:
    with pytest.raises(
        ValueError,
        match="metadata or at least one engineering fact is required",
    ):
        EngineeringKnowledgeIndexer().build([])


def test_build_allows_empty_fact_collection_with_metadata() -> None:
    metadata = make_metadata()

    result = EngineeringKnowledgeIndexer().build(
        [],
        metadata=metadata,
    )

    assert result.document_id == metadata.document_id
    assert result.records == []
    assert result.indexed_fact_count == 0


# ---------------------------------------------------------------------------
# Search behaviour
# ---------------------------------------------------------------------------


def test_search_exact_model_identifier_has_high_priority() -> None:
    document_id = uuid4()
    metadata = make_metadata(
        document_id=document_id,
        model_numbers=["PN7094"],
    )
    records = [
        build_record(
            fact=make_fact(
                document_id=document_id,
                title="PN7094 pressure limit",
            ),
            metadata=metadata,
        ),
        build_record(
            fact=make_fact(
                title="General pressure guidance",
                statement="Select a suitable pressure sensor.",
            ),
            metadata=None,
        ),
    ]

    response = EngineeringKnowledgeIndexSearch().search(
        records,
        KnowledgeSearchRequest(text="PN-7094"),
    )

    assert response.total_matches == 1
    assert response.results[0].record.model_numbers == ["PN7094"]
    assert (
        response.results[0].match_type
        == SearchMatchType.EXACT_IDENTIFIER
    )
    assert "identifiers" in response.results[0].matched_fields


def test_search_exact_title_phrase() -> None:
    record = build_record(
        fact=make_fact(
            title="Rated pressure",
            statement="The rated pressure is 10 bar.",
        )
    )

    response = EngineeringKnowledgeIndexSearch().search(
        [record],
        KnowledgeSearchRequest(text="Rated pressure"),
    )

    assert response.total_matches == 1
    assert response.results[0].match_type == SearchMatchType.EXACT_PHRASE
    assert "title" in response.results[0].matched_fields


def test_search_matches_statement_tokens() -> None:
    record = build_record(
        fact=make_fact(
            title="Sensor overload",
            statement=(
                "Reduce the process pressure and restart the device."
            ),
        )
    )

    response = EngineeringKnowledgeIndexSearch().search(
        [record],
        KnowledgeSearchRequest(text="reduce process pressure"),
    )

    assert response.total_matches == 1
    assert {
        "reduce",
        "process",
        "pressure",
    }.issubset(set(response.results[0].matched_terms))


def test_search_require_all_terms_excludes_partial_match() -> None:
    record = build_record(
        fact=make_fact(
            statement="Reduce the process pressure.",
        )
    )

    response = EngineeringKnowledgeIndexSearch().search(
        [record],
        KnowledgeSearchRequest(
            text="reduce pressure temperature",
            require_all_terms=True,
        ),
    )

    assert response.total_matches == 0
    assert response.results == []


def test_empty_text_returns_filter_matches() -> None:
    record = build_record()

    response = EngineeringKnowledgeIndexSearch().search(
        [record],
        KnowledgeSearchRequest(),
    )

    assert response.total_matches == 1
    assert response.results[0].match_type == SearchMatchType.FILTER_MATCH


def test_search_pagination() -> None:
    records = [
        build_record(
            fact=make_fact(
                title=f"Pressure fact {index}",
                statement=f"Pressure specification number {index}.",
            )
        )
        for index in range(5)
    ]

    response = EngineeringKnowledgeIndexSearch().search(
        records,
        KnowledgeSearchRequest(
            text="pressure",
            limit=2,
            offset=1,
        ),
    )

    assert response.total_matches == 5
    assert response.returned_matches == 2
    assert len(response.results) == 2


def test_search_filters_by_fact_type() -> None:
    specification = build_record(
        fact=make_fact(
            fact_type=EngineeringFactType.SPECIFICATION,
            title="Pressure specification",
        )
    )
    safety = build_record(
        fact=make_fact(
            fact_type=EngineeringFactType.SAFETY_WARNING,
            title="Pressure warning",
        )
    )

    response = EngineeringKnowledgeIndexSearch().search(
        [specification, safety],
        KnowledgeSearchRequest(
            filters=KnowledgeSearchFilters(
                fact_types=[EngineeringFactType.SAFETY_WARNING]
            )
        ),
    )

    assert response.total_matches == 1
    assert (
        response.results[0].record.fact_type
        == EngineeringFactType.SAFETY_WARNING
    )


def test_search_filters_by_manufacturer_case_insensitively() -> None:
    ifm_record = build_record(
        metadata=make_metadata(manufacturer="IFM")
    )
    emerson_record = build_record(
        metadata=make_metadata(manufacturer="Emerson")
    )

    response = EngineeringKnowledgeIndexSearch().search(
        [ifm_record, emerson_record],
        KnowledgeSearchRequest(
            filters=KnowledgeSearchFilters(
                manufacturers=["ifm"]
            )
        ),
    )

    assert response.total_matches == 1
    assert response.results[0].record.manufacturer == "IFM"


def test_search_filters_by_model_number() -> None:
    matching = build_record(
        metadata=make_metadata(model_numbers=["PN7094"])
    )
    other = build_record(
        metadata=make_metadata(model_numbers=["PN7096"])
    )

    response = EngineeringKnowledgeIndexSearch().search(
        [matching, other],
        KnowledgeSearchRequest(
            filters=KnowledgeSearchFilters(
                model_numbers=["pn7094"]
            )
        ),
    )

    assert response.total_matches == 1
    assert response.results[0].record.model_numbers == ["PN7094"]


def test_search_filters_by_equipment_category() -> None:
    pressure = build_record(
        metadata=make_metadata(
            equipment_categories=[
                EquipmentCategory.PRESSURE_INSTRUMENT
            ]
        )
    )
    valve = build_record(
        metadata=make_metadata(
            equipment_categories=[EquipmentCategory.CONTROL_VALVE]
        )
    )

    response = EngineeringKnowledgeIndexSearch().search(
        [pressure, valve],
        KnowledgeSearchRequest(
            filters=KnowledgeSearchFilters(
                equipment_categories=[
                    EquipmentCategory.CONTROL_VALVE
                ]
            )
        ),
    )

    assert response.total_matches == 1
    assert (
        EquipmentCategory.CONTROL_VALVE
        in response.results[0].record.equipment_categories
    )


def test_search_filters_by_minimum_confidence() -> None:
    high_confidence = build_record(
        fact=make_fact(extraction_confidence=0.95)
    )
    low_confidence = build_record(
        fact=make_fact(
            extraction_confidence=0.45,
            requires_human_review=True,
            review_status=ReviewStatus.PENDING,
        )
    )

    response = EngineeringKnowledgeIndexSearch().search(
        [high_confidence, low_confidence],
        KnowledgeSearchRequest(
            filters=KnowledgeSearchFilters(
                minimum_confidence=0.80
            )
        ),
    )

    assert response.total_matches == 1
    assert response.results[0].record.extraction_confidence == 0.95


def test_search_filters_verified_evidence_only() -> None:
    verified_document_id = uuid4()
    unverified_document_id = uuid4()

    verified = build_record(
        fact=make_fact(
            document_id=verified_document_id,
            evidence=[
                make_evidence(
                    document_id=verified_document_id,
                    verified=True,
                )
            ],
        ),
        metadata=make_metadata(document_id=verified_document_id),
    )
    unverified = build_record(
        fact=make_fact(
            document_id=unverified_document_id,
            evidence=[
                make_evidence(
                    document_id=unverified_document_id,
                    verified=False,
                )
            ],
        ),
        metadata=make_metadata(document_id=unverified_document_id),
    )

    response = EngineeringKnowledgeIndexSearch().search(
        [verified, unverified],
        KnowledgeSearchRequest(
            filters=KnowledgeSearchFilters(
                verified_evidence_only=True
            )
        ),
    )

    assert response.total_matches == 1
    assert response.results[0].record.verified_evidence_count == 1


def test_search_filters_safety_only() -> None:
    safety = build_record(
        fact=make_fact(
            fact_type=EngineeringFactType.SAFETY_REQUIREMENT,
            title="Isolation requirement",
            statement="Isolate the process before maintenance.",
        )
    )
    specification = build_record(
        fact=make_fact(
            fact_type=EngineeringFactType.SPECIFICATION,
            title="Pressure specification",
        )
    )

    response = EngineeringKnowledgeIndexSearch().search(
        [safety, specification],
        KnowledgeSearchRequest(
            filters=KnowledgeSearchFilters(safety_only=True)
        ),
    )

    assert response.total_matches == 1
    assert response.results[0].record.is_safety_related is True


def test_search_filters_fault_related_only() -> None:
    fault = build_record(
        fact=make_fact(
            fact_type=EngineeringFactType.CORRECTIVE_ACTION,
            title="Correct overload",
            statement="Reduce the process pressure.",
        )
    )
    maintenance = build_record(
        fact=make_fact(
            fact_type=EngineeringFactType.MAINTENANCE_TASK,
            title="Clean sensor",
        )
    )

    response = EngineeringKnowledgeIndexSearch().search(
        [fault, maintenance],
        KnowledgeSearchRequest(
            filters=KnowledgeSearchFilters(
                fault_related_only=True
            )
        ),
    )

    assert response.total_matches == 1
    assert response.results[0].record.is_fault_related is True


def test_search_filters_human_review_required() -> None:
    reviewed = build_record(
        fact=make_fact(
            requires_human_review=False,
            review_status=ReviewStatus.NOT_REQUIRED,
        )
    )
    pending = build_record(
        fact=make_fact(
            requires_human_review=True,
            review_status=ReviewStatus.PENDING,
        )
    )

    response = EngineeringKnowledgeIndexSearch().search(
        [reviewed, pending],
        KnowledgeSearchRequest(
            filters=KnowledgeSearchFilters(
                human_review_required=True
            )
        ),
    )

    assert response.total_matches == 1
    assert response.results[0].record.requires_human_review is True


def test_safety_blocking_record_receives_ranking_priority() -> None:
    document_id = uuid4()

    safety = build_record(
        fact=make_fact(
            document_id=document_id,
            fact_type=EngineeringFactType.SAFETY_WARNING,
            title="Pressure safety warning",
            statement="Pressure must be isolated before maintenance.",
            safety_information=[
                SafetyInformation(
                    severity=SafetySeverity.DANGER,
                    hazard="Stored pressure",
                    escalation_required=True,
                )
            ],
        ),
        metadata=make_metadata(document_id=document_id),
    )

    ordinary = build_record(
        fact=make_fact(
            fact_type=EngineeringFactType.SPECIFICATION,
            title="Pressure information",
            statement="Pressure is measured in bar.",
        )
    )

    response = EngineeringKnowledgeIndexSearch().search(
        [ordinary, safety],
        KnowledgeSearchRequest(text="pressure"),
    )

    assert response.total_matches == 2
    assert response.results[0].record.fact_id == safety.fact_id
    assert response.results[0].record.safety_blocking is True


def test_verified_evidence_increases_result_score() -> None:
    verified_document_id = uuid4()
    plain_document_id = uuid4()

    verified = build_record(
        fact=make_fact(
            document_id=verified_document_id,
            title="Pressure limit",
            statement="The pressure limit is 10 bar.",
            evidence=[
                make_evidence(
                    document_id=verified_document_id,
                    verified=True,
                )
            ],
        ),
        metadata=make_metadata(document_id=verified_document_id),
    )

    plain = build_record(
        fact=make_fact(
            document_id=plain_document_id,
            title="Pressure limit",
            statement="The pressure limit is 10 bar.",
        ),
        metadata=make_metadata(document_id=plain_document_id),
    )

    response = EngineeringKnowledgeIndexSearch().search(
        [plain, verified],
        KnowledgeSearchRequest(text="pressure limit"),
    )

    assert response.total_matches == 2
    assert response.results[0].record.fact_id == verified.fact_id
    assert response.results[0].score > response.results[1].score


def test_search_results_have_deterministic_tie_breaking() -> None:
    first_fact = make_fact(
        fact_id=UUID("00000000-0000-0000-0000-000000000001"),
        title="Alpha pressure",
        statement="Pressure information.",
    )
    second_fact = make_fact(
        fact_id=UUID("00000000-0000-0000-0000-000000000002"),
        title="Beta pressure",
        statement="Pressure information.",
    )

    records = [
        build_record(fact=second_fact),
        build_record(fact=first_fact),
    ]

    response = EngineeringKnowledgeIndexSearch().search(
        records,
        KnowledgeSearchRequest(text="pressure"),
    )

    assert response.total_matches == 2
    assert response.results[0].record.title == "Alpha pressure"
    assert response.results[1].record.title == "Beta pressure"


# ---------------------------------------------------------------------------
# Confidence and attributes
# ---------------------------------------------------------------------------


def test_index_preserves_derived_confidence_level() -> None:
    record = build_record(
        fact=make_fact(extraction_confidence=0.92)
    )

    assert record.confidence_level == ConfidenceLevel.VERY_HIGH


def test_index_adds_priority_attributes() -> None:
    document_id = uuid4()
    record = build_record(
        fact=make_fact(
            document_id=document_id,
            fact_type=EngineeringFactType.FAULT_CODE,
            title="Fault E101",
            statement="Fault E101 indicates overload.",
            evidence=[
                make_evidence(
                    document_id=document_id,
                    verified=True,
                )
            ],
        ),
        metadata=make_metadata(document_id=document_id),
    )

    assert record.attributes["is_fault_related"] is True
    assert record.attributes["high_priority_fact"] is True
    assert record.attributes["verified_evidence_count"] == 1