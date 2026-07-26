"""
Tests for the Engineer4Me ingestion document models.

These tests validate:

- uploaded document validation
- checksum handling
- parsed document behaviour
- metadata models
- engineering fact confidence classification
- evidence traceability
- duplicate detection
- human review workflows
- publication rules
- ingestion job state management
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.ingestion.document_models import (
    ConfidenceLevel,
    ContentBlockType,
    DocumentFormat,
    DocumentLanguage,
    DocumentReview,
    DocumentRevision,
    DocumentSource,
    DocumentType,
    DocumentUpload,
    DuplicateCandidate,
    DuplicateDetectionResult,
    DuplicateMatchType,
    EngineeringExtractionResult,
    EngineeringFactType,
    EngineeringValue,
    EquipmentCategory,
    EvidenceLocation,
    EvidenceReference,
    EvidenceType,
    ExtractedDocumentMetadata,
    ExtractedEngineeringFact,
    ExtractionMethod,
    FactReview,
    IngestionError,
    IngestionJob,
    IngestionStatus,
    KnowledgePublicationStatus,
    ParsedContentBlock,
    ParsedDocument,
    ParsedPage,
    ParsedTable,
    ProductReference,
    PublicationRecord,
    ReviewComment,
    ReviewDecision,
    ReviewStatus,
    SafetyInformation,
    SafetySeverity,
    SpreadsheetCellRange,
    TimestampedModel,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def document_id():
    return uuid4()


@pytest.fixture
def document_source():
    return DocumentSource(
        source_name="Manufacturer website",
        source_uri="https://example.com/manual.pdf",
        supplier="Example Instruments",
        uploaded_by="engineer@example.com",
        notes="Official manufacturer documentation.",
    )


@pytest.fixture
def valid_checksum():
    return "a" * 64


@pytest.fixture
def document_upload(document_id, document_source, valid_checksum):
    return DocumentUpload(
        document_id=document_id,
        filename="pressure_transmitter_manual.pdf",
        original_filename="pressure_transmitter_manual.pdf",
        document_format=DocumentFormat.PDF,
        media_type="application/pdf",
        size_bytes=125_000,
        storage_key=(
            f"engineering-documents/{document_id}/"
            "pressure_transmitter_manual.pdf"
        ),
        checksum_sha256=valid_checksum,
        source=document_source,
    )


@pytest.fixture
def evidence_reference(document_id):
    return EvidenceReference(
        document_id=document_id,
        evidence_type=EvidenceType.TEXT,
        location=EvidenceLocation(
            page_number=14,
            section="Troubleshooting",
            paragraph_number=3,
        ),
        quoted_text=(
            "Verify that the impulse lines are not blocked before replacing "
            "the transmitter."
        ),
        source_title="Pressure Transmitter Service Manual",
        source_revision="Rev 4",
        extraction_confidence=0.96,
    )


@pytest.fixture
def engineering_fact(document_id, evidence_reference):
    return ExtractedEngineeringFact(
        document_id=document_id,
        fact_type=EngineeringFactType.TROUBLESHOOTING_STEP,
        title="Check impulse lines",
        statement=(
            "Verify that both impulse lines are clear before replacing the "
            "pressure transmitter."
        ),
        manufacturer="Example Instruments",
        product_family="PX Pressure Transmitters",
        equipment_categories=[EquipmentCategory.PRESSURE_INSTRUMENT],
        actions=[
            "Isolate the process connection.",
            "Depressurise the impulse lines.",
            "Inspect both impulse lines for blockage.",
        ],
        verification_steps=[
            "Restore the process safely.",
            "Confirm that the pressure reading responds correctly.",
        ],
        required_tools=[
            "Calibrated pressure source",
            "Digital multimeter",
        ],
        safety_information=[
            SafetyInformation(
                severity=SafetySeverity.WARNING,
                hazard="Stored process pressure",
                consequence="Unexpected pressure release may cause injury.",
                required_actions=[
                    "Isolate the process.",
                    "Depressurise the impulse lines.",
                ],
                required_ppe=[
                    "Safety glasses",
                    "Protective gloves",
                ],
            )
        ],
        evidence=[evidence_reference],
        extraction_confidence=0.92,
    )


# ---------------------------------------------------------------------------
# Timestamped model tests
# ---------------------------------------------------------------------------


def test_timestamped_model_accepts_valid_timestamps():
    created_at = datetime.now(UTC)
    updated_at = created_at + timedelta(seconds=1)

    model = TimestampedModel(
        created_at=created_at,
        updated_at=updated_at,
    )

    assert model.created_at == created_at
    assert model.updated_at == updated_at


def test_timestamped_model_rejects_updated_at_before_created_at():
    created_at = datetime.now(UTC)
    updated_at = created_at - timedelta(seconds=1)

    with pytest.raises(
        ValidationError,
        match="updated_at cannot be earlier than created_at",
    ):
        TimestampedModel(
            created_at=created_at,
            updated_at=updated_at,
        )


# ---------------------------------------------------------------------------
# Document source and upload tests
# ---------------------------------------------------------------------------


def test_document_source_accepts_valid_values():
    source = DocumentSource(
        source_name="Plant document library",
        source_uri="s3://documents/manual.pdf",
        supplier="Example Supplier",
        uploaded_by="user-123",
        organisation_id=uuid4(),
        notes="Approved plant document.",
    )

    assert source.source_name == "Plant document library"
    assert source.supplier == "Example Supplier"


def test_document_source_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        DocumentSource(
            source_name="Manual upload",
            unsupported_field="value",
        )


def test_document_upload_accepts_valid_document(document_upload):
    assert document_upload.document_format == DocumentFormat.PDF
    assert document_upload.size_bytes == 125_000
    assert document_upload.filename == "pressure_transmitter_manual.pdf"


def test_document_upload_removes_directory_from_filename(
    document_id,
    document_source,
    valid_checksum,
):
    upload = DocumentUpload(
        document_id=document_id,
        filename=r"C:\Users\Engineer\Documents\manual.pdf",
        original_filename="../../unsafe/manual.pdf",
        document_format=DocumentFormat.PDF,
        size_bytes=100,
        storage_key="documents/manual.pdf",
        checksum_sha256=valid_checksum,
        source=document_source,
    )

    assert upload.filename == "manual.pdf"
    assert upload.original_filename == "manual.pdf"


@pytest.mark.parametrize(
    "invalid_filename",
    [
        "",
        ".",
        "..",
        "/",
        "\\",
    ],
)
def test_document_upload_rejects_invalid_filename(
    invalid_filename,
    document_id,
    document_source,
    valid_checksum,
):
    with pytest.raises(ValidationError):
        DocumentUpload(
            document_id=document_id,
            filename=invalid_filename,
            document_format=DocumentFormat.PDF,
            size_bytes=100,
            storage_key="documents/manual.pdf",
            checksum_sha256=valid_checksum,
            source=document_source,
        )


@pytest.mark.parametrize(
    "invalid_checksum",
    [
        "",
        "a" * 63,
        "a" * 65,
        "g" * 64,
        "not-a-checksum",
    ],
)
def test_document_upload_rejects_invalid_sha256(
    invalid_checksum,
    document_id,
    document_source,
):
    with pytest.raises(ValidationError):
        DocumentUpload(
            document_id=document_id,
            filename="manual.pdf",
            document_format=DocumentFormat.PDF,
            size_bytes=100,
            storage_key="documents/manual.pdf",
            checksum_sha256=invalid_checksum,
            source=document_source,
        )


def test_document_upload_normalises_checksum_to_lowercase(
    document_id,
    document_source,
):
    upload = DocumentUpload(
        document_id=document_id,
        filename="manual.pdf",
        document_format=DocumentFormat.PDF,
        size_bytes=100,
        storage_key="documents/manual.pdf",
        checksum_sha256="A" * 64,
        source=document_source,
    )

    assert upload.checksum_sha256 == "a" * 64


def test_document_upload_calculates_expected_sha256():
    checksum = DocumentUpload.calculate_sha256(b"Engineer4Me")

    assert checksum == (
        "5dfbbdf8b119aef320cdd50c84fe2857"
        "d83347bea821d59653d252488d9b57ad"
    )


def test_document_upload_rejects_negative_size(
    document_id,
    document_source,
    valid_checksum,
):
    with pytest.raises(ValidationError):
        DocumentUpload(
            document_id=document_id,
            filename="manual.pdf",
            document_format=DocumentFormat.PDF,
            size_bytes=-1,
            storage_key="documents/manual.pdf",
            checksum_sha256=valid_checksum,
            source=document_source,
        )


# ---------------------------------------------------------------------------
# Parsed table and content block tests
# ---------------------------------------------------------------------------


def test_parsed_table_derives_dimensions():
    table = ParsedTable(
        headers=["Parameter", "Value", "Unit"],
        rows=[
            ["Range", "0 to 10", "bar"],
            ["Accuracy", "0.1", "%"],
        ],
    )

    assert table.column_count == 3
    assert table.row_count == 2


def test_parsed_table_supports_rows_wider_than_headers():
    table = ParsedTable(
        headers=["Parameter", "Value"],
        rows=[
            ["Range", "0 to 10", "bar"],
        ],
    )

    assert table.column_count == 3
    assert table.row_count == 1


def test_parsed_table_rejects_column_count_smaller_than_data():
    with pytest.raises(
        ValidationError,
        match="column_count cannot be smaller",
    ):
        ParsedTable(
            headers=["A", "B", "C"],
            rows=[["1", "2", "3"]],
            column_count=2,
        )


def test_parsed_table_rejects_row_count_smaller_than_rows():
    with pytest.raises(
        ValidationError,
        match="row_count cannot be smaller",
    ):
        ParsedTable(
            rows=[
                ["1"],
                ["2"],
            ],
            row_count=1,
        )


def test_text_content_block_accepts_text():
    block = ParsedContentBlock(
        block_type=ContentBlockType.PARAGRAPH,
        text="The transmitter requires a 24 VDC power supply.",
        page_number=2,
        sequence_number=1,
        extraction_method=ExtractionMethod.NATIVE_TEXT,
        extraction_confidence=0.99,
    )

    assert block.page_number == 2
    assert block.text.startswith("The transmitter")


def test_table_content_block_accepts_structured_table_without_text():
    block = ParsedContentBlock(
        block_type=ContentBlockType.TABLE,
        table=ParsedTable(
            headers=["Parameter", "Value"],
            rows=[["Accuracy", "0.1%"]],
        ),
        page_number=3,
        sequence_number=5,
        extraction_method=ExtractionMethod.TABLE_EXTRACTION,
    )

    assert block.table is not None
    assert block.table.row_count == 1


@pytest.mark.parametrize(
    "block_type",
    [
        ContentBlockType.IMAGE,
        ContentBlockType.DIAGRAM,
        ContentBlockType.DRAWING,
        ContentBlockType.PAGE_NUMBER,
    ],
)
def test_non_text_visual_blocks_may_be_empty(block_type):
    block = ParsedContentBlock(
        block_type=block_type,
        sequence_number=1,
        extraction_method=ExtractionMethod.IMAGE_ANALYSIS,
    )

    assert block.text == ""


def test_paragraph_block_rejects_empty_content():
    with pytest.raises(
        ValidationError,
        match="content block must contain text",
    ):
        ParsedContentBlock(
            block_type=ContentBlockType.PARAGRAPH,
            sequence_number=1,
        )


def test_content_block_rejects_confidence_above_one():
    with pytest.raises(ValidationError):
        ParsedContentBlock(
            block_type=ContentBlockType.PARAGRAPH,
            text="Valid text",
            sequence_number=1,
            extraction_confidence=1.1,
        )


def test_spreadsheet_cell_range_accepts_valid_values():
    cell_range = SpreadsheetCellRange(
        sheet_name="Specifications",
        start_cell="A2",
        end_cell="D10",
    )

    assert cell_range.sheet_name == "Specifications"
    assert cell_range.start_cell == "A2"


# ---------------------------------------------------------------------------
# Parsed page and document tests
# ---------------------------------------------------------------------------


def test_parsed_page_assigns_page_number_to_blocks():
    block = ParsedContentBlock(
        block_type=ContentBlockType.PARAGRAPH,
        text="Installation requirements.",
        sequence_number=1,
    )

    page = ParsedPage(
        page_number=4,
        text="Installation requirements.",
        blocks=[block],
        extraction_method=ExtractionMethod.NATIVE_TEXT,
    )

    assert page.blocks[0].page_number == 4


def test_parsed_page_rejects_mismatched_block_page_number():
    block = ParsedContentBlock(
        block_type=ContentBlockType.PARAGRAPH,
        text="Installation requirements.",
        page_number=3,
        sequence_number=1,
    )

    with pytest.raises(
        ValidationError,
        match="block page_number must match",
    ):
        ParsedPage(
            page_number=4,
            blocks=[block],
            extraction_method=ExtractionMethod.NATIVE_TEXT,
        )


def test_parsed_document_derives_text_and_statistics(document_id):
    page_one = ParsedPage(
        page_number=1,
        text="Pressure transmitter manual.",
        extraction_method=ExtractionMethod.NATIVE_TEXT,
    )
    page_two = ParsedPage(
        page_number=2,
        text="Installation and commissioning instructions.",
        extraction_method=ExtractionMethod.NATIVE_TEXT,
    )

    document = ParsedDocument(
        document_id=document_id,
        pages=[page_one, page_two],
        parser_name="test-parser",
        parser_version="1.0.0",
        extraction_method=ExtractionMethod.NATIVE_TEXT,
    )

    assert document.page_count == 2
    assert "Pressure transmitter manual." in document.full_text
    assert "Installation and commissioning instructions." in document.full_text
    assert document.character_count == len(document.full_text)
    assert document.word_count == len(document.full_text.split())


def test_parsed_document_rejects_page_count_smaller_than_pages(document_id):
    pages = [
        ParsedPage(page_number=1),
        ParsedPage(page_number=2),
    ]

    with pytest.raises(
        ValidationError,
        match="page_count cannot be smaller",
    ):
        ParsedDocument(
            document_id=document_id,
            pages=pages,
            page_count=1,
            parser_name="test-parser",
            parser_version="1.0",
            extraction_method=ExtractionMethod.NATIVE_TEXT,
        )


def test_parsed_document_rejects_duplicate_page_numbers(document_id):
    pages = [
        ParsedPage(page_number=1),
        ParsedPage(page_number=1),
    ]

    with pytest.raises(
        ValidationError,
        match="parsed pages must have unique page numbers",
    ):
        ParsedDocument(
            document_id=document_id,
            pages=pages,
            parser_name="test-parser",
            parser_version="1.0",
            extraction_method=ExtractionMethod.NATIVE_TEXT,
        )


# ---------------------------------------------------------------------------
# Metadata tests
# ---------------------------------------------------------------------------


def test_document_revision_accepts_valid_dates():
    revision = DocumentRevision(
        revision="Rev 3",
        edition="2026 Edition",
        publication_date=date(2026, 1, 10),
        effective_date=date(2026, 2, 1),
        supersedes_revision="Rev 2",
        document_number="DOC-1001",
    )

    assert revision.revision == "Rev 3"
    assert revision.document_number == "DOC-1001"


def test_document_revision_rejects_effective_date_before_publication_date():
    with pytest.raises(
        ValidationError,
        match="effective_date cannot be earlier",
    ):
        DocumentRevision(
            publication_date=date(2026, 5, 1),
            effective_date=date(2026, 4, 1),
        )


def test_product_reference_accepts_multiple_product_identifiers():
    reference = ProductReference(
        manufacturer="Example Instruments",
        brand="Example",
        product_family="PX Series",
        product_series="PX300",
        model_numbers=["PX301", "PX305"],
        part_numbers=["PX301-A1", "PX305-B2"],
        equipment_categories=[
            EquipmentCategory.PRESSURE_INSTRUMENT,
            EquipmentCategory.TRANSMITTER,
        ],
    )

    assert len(reference.model_numbers) == 2
    assert EquipmentCategory.TRANSMITTER in reference.equipment_categories


def test_extracted_document_metadata_accepts_valid_metadata(document_id):
    metadata = ExtractedDocumentMetadata(
        document_id=document_id,
        title="PX Series Pressure Transmitter Manual",
        document_type=DocumentType.USER_MANUAL,
        language=DocumentLanguage.ENGLISH,
        revision=DocumentRevision(
            revision="Rev 4",
            publication_date=date(2026, 3, 15),
            document_number="PX-MAN-004",
        ),
        product_reference=ProductReference(
            manufacturer="Example Instruments",
            product_family="PX Series",
            model_numbers=["PX301"],
            equipment_categories=[
                EquipmentCategory.PRESSURE_INSTRUMENT,
            ],
        ),
        publisher="Example Instruments",
        applicable_industries=["Mining", "Oil and Gas"],
        standards_referenced=["IEC 61508"],
        hazardous_area_certifications=["ATEX", "IECEx"],
        keywords=["pressure", "transmitter", "calibration"],
        metadata_confidence=0.94,
        field_confidences={
            "manufacturer": 0.99,
            "document_type": 0.93,
        },
    )

    assert metadata.document_type == DocumentType.USER_MANUAL
    assert metadata.metadata_confidence == 0.94


@pytest.mark.parametrize(
    "invalid_confidence",
    [
        -0.01,
        1.01,
        2,
    ],
)
def test_extracted_document_metadata_rejects_invalid_field_confidence(
    invalid_confidence,
    document_id,
):
    with pytest.raises(
        ValidationError,
        match="all field confidence values",
    ):
        ExtractedDocumentMetadata(
            document_id=document_id,
            field_confidences={
                "manufacturer": invalid_confidence,
            },
        )


# ---------------------------------------------------------------------------
# Evidence tests
# ---------------------------------------------------------------------------


def test_evidence_reference_accepts_page_location(evidence_reference):
    assert evidence_reference.location.page_number == 14
    assert evidence_reference.evidence_type == EvidenceType.TEXT


def test_evidence_reference_accepts_spreadsheet_location(document_id):
    evidence = EvidenceReference(
        document_id=document_id,
        evidence_type=EvidenceType.SPREADSHEET_CELL,
        location=EvidenceLocation(
            spreadsheet_range=SpreadsheetCellRange(
                sheet_name="Technical Data",
                start_cell="B4",
                end_cell="C6",
            )
        ),
        quoted_text="Operating temperature: -40 to 85 °C",
    )

    assert evidence.location.spreadsheet_range is not None
    assert evidence.location.spreadsheet_range.sheet_name == "Technical Data"


def test_evidence_reference_rejects_missing_location(document_id):
    with pytest.raises(
        ValidationError,
        match="evidence must include at least one source location",
    ):
        EvidenceReference(
            document_id=document_id,
            evidence_type=EvidenceType.TEXT,
            location=EvidenceLocation(),
            quoted_text="Unsupported evidence.",
        )


# ---------------------------------------------------------------------------
# Engineering value and safety tests
# ---------------------------------------------------------------------------


def test_engineering_value_accepts_range():
    value = EngineeringValue(
        value="-40 to 85",
        unit="°C",
        minimum=-40,
        maximum=85,
        nominal=25,
        tolerance=0.5,
        conditions=["Non-condensing atmosphere"],
    )

    assert value.minimum == -40
    assert value.maximum == 85
    assert value.unit == "°C"


def test_engineering_value_rejects_minimum_above_maximum():
    with pytest.raises(
        ValidationError,
        match="minimum cannot be greater than maximum",
    ):
        EngineeringValue(
            value="Invalid range",
            minimum=100,
            maximum=10,
        )


@pytest.mark.parametrize(
    ("minimum", "maximum", "nominal", "expected_message"),
    [
        (0, 100, -1, "nominal cannot be smaller than minimum"),
        (0, 100, 101, "nominal cannot be greater than maximum"),
    ],
)
def test_engineering_value_rejects_nominal_outside_range(
    minimum,
    maximum,
    nominal,
    expected_message,
):
    with pytest.raises(ValidationError, match=expected_message):
        EngineeringValue(
            value=nominal,
            minimum=minimum,
            maximum=maximum,
            nominal=nominal,
        )


def test_safety_information_accepts_complete_safety_context():
    safety = SafetyInformation(
        severity=SafetySeverity.DANGER,
        hazard="Live electrical conductors",
        consequence="Electric shock or fatal injury.",
        required_actions=[
            "Isolate the electrical supply.",
            "Test for dead.",
        ],
        prohibited_actions=[
            "Do not work live.",
        ],
        required_ppe=[
            "Arc-rated clothing",
            "Insulated gloves",
        ],
        isolation_requirements=[
            "Apply lockout and tagout.",
        ],
        permit_requirements=[
            "Electrical work permit",
        ],
        escalation_required=True,
    )

    assert safety.severity == SafetySeverity.DANGER
    assert safety.escalation_required is True


# ---------------------------------------------------------------------------
# Engineering fact tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("confidence", "expected_level"),
    [
        (0.00, ConfidenceLevel.VERY_LOW),
        (0.19, ConfidenceLevel.VERY_LOW),
        (0.20, ConfidenceLevel.LOW),
        (0.39, ConfidenceLevel.LOW),
        (0.40, ConfidenceLevel.MEDIUM),
        (0.69, ConfidenceLevel.MEDIUM),
        (0.70, ConfidenceLevel.HIGH),
        (0.89, ConfidenceLevel.HIGH),
        (0.90, ConfidenceLevel.VERY_HIGH),
        (1.00, ConfidenceLevel.VERY_HIGH),
    ],
)
def test_engineering_fact_derives_confidence_level(
    confidence,
    expected_level,
    document_id,
):
    fact = ExtractedEngineeringFact(
        document_id=document_id,
        fact_type=EngineeringFactType.SPECIFICATION,
        title="Accuracy",
        statement="The stated reference accuracy is ±0.1%.",
        extraction_confidence=confidence,
    )

    assert fact.confidence_level == expected_level


def test_engineering_fact_preserves_pending_review_by_default(
    engineering_fact,
):
    assert engineering_fact.requires_human_review is True
    assert engineering_fact.review_status == ReviewStatus.PENDING


def test_engineering_fact_sets_review_not_required():
    fact = ExtractedEngineeringFact(
        document_id=uuid4(),
        fact_type=EngineeringFactType.PRODUCT_FEATURE,
        title="Digital display",
        statement="The device includes an optional digital display.",
        extraction_confidence=0.99,
        requires_human_review=False,
    )

    assert fact.review_status == ReviewStatus.NOT_REQUIRED


def test_engineering_fact_resets_inconsistent_not_required_review_status():
    fact = ExtractedEngineeringFact(
        document_id=uuid4(),
        fact_type=EngineeringFactType.SPECIFICATION,
        title="Output signal",
        statement="The output signal is 4-20 mA.",
        extraction_confidence=0.90,
        requires_human_review=True,
        review_status=ReviewStatus.NOT_REQUIRED,
    )

    assert fact.review_status == ReviewStatus.PENDING


def test_engineering_fact_contains_traceable_safety_information(
    engineering_fact,
):
    assert len(engineering_fact.evidence) == 1
    assert len(engineering_fact.safety_information) == 1
    assert (
        engineering_fact.safety_information[0].severity
        == SafetySeverity.WARNING
    )


# ---------------------------------------------------------------------------
# Engineering extraction result tests
# ---------------------------------------------------------------------------


def test_engineering_extraction_result_counts_facts(
    document_id,
    engineering_fact,
):
    safety_fact = ExtractedEngineeringFact(
        document_id=document_id,
        fact_type=EngineeringFactType.SAFETY_WARNING,
        title="Stored pressure hazard",
        statement="Depressurise the system before opening process connections.",
        extraction_confidence=0.98,
    )

    result = EngineeringExtractionResult(
        document_id=document_id,
        facts=[engineering_fact, safety_fact],
        extraction_engine="Engineer4Me Rules Engine",
        extraction_engine_version="1.0.0",
        extraction_confidence=0.91,
        processed_block_count=24,
        skipped_block_count=2,
    )

    assert result.fact_count == 2
    assert result.safety_fact_count == 2


def test_engineering_extraction_result_counts_non_safety_fact_as_zero(
    document_id,
):
    fact = ExtractedEngineeringFact(
        document_id=document_id,
        fact_type=EngineeringFactType.PRODUCT_FEATURE,
        title="Local display",
        statement="The transmitter supports a local display.",
        extraction_confidence=0.95,
    )

    result = EngineeringExtractionResult(
        document_id=document_id,
        facts=[fact],
        extraction_engine="Test extractor",
        extraction_engine_version="1.0",
    )

    assert result.fact_count == 1
    assert result.safety_fact_count == 0


# ---------------------------------------------------------------------------
# Duplicate detection tests
# ---------------------------------------------------------------------------


def test_duplicate_candidate_validates_checksum(valid_checksum):
    candidate = DuplicateCandidate(
        candidate_document_id=uuid4(),
        match_type=DuplicateMatchType.EXACT_FILE,
        similarity_score=1.0,
        filename="manual.pdf",
        checksum_sha256=valid_checksum,
        matching_reasons=["Identical SHA-256 checksum"],
    )

    assert candidate.checksum_sha256 == valid_checksum


def test_duplicate_candidate_rejects_invalid_checksum():
    with pytest.raises(ValidationError):
        DuplicateCandidate(
            candidate_document_id=uuid4(),
            match_type=DuplicateMatchType.EXACT_FILE,
            similarity_score=1.0,
            checksum_sha256="invalid",
        )


def test_duplicate_detection_derives_exact_duplicate_state(document_id):
    candidate = DuplicateCandidate(
        candidate_document_id=uuid4(),
        match_type=DuplicateMatchType.EXACT_CONTENT,
        similarity_score=1.0,
        filename="existing_manual.pdf",
    )

    result = DuplicateDetectionResult(
        document_id=document_id,
        candidates=[candidate],
    )

    assert result.is_duplicate is True
    assert result.match_type == DuplicateMatchType.EXACT_CONTENT
    assert result.highest_similarity_score == 1.0


def test_duplicate_detection_near_duplicate_is_not_exact_duplicate(
    document_id,
):
    candidate = DuplicateCandidate(
        candidate_document_id=uuid4(),
        match_type=DuplicateMatchType.NEAR_DUPLICATE,
        similarity_score=0.91,
    )

    result = DuplicateDetectionResult(
        document_id=document_id,
        candidates=[candidate],
    )

    assert result.is_duplicate is False
    assert result.match_type == DuplicateMatchType.NEAR_DUPLICATE
    assert result.highest_similarity_score == 0.91


def test_duplicate_detection_keeps_higher_explicit_similarity(document_id):
    candidate = DuplicateCandidate(
        candidate_document_id=uuid4(),
        match_type=DuplicateMatchType.POSSIBLE_DUPLICATE,
        similarity_score=0.70,
    )

    result = DuplicateDetectionResult(
        document_id=document_id,
        highest_similarity_score=0.80,
        candidates=[candidate],
    )

    assert result.highest_similarity_score == 0.80


# ---------------------------------------------------------------------------
# Review workflow tests
# ---------------------------------------------------------------------------


def test_review_comment_marks_resolution_time_automatically():
    comment = ReviewComment(
        author_id="reviewer-1",
        comment="Verify the pressure unit.",
        resolved=True,
        resolved_by="reviewer-2",
    )

    assert comment.resolved is True
    assert comment.resolved_at is not None


def test_review_comment_clears_resolution_fields_when_unresolved():
    comment = ReviewComment(
        author_id="reviewer-1",
        comment="Verify the pressure unit.",
        resolved=False,
        resolved_by="reviewer-2",
        resolved_at=datetime.now(UTC),
    )

    assert comment.resolved_by is None
    assert comment.resolved_at is None


def test_completed_fact_review_requires_decision():
    with pytest.raises(
        ValidationError,
        match="completed review must include a review decision",
    ):
        FactReview(
            fact_id=uuid4(),
            status=ReviewStatus.APPROVED,
            reviewer_id="engineer-1",
        )


def test_completed_fact_review_requires_reviewer():
    with pytest.raises(
        ValidationError,
        match="completed review must include reviewer_id",
    ):
        FactReview(
            fact_id=uuid4(),
            status=ReviewStatus.APPROVED,
            decision=ReviewDecision.APPROVE,
        )


def test_completed_fact_review_sets_reviewed_at():
    review = FactReview(
        fact_id=uuid4(),
        status=ReviewStatus.APPROVED,
        decision=ReviewDecision.APPROVE,
        reviewer_id="engineer-1",
    )

    assert review.reviewed_at is not None


def test_document_review_accepts_sufficient_approvals(document_id):
    review = DocumentReview(
        document_id=document_id,
        status=ReviewStatus.APPROVED,
        assigned_reviewer_ids=["engineer-1", "engineer-2"],
        required_approvals=2,
        approval_count=2,
    )

    assert review.status == ReviewStatus.APPROVED
    assert review.approval_count == 2


def test_document_review_rejects_approval_count_above_assigned_reviewers(
    document_id,
):
    with pytest.raises(
        ValidationError,
        match="approval_count cannot exceed",
    ):
        DocumentReview(
            document_id=document_id,
            assigned_reviewer_ids=["engineer-1"],
            approval_count=2,
        )


def test_document_review_rejects_insufficient_approvals(document_id):
    with pytest.raises(
        ValidationError,
        match="approved review must meet",
    ):
        DocumentReview(
            document_id=document_id,
            status=ReviewStatus.APPROVED,
            assigned_reviewer_ids=["engineer-1", "engineer-2"],
            required_approvals=2,
            approval_count=1,
        )


def test_rejected_document_review_requires_reason(document_id):
    with pytest.raises(
        ValidationError,
        match="rejected document review must include",
    ):
        DocumentReview(
            document_id=document_id,
            status=ReviewStatus.REJECTED,
            assigned_reviewer_ids=["engineer-1"],
        )


# ---------------------------------------------------------------------------
# Publication record tests
# ---------------------------------------------------------------------------


def test_published_record_requires_facts(document_id):
    with pytest.raises(
        ValidationError,
        match="published record must include at least one fact",
    ):
        PublicationRecord(
            document_id=document_id,
            status=KnowledgePublicationStatus.PUBLISHED,
            published_by="engineer-1",
        )


def test_published_record_sets_published_at(document_id):
    record = PublicationRecord(
        document_id=document_id,
        status=KnowledgePublicationStatus.PUBLISHED,
        published_fact_ids=[uuid4()],
        repository_version="2026.07.1",
        published_by="engineer-1",
    )

    assert record.published_at is not None


def test_withdrawn_record_requires_reason(document_id):
    with pytest.raises(
        ValidationError,
        match="withdrawn publication must include a reason",
    ):
        PublicationRecord(
            document_id=document_id,
            status=KnowledgePublicationStatus.WITHDRAWN,
        )


def test_withdrawn_record_sets_withdrawn_at(document_id):
    record = PublicationRecord(
        document_id=document_id,
        status=KnowledgePublicationStatus.WITHDRAWN,
        withdrawal_reason="Superseded by a newer approved revision.",
    )

    assert record.withdrawn_at is not None


# ---------------------------------------------------------------------------
# Ingestion error and job tests
# ---------------------------------------------------------------------------


def test_ingestion_error_accepts_structured_error():
    error = IngestionError(
        stage=IngestionStatus.PARSING,
        code="PARSE_FAILED",
        message="Unable to extract document text.",
        recoverable=True,
        technical_details="Encrypted PDF.",
    )

    assert error.code == "PARSE_FAILED"
    assert error.recoverable is True


def test_ingestion_job_accepts_matching_document_objects(
    document_upload,
    engineering_fact,
):
    extraction_result = EngineeringExtractionResult(
        document_id=document_upload.document_id,
        facts=[engineering_fact],
        extraction_engine="Engineer4Me Extractor",
        extraction_engine_version="1.0.0",
    )

    job = IngestionJob(
        document=document_upload,
        status=IngestionStatus.ENGINEERING_DATA_EXTRACTED,
        extraction_result=extraction_result,
        progress_percent=55,
    )

    assert job.document.document_id == extraction_result.document_id
    assert job.progress_percent == 55


def test_ingestion_job_rejects_mismatched_related_document(
    document_upload,
):
    parsed_document = ParsedDocument(
        document_id=uuid4(),
        parser_name="test-parser",
        parser_version="1.0",
        extraction_method=ExtractionMethod.NATIVE_TEXT,
    )

    with pytest.raises(
        ValidationError,
        match="all ingestion job objects must reference",
    ):
        IngestionJob(
            document=document_upload,
            parsed_document=parsed_document,
        )


def test_published_ingestion_job_requires_published_record(
    document_upload,
):
    with pytest.raises(
        ValidationError,
        match="published ingestion job requires",
    ):
        IngestionJob(
            document=document_upload,
            status=IngestionStatus.PUBLISHED,
        )


def test_published_ingestion_job_sets_progress_to_100(
    document_upload,
):
    publication = PublicationRecord(
        document_id=document_upload.document_id,
        status=KnowledgePublicationStatus.PUBLISHED,
        published_fact_ids=[uuid4()],
        published_by="engineer-1",
    )

    job = IngestionJob(
        document=document_upload,
        status=IngestionStatus.PUBLISHED,
        publication=publication,
        progress_percent=90,
    )

    assert job.progress_percent == 100


def test_failed_ingestion_job_requires_error(document_upload):
    with pytest.raises(
        ValidationError,
        match="failed ingestion job must contain at least one error",
    ):
        IngestionJob(
            document=document_upload,
            status=IngestionStatus.FAILED,
        )


def test_ingestion_job_transition_records_event(document_upload):
    job = IngestionJob(document=document_upload)

    job.transition_to(
        IngestionStatus.VALIDATING,
        message="Validating uploaded document.",
        actor_id="system",
        progress_percent=10,
        metadata={"validator": "document-validator-v1"},
    )

    assert job.status == IngestionStatus.VALIDATING
    assert job.progress_percent == 10
    assert job.current_stage_message == "Validating uploaded document."
    assert len(job.events) == 1
    assert job.events[0].status == IngestionStatus.VALIDATING
    assert job.events[0].actor_id == "system"
    assert job.events[0].metadata["validator"] == "document-validator-v1"


def test_ingestion_job_rejects_backwards_progress(document_upload):
    job = IngestionJob(
        document=document_upload,
        progress_percent=50,
    )

    with pytest.raises(
        ValueError,
        match="ingestion progress cannot move backwards",
    ):
        job.transition_to(
            IngestionStatus.PARSING,
            progress_percent=40,
        )


def test_ingestion_job_adds_recoverable_error_without_failing(
    document_upload,
):
    job = IngestionJob(
        document=document_upload,
        status=IngestionStatus.PARSING,
        progress_percent=30,
    )

    error = job.add_error(
        stage=IngestionStatus.PARSING,
        code="PAGE_SKIPPED",
        message="One page could not be parsed.",
        recoverable=True,
    )

    assert error.recoverable is True
    assert job.status == IngestionStatus.PARSING
    assert len(job.errors) == 1


def test_ingestion_job_adds_unrecoverable_error_and_fails(
    document_upload,
):
    job = IngestionJob(
        document=document_upload,
        status=IngestionStatus.PARSING,
        progress_percent=30,
    )

    error = job.add_error(
        stage=IngestionStatus.PARSING,
        code="UNSUPPORTED_ENCRYPTION",
        message="The document encryption method is unsupported.",
        recoverable=False,
        technical_details="AES-256 protected document.",
    )

    assert error.recoverable is False
    assert job.status == IngestionStatus.FAILED
    assert job.progress_percent == 30
    assert len(job.errors) == 1
    assert len(job.events) == 1
    assert job.events[0].status == IngestionStatus.FAILED
    assert job.events[0].metadata["error_code"] == "UNSUPPORTED_ENCRYPTION"


# ---------------------------------------------------------------------------
# Enumeration tests
# ---------------------------------------------------------------------------


def test_document_format_values_are_stable():
    assert DocumentFormat.PDF.value == "pdf"
    assert DocumentFormat.DOCX.value == "docx"
    assert DocumentFormat.ZIP.value == "zip"
    assert DocumentFormat.UNKNOWN.value == "unknown"


def test_document_type_includes_fault_and_safety_documents():
    assert DocumentType.FAULT_CODE_MANUAL.value == "fault_code_manual"
    assert DocumentType.SAFETY_MANUAL.value == "safety_manual"
    assert DocumentType.MIGRATION_GUIDE.value == "migration_guide"


def test_equipment_categories_include_multidisciplinary_assets():
    assert EquipmentCategory.CONTROL_VALVE.value == "control_valve"
    assert EquipmentCategory.PLC.value == "plc"
    assert EquipmentCategory.SWITCHGEAR.value == "switchgear"
    assert EquipmentCategory.FIRE_AND_GAS.value == "fire_and_gas"


def test_engineering_fact_types_include_safety_and_fault_intelligence():
    assert EngineeringFactType.FAULT_CODE.value == "fault_code"
    assert EngineeringFactType.SAFETY_WARNING.value == "safety_warning"
    assert EngineeringFactType.REQUIRED_TOOL.value == "required_tool"
    assert (
        EngineeringFactType.OBSOLESCENCE_INFORMATION.value
        == "obsolescence_information"
    )