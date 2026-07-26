"""Tests for deterministic engineering knowledge extraction."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from app.ingestion.document_models import (
    ContentBlockType,
    EngineeringFactType,
    ExtractionMethod,
    ParsedContentBlock,
    ParsedDocument,
    ParsedPage,
    ReviewStatus,
    SafetySeverity,
)
from app.ingestion.engineering_extractor import (
    EngineeringExtractionError,
    EngineeringExtractor,
    EngineeringExtractorConfig,
)


def make_block(
    text: str,
    *,
    block_type: ContentBlockType = ContentBlockType.PARAGRAPH,
    page_number: int = 1,
    sequence_number: int = 0,
    extraction_confidence: float = 1.0,
    section_path: list[str] | None = None,
) -> ParsedContentBlock:
    """Create a parsed content block for extraction tests."""

    return ParsedContentBlock(
        block_type=block_type,
        text=text,
        page_number=page_number,
        section_path=section_path or [],
        sequence_number=sequence_number,
        extraction_method=ExtractionMethod.NATIVE_TEXT,
        extraction_confidence=extraction_confidence,
    )


def make_document(
    blocks: list[ParsedContentBlock],
    *,
    document_id: UUID | None = None,
    title: str = "Test Engineering Document",
    extraction_confidence: float = 1.0,
) -> ParsedDocument:
    """Create a parsed document containing one page."""

    resolved_document_id = document_id or uuid4()

    page_text = "\n".join(block.text for block in blocks if block.text)

    return ParsedDocument(
        document_id=resolved_document_id,
        title=title,
        pages=[
            ParsedPage(
                page_number=1,
                text=page_text,
                blocks=blocks,
                extraction_method=ExtractionMethod.NATIVE_TEXT,
                extraction_confidence=extraction_confidence,
            )
        ],
        parser_name="test-parser",
        parser_version="1.0.0",
        extraction_method=ExtractionMethod.NATIVE_TEXT,
        extraction_confidence=extraction_confidence,
    )


def extract_single_fact(
    text: str,
    *,
    block_type: ContentBlockType = ContentBlockType.PARAGRAPH,
):
    """Extract and return one expected fact."""

    extractor = EngineeringExtractor()
    document = make_document(
        [
            make_block(
                text,
                block_type=block_type,
            )
        ]
    )

    result = extractor.extract(document)

    assert result.fact_count == 1

    return result.facts[0]


def test_default_configuration() -> None:
    config = EngineeringExtractorConfig()

    assert (
        config.engine_name
        == "Engineer4Me deterministic engineering extractor"
    )
    assert config.engine_version == "1.0.0"
    assert config.safety_review_required is True
    assert config.include_tables is True


@pytest.mark.parametrize(
    ("field_name", "value", "expected_message"),
    [
        ("engine_name", "", "engine_name cannot be empty"),
        ("engine_version", "", "engine_version cannot be empty"),
        (
            "minimum_text_length",
            0,
            "minimum_text_length must be positive",
        ),
        (
            "maximum_block_characters",
            0,
            "maximum_block_characters must be positive",
        ),
        (
            "maximum_fact_count",
            0,
            "maximum_fact_count must be positive",
        ),
        (
            "minimum_extraction_confidence",
            -0.1,
            "minimum_extraction_confidence must be between 0 and 1",
        ),
        (
            "automatic_review_threshold",
            1.1,
            "automatic_review_threshold must be between 0 and 1",
        ),
    ],
)
def test_invalid_configuration_values(
    field_name: str,
    value: object,
    expected_message: str,
) -> None:
    with pytest.raises(ValueError, match=expected_message):
        EngineeringExtractorConfig(**{field_name: value})


def test_rejects_non_parsed_document() -> None:
    extractor = EngineeringExtractor()

    with pytest.raises(
        EngineeringExtractionError,
        match="document must be a ParsedDocument instance",
    ):
        extractor.extract("not-a-document")  # type: ignore[arg-type]


def test_empty_document_returns_empty_result() -> None:
    extractor = EngineeringExtractor()
    document = make_document([])

    result = extractor.extract(document)

    assert result.document_id == document.document_id
    assert result.fact_count == 0
    assert result.facts == []
    assert result.extraction_confidence == 0.0
    assert result.processed_block_count == 0
    assert result.skipped_block_count == 0
    assert result.errors == []


def test_extracts_safety_warning_from_warning_block() -> None:
    fact = extract_single_fact(
        "Disconnect the power supply before opening the enclosure.",
        block_type=ContentBlockType.WARNING,
    )

    assert fact.fact_type == EngineeringFactType.SAFETY_WARNING
    assert fact.title == "Warning"
    assert fact.requires_human_review is True
    assert fact.review_status == ReviewStatus.PENDING
    assert fact.safety_information
    assert (
        fact.safety_information[0].severity
        == SafetySeverity.WARNING
    )
    assert fact.safety_information[0].isolation_requirements
    assert "safety" in fact.tags


def test_extracts_danger_severity() -> None:
    fact = extract_single_fact(
        "Danger: Explosion hazard may cause death.",
        block_type=ContentBlockType.DANGER,
    )

    assert fact.fact_type == EngineeringFactType.SAFETY_WARNING
    assert fact.safety_information
    assert (
        fact.safety_information[0].severity
        == SafetySeverity.DANGER
    )
    assert fact.safety_information[0].escalation_required is True


def test_extracts_caution_severity() -> None:
    fact = extract_single_fact(
        "Caution: Incorrect wiring may cause equipment damage.",
        block_type=ContentBlockType.CAUTION,
    )

    assert fact.fact_type == EngineeringFactType.SAFETY_WARNING
    assert fact.safety_information
    assert (
        fact.safety_information[0].severity
        == SafetySeverity.CAUTION
    )


def test_extracts_fault_code() -> None:
    fact = extract_single_fact(
        "Fault code E101 indicates a sensor communication failure."
    )

    assert fact.fact_type == EngineeringFactType.FAULT_CODE
    assert fact.title == "Fault code"


def test_extracts_likely_cause() -> None:
    fact = extract_single_fact(
        "Possible causes include a blocked impulse line."
    )

    assert fact.fact_type == EngineeringFactType.LIKELY_CAUSE


def test_extracts_corrective_action() -> None:
    fact = extract_single_fact(
        "Corrective action: Replace the damaged pressure sensor."
    )

    assert fact.fact_type == EngineeringFactType.CORRECTIVE_ACTION
    assert fact.actions == [
        "Corrective action: Replace the damaged pressure sensor."
    ]
    assert "sensor" in fact.required_parts


def test_extracts_troubleshooting_step() -> None:
    fact = extract_single_fact(
        "Check the signal cable for loose connections."
    )

    assert fact.fact_type == EngineeringFactType.TROUBLESHOOTING_STEP
    assert fact.actions == [
        "Check the signal cable for loose connections."
    ]
    assert "cable" in fact.required_parts


def test_extracts_verification_step() -> None:
    fact = extract_single_fact(
        "Confirm that the output signal is stable after calibration."
    )

    assert fact.fact_type == EngineeringFactType.VERIFICATION_STEP
    assert fact.verification_steps == [
        "Confirm that the output signal is stable after calibration."
    ]


def test_extracts_installation_requirement() -> None:
    fact = extract_single_fact(
        "Install the transmitter vertically with a minimum clearance "
        "of 200 mm."
    )

    assert (
        fact.fact_type
        == EngineeringFactType.INSTALLATION_REQUIREMENT
    )
    assert fact.actions
    assert fact.value is not None
    assert fact.value.unit == "mm"
    assert fact.value.nominal == 200.0


def test_extracts_calibration_step() -> None:
    fact = extract_single_fact(
        "Calibrate the transmitter using a pressure calibrator."
    )

    assert fact.fact_type == EngineeringFactType.CALIBRATION_STEP
    assert "pressure calibrator" in fact.required_tools
    assert fact.actions


def test_extracts_maintenance_interval_range() -> None:
    fact = extract_single_fact(
        "Perform maintenance every 6 months."
    )

    assert fact.fact_type == EngineeringFactType.MAINTENANCE_INTERVAL
    assert fact.value is not None
    assert fact.value.nominal == 6.0
    assert fact.value.unit.lower() == "months"


def test_extracts_operating_limit_with_range() -> None:
    fact = extract_single_fact(
        "The operating temperature range is -20 to 80 °C."
    )

    assert fact.fact_type == EngineeringFactType.OPERATING_LIMIT
    assert fact.value is not None
    assert fact.value.minimum == -20.0
    assert fact.value.maximum == 80.0
    assert fact.value.unit == "°C"


def test_extracts_environmental_limit() -> None:
    fact = extract_single_fact(
        "The ambient temperature must remain below 60 °C."
    )

    assert fact.fact_type == EngineeringFactType.ENVIRONMENTAL_LIMIT
    assert fact.value is not None
    assert fact.value.nominal == 60.0
    assert fact.value.unit == "°C"


def test_extracts_material_compatibility() -> None:
    fact = extract_single_fact(
        "The wetted material is compatible with clean water."
    )

    assert (
        fact.fact_type
        == EngineeringFactType.MATERIAL_COMPATIBILITY
    )


def test_extracts_required_tool() -> None:
    fact = extract_single_fact(
        "Required tools include a multimeter and torque wrench."
    )

    assert fact.fact_type == EngineeringFactType.REQUIRED_TOOL
    assert "multimeter" in fact.required_tools
    assert "torque wrench" in fact.required_tools


def test_extracts_spare_part() -> None:
    fact = extract_single_fact(
        "Recommended spare parts include one replacement gasket."
    )

    assert fact.fact_type == EngineeringFactType.SPARE_PART
    assert "gasket" in fact.required_parts


def test_extracts_obsolescence_information() -> None:
    fact = extract_single_fact(
        "This controller is discontinued and no longer supported."
    )

    assert (
        fact.fact_type
        == EngineeringFactType.OBSOLESCENCE_INFORMATION
    )


def test_extracts_migration_guidance() -> None:
    fact = extract_single_fact(
        "The recommended migration path is to upgrade the controller."
    )

    assert fact.fact_type == EngineeringFactType.MIGRATION_GUIDANCE


def test_extracts_communication_protocol() -> None:
    fact = extract_single_fact(
        "The transmitter supports HART communication."
    )

    assert (
        fact.fact_type
        == EngineeringFactType.COMMUNICATION_PROTOCOL
    )


def test_extracts_certification_and_standard() -> None:
    fact = extract_single_fact(
        "The device is IECEx certified in accordance with IEC 60079-0."
    )

    assert fact.fact_type == EngineeringFactType.CERTIFICATION
    assert "IEC 60079-0" in fact.standards_referenced
    assert "standards" in fact.tags


def test_evidence_contains_page_section_and_block() -> None:
    extractor = EngineeringExtractor()
    block = make_block(
        "The rated pressure is 10 bar.",
        page_number=1,
        sequence_number=3,
        section_path=["Technical Data", "Pressure"],
    )
    document = make_document([block])

    result = extractor.extract(document)

    assert result.fact_count == 1

    fact = result.facts[0]
    evidence = fact.evidence[0]

    assert evidence.document_id == document.document_id
    assert evidence.location.page_number == 1
    assert evidence.location.section == "Technical Data > Pressure"
    assert evidence.location.block_id == block.block_id
    assert evidence.quoted_text == "The rated pressure is 10 bar."
    assert evidence.source_title == "Test Engineering Document"


def test_skips_header_footer_and_page_number_blocks() -> None:
    extractor = EngineeringExtractor()

    document = make_document(
        [
            make_block(
                "Technical data rated pressure 10 bar.",
                block_type=ContentBlockType.HEADER,
                sequence_number=0,
            ),
            make_block(
                "Technical data rated pressure 10 bar.",
                block_type=ContentBlockType.FOOTER,
                sequence_number=1,
            ),
            make_block(
                "Page number 1",
                block_type=ContentBlockType.PAGE_NUMBER,
                sequence_number=2,
            ),
        ]
    )

    result = extractor.extract(document)

    assert result.fact_count == 0
    assert result.processed_block_count == 0
    assert result.skipped_block_count == 3


def test_skips_heading_by_default() -> None:
    extractor = EngineeringExtractor()

    document = make_document(
        [
            make_block(
                "Technical data and specifications",
                block_type=ContentBlockType.HEADING,
            )
        ]
    )

    result = extractor.extract(document)

    assert result.fact_count == 0
    assert result.processed_block_count == 0
    assert result.skipped_block_count == 1


def test_can_include_heading_blocks() -> None:
    extractor = EngineeringExtractor(
        EngineeringExtractorConfig(include_headings=True)
    )

    document = make_document(
        [
            make_block(
                "Technical data and specifications",
                block_type=ContentBlockType.HEADING,
            )
        ]
    )

    result = extractor.extract(document)

    assert result.fact_count == 1
    assert result.processed_block_count == 1
    assert (
        result.facts[0].fact_type
        == EngineeringFactType.SPECIFICATION
    )


def test_deduplicates_identical_facts_on_same_page() -> None:
    extractor = EngineeringExtractor()

    statement = "The rated pressure is 10 bar."

    document = make_document(
        [
            make_block(statement, sequence_number=0),
            make_block(statement, sequence_number=1),
        ]
    )

    result = extractor.extract(document)

    assert result.fact_count == 1


def test_keeps_different_fact_types() -> None:
    extractor = EngineeringExtractor()

    document = make_document(
        [
            make_block(
                "The rated pressure is 10 bar.",
                sequence_number=0,
            ),
            make_block(
                "Warning: Do not exceed the rated pressure.",
                block_type=ContentBlockType.WARNING,
                sequence_number=1,
            ),
        ]
    )

    result = extractor.extract(document)

    assert result.fact_count == 2
    assert {
        fact.fact_type for fact in result.facts
    } == {
        EngineeringFactType.OPERATING_LIMIT,
        EngineeringFactType.SAFETY_WARNING,
    }


def test_result_includes_engine_metadata() -> None:
    extractor = EngineeringExtractor()
    document = make_document(
        [make_block("The rated pressure is 10 bar.")]
    )

    result = extractor.extract(document)

    assert (
        result.extraction_engine
        == "Engineer4Me deterministic engineering extractor"
    )
    assert result.extraction_engine_version == "1.0.0"
    assert result.extraction_metadata["parser_name"] == "test-parser"
    assert result.extraction_metadata["parser_version"] == "1.0.0"
    assert result.extraction_metadata["metadata_applied"] is False
    assert result.extraction_metadata["deterministic_extraction"] is True


def test_result_confidence_is_bounded() -> None:
    extractor = EngineeringExtractor()

    document = make_document(
        [make_block("The rated pressure is 10 bar.")],
        extraction_confidence=0.80,
    )

    result = extractor.extract(document)

    assert 0.0 <= result.extraction_confidence <= 1.0
    assert 0.0 <= result.facts[0].extraction_confidence <= 1.0


def test_document_warnings_and_errors_are_preserved() -> None:
    extractor = EngineeringExtractor()
    document = make_document(
        [make_block("The rated pressure is 10 bar.")]
    )

    document.warnings.extend(
        [
            "Low-quality scan",
            "Low-quality scan",
        ]
    )
    document.errors.extend(
        [
            "One image could not be parsed",
            "One image could not be parsed",
        ]
    )

    result = extractor.extract(document)

    assert result.warnings == ["Low-quality scan"]
    assert result.errors == ["One image could not be parsed"]


def test_compatibility_alias_matches_extract() -> None:
    extractor = EngineeringExtractor()
    document = make_document(
        [make_block("The rated pressure is 10 bar.")]
    )

    direct_result = extractor.extract(document)
    alias_result = extractor.extract_engineering_facts(document)

    assert direct_result.document_id == alias_result.document_id
    assert direct_result.fact_count == alias_result.fact_count
    assert (
        direct_result.facts[0].fact_type
        == alias_result.facts[0].fact_type
    )
    assert (
        direct_result.facts[0].statement
        == alias_result.facts[0].statement
    )