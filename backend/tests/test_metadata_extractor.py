"""Tests for deterministic engineering document metadata extraction."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from app.ingestion.document_models import ExtractedDocumentMetadata
from app.ingestion.metadata_extractor import (
    MetadataExtractionError,
    MetadataExtractor,
    MetadataExtractorConfig,
    extract_metadata,
)


@pytest.fixture
def extractor() -> MetadataExtractor:
    """Return a metadata extractor using the default configuration."""

    return MetadataExtractor()


@pytest.fixture
def rosemount_document() -> str:
    """Return a representative process-instrumentation datasheet."""

    return """
Rosemount 3051 Pressure Transmitter
Product Data Sheet

Document Number: 00813-0100-4001
Revision: BA
Publication Date: 2025-04-15

Emerson Automation Solutions

Models: 3051CD, 3051TG
Part Number: 3051CD2A22A1AB4M5

Designed in accordance with IEC 61508 and ISA 84.00.01.
Hazardous area approvals include ATEX, IECEx and Ex ia.
Ingress protection: IP66.

Applications include oil and gas, chemical processing and power generation.
"""


def enum_value(value: object) -> str:
    """Return a consistent text value for string-like enum values."""

    return str(getattr(value, "value", value))


class TestMetadataExtractorConfig:
    """Configuration validation tests."""

    def test_default_configuration_is_valid(self) -> None:
        config = MetadataExtractorConfig()

        assert config.maximum_text_characters == 2_000_000
        assert config.maximum_keyword_count == 30
        assert config.confidence_floor == 0.0
        assert config.confidence_ceiling == 1.0

    @pytest.mark.parametrize(
        ("field_name", "value"),
        (
            ("maximum_text_characters", 0),
            ("title_search_line_count", 0),
            ("maximum_title_length", 0),
            ("minimum_keyword_length", 0),
            ("minimum_model_number_length", 0),
            ("maximum_list_values", 0),
        ),
    )
    def test_positive_configuration_fields_are_validated(
        self,
        field_name: str,
        value: int,
    ) -> None:
        with pytest.raises(ValueError):
            MetadataExtractorConfig(**{field_name: value})

    def test_keyword_count_cannot_be_negative(self) -> None:
        with pytest.raises(ValueError):
            MetadataExtractorConfig(maximum_keyword_count=-1)

    def test_maximum_model_length_cannot_be_smaller_than_minimum(self) -> None:
        with pytest.raises(ValueError):
            MetadataExtractorConfig(
                minimum_model_number_length=10,
                maximum_model_number_length=5,
            )

    @pytest.mark.parametrize(
        ("field_name", "value"),
        (
            ("confidence_floor", -0.01),
            ("confidence_floor", 1.01),
            ("confidence_ceiling", -0.01),
            ("confidence_ceiling", 1.01),
        ),
    )
    def test_confidence_limits_must_be_between_zero_and_one(
        self,
        field_name: str,
        value: float,
    ) -> None:
        with pytest.raises(ValueError):
            MetadataExtractorConfig(**{field_name: value})

    def test_confidence_floor_cannot_exceed_ceiling(self) -> None:
        with pytest.raises(ValueError):
            MetadataExtractorConfig(
                confidence_floor=0.8,
                confidence_ceiling=0.5,
            )


class TestInputNormalisation:
    """Input handling and validation tests."""

    def test_extract_accepts_plain_text(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract("Pressure Transmitter Data Sheet")

        assert isinstance(result, ExtractedDocumentMetadata)
        assert isinstance(result.document_id, UUID)

    def test_extract_accepts_utf8_bytes(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            "Temperature Transmitter Manual".encode("utf-8")
        )

        assert result.title == "Temperature Transmitter Manual"

    def test_non_utf8_bytes_raise_error(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        with pytest.raises(
            MetadataExtractionError,
            match="UTF-8",
        ):
            extractor.extract(b"\x96")

    @pytest.mark.parametrize("value", (None, "", "   ", "\n\t"))
    def test_empty_input_raises_error(
        self,
        extractor: MetadataExtractor,
        value: object,
    ) -> None:
        with pytest.raises(MetadataExtractionError):
            extractor.extract(value)

    def test_invalid_document_uuid_raises_error(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        with pytest.raises(
            MetadataExtractionError,
            match="invalid document UUID",
        ):
            extractor.extract(
                "Valve Manual",
                document_id="not-a-uuid",
            )

    def test_supplied_document_uuid_is_preserved(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        document_id = uuid4()

        result = extractor.extract(
            "Valve Manual",
            document_id=document_id,
        )

        assert result.document_id == document_id

    def test_string_document_uuid_is_converted(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        document_id = uuid4()

        result = extractor.extract(
            "Valve Manual",
            document_id=str(document_id),
        )

        assert result.document_id == document_id

    def test_object_text_attribute_is_supported(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        document = SimpleNamespace(
            text="Flow Transmitter Data Sheet",
            document_id=uuid4(),
            filename="flow-transmitter.txt",
        )

        result = extractor.extract(document)

        assert result.title == "Flow Transmitter Data Sheet"
        assert result.raw_metadata["source_filename"] == "flow-transmitter.txt"

    def test_object_content_attribute_is_supported(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        document = SimpleNamespace(
            content="Control Valve Installation Manual",
        )

        result = extractor.extract(document)

        assert result.title == "Control Valve Installation Manual"

    def test_object_blocks_are_combined(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        first_block_id = uuid4()
        second_block_id = uuid4()

        document = SimpleNamespace(
            blocks=[
                SimpleNamespace(
                    block_id=first_block_id,
                    text="Yokogawa Pressure Transmitter",
                ),
                SimpleNamespace(
                    block_id=second_block_id,
                    text="Installation Manual",
                ),
            ]
        )

        result = extractor.extract(document)

        assert result.title == "Yokogawa Pressure Transmitter"
        assert result.source_block_ids == [
            first_block_id,
            second_block_id,
        ]

    def test_invalid_block_ids_are_ignored(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        valid_block_id = uuid4()

        document = SimpleNamespace(
            blocks=[
                SimpleNamespace(block_id="invalid", text="Valve"),
                SimpleNamespace(
                    block_id=valid_block_id,
                    text="Manual",
                ),
            ]
        )

        result = extractor.extract(document)

        assert result.source_block_ids == [valid_block_id]

    def test_object_without_text_raises_error(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        with pytest.raises(
            MetadataExtractionError,
            match="does not expose usable text",
        ):
            extractor.extract(SimpleNamespace())

    def test_object_metadata_is_preserved(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        document = SimpleNamespace(
            text="Pressure Transmitter Manual",
            metadata={"parser": "standard-parser"},
            parser_metadata={"encoding": "utf-8"},
        )

        result = extractor.extract(
            document,
            raw_metadata={"source": "unit-test"},
        )

        assert result.raw_metadata["parser"] == "standard-parser"
        assert result.raw_metadata["encoding"] == "utf-8"
        assert result.raw_metadata["source"] == "unit-test"


class TestCompleteExtraction:
    """Integrated metadata extraction tests."""

    def test_extracts_complete_rosemount_metadata(
        self,
        extractor: MetadataExtractor,
        rosemount_document: str,
    ) -> None:
        result = extractor.extract(
            rosemount_document,
            document_id=uuid4(),
            filename="rosemount-3051-datasheet.txt",
        )

        assert result.title == "Rosemount 3051 Pressure Transmitter"
        assert enum_value(result.document_type) == "datasheet"
        assert result.product_reference.manufacturer == "Emerson"
        assert result.product_reference.brand == "Rosemount"
        assert result.product_reference.model_numbers == [
            "3051CD",
            "3051TG",
        ]
        assert result.product_reference.part_numbers == [
            "3051CD2A22A1AB4M5"
        ]
        assert result.revision.document_number == "00813-0100-4001"
        assert result.revision.revision == "BA"
        assert result.revision.publication_date == date(2025, 4, 15)
        assert "IEC 61508" in result.standards_referenced
        assert "ISA 84.00.01" in result.standards_referenced
        assert "ATEX" in result.hazardous_area_certifications
        assert "IECEx" in result.hazardous_area_certifications
        assert "Ex ia" in result.hazardous_area_certifications
        assert "IP66" in result.hazardous_area_certifications
        assert 0 <= result.metadata_confidence <= 1

    def test_complete_result_contains_extractor_metadata(
        self,
        extractor: MetadataExtractor,
        rosemount_document: str,
    ) -> None:
        result = extractor.extract(rosemount_document)

        assert (
            result.raw_metadata["extractor"]
            == "deterministic_metadata_extractor"
        )
        assert result.raw_metadata["extractor_version"] == "1.0.0"
        assert result.raw_metadata["processed_character_count"] > 0
        assert result.raw_metadata["source_character_count"] > 0
        assert result.raw_metadata["text_was_truncated"] is False

    def test_all_field_confidences_are_valid(
        self,
        extractor: MetadataExtractor,
        rosemount_document: str,
    ) -> None:
        result = extractor.extract(rosemount_document)

        assert result.field_confidences
        assert all(
            0 <= confidence <= 1
            for confidence in result.field_confidences.values()
        )


class TestTitleExtraction:
    """Title extraction tests."""

    def test_first_specific_line_beats_generic_subtitle(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Rosemount 3051 Pressure Transmitter
Product Data Sheet
"""
        )

        assert result.title == "Rosemount 3051 Pressure Transmitter"

    def test_title_hint_has_priority(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        document = SimpleNamespace(
            text="Generic Manual",
            title="Official Equipment Manual",
        )

        result = extractor.extract(document)

        assert result.title == "Official Equipment Manual"
        assert result.field_confidences["title"] == 0.98

    def test_markdown_title_is_cleaned(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            "# Yokogawa EJA Pressure Transmitter\nManual"
        )

        assert result.title == "Yokogawa EJA Pressure Transmitter"

    def test_filename_is_used_when_no_title_candidate_exists(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            "12345\n-----",
            filename="fisher-control-valve-manual.txt",
        )

        assert result.title == "fisher control valve manual"

    def test_warning_line_is_not_selected_as_title(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
WARNING: Isolate the process before maintenance
Fisher DVC6200 Positioner
Instruction Manual
"""
        )

        assert result.title == "Fisher DVC6200 Positioner"


class TestDocumentTypeExtraction:
    """Document-type classification tests."""

    @pytest.mark.parametrize(
        ("text", "expected"),
        (
            ("Product Data Sheet", "datasheet"),
            ("Installation Manual", "installation_manual"),
            ("Operating Instructions", "operation_manual"),
            ("Maintenance Manual", "maintenance_manual"),
            ("Safety Manual", "safety_manual"),
            ("Certificate of Conformity", "certificate"),
            ("General Arrangement Drawing", "drawing"),
            ("Technical Specification", "specification"),
            ("Standard Operating Procedure", "procedure"),
            ("Product Catalogue", "catalogue"),
            ("Application Note", "application_note"),
            ("White Paper", "white_paper"),
            ("Release Notes", "release_note"),
        ),
    )
    def test_document_types_are_classified(
        self,
        extractor: MetadataExtractor,
        text: str,
        expected: str,
    ) -> None:
        result = extractor.extract(text)

        assert enum_value(result.document_type) == expected

    def test_unknown_document_type_uses_unknown_enum(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract("Industrial Engineering Information")

        assert enum_value(result.document_type) == "unknown"


class TestLanguageExtraction:
    """Language detection tests."""

    @pytest.mark.parametrize(
        ("text", "expected"),
        (
            (
                "The installation and operation manual contains the warning.",
                "en",
            ),
            (
                "Die Installation und der Betrieb enthalten eine Warnung.",
                "de",
            ),
            (
                "Le fonctionnement et les instructions contiennent "
                "un avertissement.",
                "fr",
            ),
            (
                "La instalaci?n y el funcionamiento contienen "
                "una advertencia.",
                "es",
            ),
        ),
    )
    def test_common_languages_are_detected(
        self,
        extractor: MetadataExtractor,
        text: str,
        expected: str,
    ) -> None:
        result = extractor.extract(text)

        assert enum_value(result.language) == expected


class TestManufacturerAndBrandExtraction:
    """Manufacturer and brand extraction tests."""

    @pytest.mark.parametrize(
        ("text", "manufacturer"),
        (
            ("ABB pressure transmitter manual", "ABB"),
            ("Yokogawa Electric flowmeter", "Yokogawa"),
            ("Siemens SITRANS pressure transmitter", "Siemens"),
            ("Endress+Hauser level transmitter", "Endress+Hauser"),
            ("Honeywell Process Solutions", "Honeywell"),
            ("KROHNE magnetic flow meter", "KROHNE"),
            ("Schneider Electric Modicon PLC", "Schneider Electric"),
        ),
    )
    def test_manufacturers_are_recognised(
        self,
        extractor: MetadataExtractor,
        text: str,
        manufacturer: str,
    ) -> None:
        result = extractor.extract(text)

        assert result.product_reference.manufacturer == manufacturer

    @pytest.mark.parametrize(
        ("text", "brand", "manufacturer"),
        (
            ("Rosemount pressure transmitter", "Rosemount", "Emerson"),
            ("Fisher control valve", "Fisher", "Emerson"),
            ("Micro Motion flow meter", "Micro Motion", "Emerson"),
            ("DeltaV distributed control system", "DeltaV", "Emerson"),
            ("SIMATIC programmable controller", "SIMATIC", "Siemens"),
            ("Modicon programmable controller", "Modicon", "Schneider Electric"),
        ),
    )
    def test_brands_are_recognised(
        self,
        extractor: MetadataExtractor,
        text: str,
        brand: str,
        manufacturer: str,
    ) -> None:
        result = extractor.extract(text)

        assert result.product_reference.brand == brand
        assert result.product_reference.manufacturer == manufacturer

    def test_unknown_manufacturer_remains_none(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract("Generic pressure instrument manual")

        assert result.product_reference.manufacturer is None
        assert result.product_reference.brand is None


class TestProductExtraction:
    """Product identity extraction tests."""

    def test_explicit_product_family_is_extracted(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Pressure Instrument Manual
Product Family: Smart Pressure Measurement
"""
        )

        assert (
            result.product_reference.product_family
            == "Smart Pressure Measurement"
        )

    def test_explicit_product_series_is_extracted(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Flow Meter Manual
Product Series: OPTIFLUX 4000
"""
        )

        assert result.product_reference.product_series == "OPTIFLUX 4000"

    def test_explicit_model_number_is_extracted(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Pressure Transmitter Manual
Model Number: EJA110E
"""
        )

        assert result.product_reference.model_numbers == ["EJA110E"]

    def test_multiple_models_are_extracted_from_models_line(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Pressure Transmitter Manual
Models: 3051CD, 3051TG
"""
        )

        assert result.product_reference.model_numbers == [
            "3051CD",
            "3051TG",
        ]

    def test_part_number_is_extracted(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Valve Manual
Part Number: DVC6200-HC
"""
        )

        assert result.product_reference.part_numbers == ["DVC6200-HC"]

    @pytest.mark.parametrize(
        "certification",
        ("IP66", "IP67", "IK10", "SIL2", "ATEX", "IECEx"),
    )
    def test_certifications_are_not_generic_model_numbers(
        self,
        extractor: MetadataExtractor,
        certification: str,
    ) -> None:
        result = extractor.extract(
            f"""
Generic Instrument
Certification: {certification}
"""
        )

        assert certification not in result.product_reference.model_numbers

    def test_standards_are_not_generic_model_numbers(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Generic Instrument
Designed to IEC 61508 and ISO 9001.
"""
        )

        assert "IEC" not in result.product_reference.model_numbers
        assert "ISO" not in result.product_reference.model_numbers


class TestEquipmentCategories:
    """Equipment-category extraction tests."""

    @pytest.mark.parametrize(
        ("text", "expected"),
        (
            ("Differential pressure transmitter", "pressure_instrument"),
            ("Coriolis mass flow meter", "flow_instrument"),
            ("Radar level transmitter", "level_instrument"),
            ("RTD temperature transmitter", "temperature_instrument"),
            ("pH analyzer and conductivity sensor", "analyser"),
            ("Pneumatic control valve", "valve"),
            ("Electric actuator and positioner", "actuator"),
            ("Programmable logic controller PLC", "plc"),
            ("Distributed control system DCS", "dcs"),
            ("SCADA supervisory control system", "scada"),
            ("Variable frequency drive VFD", "drive"),
            ("Electric induction motor", "motor"),
            ("Medium-voltage switchgear", "switchgear"),
            ("Protection relay", "relay"),
            ("Safety instrumented system SIS", "safety_system"),
            ("Flame detector and gas detector", "fire_and_gas"),
            ("Industrial Ethernet network switch", "network"),
        ),
    )
    def test_equipment_categories_are_detected(
        self,
        extractor: MetadataExtractor,
        text: str,
        expected: str,
    ) -> None:
        result = extractor.extract(text)

        values = [
            enum_value(category)
            for category in result.product_reference.equipment_categories
        ]

        assert expected in values

    def test_multiple_equipment_categories_are_supported(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Control valve with pneumatic actuator and digital positioner.
"""
        )

        values = {
            enum_value(category)
            for category in result.product_reference.equipment_categories
        }

        assert "valve" in values
        assert "actuator" in values


class TestRevisionExtraction:
    """Document revision extraction tests."""

    def test_document_number_is_extracted(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Instrument Manual
Document Number: DOC-1234-A
"""
        )

        assert result.revision.document_number == "DOC-1234-A"

    @pytest.mark.parametrize(
        ("label", "expected"),
        (
            ("Revision: C", "C"),
            ("Rev. 05", "05"),
            ("Issue: B2", "B2"),
        ),
    )
    def test_revision_values_are_extracted(
        self,
        extractor: MetadataExtractor,
        label: str,
        expected: str,
    ) -> None:
        result = extractor.extract(f"Instrument Manual\n{label}")

        assert result.revision.revision == expected

    @pytest.mark.parametrize(
        ("label", "expected"),
        (
            ("Edition: 4", "4"),
            ("3rd Edition", "3rd"),
        ),
    )
    def test_edition_values_are_extracted(
        self,
        extractor: MetadataExtractor,
        label: str,
        expected: str,
    ) -> None:
        result = extractor.extract(f"Instrument Manual\n{label}")

        assert result.revision.edition == expected

    @pytest.mark.parametrize(
        ("label", "expected"),
        (
            ("Publication Date: 2025-04-15", date(2025, 4, 15)),
            ("Issued: 15/04/2025", date(2025, 4, 15)),
            ("Published: April 15, 2025", date(2025, 4, 15)),
            ("Release Date: 15 April 2025", date(2025, 4, 15)),
        ),
    )
    def test_publication_dates_are_extracted(
        self,
        extractor: MetadataExtractor,
        label: str,
        expected: date,
    ) -> None:
        result = extractor.extract(f"Instrument Manual\n{label}")

        assert result.revision.publication_date == expected

    def test_invalid_date_remains_none(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Instrument Manual
Publication Date: 2025-99-99
"""
        )

        assert result.revision.publication_date is None


class TestStandardsExtraction:
    """Engineering-standard extraction tests."""

    def test_multiple_standards_are_extracted(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Technical Specification
IEC 61508
ISO 9001
ISA 84.00.01
API 6D
ASME B16.34
IEEE 802.3
SANS 10142-1
"""
        )

        assert "IEC 61508" in result.standards_referenced
        assert "ISO 9001" in result.standards_referenced
        assert "ISA 84.00.01" in result.standards_referenced
        assert "API 6D" in result.standards_referenced
        assert "ASME B16.34" in result.standards_referenced
        assert "IEEE 802.3" in result.standards_referenced
        assert "SANS 10142-1" in result.standards_referenced

    def test_standards_are_deduplicated_case_insensitively(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
IEC 61508
iec 61508
IEC 61508
"""
        )

        assert result.standards_referenced == ["IEC 61508"]

    def test_iecex_is_not_recorded_as_standard(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Hazardous area approval: IECEx and ATEX.
"""
        )

        assert result.standards_referenced == []
        assert "IECEx" in result.hazardous_area_certifications


class TestHazardousAreaExtraction:
    """Hazardous-area and safety-certification tests."""

    @pytest.mark.parametrize(
        "certification",
        (
            "ATEX",
            "IECEx",
            "Class I, Division 1",
            "Class I, Zone 1",
            "Zone 2",
            "Ex ia",
            "FM Approved",
            "CSA Certified",
            "UL Listed",
            "SIL2",
            "IP66",
        ),
    )
    def test_certifications_are_extracted(
        self,
        extractor: MetadataExtractor,
        certification: str,
    ) -> None:
        result = extractor.extract(
            f"""
Hazardous Area Instrument
Certification: {certification}
"""
        )

        normalised = {
            value.casefold()
            for value in result.hazardous_area_certifications
        }

        assert certification.casefold() in normalised

    def test_certifications_are_deduplicated(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
ATEX approved.
ATEX certification.
atex compliance.
"""
        )

        assert result.hazardous_area_certifications == ["ATEX"]


class TestPublisherAuthorsIndustryAndRegion:
    """Supporting metadata tests."""

    def test_explicit_publisher_is_extracted(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Valve Manual
Published by: Example Engineering Company
"""
        )

        assert result.publisher == "Example Engineering Company"

    def test_manufacturer_is_used_as_publisher_fallback(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Yokogawa Pressure Transmitter
Instruction Manual
"""
        )

        assert result.publisher == "Yokogawa"

    def test_authors_are_extracted(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Technical Paper
Authors: Alice Engineer, Bob Technician and Carol Specialist
"""
        )

        assert result.authors == [
            "Alice Engineer",
            "Bob Technician",
            "Carol Specialist",
        ]

    @pytest.mark.parametrize(
        ("text", "expected"),
        (
            ("Oil and gas refinery application", "Oil and Gas"),
            ("Mining and minerals processing", "Mining and Minerals"),
            ("Power generation station", "Power Generation"),
            ("Water and wastewater treatment", "Water and Wastewater"),
            ("Food and beverage brewery", "Food and Beverage"),
            ("Pharmaceutical production", "Pharmaceutical"),
        ),
    )
    def test_industries_are_extracted(
        self,
        extractor: MetadataExtractor,
        text: str,
        expected: str,
    ) -> None:
        result = extractor.extract(text)

        assert expected in result.applicable_industries

    @pytest.mark.parametrize(
        ("text", "expected"),
        (
            ("European Union CE marking", "European Union"),
            ("UKCA approved for the United Kingdom", "United Kingdom"),
            ("United States OSHA requirements", "United States"),
            ("SANS 10142 requirements in South Africa", "South Africa"),
            ("IECEx international certification", "International"),
        ),
    )
    def test_regions_are_extracted(
        self,
        extractor: MetadataExtractor,
        text: str,
        expected: str,
    ) -> None:
        result = extractor.extract(text)

        assert expected in result.applicable_regions


class TestKeywords:
    """Keyword extraction tests."""

    def test_keywords_include_priority_metadata(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
Rosemount 3051 Pressure Transmitter
Product Data Sheet
Emerson Automation Solutions
"""
        )

        keyword_values = {keyword.casefold() for keyword in result.keywords}

        assert "emerson" in keyword_values
        assert "rosemount" in keyword_values
        assert "pressure instrument" in keyword_values

    def test_keywords_respect_configured_limit(self) -> None:
        extractor = MetadataExtractor(
            MetadataExtractorConfig(maximum_keyword_count=5)
        )

        result = extractor.extract(
            """
Pressure transmitter calibration maintenance installation
diagnostics verification configuration commissioning troubleshooting
"""
        )

        assert len(result.keywords) <= 5

    def test_ignored_keywords_are_excluded(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        result = extractor.extract(
            """
The pressure transmitter and the control valve are within the plant.
"""
        )

        keyword_values = {keyword.casefold() for keyword in result.keywords}

        assert "the" not in keyword_values
        assert "and" not in keyword_values
        assert "within" not in keyword_values


class TestConfidenceAndLimits:
    """Confidence and configured extraction-limit tests."""

    def test_rich_document_has_higher_confidence_than_sparse_document(
        self,
        extractor: MetadataExtractor,
        rosemount_document: str,
    ) -> None:
        rich_result = extractor.extract(rosemount_document)
        sparse_result = extractor.extract("Engineering information")

        assert (
            rich_result.metadata_confidence
            > sparse_result.metadata_confidence
        )

    def test_metadata_confidence_is_rounded(
        self,
        extractor: MetadataExtractor,
        rosemount_document: str,
    ) -> None:
        result = extractor.extract(rosemount_document)

        assert result.metadata_confidence == round(
            result.metadata_confidence,
            4,
        )

    def test_text_truncation_is_recorded(self) -> None:
        extractor = MetadataExtractor(
            MetadataExtractorConfig(maximum_text_characters=20)
        )

        result = extractor.extract(
            "Pressure Transmitter Data Sheet with additional content"
        )

        assert result.raw_metadata["processed_character_count"] == 20
        assert result.raw_metadata["text_was_truncated"] is True

    def test_maximum_list_values_limits_source_blocks(self) -> None:
        extractor = MetadataExtractor(
            MetadataExtractorConfig(maximum_list_values=2)
        )

        document = SimpleNamespace(
            blocks=[
                SimpleNamespace(block_id=uuid4(), text="Pressure"),
                SimpleNamespace(block_id=uuid4(), text="Transmitter"),
                SimpleNamespace(block_id=uuid4(), text="Manual"),
            ]
        )

        result = extractor.extract(document)

        assert len(result.source_block_ids) == 2


class TestConvenienceFunctions:
    """Public convenience API tests."""

    def test_extract_metadata_function_returns_metadata(self) -> None:
        document_id = uuid4()

        result = extract_metadata(
            "Control Valve Data Sheet",
            document_id=document_id,
        )

        assert isinstance(result, ExtractedDocumentMetadata)
        assert result.document_id == document_id

    def test_extract_metadata_alias_matches_extract(
        self,
        extractor: MetadataExtractor,
    ) -> None:
        text = "Flow Meter Product Data Sheet"

        direct = extractor.extract(text, document_id=uuid4())
        alias = extractor.extract_metadata(text, document_id=uuid4())

        assert direct.title == alias.title
        assert direct.document_type == alias.document_type
        assert (
            direct.product_reference.equipment_categories
            == alias.product_reference.equipment_categories
        )

    def test_public_function_accepts_custom_configuration(self) -> None:
        result = extract_metadata(
            "Pressure transmitter calibration maintenance installation",
            config=MetadataExtractorConfig(maximum_keyword_count=2),
        )

        assert len(result.keywords) <= 2
