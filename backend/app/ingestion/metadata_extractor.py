"""Engineering document metadata extraction.

This module converts parsed engineering-document content into structured
metadata defined in :mod:`app.ingestion.document_models`.

The extractor is deliberately deterministic and vendor-neutral. It does not
depend on an external AI service, which makes it suitable for ingestion,
testing, offline processing, and later augmentation by an AI extraction layer.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from app.ingestion.document_models import (
    DocumentLanguage,
    DocumentRevision,
    DocumentType,
    EquipmentCategory,
    ExtractedDocumentMetadata,
    ProductReference,
)


class MetadataExtractionError(ValueError):
    """Raised when document metadata cannot be extracted safely."""


@dataclass(frozen=True, slots=True)
class MetadataExtractorConfig:
    """Configuration for deterministic metadata extraction."""

    maximum_text_characters: int = 2_000_000
    title_search_line_count: int = 40
    maximum_title_length: int = 300
    maximum_keyword_count: int = 30
    minimum_keyword_length: int = 3
    minimum_model_number_length: int = 3
    maximum_model_number_length: int = 80
    maximum_list_values: int = 100
    default_language: str = "unknown"
    confidence_floor: float = 0.0
    confidence_ceiling: float = 1.0

    ignored_title_prefixes: tuple[str, ...] = (
        "warning",
        "caution",
        "danger",
        "notice",
        "contents",
        "table of contents",
        "copyright",
        "document number",
        "revision",
        "page ",
    )

    ignored_keywords: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "about",
                "above",
                "after",
                "again",
                "against",
                "also",
                "and",
                "any",
                "are",
                "because",
                "been",
                "before",
                "being",
                "between",
                "both",
                "but",
                "can",
                "could",
                "data",
                "document",
                "each",
                "from",
                "have",
                "into",
                "its",
                "may",
                "more",
                "must",
                "not",
                "only",
                "other",
                "our",
                "page",
                "shall",
                "should",
                "such",
                "than",
                "that",
                "the",
                "their",
                "then",
                "there",
                "these",
                "they",
                "this",
                "through",
                "under",
                "using",
                "was",
                "were",
                "which",
                "with",
                "within",
                "without",
                "would",
                "your",
            }
        )
    )

    def __post_init__(self) -> None:
        if self.maximum_text_characters < 1:
            raise ValueError("maximum_text_characters must be positive")

        if self.title_search_line_count < 1:
            raise ValueError("title_search_line_count must be positive")

        if self.maximum_title_length < 1:
            raise ValueError("maximum_title_length must be positive")

        if self.maximum_keyword_count < 0:
            raise ValueError("maximum_keyword_count cannot be negative")

        if self.minimum_keyword_length < 1:
            raise ValueError("minimum_keyword_length must be positive")

        if self.minimum_model_number_length < 1:
            raise ValueError("minimum_model_number_length must be positive")

        if (
            self.maximum_model_number_length
            < self.minimum_model_number_length
        ):
            raise ValueError(
                "maximum_model_number_length cannot be smaller than "
                "minimum_model_number_length"
            )

        if self.maximum_list_values < 1:
            raise ValueError("maximum_list_values must be positive")

        if not 0 <= self.confidence_floor <= 1:
            raise ValueError("confidence_floor must be between 0 and 1")

        if not 0 <= self.confidence_ceiling <= 1:
            raise ValueError("confidence_ceiling must be between 0 and 1")

        if self.confidence_floor > self.confidence_ceiling:
            raise ValueError(
                "confidence_floor cannot exceed confidence_ceiling"
            )


@dataclass(slots=True)
class _DocumentInput:
    """Normalised input consumed internally by the extractor."""

    document_id: UUID
    text: str
    filename: str | None
    title_hint: str | None
    source_block_ids: list[UUID]
    raw_metadata: dict[str, Any]


@dataclass(slots=True)
class _FieldResult:
    """Internal extracted value with confidence and evidence."""

    value: Any
    confidence: float
    source_block_ids: list[UUID] = field(default_factory=list)


class MetadataExtractor:
    """Extract structured metadata from engineering documents."""

    _manufacturer_aliases: dict[str, tuple[str, ...]] = {
        "ABB": (
            "abb",
            "a b b",
            "abb instrumentation",
            "abb automation",
        ),
        "Allen-Bradley": (
            "allen-bradley",
            "allen bradley",
            "rockwell automation",
        ),
        "Azbil": ("azbil", "yamatake"),
        "Baker Hughes": ("baker hughes", "bently nevada"),
        "Bosch Rexroth": ("bosch rexroth", "rexroth"),
        "Danfoss": ("danfoss",),
        "Emerson": (
            "emerson",
            "emerson automation solutions",
            "fisher controls",
            "micro motion",
            "rosemount",
            "delta v",
            "deltav",
        ),
        "Endress+Hauser": (
            "endress+hauser",
            "endress and hauser",
            "endress hauser",
            "e+h",
        ),
        "Festo": ("festo",),
        "GE": (
            "general electric",
            "ge measurement",
            "ge digital",
            "ge vernova",
        ),
        "Honeywell": (
            "honeywell",
            "honeywell process solutions",
        ),
        "KROHNE": ("krohne",),
        "Metso": ("metso", "neles"),
        "Mitsubishi Electric": (
            "mitsubishi electric",
            "mitsubishi automation",
        ),
        "Pepperl+Fuchs": (
            "pepperl+fuchs",
            "pepperl fuchs",
        ),
        "Phoenix Contact": ("phoenix contact",),
        "Rockwell Automation": (
            "rockwell automation",
            "factorytalk",
        ),
        "Schneider Electric": (
            "schneider electric",
            "modicon",
            "telemecanique",
            "aveva",
        ),
        "Siemens": (
            "siemens",
            "siemens industry",
            "siemens energy",
            "simatic",
            "sitrans",
        ),
        "SMC": ("smc corporation", "smc pneumatic"),
        "VEGA": ("vega grieshaber", "vega"),
        "WAGO": ("wago",),
        "Weidm?ller": ("weidmuller", "weidm?ller"),
        "WIKA": ("wika",),
        "Yaskawa": ("yaskawa",),
        "Yokogawa": (
            "yokogawa",
            "yokogawa electric",
        ),
    }

    _brand_to_manufacturer: dict[str, str] = {
        "AMS": "Emerson",
        "Bently Nevada": "Baker Hughes",
        "DeltaV": "Emerson",
        "Fisher": "Emerson",
        "Micro Motion": "Emerson",
        "Modicon": "Schneider Electric",
        "Rosemount": "Emerson",
        "SIMATIC": "Siemens",
        "SITRANS": "Siemens",
    }

    _document_type_patterns: tuple[
        tuple[str, tuple[str, ...], float], ...
    ] = (
        (
            "datasheet",
            (
                r"\bdata\s*sheet\b",
                r"\bdatasheet\b",
                r"\btechnical\s+data\b",
                r"\bproduct\s+data\s+sheet\b",
            ),
            0.95,
        ),
        (
            "installation_manual",
            (
                r"\binstallation\s+(?:manual|guide|instructions?)\b",
                r"\bmounting\s+instructions?\b",
            ),
            0.95,
        ),
        (
            "operation_manual",
            (
                r"\boperation\s+(?:manual|guide|instructions?)\b",
                r"\boperating\s+instructions?\b",
                r"\buser\s+manual\b",
            ),
            0.93,
        ),
        (
            "maintenance_manual",
            (
                r"\bmaintenance\s+manual\b",
                r"\bservice\s+manual\b",
                r"\bmaintenance\s+instructions?\b",
            ),
            0.95,
        ),
        (
            "instruction_manual",
            (
                r"\binstruction\s+manual\b",
                r"\binstruction\s+sheet\b",
                r"\bmanual\b",
            ),
            0.80,
        ),
        (
            "safety_manual",
            (
                r"\bsafety\s+manual\b",
                r"\bfunctional\s+safety\b",
                r"\bsafety\s+instructions?\b",
            ),
            0.97,
        ),
        (
            "certificate",
            (
                r"\bcertificate\s+of\s+conformity\b",
                r"\bdeclaration\s+of\s+conformity\b",
                r"\btype\s+approval\b",
                r"\bcertificate\b",
            ),
            0.92,
        ),
        (
            "drawing",
            (
                r"\bgeneral\s+arrangement\s+drawing\b",
                r"\bwiring\s+diagram\b",
                r"\bloop\s+diagram\b",
                r"\bschematic\b",
                r"\bdrawing\b",
            ),
            0.90,
        ),
        (
            "specification",
            (
                r"\btechnical\s+specification\b",
                r"\bengineering\s+specification\b",
                r"\bproject\s+specification\b",
                r"\bspecification\b",
            ),
            0.90,
        ),
        (
            "procedure",
            (
                r"\bstandard\s+operating\s+procedure\b",
                r"\bwork\s+instruction\b",
                r"\btest\s+procedure\b",
                r"\bprocedure\b",
            ),
            0.90,
        ),
        (
            "catalogue",
            (
                r"\bproduct\s+catalog(?:ue)?\b",
                r"\bcatalog(?:ue)?\b",
            ),
            0.88,
        ),
        (
            "application_note",
            (
                r"\bapplication\s+note\b",
                r"\btechnical\s+note\b",
            ),
            0.92,
        ),
        (
            "white_paper",
            (
                r"\bwhite\s+paper\b",
                r"\btechnical\s+paper\b",
            ),
            0.92,
        ),
        (
            "release_note",
            (
                r"\brelease\s+notes?\b",
                r"\bfirmware\s+release\b",
            ),
            0.92,
        ),
    )

    _equipment_category_patterns: dict[str, tuple[str, ...]] = {
        "pressure": (
            r"\bpressure\s+transmitter\b",
            r"\bpressure\s+sensor\b",
            r"\bpressure\s+gauge\b",
            r"\bdifferential\s+pressure\b",
            r"\bmanometer\b",
        ),
        "flow": (
            r"\bflow\s+meter\b",
            r"\bflowmeter\b",
            r"\bflow\s+transmitter\b",
            r"\bmass\s+flow\b",
            r"\bmagnetic\s+flow\b",
            r"\bcoriolis\b",
            r"\bvortex\s+meter\b",
        ),
        "level": (
            r"\blevel\s+transmitter\b",
            r"\blevel\s+sensor\b",
            r"\blevel\s+switch\b",
            r"\bradar\s+level\b",
            r"\bultrasonic\s+level\b",
        ),
        "temperature": (
            r"\btemperature\s+transmitter\b",
            r"\btemperature\s+sensor\b",
            r"\bthermocouple\b",
            r"\brtd\b",
            r"\bthermowell\b",
        ),
        "analytical": (
            r"\bph\s+(?:sensor|analy[sz]er|transmitter)\b",
            r"\bconductivity\s+(?:sensor|analy[sz]er)\b",
            r"\boxygen\s+analy[sz]er\b",
            r"\bgas\s+analy[sz]er\b",
            r"\bchromatograph\b",
        ),
        "valve": (
            r"\bcontrol\s+valve\b",
            r"\bball\s+valve\b",
            r"\bbutterfly\s+valve\b",
            r"\bgate\s+valve\b",
            r"\bglobe\s+valve\b",
            r"\bvalve\b",
        ),
        "actuator": (
            r"\bpneumatic\s+actuator\b",
            r"\belectric\s+actuator\b",
            r"\bhydraulic\s+actuator\b",
            r"\bactuator\b",
            r"\bpositioner\b",
        ),
        "plc": (
            r"\bprogrammable\s+logic\s+controller\b",
            r"\bplc\b",
            r"\bsimatic\s+s7\b",
            r"\bcompactlogix\b",
            r"\bcontrollogix\b",
        ),
        "dcs": (
            r"\bdistributed\s+control\s+system\b",
            r"\bdcs\b",
            r"\bdeltav\b",
            r"\bsystem\s+800xa\b",
        ),
        "scada": (
            r"\bsupervisory\s+control\s+and\s+data\s+acquisition\b",
            r"\bscada\b",
        ),
        "drive": (
            r"\bvariable\s+(?:speed|frequency)\s+drive\b",
            r"\bvsd\b",
            r"\bvfd\b",
            r"\bac\s+drive\b",
            r"\bmotor\s+drive\b",
        ),
        "motor": (
            r"\belectric\s+motor\b",
            r"\binduction\s+motor\b",
            r"\bsynchronous\s+motor\b",
        ),
        "switchgear": (
            r"\bswitchgear\b",
            r"\bcircuit\s+breaker\b",
            r"\bcontactor\b",
            r"\bmotor\s+control\s+cent(?:er|re)\b",
            r"\bmcc\b",
        ),
        "relay": (
            r"\bprotection\s+relay\b",
            r"\bsafety\s+relay\b",
            r"\brelay\b",
        ),
        "safety_system": (
            r"\bsafety\s+instrumented\s+system\b",
            r"\bsis\b",
            r"\bemergency\s+shutdown\b",
            r"\besd\b",
        ),
        "fire_and_gas": (
            r"\bfire\s+and\s+gas\b",
            r"\bflame\s+detector\b",
            r"\bgas\s+detector\b",
            r"\btoxic\s+gas\b",
            r"\bcombustible\s+gas\b",
        ),
        "network": (
            r"\bindustrial\s+ethernet\b",
            r"\bnetwork\s+switch\b",
            r"\bfieldbus\b",
            r"\bgateway\b",
        ),
    }

    _standard_patterns: tuple[re.Pattern[str], ...] = (
        re.compile(
            r"\b(?:IEC(?!Ex\b)|ISO|ISA|API|ASME|ANSI|IEEE|NFPA|NEMA|"
            r"EN|DIN|BS|SANS|ASTM|UL|CSA)\s*[-:]?\s*[A-Z]{0,4}\d+[A-Z0-9]*"
            r"(?:[-./:]\d+[A-Z0-9]*)*(?:\s*[-?]\s*\d{4})?\b",
            re.IGNORECASE,
        ),
    )

    _hazardous_area_patterns: tuple[re.Pattern[str], ...] = (
        re.compile(r"\bATEX\b", re.IGNORECASE),
        re.compile(r"\bIECEx\b", re.IGNORECASE),
        re.compile(r"\bClass\s+I{1,3}\s*,?\s*Division\s+[12]\b", re.IGNORECASE),
        re.compile(r"\bClass\s+I{1,3}\s*,?\s*Zone\s+[012]\b", re.IGNORECASE),
        re.compile(r"\bZone\s+(?:0|1|2|20|21|22)\b", re.IGNORECASE),
        re.compile(
            r"\bEx\s+(?:ia|ib|ic|d|e|nA|nC|p|q|m|o|s|t)"
            r"(?:\s+[A-Za-z0-9]+)*\b",
            re.IGNORECASE,
        ),
        re.compile(r"\b(?:FM|CSA|UL)\s+(?:Approved|Listed|Certified)\b", re.I),
        re.compile(r"\b(?:SIL|Safety Integrity Level)\s*[1234]\b", re.I),
        re.compile(r"\bIP\s*[0-6][0-9K]\b", re.IGNORECASE),
    )

    _document_number_patterns: tuple[re.Pattern[str], ...] = (
        re.compile(
            r"\b(?:document|manual|drawing|publication|reference)"
            r"\s*(?:number|no\.?|#)\s*[:\-]?\s*"
            r"([A-Z0-9][A-Z0-9._/\-]{2,80})",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:doc(?:ument)?\s*id)\s*[:\-]\s*"
            r"([A-Z0-9][A-Z0-9._/\-]{2,80})",
            re.IGNORECASE,
        ),
    )

    _revision_patterns: tuple[re.Pattern[str], ...] = (
        re.compile(
            r"\b(?:revision|rev\.?)\s*[:\-]?\s*"
            r"([A-Z0-9][A-Z0-9._/\-]{0,20})\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bissue\s*[:\-]?\s*"
            r"([A-Z0-9][A-Z0-9._/\-]{0,20})\b",
            re.IGNORECASE,
        ),
    )

    _edition_patterns: tuple[re.Pattern[str], ...] = (
        re.compile(
            r"\b([0-9]{1,2}(?:st|nd|rd|th))\s+edition\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bedition\s*[:\-]?\s*([A-Z0-9][A-Z0-9._/\-]{0,20})\b",
            re.IGNORECASE,
        ),
    )

    _date_patterns: tuple[re.Pattern[str], ...] = (
        re.compile(
            r"\b(?:publication|published|release|issued|issue|date)"
            r"\s*(?:date)?\s*[:\-]?\s*"
            r"(\d{4}-\d{1,2}-\d{1,2})\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:publication|published|release|issued|issue|date)"
            r"\s*(?:date)?\s*[:\-]?\s*"
            r"(\d{1,2}[/-]\d{1,2}[/-]\d{4})\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:publication|published|release|issued|issue|date)"
            r"\s*(?:date)?\s*[:\-]?\s*"
            r"([A-Za-z]{3,9}\s+\d{1,2},?\s+\d{4})\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:publication|published|release|issued|issue|date)"
            r"\s*(?:date)?\s*[:\-]?\s*"
            r"(\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})\b",
            re.IGNORECASE,
        ),
    )

    _model_label_pattern = re.compile(
        r"\b(?:model|model\s+number|model\s+no\.?|type|series)"
        r"\s*[:#\-]?\s*"
        r"([A-Z0-9][A-Z0-9._/+()\-]{2,79})",
        re.IGNORECASE,
    )

    _part_number_pattern = re.compile(
        r"\b(?:part|catalog|catalogue|ordering)"
        r"\s*(?:number|no\.?|code|#)\s*[:\-]?\s*"
        r"([A-Z0-9][A-Z0-9._/+()\-]{2,79})",
        re.IGNORECASE,
    )

    _generic_model_pattern = re.compile(
        r"\b(?=[A-Z0-9._/\-]{3,80}\b)"
        r"(?=[A-Z0-9._/\-]*[A-Z])"
        r"(?=[A-Z0-9._/\-]*\d)"
        r"[A-Z0-9][A-Z0-9._/\-]{2,79}\b"
    )

    _brand_patterns: dict[str, re.Pattern[str]] = {
        brand: re.compile(rf"\b{re.escape(brand)}\b", re.IGNORECASE)
        for brand in _brand_to_manufacturer
    }

    _language_markers: dict[str, tuple[str, ...]] = {
        "english": (
            "the",
            "and",
            "warning",
            "installation",
            "operation",
            "maintenance",
        ),
        "german": (
            "und",
            "der",
            "die",
            "das",
            "warnung",
            "installation",
            "betrieb",
        ),
        "french": (
            "et",
            "le",
            "la",
            "les",
            "des",
            "du",
            "une",
            "un",
            "pour",
            "avec",
            "dans",
            "instructions",
            "contiennent",
            "avertissement",
            "installation",
            "fonctionnement",
            "maintenance",
            "pression",
            "temp?rature",
            "?quipement",
            "s?curit?",
        ),
        "spanish": (
            "el",
            "la",
            "los",
            "las",
            "advertencia",
            "instalaci?n",
            "funcionamiento",
        ),
        "portuguese": (
            "e",
            "o",
            "a",
            "os",
            "as",
            "aviso",
            "instala??o",
            "opera??o",
        ),
        "italian": (
            "e",
            "il",
            "la",
            "avvertenza",
            "installazione",
            "funzionamento",
        ),
        "dutch": (
            "en",
            "de",
            "het",
            "waarschuwing",
            "installatie",
            "bediening",
        ),
    }

    def __init__(
        self,
        config: MetadataExtractorConfig | None = None,
    ) -> None:
        self.config = config or MetadataExtractorConfig()

    def extract(
        self,
        document: Any,
        *,
        document_id: UUID | str | None = None,
        filename: str | None = None,
        raw_metadata: Mapping[str, Any] | None = None,
    ) -> ExtractedDocumentMetadata:
        """Extract metadata from text or a parsed-document-like object."""

        source = self._normalise_input(
            document,
            document_id=document_id,
            filename=filename,
            raw_metadata=raw_metadata,
        )

        text = source.text[: self.config.maximum_text_characters]
        header_text = self._header_text(text)

        title = self._extract_title(
            text=text,
            filename=source.filename,
            title_hint=source.title_hint,
        )
        document_type = self._extract_document_type(header_text, source.filename)
        language = self._extract_language(text)
        manufacturer = self._extract_manufacturer(text)
        brand = self._extract_brand(text)

        if brand.value:
            mapped_manufacturer = self._brand_to_manufacturer.get(
                brand.value
            )

            if mapped_manufacturer is None:
                mapped_manufacturer = next(
                    (
                        manufacturer_name
                        for brand_name, manufacturer_name
                        in self._brand_to_manufacturer.items()
                        if brand_name.casefold() == brand.value.casefold()
                    ),
                    None,
                )

            if mapped_manufacturer is not None:
                manufacturer = _FieldResult(
                    mapped_manufacturer,
                    max(0.90, brand.confidence),
                )
        product_family = self._extract_product_family(
            text=text,
            title=title.value,
            manufacturer=manufacturer.value,
            brand=brand.value,
        )
        product_series = self._extract_product_series(text)
        model_numbers = self._extract_model_numbers(text)
        part_numbers = self._extract_part_numbers(text)
        equipment_categories = self._extract_equipment_categories(text)
        revision = self._extract_revision(text)
        standards = self._extract_standards(text)
        hazardous_certifications = self._extract_hazardous_certifications(text)
        publisher = self._extract_publisher(
            text=text,
            manufacturer=manufacturer.value,
        )
        authors = self._extract_authors(text)
        industries = self._extract_industries(text)
        regions = self._extract_regions(text)
        keywords = self._extract_keywords(
            text=text,
            title=title.value,
            manufacturer=manufacturer.value,
            product_family=product_family.value,
            equipment_categories=equipment_categories.value,
        )

        field_confidences = {
            "title": title.confidence,
            "document_type": document_type.confidence,
            "language": language.confidence,
            "manufacturer": manufacturer.confidence,
            "brand": brand.confidence,
            "product_family": product_family.confidence,
            "product_series": product_series.confidence,
            "model_numbers": model_numbers.confidence,
            "part_numbers": part_numbers.confidence,
            "equipment_categories": equipment_categories.confidence,
            "revision": revision.confidence,
            "standards_referenced": standards.confidence,
            "hazardous_area_certifications": hazardous_certifications.confidence,
            "publisher": publisher.confidence,
            "authors": authors.confidence,
            "applicable_industries": industries.confidence,
            "applicable_regions": regions.confidence,
            "keywords": keywords.confidence,
        }

        metadata_confidence = self._calculate_overall_confidence(
            field_confidences
        )

        combined_raw_metadata = dict(source.raw_metadata)
        combined_raw_metadata.update(
            {
                "extractor": "deterministic_metadata_extractor",
                "extractor_version": "1.0.0",
                "source_filename": source.filename,
                "processed_character_count": len(text),
                "source_character_count": len(source.text),
                "text_was_truncated": len(source.text) > len(text),
            }
        )

        return ExtractedDocumentMetadata(
            document_id=source.document_id,
            title=title.value,
            document_type=document_type.value,
            language=language.value,
            revision=revision.value,
            product_reference=ProductReference(
                manufacturer=manufacturer.value,
                brand=brand.value,
                product_family=product_family.value,
                product_series=product_series.value,
                model_numbers=model_numbers.value,
                part_numbers=part_numbers.value,
                equipment_categories=equipment_categories.value,
            ),
            authors=authors.value,
            publisher=publisher.value,
            applicable_industries=industries.value,
            applicable_regions=regions.value,
            standards_referenced=standards.value,
            hazardous_area_certifications=hazardous_certifications.value,
            keywords=keywords.value,
            metadata_confidence=metadata_confidence,
            field_confidences=field_confidences,
            source_block_ids=source.source_block_ids,
            raw_metadata=combined_raw_metadata,
        )

    def extract_metadata(
        self,
        document: Any,
        *,
        document_id: UUID | str | None = None,
        filename: str | None = None,
        raw_metadata: Mapping[str, Any] | None = None,
    ) -> ExtractedDocumentMetadata:
        """Compatibility alias for :meth:`extract`."""

        return self.extract(
            document,
            document_id=document_id,
            filename=filename,
            raw_metadata=raw_metadata,
        )

    def _normalise_input(
        self,
        document: Any,
        *,
        document_id: UUID | str | None,
        filename: str | None,
        raw_metadata: Mapping[str, Any] | None,
    ) -> _DocumentInput:
        if document is None:
            raise MetadataExtractionError("document cannot be None")

        discovered_metadata: dict[str, Any] = {}
        source_block_ids: list[UUID] = []
        title_hint: str | None = None

        if isinstance(document, bytes):
            try:
                text = document.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise MetadataExtractionError(
                    "byte input must be UTF-8 encoded"
                ) from exc
        elif isinstance(document, str):
            text = document
        else:
            text = self._extract_object_text(document)

            object_metadata = getattr(document, "metadata", None)
            if isinstance(object_metadata, Mapping):
                discovered_metadata.update(dict(object_metadata))

            parser_metadata = getattr(document, "parser_metadata", None)
            if isinstance(parser_metadata, Mapping):
                discovered_metadata.update(dict(parser_metadata))

            title_hint = self._normalise_optional_string(
                getattr(document, "title", None)
            )

            if filename is None:
                filename = self._discover_filename(document)

            if document_id is None:
                document_id = getattr(document, "document_id", None)

            source_block_ids = self._discover_block_ids(document)

        if not isinstance(text, str):
            raise MetadataExtractionError("document text must be a string")

        if not text.strip():
            raise MetadataExtractionError("document text cannot be empty")

        if raw_metadata:
            discovered_metadata.update(dict(raw_metadata))

        return _DocumentInput(
            document_id=self._coerce_uuid(document_id),
            text=text,
            filename=self._normalise_optional_string(filename),
            title_hint=title_hint,
            source_block_ids=source_block_ids,
            raw_metadata=discovered_metadata,
        )

    def _extract_object_text(self, document: Any) -> str:
        for attribute in (
            "text",
            "full_text",
            "content",
            "plain_text",
            "extracted_text",
        ):
            value = getattr(document, attribute, None)
            if isinstance(value, str) and value.strip():
                return value

        blocks = getattr(document, "blocks", None)
        if isinstance(blocks, Sequence):
            block_texts: list[str] = []

            for block in blocks:
                block_text = getattr(block, "text", None)

                if not isinstance(block_text, str):
                    block_text = getattr(block, "content", None)

                if isinstance(block_text, str) and block_text.strip():
                    block_texts.append(block_text)

            if block_texts:
                return "\n\n".join(block_texts)

        raise MetadataExtractionError(
            "document does not expose usable text or text blocks"
        )

    def _discover_filename(self, document: Any) -> str | None:
        for attribute in (
            "filename",
            "file_name",
            "source_filename",
            "original_filename",
        ):
            value = getattr(document, attribute, None)
            if isinstance(value, str) and value.strip():
                return value.strip()

        source = getattr(document, "source", None)
        if isinstance(source, (str, Path)):
            return Path(source).name

        return None

    def _discover_block_ids(self, document: Any) -> list[UUID]:
        blocks = getattr(document, "blocks", None)
        if not isinstance(blocks, Sequence):
            return []

        block_ids: list[UUID] = []

        for block in blocks:
            value = getattr(block, "block_id", None)

            if value is None:
                value = getattr(block, "id", None)

            try:
                block_id = self._coerce_uuid(value, create_when_missing=False)
            except MetadataExtractionError:
                continue

            if block_id is not None and block_id not in block_ids:
                block_ids.append(block_id)

        return block_ids[: self.config.maximum_list_values]

    def _extract_title(
        self,
        *,
        text: str,
        filename: str | None,
        title_hint: str | None,
    ) -> _FieldResult:
        if title_hint:
            return _FieldResult(
                self._clean_title(title_hint),
                0.98,
            )

        lines = [
            self._clean_title(line)
            for line in text.splitlines()[
                : self.config.title_search_line_count
            ]
        ]

        candidates: list[tuple[float, str]] = []

        for index, line in enumerate(lines):
            if not self._is_title_candidate(line):
                continue

            score = 0.90 - min(index * 0.02, 0.40)

            # The first meaningful line on an engineering document is
            # commonly the product or document title. Give it enough weight
            # to prevent generic subtitles such as "Product Data Sheet" from
            # replacing a more specific product title.
            if index == 0:
                score += 0.08

            if line.isupper():
                score += 0.03

            if 3 <= len(line.split()) <= 14:
                score += 0.04

            if re.search(
                r"\b(?:manual|guide|datasheet|data sheet|"
                r"specification|instructions?|catalog(?:ue)?|"
                r"procedure|certificate|drawing)\b",
                line,
                re.IGNORECASE,
            ):
                score += 0.01

            candidates.append((min(score, 0.98), line))

        if candidates:
            candidates.sort(key=lambda item: item[0], reverse=True)
            confidence, value = candidates[0]
            return _FieldResult(value, confidence)

        if filename:
            stem = Path(filename).stem
            stem = re.sub(r"[_\-]+", " ", stem)
            stem = re.sub(r"\s+", " ", stem).strip()

            if stem:
                return _FieldResult(
                    self._clean_title(stem),
                    0.62,
                )

        return _FieldResult(None, 0.0)

    def _extract_document_type(
        self,
        header_text: str,
        filename: str | None,
    ) -> _FieldResult:
        search_text = header_text

        if filename:
            search_text = f"{filename}\n{search_text}"

        best_name: str | None = None
        best_confidence = 0.0

        for enum_hint, patterns, confidence in self._document_type_patterns:
            if any(re.search(pattern, search_text, re.IGNORECASE) for pattern in patterns):
                if confidence > best_confidence:
                    best_name = enum_hint
                    best_confidence = confidence

        value = self._resolve_enum(
            DocumentType,
            best_name,
            fallback_names=("UNKNOWN",),
        )

        if best_name is None:
            return _FieldResult(value, 0.15)

        return _FieldResult(value, best_confidence)

    def _extract_language(self, text: str) -> _FieldResult:
        sample = text[:100_000].casefold()

        words = re.findall(
            r"[a-z?-??-??-?]+",
            sample,
        )

        language_values = {
            "english": DocumentLanguage.ENGLISH,
            "german": DocumentLanguage.GERMAN,
            "french": DocumentLanguage.FRENCH,
            "spanish": DocumentLanguage.SPANISH,
            "portuguese": DocumentLanguage.PORTUGUESE,
            "italian": DocumentLanguage.ITALIAN,
            "dutch": DocumentLanguage.DUTCH,
        }

        if not words:
            default_language = self._resolve_enum(
                DocumentLanguage,
                self.config.default_language,
                fallback_names=("UNKNOWN", "ENGLISH"),
            )

            return _FieldResult(default_language, 0.10)

        word_counts = Counter(words)
        scores: dict[str, int] = {}

        for language, markers in self._language_markers.items():
            scores[language] = sum(
                word_counts.get(marker.casefold(), 0)
                for marker in markers
            )

        language_name, score = max(
            scores.items(),
            key=lambda item: item[1],
        )

        if score == 0:
            default_language = self._resolve_enum(
                DocumentLanguage,
                self.config.default_language,
                fallback_names=("UNKNOWN", "ENGLISH"),
            )

            return _FieldResult(default_language, 0.20)

        total_marker_hits = sum(scores.values())

        confidence = min(
            0.98,
            0.55
            + (
                score
                / max(total_marker_hits, 1)
            )
            * 0.40,
        )

        language = language_values.get(
            language_name,
            DocumentLanguage.OTHER,
        )

        return _FieldResult(language, confidence)

    def _extract_manufacturer(self, text: str) -> _FieldResult:
        lowered = text.lower()
        scores: Counter[str] = Counter()

        for manufacturer, aliases in self._manufacturer_aliases.items():
            for alias in aliases:
                matches = len(
                    re.findall(
                        rf"(?<!\w){re.escape(alias.lower())}(?!\w)",
                        lowered,
                    )
                )

                if matches:
                    alias_weight = 3 if alias == manufacturer.lower() else 1
                    scores[manufacturer] += matches * alias_weight

        if not scores:
            return _FieldResult(None, 0.0)

        manufacturer, score = scores.most_common(1)[0]
        confidence = min(0.99, 0.70 + min(score, 10) * 0.025)

        return _FieldResult(manufacturer, confidence)

    def _extract_brand(self, text: str) -> _FieldResult:
        matches: list[tuple[int, str]] = []

        for brand, pattern in self._brand_patterns.items():
            count = len(pattern.findall(text))

            if count:
                matches.append((count, brand))

        if not matches:
            return _FieldResult(None, 0.0)

        matches.sort(reverse=True)
        count, brand = matches[0]

        return _FieldResult(
            brand,
            min(0.98, 0.75 + min(count, 5) * 0.04),
        )

    def _extract_product_family(
        self,
        *,
        text: str,
        title: str | None,
        manufacturer: str | None,
        brand: str | None,
    ) -> _FieldResult:
        patterns = (
            re.compile(
                r"\bproduct\s+family\s*[:\-]\s*([^\n\r]{2,120})",
                re.IGNORECASE,
            ),
            re.compile(
                r"\bfamily\s*[:\-]\s*([^\n\r]{2,120})",
                re.IGNORECASE,
            ),
            re.compile(
                r"\bproduct\s+line\s*[:\-]\s*([^\n\r]{2,120})",
                re.IGNORECASE,
            ),
        )

        for pattern in patterns:
            match = pattern.search(text[:100_000])

            if match:
                value = self._clean_metadata_value(match.group(1))
                if value:
                    return _FieldResult(value, 0.91)

        if title:
            value = title

            for removable in (manufacturer, brand):
                if removable:
                    value = re.sub(
                        rf"\b{re.escape(removable)}\b",
                        "",
                        value,
                        flags=re.IGNORECASE,
                    )

            value = re.sub(
                r"\b(?:instruction|installation|operation|maintenance|"
                r"safety|service|user|reference|technical|product|"
                r"manual|guide|datasheet|data sheet|specification|"
                r"catalogue|catalog)\b",
                "",
                value,
                flags=re.IGNORECASE,
            )
            value = self._clean_metadata_value(value)

            if value and len(value) >= 3:
                return _FieldResult(value, 0.58)

        return _FieldResult(None, 0.0)

    def _extract_product_series(self, text: str) -> _FieldResult:
        patterns = (
            re.compile(
                r"\bproduct\s+series\s*[:\-]\s*([^\n\r]{2,100})",
                re.IGNORECASE,
            ),
            re.compile(
                r"\bseries\s*[:\-]\s*([A-Z0-9][A-Z0-9 ._/\-]{1,80})",
                re.IGNORECASE,
            ),
        )

        for pattern in patterns:
            match = pattern.search(text[:100_000])

            if match:
                value = self._clean_metadata_value(match.group(1))

                if value:
                    return _FieldResult(value, 0.88)

        return _FieldResult(None, 0.0)

    def _extract_model_numbers(self, text: str) -> _FieldResult:
        explicit_part_numbers = set(
            self._normalise_identifiers(
                self._part_number_pattern.findall(text[:300_000])
            )
        )

        explicit_model_numbers = self._normalise_identifiers(
            self._model_label_pattern.findall(text[:300_000])
        )

        explicit_model_numbers = [
            value
            for value in explicit_model_numbers
            if value not in explicit_part_numbers
        ]

        if explicit_model_numbers:
            return _FieldResult(
                explicit_model_numbers,
                0.94,
            )

        generic_model_numbers = self._normalise_identifiers(
            self._generic_model_pattern.findall(text[:100_000])
        )

        generic_model_numbers = [
            value
            for value in generic_model_numbers
            if value not in explicit_part_numbers
            and not self._looks_like_standard(value)
            and not self._looks_like_date(value)
            and not self._looks_like_certification(value)
            and not value.upper().startswith(("HTTP", "WWW"))
        ]

        if generic_model_numbers:
            return _FieldResult(
                generic_model_numbers[:20],
                0.55,
            )

        return _FieldResult([], 0.0)

    def _extract_part_numbers(self, text: str) -> _FieldResult:
        values = self._normalise_identifiers(
            self._part_number_pattern.findall(text[:300_000])
        )

        return _FieldResult(values, 0.94 if values else 0.0)

    def _extract_equipment_categories(self, text: str) -> _FieldResult:
        category_mapping: dict[str, EquipmentCategory] = {
            "pressure": EquipmentCategory.PRESSURE_INSTRUMENT,
            "flow": EquipmentCategory.FLOW_INSTRUMENT,
            "level": EquipmentCategory.LEVEL_INSTRUMENT,
            "temperature": EquipmentCategory.TEMPERATURE_INSTRUMENT,
            "analytical": EquipmentCategory.ANALYSER,
            "valve": EquipmentCategory.VALVE,
            "actuator": EquipmentCategory.ACTUATOR,
            "plc": EquipmentCategory.PLC,
            "dcs": EquipmentCategory.DCS,
            "scada": EquipmentCategory.SCADA,
            "drive": EquipmentCategory.DRIVE,
            "motor": EquipmentCategory.MOTOR,
            "switchgear": EquipmentCategory.SWITCHGEAR,
            "relay": EquipmentCategory.RELAY,
            "safety_system": EquipmentCategory.SAFETY_SYSTEM,
            "fire_and_gas": EquipmentCategory.FIRE_AND_GAS,
            "network": EquipmentCategory.NETWORK,
        }

        matches: list[tuple[int, EquipmentCategory]] = []

        for category_hint, patterns in self._equipment_category_patterns.items():
            score = sum(
                len(re.findall(pattern, text, re.IGNORECASE))
                for pattern in patterns
            )

            if score == 0:
                continue

            category = category_mapping.get(category_hint)

            if category is not None:
                matches.append((score, category))

        matches.sort(
            key=lambda item: (-item[0], self._enum_text(item[1]))
        )

        categories = self._deduplicate(
            category for _, category in matches
        )

        if not categories:
            return _FieldResult([], 0.0)

        strongest_score = matches[0][0]

        return _FieldResult(
            categories[: self.config.maximum_list_values],
            min(0.98, 0.68 + min(strongest_score, 8) * 0.035),
        )


    def _extract_revision(self, text: str) -> _FieldResult:
        header_text = self._header_text(text, maximum_lines=120)
        revision_value = self._first_pattern_value(
            self._revision_patterns,
            header_text,
        )
        edition_value = self._first_pattern_value(
            self._edition_patterns,
            header_text,
        )
        document_number = self._first_pattern_value(
            self._document_number_patterns,
            header_text,
        )
        publication_date = self._extract_publication_date(header_text)

        populated_count = sum(
            value is not None
            for value in (
                revision_value,
                edition_value,
                document_number,
                publication_date,
            )
        )

        confidence = 0.0
        if populated_count:
            confidence = min(0.98, 0.62 + populated_count * 0.09)

        return _FieldResult(
            DocumentRevision(
                revision=revision_value,
                edition=edition_value,
                publication_date=publication_date,
                document_number=document_number,
            ),
            confidence,
        )

    def _extract_standards(self, text: str) -> _FieldResult:
        values: list[str] = []

        for pattern in self._standard_patterns:
            values.extend(match.group(0) for match in pattern.finditer(text))

        values = [
            self._normalise_standard(value)
            for value in values
        ]
        values = self._deduplicate(values)

        return _FieldResult(
            values[: self.config.maximum_list_values],
            0.93 if values else 0.0,
        )

    def _extract_hazardous_certifications(self, text: str) -> _FieldResult:
        values: list[str] = []

        for pattern in self._hazardous_area_patterns:
            values.extend(match.group(0) for match in pattern.finditer(text))

        values = [
            re.sub(r"\s+", " ", value).strip()
            for value in values
        ]
        values = self._deduplicate(values)

        return _FieldResult(
            values[: self.config.maximum_list_values],
            0.94 if values else 0.0,
        )

    def _extract_publisher(
        self,
        *,
        text: str,
        manufacturer: str | None,
    ) -> _FieldResult:
        match = re.search(
            r"\b(?:published|publisher|issued)\s+by\s*[:\-]?\s*"
            r"([^\n\r]{2,120})",
            text[:100_000],
            re.IGNORECASE,
        )

        if match:
            value = self._clean_metadata_value(match.group(1))
            if value:
                return _FieldResult(value, 0.90)

        if manufacturer:
            return _FieldResult(manufacturer, 0.72)

        return _FieldResult(None, 0.0)

    def _extract_authors(self, text: str) -> _FieldResult:
        patterns = (
            re.compile(
                r"^\s*(?:author|authors|prepared\s+by|written\s+by)"
                r"\s*[:\-]\s*(.+)$",
                re.IGNORECASE | re.MULTILINE,
            ),
            re.compile(
                r"^\s*(?:compiled\s+by|approved\s+by)"
                r"\s*[:\-]\s*(.+)$",
                re.IGNORECASE | re.MULTILINE,
            ),
        )

        values: list[str] = []

        for pattern in patterns:
            for match in pattern.finditer(text[:100_000]):
                values.extend(
                    part.strip()
                    for part in re.split(
                        r"\s*(?:,|;|\band\b|&)\s*",
                        match.group(1),
                        flags=re.IGNORECASE,
                    )
                    if part.strip()
                )

        values = [
            self._clean_metadata_value(value)
            for value in values
        ]
        values = self._deduplicate(value for value in values if value)

        return _FieldResult(
            values[: self.config.maximum_list_values],
            0.86 if values else 0.0,
        )

    def _extract_industries(self, text: str) -> _FieldResult:
        patterns: dict[str, tuple[str, ...]] = {
            "Oil and Gas": (
                r"\boil\s+and\s+gas\b",
                r"\bpetrochemical\b",
                r"\brefiner(?:y|ies)\b",
            ),
            "Mining and Minerals": (
                r"\bmining\b",
                r"\bminerals?\s+processing\b",
                r"\bbeneficiation\b",
            ),
            "Power Generation": (
                r"\bpower\s+generation\b",
                r"\bpower\s+plant\b",
                r"\bpower\s+station\b",
            ),
            "Water and Wastewater": (
                r"\bwater\s+and\s+wastewater\b",
                r"\bwastewater\b",
                r"\bwater\s+treatment\b",
            ),
            "Chemical": (
                r"\bchemical\s+industry\b",
                r"\bchemical\s+processing\b",
            ),
            "Food and Beverage": (
                r"\bfood\s+and\s+beverage\b",
                r"\bbrew(?:ery|ing)\b",
                r"\bdairy\b",
            ),
            "Pharmaceutical": (
                r"\bpharmaceutical\b",
                r"\bbiopharma\b",
            ),
            "Pulp and Paper": (
                r"\bpulp\s+and\s+paper\b",
                r"\bpaper\s+mill\b",
            ),
            "Marine": (
                r"\bmarine\b",
                r"\boffshore\b",
                r"\bshipboard\b",
            ),
        }

        values = [
            industry
            for industry, industry_patterns in patterns.items()
            if any(
                re.search(pattern, text, re.IGNORECASE)
                for pattern in industry_patterns
            )
        ]

        return _FieldResult(
            values,
            0.78 if values else 0.0,
        )

    def _extract_regions(self, text: str) -> _FieldResult:
        patterns: dict[str, tuple[str, ...]] = {
            "European Union": (
                r"\beuropean\s+union\b",
                r"\beu\s+directives?\b",
                r"\bce\s+mark(?:ing)?\b",
            ),
            "United Kingdom": (
                r"\bunited\s+kingdom\b",
                r"\bukca\b",
            ),
            "United States": (
                r"\bunited\s+states\b",
                r"\busa\b",
                r"\bosha\b",
            ),
            "Canada": (
                r"\bcanada\b",
                r"\bcanadian\b",
            ),
            "South Africa": (
                r"\bsouth\s+africa\b",
                r"\bsans\s+\d",
            ),
            "Australia": (
                r"\baustralia\b",
                r"\baustralian\b",
            ),
            "New Zealand": (
                r"\bnew\s+zealand\b",
            ),
            "International": (
                r"\binternational\b",
                r"\biecex\b",
            ),
        }

        values = [
            region
            for region, region_patterns in patterns.items()
            if any(
                re.search(pattern, text, re.IGNORECASE)
                for pattern in region_patterns
            )
        ]

        return _FieldResult(
            self._deduplicate(values),
            0.75 if values else 0.0,
        )

    def _extract_keywords(
        self,
        *,
        text: str,
        title: str | None,
        manufacturer: str | None,
        product_family: str | None,
        equipment_categories: Sequence[EquipmentCategory],
    ) -> _FieldResult:
        keyword_counts: Counter[str] = Counter()

        for word in re.findall(r"[A-Za-z][A-Za-z0-9+\-]{2,40}", text.lower()):
            cleaned = word.strip("-+")

            if len(cleaned) < self.config.minimum_keyword_length:
                continue

            if cleaned in self.config.ignored_keywords:
                continue

            if cleaned.isdigit():
                continue

            keyword_counts[cleaned] += 1

        priority_values: list[str] = []

        for value in (manufacturer, product_family):
            if value:
                priority_values.append(value)

        if title:
            priority_values.extend(
                word
                for word in re.findall(
                    r"[A-Za-z][A-Za-z0-9+\-]{2,40}",
                    title,
                )
                if word.lower() not in self.config.ignored_keywords
            )

        priority_values.extend(
            self._enum_text(category)
            for category in equipment_categories
        )

        ranked_words = [
            word
            for word, _ in keyword_counts.most_common(
                self.config.maximum_keyword_count * 3
            )
        ]

        values = self._deduplicate(
            value.strip()
            for value in (*priority_values, *ranked_words)
            if value and value.strip()
        )

        values = values[: self.config.maximum_keyword_count]

        return _FieldResult(
            values,
            0.70 if values else 0.0,
        )

    def _calculate_overall_confidence(
        self,
        field_confidences: Mapping[str, float],
    ) -> float:
        weights = {
            "title": 1.5,
            "document_type": 1.3,
            "language": 0.5,
            "manufacturer": 1.5,
            "brand": 0.5,
            "product_family": 1.2,
            "product_series": 0.7,
            "model_numbers": 1.2,
            "part_numbers": 0.8,
            "equipment_categories": 1.2,
            "revision": 1.0,
            "standards_referenced": 0.6,
            "hazardous_area_certifications": 0.7,
            "publisher": 0.5,
            "authors": 0.3,
            "applicable_industries": 0.4,
            "applicable_regions": 0.3,
            "keywords": 0.5,
        }

        weighted_total = 0.0
        total_weight = 0.0

        for field_name, confidence in field_confidences.items():
            weight = weights.get(field_name, 1.0)
            weighted_total += self._clamp_confidence(confidence) * weight
            total_weight += weight

        if total_weight == 0:
            return self.config.confidence_floor

        return round(
            self._clamp_confidence(weighted_total / total_weight),
            4,
        )

    def _extract_publication_date(self, text: str) -> date | None:
        value = self._first_pattern_value(self._date_patterns, text)

        if not value:
            return None

        formats = (
            "%Y-%m-%d",
            "%d/%m/%Y",
            "%m/%d/%Y",
            "%d-%m-%Y",
            "%m-%d-%Y",
            "%B %d, %Y",
            "%B %d %Y",
            "%b %d, %Y",
            "%b %d %Y",
            "%d %B %Y",
            "%d %b %Y",
        )

        for format_string in formats:
            try:
                return datetime.strptime(value, format_string).date()
            except ValueError:
                continue

        return None

    def _first_pattern_value(
        self,
        patterns: Iterable[re.Pattern[str]],
        text: str,
    ) -> str | None:
        for pattern in patterns:
            match = pattern.search(text)

            if match:
                return self._clean_metadata_value(match.group(1))

        return None

    def _normalise_identifiers(
        self,
        values: Iterable[str],
    ) -> list[str]:
        normalised: list[str] = []

        for value in values:
            cleaned = value.strip(" \t\r\n.,;:()[]{}")

            if not (
                self.config.minimum_model_number_length
                <= len(cleaned)
                <= self.config.maximum_model_number_length
            ):
                continue

            if cleaned.lower() in {
                "number",
                "model",
                "series",
                "type",
                "unknown",
                "n/a",
            }:
                continue

            normalised.append(cleaned)

        return self._deduplicate(normalised)[
            : self.config.maximum_list_values
        ]

    def _is_title_candidate(self, line: str) -> bool:
        if not line:
            return False

        if len(line) < 3 or len(line) > self.config.maximum_title_length:
            return False

        lowered = line.lower()

        if any(
            lowered.startswith(prefix)
            for prefix in self.config.ignored_title_prefixes
        ):
            return False

        if re.fullmatch(r"[\W\d_]+", line):
            return False

        if re.fullmatch(
            r"(?:rev(?:ision)?|date|document\s*(?:number|no\.?))"
            r"\s*[:\-].*",
            line,
            re.IGNORECASE,
        ):
            return False

        if line.endswith((".", ";")) and len(line.split()) > 12:
            return False

        return True

    def _clean_title(self, value: str) -> str:
        value = re.sub(r"^[#=*_\-\s]+", "", value)
        value = re.sub(r"[#=*_\-\s]+$", "", value)
        value = re.sub(r"\s+", " ", value).strip()

        return value[: self.config.maximum_title_length]

    @staticmethod
    def _clean_metadata_value(value: str) -> str | None:
        value = re.sub(r"\s+", " ", value).strip(" \t\r\n:;,.|-")

        if not value:
            return None

        return value

    @staticmethod
    def _normalise_optional_string(value: Any) -> str | None:
        if not isinstance(value, str):
            return None

        value = value.strip()
        return value or None

    def _header_text(
        self,
        text: str,
        *,
        maximum_lines: int = 80,
    ) -> str:
        return "\n".join(text.splitlines()[:maximum_lines])

    def _resolve_enum(
        self,
        enum_class: type[Enum],
        hint: str | None,
        *,
        fallback_names: Sequence[str],
        allow_none: bool = False,
    ) -> Any:
        if hint:
            normalised_hint = self._normalise_enum_key(hint)

            for member in enum_class:
                candidates = {
                    self._normalise_enum_key(member.name),
                    self._normalise_enum_key(str(member.value)),
                }

                if normalised_hint in candidates:
                    return member

                if any(
                    normalised_hint in candidate
                    or candidate in normalised_hint
                    for candidate in candidates
                    if candidate
                ):
                    return member

        for fallback_name in fallback_names:
            fallback_key = self._normalise_enum_key(fallback_name)

            for member in enum_class:
                if fallback_key in {
                    self._normalise_enum_key(member.name),
                    self._normalise_enum_key(str(member.value)),
                }:
                    return member

        if allow_none:
            return None

        members = list(enum_class)

        if not members:
            raise MetadataExtractionError(
                f"{enum_class.__name__} does not define any values"
            )

        return members[0]

    @staticmethod
    def _normalise_enum_key(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", value.lower())

    @staticmethod
    def _enum_text(value: Enum) -> str:
        return str(value.value).replace("_", " ").strip()

    @staticmethod
    def _normalise_standard(value: str) -> str:
        value = re.sub(r"\s+", " ", value).strip()
        value = re.sub(r"\s*[-:]\s*", "-", value, count=1)
        return value.upper()

    @staticmethod
    def _looks_like_standard(value: str) -> bool:
        return bool(
            re.match(
                r"^(?:IEC|ISO|ISA|API|ASME|ANSI|IEEE|NFPA|"
                r"NEMA|EN|DIN|BS|SANS|ASTM|UL|CSA)[- ]?\d",
                value,
                re.IGNORECASE,
            )
        )

    @staticmethod
    def _looks_like_date(value: str) -> bool:
        return bool(
            re.fullmatch(
                r"\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}",
                value,
            )
        )

    @staticmethod
    def _looks_like_certification(value: str) -> bool:
        """Return whether an identifier is a certification, not a model."""

        normalised = re.sub(r"\s+", "", value).upper()

        return bool(
            re.fullmatch(r"IP[0-6][0-9K]", normalised)
            or re.fullmatch(r"IK(?:0[0-9]|10)", normalised)
            or re.fullmatch(r"SIL[1-4]", normalised)
            or normalised in {"ATEX", "IECEX"}
        )

    @staticmethod
    def _deduplicate(values: Iterable[Any]) -> list[Any]:
        result: list[Any] = []
        seen: set[Any] = set()

        for value in values:
            key: Any

            if isinstance(value, str):
                key = value.casefold()
            elif isinstance(value, Enum):
                key = (type(value), value.value)
            else:
                key = value

            if key in seen:
                continue

            seen.add(key)
            result.append(value)

        return result

    def _clamp_confidence(self, value: float) -> float:
        return max(
            self.config.confidence_floor,
            min(self.config.confidence_ceiling, float(value)),
        )

    @staticmethod
    def _coerce_uuid(
        value: UUID | str | Any | None,
        *,
        create_when_missing: bool = True,
    ) -> UUID | None:
        if value is None:
            return uuid4() if create_when_missing else None

        if isinstance(value, UUID):
            return value

        try:
            return UUID(str(value))
        except (TypeError, ValueError, AttributeError) as exc:
            raise MetadataExtractionError(
                f"invalid document UUID: {value!r}"
            ) from exc


def extract_metadata(
    document: Any,
    *,
    document_id: UUID | str | None = None,
    filename: str | None = None,
    raw_metadata: Mapping[str, Any] | None = None,
    config: MetadataExtractorConfig | None = None,
) -> ExtractedDocumentMetadata:
    """Extract structured metadata using a default extractor instance."""

    return MetadataExtractor(config).extract(
        document,
        document_id=document_id,
        filename=filename,
        raw_metadata=raw_metadata,
    )


__all__ = [
    "MetadataExtractionError",
    "MetadataExtractor",
    "MetadataExtractorConfig",
    "extract_metadata",
]
