"""
Deterministic engineering knowledge extraction.

This module converts parsed engineering-document content into structured
engineering facts defined in :mod:`app.ingestion.document_models`.

The extractor is vendor-neutral, evidence-based, safety-first, and does not
depend on an external AI service. It provides a deterministic foundation that
can later be augmented by machine-learning or large-language-model services.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from app.ingestion.document_models import (
    ConfidenceLevel,
    ContentBlockType,
    EngineeringExtractionResult,
    EngineeringFactType,
    EngineeringValue,
    EquipmentCategory,
    EvidenceLocation,
    EvidenceReference,
    EvidenceType,
    ExtractedDocumentMetadata,
    ExtractedEngineeringFact,
    ParsedContentBlock,
    ParsedDocument,
    ReviewStatus,
    SafetyInformation,
    SafetySeverity,
)


class EngineeringExtractionError(ValueError):
    """Raised when engineering content cannot be extracted safely."""


@dataclass(frozen=True, slots=True)
class EngineeringExtractorConfig:
    """Configuration for deterministic engineering extraction."""

    engine_name: str = "Engineer4Me deterministic engineering extractor"
    engine_version: str = "1.0.0"

    minimum_text_length: int = 8
    maximum_block_characters: int = 20_000
    maximum_fact_statement_characters: int = 10_000
    maximum_evidence_characters: int = 10_000
    maximum_fact_count: int = 10_000

    minimum_extraction_confidence: float = 0.20
    automatic_review_threshold: float = 0.90
    safety_review_required: bool = True

    include_headings: bool = False
    include_notes: bool = True
    include_tables: bool = True
    include_unknown_blocks: bool = False

    def __post_init__(self) -> None:
        if not self.engine_name.strip():
            raise ValueError("engine_name cannot be empty")

        if not self.engine_version.strip():
            raise ValueError("engine_version cannot be empty")

        if self.minimum_text_length < 1:
            raise ValueError("minimum_text_length must be positive")

        if self.maximum_block_characters < 1:
            raise ValueError("maximum_block_characters must be positive")

        if self.maximum_fact_statement_characters < 1:
            raise ValueError(
                "maximum_fact_statement_characters must be positive"
            )

        if self.maximum_evidence_characters < 1:
            raise ValueError("maximum_evidence_characters must be positive")

        if self.maximum_fact_count < 1:
            raise ValueError("maximum_fact_count must be positive")

        if not 0 <= self.minimum_extraction_confidence <= 1:
            raise ValueError(
                "minimum_extraction_confidence must be between 0 and 1"
            )

        if not 0 <= self.automatic_review_threshold <= 1:
            raise ValueError(
                "automatic_review_threshold must be between 0 and 1"
            )


@dataclass(slots=True)
class _FactClassification:
    """Internal result describing a classified engineering statement."""

    fact_type: EngineeringFactType
    title: str
    confidence: float


class EngineeringExtractor:
    """Extract structured engineering knowledge from parsed documents."""

    _excluded_block_types: frozenset[ContentBlockType] = frozenset(
        {
            ContentBlockType.HEADER,
            ContentBlockType.FOOTER,
            ContentBlockType.PAGE_NUMBER,
            ContentBlockType.IMAGE,
            ContentBlockType.DIAGRAM,
            ContentBlockType.DRAWING,
            ContentBlockType.CODE,
        }
    )

    _fact_patterns: tuple[
        tuple[
            EngineeringFactType,
            str,
            tuple[str, ...],
            float,
        ],
        ...,
    ] = (
        (
            EngineeringFactType.SAFETY_WARNING,
            "Safety warning",
            (
                r"\bdanger\b",
                r"\bwarning\b",
                r"\brisk of (?:death|injury|electric shock)\b",
                r"\bserious (?:injury|harm)\b",
                r"\bexplosion hazard\b",
                r"\bfire hazard\b",
            ),
            0.96,
        ),
        (
            EngineeringFactType.SAFETY_REQUIREMENT,
            "Safety requirement",
            (
                r"\bmust be (?:isolated|de-energised|de-energized)\b",
                r"\blockout(?:/tagout|\s+tagout|\s+and\s+tagout)?\b",
                r"\bpersonal protective equipment\b",
                r"\brequired ppe\b",
                r"\bqualified personnel only\b",
                r"\bpermit to work\b",
                r"\bverify zero energy\b",
            ),
            0.95,
        ),
        (
            EngineeringFactType.FAULT_CODE,
            "Fault code",
            (
                r"\b(?:fault|error|alarm|diagnostic)\s+code\b",
                r"\b(?:fault|error|alarm)\s+[A-Z]?\d{1,6}\b",
                r"\bcode\s+[A-Z]{0,4}[- ]?\d{1,6}\b",
            ),
            0.94,
        ),
        (
            EngineeringFactType.LIKELY_CAUSE,
            "Likely cause",
            (
                r"\bpossible cause(?:s)?\b",
                r"\blikely cause(?:s)?\b",
                r"\bprobable cause(?:s)?\b",
                r"\bcaused by\b",
                r"\bdue to\b",
            ),
            0.89,
        ),
        (
            EngineeringFactType.CORRECTIVE_ACTION,
            "Corrective action",
            (
                r"\bcorrective action\b",
                r"\bremedial action\b",
                r"\bto correct\b",
                r"\breplace the\b",
                r"\brepair the\b",
                r"\breset the\b",
                r"\brestore the\b",
            ),
            0.88,
        ),
        (
            EngineeringFactType.TROUBLESHOOTING_STEP,
            "Troubleshooting step",
            (
                r"\btroubleshoot",
                r"\bcheck (?:the|that|for)\b",
                r"\binspect (?:the|for)\b",
                r"\bdiagnos",
                r"\bverify (?:the|that|whether)\b",
                r"\btest (?:the|for)\b",
            ),
            0.84,
        ),
        (
            EngineeringFactType.VERIFICATION_STEP,
            "Verification step",
            (
                r"\bverify that\b",
                r"\bconfirm that\b",
                r"\bensure that\b",
                r"\bvalidation\b",
                r"\bacceptance criteria\b",
                r"\bfunctional test\b",
            ),
            0.86,
        ),
        (
            EngineeringFactType.INSTALLATION_REQUIREMENT,
            "Installation requirement",
            (
                r"\binstall(?:ation|ed)?\b",
                r"\bmount(?:ing|ed)?\b",
                r"\bminimum clearance\b",
                r"\borientation\b",
                r"\bwiring requirement\b",
                r"\binstallation shall\b",
            ),
            0.85,
        ),
        (
            EngineeringFactType.COMMISSIONING_STEP,
            "Commissioning step",
            (
                r"\bcommission(?:ing)?\b",
                r"\bstart-up procedure\b",
                r"\bstartup procedure\b",
                r"\bfirst energisation\b",
                r"\bfirst energization\b",
            ),
            0.88,
        ),
        (
            EngineeringFactType.CONFIGURATION_PARAMETER,
            "Configuration parameter",
            (
                r"\bconfiguration parameter\b",
                r"\bparameter setting\b",
                r"\bset(?:ting)?\s+(?:the|to)\b",
                r"\bdefault value\b",
                r"\bmenu parameter\b",
            ),
            0.84,
        ),
        (
            EngineeringFactType.CALIBRATION_STEP,
            "Calibration step",
            (
                r"\bcalibrat",
                r"\bzero adjustment\b",
                r"\bspan adjustment\b",
                r"\btrim the\b",
            ),
            0.90,
        ),
        (
            EngineeringFactType.MAINTENANCE_INTERVAL,
            "Maintenance interval",
            (
                r"\bevery\s+\d+\s+(?:hours?|days?|weeks?|months?|years?)\b",
                r"\bat intervals? of\b",
                r"\bmaintenance interval\b",
                r"\bservice interval\b",
                r"\bperiodic(?:ally)?\b",
            ),
            0.91,
        ),
        (
            EngineeringFactType.MAINTENANCE_TASK,
            "Maintenance task",
            (
                r"\bmaintenance\b",
                r"\bservice the\b",
                r"\blubricat",
                r"\bclean the\b",
                r"\breplace the (?:seal|filter|gasket|bearing)\b",
            ),
            0.82,
        ),
        (
            EngineeringFactType.INSPECTION_REQUIREMENT,
            "Inspection requirement",
            (
                r"\binspection\b",
                r"\binspect the\b",
                r"\bvisual check\b",
                r"\bexamine the\b",
            ),
            0.84,
        ),
        (
            EngineeringFactType.OPERATING_LIMIT,
            "Operating limit",
            (
                r"\boperating (?:range|limit|pressure|temperature)\b",
                r"\bmaximum (?:working|operating|allowable)\b",
                r"\bminimum operating\b",
                r"\bmust not exceed\b",
                r"\bdo not exceed\b",
                r"\brated (?:pressure|temperature|voltage|current)\b",
            ),
            0.91,
        ),
        (
            EngineeringFactType.ENVIRONMENTAL_LIMIT,
            "Environmental limit",
            (
                r"\bambient temperature\b",
                r"\bstorage temperature\b",
                r"\brelative humidity\b",
                r"\bingress protection\b",
                r"\bip\s?\d{2}\b",
                r"\baltitude\b",
                r"\bvibration\b",
                r"\bcorrosive atmosphere\b",
            ),
            0.90,
        ),
        (
            EngineeringFactType.MATERIAL_COMPATIBILITY,
            "Material compatibility",
            (
                r"\bmaterial compatibility\b",
                r"\bcompatible with\b",
                r"\bnot compatible with\b",
                r"\bwetted material\b",
                r"\bchemical resistance\b",
            ),
            0.88,
        ),
        (
            EngineeringFactType.REQUIRED_TOOL,
            "Required tool",
            (
                r"\brequired tools?\b",
                r"\btools? required\b",
                r"\busing a\b.*\b(?:wrench|spanner|multimeter|calibrator)\b",
            ),
            0.88,
        ),
        (
            EngineeringFactType.SPARE_PART,
            "Spare part",
            (
                r"\bspare parts?\b",
                r"\bspares list\b",
                r"\brecommended spares?\b",
            ),
            0.91,
        ),
        (
            EngineeringFactType.REQUIRED_PART,
            "Required part",
            (
                r"\brequired parts?\b",
                r"\bparts? required\b",
                r"\breplacement (?:seal|gasket|filter|module|sensor)\b",
            ),
            0.86,
        ),
        (
            EngineeringFactType.REPLACEMENT_PRODUCT,
            "Replacement product",
            (
                r"\breplacement product\b",
                r"\breplaced by\b",
                r"\bsuperseded by\b",
                r"\brecommended replacement\b",
            ),
            0.92,
        ),
        (
            EngineeringFactType.OBSOLESCENCE_INFORMATION,
            "Obsolescence information",
            (
                r"\bobsolete\b",
                r"\bobsolescence\b",
                r"\bdiscontinued\b",
                r"\bend of life\b",
                r"\bend-of-life\b",
                r"\bno longer supported\b",
            ),
            0.94,
        ),
        (
            EngineeringFactType.MIGRATION_GUIDANCE,
            "Migration guidance",
            (
                r"\bmigration\b",
                r"\bupgrade path\b",
                r"\bmodernisation\b",
                r"\bmodernization\b",
                r"\bconversion kit\b",
            ),
            0.88,
        ),
        (
            EngineeringFactType.COMMUNICATION_PROTOCOL,
            "Communication protocol",
            (
                r"\bhart\b",
                r"\bprofibus\b",
                r"\bprofinet\b",
                r"\bmodbus\b",
                r"\bfieldbus\b",
                r"\bethernet/ip\b",
                r"\bopc\s*ua\b",
            ),
            0.86,
        ),
        (
            EngineeringFactType.FIRMWARE_INFORMATION,
            "Firmware information",
            (
                r"\bfirmware\b",
                r"\bsoftware revision\b",
                r"\bdevice revision\b",
            ),
            0.87,
        ),
      (
            EngineeringFactType.CERTIFICATION,
            "Certification",
            (
                r"\bcertified to\b",
                r"\bcertification\b",
                r"\biecex\b",
                r"\batex\b",
                r"\bsil\s*[1-4]\b",
            ),
            0.91,
        ),
        (
            EngineeringFactType.COMPLIANCE_REQUIREMENT,
            "Compliance requirement",
            (
                r"\bshall comply with\b",
                r"\bin accordance with\b",
                r"\bcompliance with\b",
                r"\bregulatory requirement\b",
            ),
            0.88,
        ),
        (
            EngineeringFactType.SELECTION_RULE,
            "Selection rule",
            (
                r"\bselect (?:the|a)\b",
                r"\bselection criteria\b",
                r"\bchoose (?:the|a)\b",
                r"\bwhen selecting\b",
            ),
            0.80,
        ),
        (
            EngineeringFactType.SIZING_RULE,
            "Sizing rule",
            (
                r"\bsizing\b",
                r"\bsize the\b",
                r"\bcalculated (?:flow|capacity|diameter)\b",
                r"\bpressure drop calculation\b",
            ),
            0.85,
        ),
        (
            EngineeringFactType.SPECIFICATION,
            "Engineering specification",
            (
                r"\bspecification\b",
                r"\btechnical data\b",
                r"\brated\b",
                r"\baccuracy\b",
                r"\brepeatability\b",
                r"\boutput signal\b",
                r"\bsupply voltage\b",
            ),
            0.78,
        ),
    )

    _engineering_value_pattern = re.compile(
        r"""
        (?P<minimum>
            -?\d+(?:[.,]\d+)?
        )
        \s*
        (?:
            (?:to|through|[-–—])
            \s*
            (?P<maximum>
                -?\d+(?:[.,]\d+)?
            )
            \s*
        )?
        (?P<unit>
            °C|°F|K|
            bar(?:g|a)?|mbar|Pa|kPa|MPa|psi|
            V|mV|kV|A|mA|
            Hz|kHz|
            mm|cm|m|in|
            mm/s|m/s|
            rpm|
            %RH|%|
            Nm|N·m|
            kg|g|
            l/min|L/min|m3/h|m³/h|
            ms|s|min|h|hours?|days?|months?|years?
        )
        \b
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    _standard_pattern = re.compile(
        r"""
        \b(
            IEC(?:\s+|[-/])?[A-Z]{0,4}\d+(?:[-:/.]\d+)*|
            ISO(?:\s+|[-/])?\d+(?:[-:/.]\d+)*|
            EN(?:\s+|[-/])?\d+(?:[-:/.]\d+)*|
            ASME(?:\s+|[-/])?[A-Z]{0,4}\d+(?:[-:/.]\d+)*|
            ANSI(?:\s+|[-/])?[A-Z]{0,4}\d+(?:[-:/.]\d+)*|
            API(?:\s+|[-/])?\d+[A-Z]?(?:[-:/.]\d+)*|
            IEEE(?:\s+|[-/])?\d+(?:[-:/.]\d+)*|
            NFPA(?:\s+|[-/])?\d+(?:[-:/.]\d+)*|
            ISA(?:\s+|[-/])?\d+(?:[-:/.]\d+)*|
            SIL\s*[1-4]
        )\b
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    _tool_terms: tuple[str, ...] = (
        "adjustable wrench",
        "allen key",
        "calibrator",
        "clamp meter",
        "handheld communicator",
        "hart communicator",
        "insulation tester",
        "multimeter",
        "pressure calibrator",
        "screwdriver",
        "socket",
        "spanner",
        "torque wrench",
    )

    _part_terms: tuple[str, ...] = (
        "actuator",
        "battery",
        "bearing",
        "cable",
        "diaphragm",
        "filter",
        "fuse",
        "gasket",
        "module",
        "o-ring",
        "packing",
        "seal",
        "sensor",
        "transmitter",
        "valve",
    )

    _ppe_terms: tuple[str, ...] = (
        "arc-rated clothing",
        "chemical-resistant gloves",
        "eye protection",
        "face shield",
        "flame-resistant clothing",
        "gloves",
        "hard hat",
        "hearing protection",
        "respirator",
        "safety glasses",
        "safety shoes",
    )

    def __init__(
        self,
        config: EngineeringExtractorConfig | None = None,
    ) -> None:
        self.config = config or EngineeringExtractorConfig()

    def extract(
        self,
        document: ParsedDocument,
        metadata: ExtractedDocumentMetadata | None = None,
    ) -> EngineeringExtractionResult:
        """Extract engineering facts from a parsed document."""

        if not isinstance(document, ParsedDocument):
            raise EngineeringExtractionError(
                "document must be a ParsedDocument instance"
            )

        if metadata is not None and metadata.document_id != document.document_id:
            raise EngineeringExtractionError(
                "metadata document_id must match parsed document document_id"
            )

        facts: list[ExtractedEngineeringFact] = []
        warnings: list[str] = list(document.warnings)
        errors: list[str] = list(document.errors)

        processed_block_count = 0
        skipped_block_count = 0

        blocks = sorted(
            self._iter_blocks(document),
            key=lambda block: (
                block.page_number or 0,
                block.sequence_number,
            ),
        )

        for block in blocks:
            if len(facts) >= self.config.maximum_fact_count:
                warnings.append(
                    "maximum fact count reached; remaining blocks were skipped"
                )
                skipped_block_count += 1
                continue

            if not self._should_process_block(block):
                skipped_block_count += 1
                continue

            processed_block_count += 1

            try:
                block_facts = self._extract_block_facts(
                    document=document,
                    block=block,
                    metadata=metadata,
                )
                facts.extend(block_facts)
            except Exception as exc:
                errors.append(
                    f"block {block.block_id} extraction failed: {exc}"
                )

        facts = self._deduplicate_facts(facts)

        extraction_confidence = self._calculate_result_confidence(
            facts=facts,
            document_confidence=document.extraction_confidence,
        )

        return EngineeringExtractionResult(
            document_id=document.document_id,
            facts=facts,
            extraction_engine=self.config.engine_name,
            extraction_engine_version=self.config.engine_version,
            extraction_confidence=extraction_confidence,
            processed_block_count=processed_block_count,
            skipped_block_count=skipped_block_count,
            warnings=self._deduplicate_strings(warnings),
            errors=self._deduplicate_strings(errors),
            extraction_metadata={
                "parser_name": document.parser_name,
                "parser_version": document.parser_version,
                "source_page_count": document.page_count,
                "source_character_count": document.character_count,
                "source_word_count": document.word_count,
                "metadata_applied": metadata is not None,
                "deterministic_extraction": True,
            },
        )

    def extract_engineering_facts(
        self,
        document: ParsedDocument,
        metadata: ExtractedDocumentMetadata | None = None,
    ) -> EngineeringExtractionResult:
        """Compatibility alias for :meth:`extract`."""

        return self.extract(document=document, metadata=metadata)

    def _iter_blocks(
        self,
        document: ParsedDocument,
    ) -> Iterable[ParsedContentBlock]:
        for page in document.pages:
            yield from page.blocks

    def _should_process_block(self, block: ParsedContentBlock) -> bool:
        if block.block_type in self._excluded_block_types:
            return False

        if (
            block.block_type == ContentBlockType.HEADING
            and not self.config.include_headings
        ):
            return False

        if (
            block.block_type == ContentBlockType.NOTE
            and not self.config.include_notes
        ):
            return False

        if (
            block.block_type == ContentBlockType.TABLE
            and not self.config.include_tables
        ):
            return False

        if (
            block.block_type == ContentBlockType.UNKNOWN
            and not self.config.include_unknown_blocks
        ):
            return False

        text = self._get_block_text(block)

        if len(text.strip()) < self.config.minimum_text_length:
            return False

        return True

    def _extract_block_facts(
        self,
        document: ParsedDocument,
        block: ParsedContentBlock,
        metadata: ExtractedDocumentMetadata | None,
    ) -> list[ExtractedEngineeringFact]:
        text = self._get_block_text(block)

        if not text:
            return []

        text = text[: self.config.maximum_block_characters]
        statements = self._split_statements(text)

        facts: list[ExtractedEngineeringFact] = []

        for statement in statements:
            classification = self._classify_statement(
                statement=statement,
                block_type=block.block_type,
            )

            if classification is None:
                continue

            confidence = self._calculate_fact_confidence(
                classification_confidence=classification.confidence,
                block_confidence=block.extraction_confidence,
                document_confidence=document.extraction_confidence,
                block_type=block.block_type,
            )

            if confidence < self.config.minimum_extraction_confidence:
                continue

            safety_information = self._extract_safety_information(
                statement=statement,
                block_type=block.block_type,
            )

            standards = self._extract_standards(statement)
            required_tools = self._extract_terms(statement, self._tool_terms)
            required_parts = self._extract_terms(statement, self._part_terms)
            engineering_value = self._extract_engineering_value(statement)

            evidence = self._build_evidence(
                document=document,
                block=block,
                statement=statement,
                confidence=confidence,
            )

            requires_human_review = self._requires_human_review(
                fact_type=classification.fact_type,
                confidence=confidence,
                safety_information=safety_information,
            )

            fact = ExtractedEngineeringFact(
                document_id=document.document_id,
                fact_type=classification.fact_type,
                title=classification.title,
                statement=statement[
                    : self.config.maximum_fact_statement_characters
                ],
                value=engineering_value,
                manufacturer=self._metadata_manufacturer(metadata),
                product_family=self._metadata_product_family(metadata),
                product_series=self._metadata_product_series(metadata),
                model_numbers=self._metadata_model_numbers(metadata),
                equipment_categories=self._metadata_equipment_categories(
                    metadata
                ),
                operating_conditions=self._extract_operating_conditions(
                    statement
                ),
                prerequisites=self._extract_prerequisites(statement),
                actions=self._extract_actions(
                    statement,
                    classification.fact_type,
                ),
                verification_steps=self._extract_verification_steps(
                    statement,
                    classification.fact_type,
                ),
                required_tools=required_tools,
                required_parts=required_parts,
                safety_information=safety_information,
                standards_referenced=standards,
                evidence=[evidence],
                extraction_confidence=confidence,
                requires_human_review=requires_human_review,
                review_status=(
                    ReviewStatus.PENDING
                    if requires_human_review
                    else ReviewStatus.NOT_REQUIRED
                ),
                tags=self._build_tags(
                    classification.fact_type,
                    safety_information,
                    standards,
                ),
                attributes={
                    "source_block_type": block.block_type.value,
                    "source_sequence_number": block.sequence_number,
                    "source_extraction_method": block.extraction_method.value,
                },
            )

            facts.append(fact)

        return facts

    def _get_block_text(self, block: ParsedContentBlock) -> str:
        text = block.text.strip()

        if text:
            return text

        if block.table is None:
            return ""

        table_data = block.table.model_dump(mode="python")

        rows = table_data.get("rows")
        if isinstance(rows, Sequence):
            rendered_rows: list[str] = []

            for row in rows:
                if isinstance(row, Sequence) and not isinstance(
                    row,
                    (str, bytes),
                ):
                    rendered_rows.append(
                        " | ".join(str(value) for value in row)
                    )
                else:
                    rendered_rows.append(str(row))

            return "\n".join(rendered_rows)

        return str(table_data)

    def _split_statements(self, text: str) -> list[str]:
        normalised = re.sub(r"[ \t]+", " ", text)
        normalised = re.sub(r"\r\n?", "\n", normalised)

        raw_statements = re.split(
            r"""
            (?:
                (?<=[.!?;])
                \s+
            )
            |
            (?:
                \n+
            )
            |
            (?:
                \s*[•●▪]\s*
            )
            """,
            normalised,
            flags=re.VERBOSE,
        )

        statements: list[str] = []

        for raw_statement in raw_statements:
            statement = re.sub(
                r"^\s*(?:[-–—*]|\d+[.)]|[A-Za-z][.)])\s*",
                "",
                raw_statement,
            ).strip()

            if len(statement) < self.config.minimum_text_length:
                continue

            statements.append(statement)

        return self._deduplicate_strings(statements)

    def _classify_statement(
        self,
        statement: str,
        block_type: ContentBlockType,
    ) -> _FactClassification | None:
        block_classification = self._classification_from_block_type(
            block_type
        )

        if block_classification is not None:
            return block_classification

        for fact_type, title, patterns, confidence in self._fact_patterns:
            if any(
                re.search(pattern, statement, re.IGNORECASE)
                for pattern in patterns
            ):
                return _FactClassification(
                    fact_type=fact_type,
                    title=title,
                    confidence=confidence,
                )

        return None

    @staticmethod
    def _classification_from_block_type(
        block_type: ContentBlockType,
    ) -> _FactClassification | None:
        mapping = {
            ContentBlockType.DANGER: _FactClassification(
                fact_type=EngineeringFactType.SAFETY_WARNING,
                title="Danger",
                confidence=0.99,
            ),
            ContentBlockType.WARNING: _FactClassification(
                fact_type=EngineeringFactType.SAFETY_WARNING,
                title="Warning",
                confidence=0.98,
            ),
            ContentBlockType.CAUTION: _FactClassification(
                fact_type=EngineeringFactType.SAFETY_WARNING,
                title="Caution",
                confidence=0.96,
            ),
        }

        return mapping.get(block_type)

    def _build_evidence(
        self,
        document: ParsedDocument,
        block: ParsedContentBlock,
        statement: str,
        confidence: float,
    ) -> EvidenceReference:
        section = " > ".join(block.section_path) or None

        evidence_type = EvidenceType.TEXT

        if block.block_type == ContentBlockType.TABLE:
            evidence_type = EvidenceType.TABLE

        return EvidenceReference(
            document_id=document.document_id,
            evidence_type=evidence_type,
            location=EvidenceLocation(
                page_number=block.page_number,
                section=section,
                block_id=block.block_id,
                bounding_box=block.bounding_box,
                spreadsheet_range=block.spreadsheet_range,
            ),
            quoted_text=statement[: self.config.maximum_evidence_characters],
            source_title=document.title,
            extraction_confidence=confidence,
            verified=False,
        )

    def _extract_engineering_value(
        self,
        statement: str,
    ) -> EngineeringValue | None:
        match = self._engineering_value_pattern.search(statement)

        if match is None:
            return None

        minimum_text = match.group("minimum")
        maximum_text = match.group("maximum")
        unit = match.group("unit")

        minimum = self._parse_float(minimum_text)

        if maximum_text is not None:
            maximum = self._parse_float(maximum_text)

            return EngineeringValue(
                value=f"{minimum_text} to {maximum_text}",
                unit=unit,
                minimum=minimum,
                maximum=maximum,
                conditions=self._extract_operating_conditions(statement),
            )

        return EngineeringValue(
            value=minimum if minimum is not None else minimum_text,
            unit=unit,
            nominal=minimum,
            conditions=self._extract_operating_conditions(statement),
        )

    def _extract_safety_information(
        self,
        statement: str,
        block_type: ContentBlockType,
    ) -> list[SafetyInformation]:
        severity = self._detect_safety_severity(statement, block_type)

        if severity is None:
            return []

        required_actions: list[str] = []
        prohibited_actions: list[str] = []
        isolation_requirements: list[str] = []

        if re.search(
            r"\b(?:disconnect|isolate|de-energise|de-energize)\b",
            statement,
            re.IGNORECASE,
        ):
            isolation_requirements.append(statement)

        if re.search(
            r"\b(?:must|shall|required|ensure|verify)\b",
            statement,
            re.IGNORECASE,
        ):
            required_actions.append(statement)

        if re.search(
            r"\b(?:do not|must not|never|prohibited)\b",
            statement,
            re.IGNORECASE,
        ):
            prohibited_actions.append(statement)

        required_ppe = self._extract_terms(statement, self._ppe_terms)

        return [
            SafetyInformation(
                severity=severity,
                hazard=statement,
                required_actions=required_actions,
                prohibited_actions=prohibited_actions,
                required_ppe=required_ppe,
                isolation_requirements=isolation_requirements,
                escalation_required=severity
                in {
                    SafetySeverity.DANGER,
                    SafetySeverity.CRITICAL,
                },
            )
        ]

    @staticmethod
    def _detect_safety_severity(
        statement: str,
        block_type: ContentBlockType,
    ) -> SafetySeverity | None:
        if block_type == ContentBlockType.DANGER:
            return SafetySeverity.DANGER

        if block_type == ContentBlockType.WARNING:
            return SafetySeverity.WARNING

        if block_type == ContentBlockType.CAUTION:
            return SafetySeverity.CAUTION

        severity_patterns = (
            (
                SafetySeverity.CRITICAL,
                (
                    r"\bimminent danger\b",
                    r"\bwill cause death\b",
                    r"\bfatal\b",
                ),
            ),
            (
                SafetySeverity.DANGER,
                (
                    r"\bdanger\b",
                    r"\brisk of death\b",
                    r"\bexplosion hazard\b",
                ),
            ),
            (
                SafetySeverity.WARNING,
                (
                    r"\bwarning\b",
                    r"\bserious injury\b",
                    r"\belectric shock\b",
                ),
            ),
            (
                SafetySeverity.CAUTION,
                (
                    r"\bcaution\b",
                    r"\bminor injury\b",
                    r"\bequipment damage\b",
                ),
            ),
            (
                SafetySeverity.NOTICE,
                (
                    r"\bnotice\b",
                    r"\bimportant safety information\b",
                ),
            ),
        )

        for severity, patterns in severity_patterns:
            if any(
                re.search(pattern, statement, re.IGNORECASE)
                for pattern in patterns
            ):
                return severity

        return None

    def _extract_standards(self, statement: str) -> list[str]:
        standards = [
            self._normalise_whitespace(match.group(1)).upper()
            for match in self._standard_pattern.finditer(statement)
        ]

        return self._deduplicate_strings(standards)

    @staticmethod
    def _extract_terms(
        statement: str,
        terms: Sequence[str],
    ) -> list[str]:
        found = [
            term
            for term in terms
            if re.search(
                rf"\b{re.escape(term)}\b",
                statement,
                re.IGNORECASE,
            )
        ]

        return list(dict.fromkeys(found))

    @staticmethod
    def _extract_operating_conditions(statement: str) -> list[str]:
        condition_patterns = (
            r"\b(?:at|above|below|between|under|within)\s+"
            r"-?\d+(?:[.,]\d+)?(?:\s*(?:to|[-–—])\s*"
            r"-?\d+(?:[.,]\d+)?)?\s*"
            r"(?:°C|°F|K|bar|kPa|MPa|psi|%RH|%)\b",
            r"\bwhen\s+[^.;:]+",
            r"\bprovided that\s+[^.;:]+",
        )

        conditions: list[str] = []

        for pattern in condition_patterns:
            conditions.extend(
                match.group(0).strip()
                for match in re.finditer(
                    pattern,
                    statement,
                    re.IGNORECASE,
                )
            )

        return list(dict.fromkeys(conditions))

    @staticmethod
    def _extract_prerequisites(statement: str) -> list[str]:
        prerequisites: list[str] = []

        patterns = (
            r"\bbefore\s+[^.;:]+",
            r"\bprior to\s+[^.;:]+",
            r"\bprerequisite(?:s)?\s*[:\-]\s*[^.;:]+",
        )

        for pattern in patterns:
            prerequisites.extend(
                match.group(0).strip()
                for match in re.finditer(
                    pattern,
                    statement,
                    re.IGNORECASE,
                )
            )

        return list(dict.fromkeys(prerequisites))

    @staticmethod
    def _extract_actions(
        statement: str,
        fact_type: EngineeringFactType,
    ) -> list[str]:
        action_types = {
            EngineeringFactType.COMMISSIONING_STEP,
            EngineeringFactType.CONFIGURATION_PARAMETER,
            EngineeringFactType.CALIBRATION_STEP,
            EngineeringFactType.MAINTENANCE_TASK,
            EngineeringFactType.INSPECTION_REQUIREMENT,
            EngineeringFactType.TROUBLESHOOTING_STEP,
            EngineeringFactType.CORRECTIVE_ACTION,
            EngineeringFactType.INSTALLATION_REQUIREMENT,
            EngineeringFactType.SAFETY_REQUIREMENT,
        }

        if fact_type in action_types:
            return [statement]

        return []

    @staticmethod
    def _extract_verification_steps(
        statement: str,
        fact_type: EngineeringFactType,
    ) -> list[str]:
        if fact_type == EngineeringFactType.VERIFICATION_STEP:
            return [statement]

        if re.search(
            r"\b(?:verify|confirm|ensure|validate|test)\b",
            statement,
            re.IGNORECASE,
        ):
            return [statement]

        return []

    def _calculate_fact_confidence(
        self,
        classification_confidence: float,
        block_confidence: float,
        document_confidence: float,
        block_type: ContentBlockType,
    ) -> float:
        confidence = (
            classification_confidence * 0.60
            + block_confidence * 0.25
            + document_confidence * 0.15
        )

        if block_type in {
            ContentBlockType.DANGER,
            ContentBlockType.WARNING,
            ContentBlockType.CAUTION,
            ContentBlockType.TABLE,
        }:
            confidence += 0.03

        return round(max(0.0, min(1.0, confidence)), 4)

    def _requires_human_review(
        self,
        fact_type: EngineeringFactType,
        confidence: float,
        safety_information: Sequence[SafetyInformation],
    ) -> bool:
        if (
            self.config.safety_review_required
            and (
                fact_type
                in {
                    EngineeringFactType.SAFETY_WARNING,
                    EngineeringFactType.SAFETY_REQUIREMENT,
                }
                or safety_information
            )
        ):
            return True

        return confidence < self.config.automatic_review_threshold

    @staticmethod
    def _build_tags(
        fact_type: EngineeringFactType,
        safety_information: Sequence[SafetyInformation],
        standards: Sequence[str],
    ) -> list[str]:
        tags = [fact_type.value]

        if safety_information:
            tags.append("safety")

        if standards:
            tags.append("standards")

        return list(dict.fromkeys(tags))

    @staticmethod
    def _metadata_manufacturer(
        metadata: ExtractedDocumentMetadata | None,
    ) -> str | None:
        if metadata is None:
            return None

        return metadata.product_reference.manufacturer

    @staticmethod
    def _metadata_product_family(
        metadata: ExtractedDocumentMetadata | None,
    ) -> str | None:
        if metadata is None:
            return None

        return metadata.product_reference.product_family

    @staticmethod
    def _metadata_product_series(
        metadata: ExtractedDocumentMetadata | None,
    ) -> str | None:
        if metadata is None:
            return None

        return metadata.product_reference.product_series

    @staticmethod
    def _metadata_model_numbers(
        metadata: ExtractedDocumentMetadata | None,
    ) -> list[str]:
        if metadata is None:
            return []

        return list(metadata.product_reference.model_numbers)

    @staticmethod
    def _metadata_equipment_categories(
        metadata: ExtractedDocumentMetadata | None,
    ) -> list[EquipmentCategory]:
        if metadata is None:
            return []

        return list(metadata.product_reference.equipment_categories)

    def _deduplicate_facts(
        self,
        facts: Sequence[ExtractedEngineeringFact],
    ) -> list[ExtractedEngineeringFact]:
        unique: dict[
            tuple[EngineeringFactType, str, int | None],
            ExtractedEngineeringFact,
        ] = {}

        for fact in facts:
            page_number = (
                fact.evidence[0].location.page_number
                if fact.evidence
                else None
            )

            key = (
                fact.fact_type,
                self._normalise_fact_statement(fact.statement),
                page_number,
            )

            existing = unique.get(key)

            if (
                existing is None
                or fact.extraction_confidence
                > existing.extraction_confidence
            ):
                unique[key] = fact

        return list(unique.values())

    @staticmethod
    def _calculate_result_confidence(
        facts: Sequence[ExtractedEngineeringFact],
        document_confidence: float,
    ) -> float:
        if not facts:
            return 0.0

        fact_average = sum(
            fact.extraction_confidence for fact in facts
        ) / len(facts)

        confidence = fact_average * 0.85 + document_confidence * 0.15

        return round(max(0.0, min(1.0, confidence)), 4)

    @staticmethod
    def _parse_float(value: str) -> float | None:
        try:
            return float(value.replace(",", "."))
        except ValueError:
            return None

    @staticmethod
    def _normalise_fact_statement(statement: str) -> str:
        return re.sub(r"\s+", " ", statement).strip().casefold()

    @staticmethod
    def _normalise_whitespace(value: str) -> str:
        return re.sub(r"\s+", " ", value).strip()

    @staticmethod
    def _deduplicate_strings(values: Sequence[str]) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()

        for value in values:
            cleaned = value.strip()

            if not cleaned:
                continue

            key = cleaned.casefold()

            if key in seen:
                continue

            seen.add(key)
            result.append(cleaned)

        return result