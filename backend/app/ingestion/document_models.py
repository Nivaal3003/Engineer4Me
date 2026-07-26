"""
Core data models for the Engineer4Me document-ingestion pipeline.

These models define the contracts shared by document parsing, metadata
extraction, engineering knowledge extraction, evidence linking,
duplicate detection, human review, and repository publishing.

The models are intentionally independent from database persistence.
They represent validated pipeline data that can later be mapped to
SQLAlchemy models, API schemas, object storage, or message queues.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class DocumentFormat(StrEnum):
    """Supported source-document formats."""

    PDF = "pdf"
    DOC = "doc"
    DOCX = "docx"
    XLS = "xls"
    XLSX = "xlsx"
    CSV = "csv"
    TXT = "txt"
    RTF = "rtf"
    HTML = "html"
    XML = "xml"
    JSON = "json"
    JPG = "jpg"
    JPEG = "jpeg"
    PNG = "png"
    TIFF = "tiff"
    BMP = "bmp"
    WEBP = "webp"
    ZIP = "zip"
    UNKNOWN = "unknown"


class DocumentType(StrEnum):
    """Engineering document classifications."""

    DATASHEET = "datasheet"
    CATALOGUE = "catalogue"
    PRODUCT_CATALOGUE = "product_catalogue"

    USER_MANUAL = "user_manual"
    INSTALLATION_MANUAL = "installation_manual"
    OPERATION_MANUAL = "operation_manual"
    MAINTENANCE_MANUAL = "maintenance_manual"
    SERVICE_MANUAL = "service_manual"
    COMMISSIONING_GUIDE = "commissioning_guide"

    PROCEDURE = "procedure"
    CALIBRATION_PROCEDURE = "calibration_procedure"
    ENGINEERING_PROCEDURE = "engineering_procedure"

    TROUBLESHOOTING_GUIDE = "troubleshooting_guide"
    FAULT_CODE_MANUAL = "fault_code_manual"
    SAFETY_MANUAL = "safety_manual"

    SPECIFICATION = "specification"
    ENGINEERING_STANDARD = "engineering_standard"

    TECHNICAL_BULLETIN = "technical_bulletin"
    APPLICATION_NOTE = "application_note"
    WHITE_PAPER = "white_paper"

    RELEASE_NOTE = "release_note"
    FIRMWARE_RELEASE_NOTE = "firmware_release_note"

    DRAWING = "drawing"
    CERTIFICATE = "certificate"
    SPARE_PARTS_LIST = "spare_parts_list"
    SOFTWARE_GUIDE = "software_guide"
    OBSOLESCENCE_NOTICE = "obsolescence_notice"
    MIGRATION_GUIDE = "migration_guide"
    TRAINING_MATERIAL = "training_material"
    PROJECT_DOCUMENT = "project_document"
    INSPECTION_REPORT = "inspection_report"
    TEST_REPORT = "test_report"

    OTHER = "other"
    UNKNOWN = "unknown"


class EquipmentCategory(StrEnum):
    """High-level industrial equipment categories."""

    PRESSURE_INSTRUMENT = "pressure_instrument"
    FLOW_INSTRUMENT = "flow_instrument"
    LEVEL_INSTRUMENT = "level_instrument"
    TEMPERATURE_INSTRUMENT = "temperature_instrument"
    ANALYSER = "analyser"
    ANALYTICAL_INSTRUMENT = "analytical_instrument"
    VALVE = "valve"
    CONTROL_VALVE = "control_valve"
    ISOLATION_VALVE = "isolation_valve"
    ACTUATOR = "actuator"
    POSITIONER = "positioner"
    PLC = "plc"
    DCS = "dcs"
    SCADA = "scada"
    HMI = "hmi"
    VSD = "vsd"
    MOTOR = "motor"
    DRIVE = "drive"
    SWITCHGEAR = "switchgear"
    RELAY = "relay"
    PROTECTION_RELAY = "protection_relay"
    POWER_SUPPLY = "power_supply"
    NETWORK = "network"
    INDUSTRIAL_NETWORK = "industrial_network"
    SAFETY_SYSTEM = "safety_system"
    FIRE_AND_GAS = "fire_and_gas"
    WEIGHING_SYSTEM = "weighing_system"
    SENSOR = "sensor"
    TRANSMITTER = "transmitter"
    CONTROLLER = "controller"
    RECORDER = "recorder"
    DATA_ACQUISITION = "data_acquisition"
    MECHANICAL_EQUIPMENT = "mechanical_equipment"
    ELECTRICAL_EQUIPMENT = "electrical_equipment"
    SOFTWARE = "software"
    GENERAL_ENGINEERING = "general_engineering"
    OTHER = "other"
    UNKNOWN = "unknown"


class DocumentLanguage(StrEnum):
    """Common engineering-document languages."""

    ENGLISH = "en"
    AFRIKAANS = "af"
    FRENCH = "fr"
    GERMAN = "de"
    SPANISH = "es"
    PORTUGUESE = "pt"
    ITALIAN = "it"
    DUTCH = "nl"
    CHINESE = "zh"
    JAPANESE = "ja"
    KOREAN = "ko"
    ARABIC = "ar"
    RUSSIAN = "ru"
    OTHER = "other"
    UNKNOWN = "unknown"


class IngestionStatus(StrEnum):
    """Lifecycle status of a document-ingestion job."""

    RECEIVED = "received"
    VALIDATING = "validating"
    VALIDATED = "validated"
    PARSING = "parsing"
    PARSED = "parsed"
    EXTRACTING_METADATA = "extracting_metadata"
    METADATA_EXTRACTED = "metadata_extracted"
    EXTRACTING_ENGINEERING_DATA = "extracting_engineering_data"
    ENGINEERING_DATA_EXTRACTED = "engineering_data_extracted"
    GENERATING_KNOWLEDGE = "generating_knowledge"
    KNOWLEDGE_GENERATED = "knowledge_generated"
    LINKING_EVIDENCE = "linking_evidence"
    EVIDENCE_LINKED = "evidence_linked"
    CHECKING_DUPLICATES = "checking_duplicates"
    DUPLICATE_FOUND = "duplicate_found"
    AWAITING_REVIEW = "awaiting_review"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    PUBLISHING = "publishing"
    PUBLISHED = "published"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ExtractionMethod(StrEnum):
    """Method used to obtain text or structured content."""

    NATIVE_TEXT = "native_text"
    OCR = "ocr"
    TABLE_EXTRACTION = "table_extraction"
    IMAGE_ANALYSIS = "image_analysis"
    EMBEDDED_METADATA = "embedded_metadata"
    ARCHIVE_EXTRACTION = "archive_extraction"
    MANUAL_ENTRY = "manual_entry"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"


class ContentBlockType(StrEnum):
    """Types of content blocks produced by document parsing."""

    TITLE = "title"
    HEADING = "heading"
    PARAGRAPH = "paragraph"
    LIST = "list"
    TABLE = "table"
    IMAGE = "image"
    DIAGRAM = "diagram"
    DRAWING = "drawing"
    FORMULA = "formula"
    CODE = "code"
    HEADER = "header"
    FOOTER = "footer"
    PAGE_NUMBER = "page_number"
    WARNING = "warning"
    CAUTION = "caution"
    DANGER = "danger"
    NOTE = "note"
    UNKNOWN = "unknown"


class EngineeringFactType(StrEnum):
    """Categories of structured engineering knowledge."""

    SPECIFICATION = "specification"
    OPERATING_LIMIT = "operating_limit"
    ENVIRONMENTAL_LIMIT = "environmental_limit"
    MATERIAL_COMPATIBILITY = "material_compatibility"
    PRODUCT_FEATURE = "product_feature"
    MODEL_NUMBER_RULE = "model_number_rule"
    SELECTION_RULE = "selection_rule"
    SIZING_RULE = "sizing_rule"
    INSTALLATION_REQUIREMENT = "installation_requirement"
    COMMISSIONING_STEP = "commissioning_step"
    CONFIGURATION_PARAMETER = "configuration_parameter"
    CALIBRATION_STEP = "calibration_step"
    MAINTENANCE_TASK = "maintenance_task"
    MAINTENANCE_INTERVAL = "maintenance_interval"
    INSPECTION_REQUIREMENT = "inspection_requirement"
    TROUBLESHOOTING_STEP = "troubleshooting_step"
    FAULT_CODE = "fault_code"
    FAILURE_MODE = "failure_mode"
    LIKELY_CAUSE = "likely_cause"
    CORRECTIVE_ACTION = "corrective_action"
    VERIFICATION_STEP = "verification_step"
    SAFETY_WARNING = "safety_warning"
    SAFETY_REQUIREMENT = "safety_requirement"
    REQUIRED_TOOL = "required_tool"
    REQUIRED_PART = "required_part"
    SPARE_PART = "spare_part"
    REPLACEMENT_PRODUCT = "replacement_product"
    COMPATIBILITY_RULE = "compatibility_rule"
    OBSOLESCENCE_INFORMATION = "obsolescence_information"
    MIGRATION_GUIDANCE = "migration_guidance"
    COMPLIANCE_REQUIREMENT = "compliance_requirement"
    CERTIFICATION = "certification"
    SOFTWARE_REQUIREMENT = "software_requirement"
    FIRMWARE_INFORMATION = "firmware_information"
    COMMUNICATION_PROTOCOL = "communication_protocol"
    GENERAL_ENGINEERING_RULE = "general_engineering_rule"
    OTHER = "other"


class ConfidenceLevel(StrEnum):
    """Human-readable confidence categories."""

    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class EvidenceType(StrEnum):
    """Evidence location or representation type."""

    TEXT = "text"
    TABLE = "table"
    IMAGE = "image"
    DIAGRAM = "diagram"
    DRAWING = "drawing"
    METADATA = "metadata"
    SPREADSHEET_CELL = "spreadsheet_cell"
    ARCHIVE_MEMBER = "archive_member"
    MANUAL_REFERENCE = "manual_reference"


class ReviewStatus(StrEnum):
    """Human-review state for extracted knowledge."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    IN_REVIEW = "in_review"
    CHANGES_REQUESTED = "changes_requested"
    APPROVED = "approved"
    REJECTED = "rejected"


class ReviewDecision(StrEnum):
    """Decision produced by a reviewer."""

    APPROVE = "approve"
    REJECT = "reject"
    REQUEST_CHANGES = "request_changes"


class DuplicateMatchType(StrEnum):
    """Nature of a detected duplicate."""

    NONE = "none"
    EXACT_FILE = "exact_file"
    EXACT_CONTENT = "exact_content"
    SAME_DOCUMENT_REVISION = "same_document_revision"
    OLDER_REVISION = "older_revision"
    NEWER_REVISION = "newer_revision"
    NEAR_DUPLICATE = "near_duplicate"
    POSSIBLE_DUPLICATE = "possible_duplicate"


class KnowledgePublicationStatus(StrEnum):
    """Repository publication status."""

    NOT_READY = "not_ready"
    READY = "ready"
    PUBLISHING = "publishing"
    PUBLISHED = "published"
    WITHDRAWN = "withdrawn"
    FAILED = "failed"


class SafetySeverity(StrEnum):
    """Severity of safety-related engineering information."""

    INFORMATION = "information"
    NOTICE = "notice"
    CAUTION = "caution"
    WARNING = "warning"
    DANGER = "danger"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Shared base models
# ---------------------------------------------------------------------------


class IngestionBaseModel(BaseModel):
    """Base configuration shared by ingestion models."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class TimestampedModel(IngestionBaseModel):
    """Base model containing creation and update timestamps."""

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def validate_timestamps(self) -> "TimestampedModel":
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot be earlier than created_at")
        return self


# ---------------------------------------------------------------------------
# Document source and upload models
# ---------------------------------------------------------------------------


class DocumentSource(IngestionBaseModel):
    """Describes where an ingested document originated."""

    source_name: str = Field(min_length=1, max_length=255)
    source_uri: str | None = Field(default=None, max_length=2_048)
    supplier: str | None = Field(default=None, max_length=255)
    uploaded_by: str | None = Field(default=None, max_length=255)
    organisation_id: UUID | None = None
    notes: str | None = Field(default=None, max_length=2_000)


class DocumentUpload(IngestionBaseModel):
    """Validated description of an uploaded source document."""

    document_id: UUID = Field(default_factory=uuid4)
    filename: str = Field(min_length=1, max_length=512)
    document_format: DocumentFormat
    media_type: str | None = Field(default=None, max_length=255)
    size_bytes: int = Field(ge=0)
    storage_key: str = Field(min_length=1, max_length=1_024)
    checksum_sha256: str
    source: DocumentSource
    uploaded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    original_filename: str | None = Field(default=None, max_length=512)
    password_protected: bool = False
    archive_member_count: int | None = Field(default=None, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("filename", "original_filename")
    @classmethod
    def validate_filename(cls, value: str | None) -> str | None:
        if value is None:
            return None

        normalised = value.replace("\\", "/")
        safe_name = PurePosixPath(normalised).name

        if safe_name in {"", ".", ".."}:
            raise ValueError("filename must contain a valid file name")

        return safe_name

    @field_validator("checksum_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        normalised = value.lower().strip()

        if len(normalised) != 64:
            raise ValueError("checksum_sha256 must contain 64 hexadecimal characters")

        try:
            int(normalised, 16)
        except ValueError as exc:
            raise ValueError(
                "checksum_sha256 must contain only hexadecimal characters"
            ) from exc

        return normalised

    @staticmethod
    def calculate_sha256(content: bytes) -> str:
        """Calculate a SHA-256 checksum for document content."""

        return hashlib.sha256(content).hexdigest()


# ---------------------------------------------------------------------------
# Parsed-document models
# ---------------------------------------------------------------------------


class BoundingBox(IngestionBaseModel):
    """Normalised or absolute coordinates for located document content."""

    x: float = Field(ge=0)
    y: float = Field(ge=0)
    width: float = Field(gt=0)
    height: float = Field(gt=0)
    page_width: float | None = Field(default=None, gt=0)
    page_height: float | None = Field(default=None, gt=0)


class SpreadsheetCellRange(IngestionBaseModel):
    """Spreadsheet evidence location."""

    sheet_name: str = Field(min_length=1, max_length=255)
    start_cell: str = Field(min_length=2, max_length=32)
    end_cell: str | None = Field(default=None, min_length=2, max_length=32)


class ParsedTable(IngestionBaseModel):
    """Structured table extracted from a source document."""

    headers: list[str] = Field(default_factory=list)
    rows: list[list[str]] = Field(default_factory=list)
    caption: str | None = Field(default=None, max_length=1_000)
    column_count: int = Field(default=0, ge=0)
    row_count: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def derive_table_dimensions(self) -> "ParsedTable":
        derived_column_count = max(
            [len(self.headers), *(len(row) for row in self.rows)],
            default=0,
        )

        if self.column_count == 0:
            object.__setattr__(self, "column_count", derived_column_count)

        if self.row_count == 0:
            object.__setattr__(self, "row_count", len(self.rows))

        if self.column_count < derived_column_count:
            raise ValueError(
                "column_count cannot be smaller than the extracted table width"
            )

        if self.row_count < len(self.rows):
            raise ValueError(
                "row_count cannot be smaller than the number of extracted rows"
            )

        return self


class ParsedContentBlock(IngestionBaseModel):
    """A single logical content block extracted from a document."""

    block_id: UUID = Field(default_factory=uuid4)
    block_type: ContentBlockType
    text: str = ""
    page_number: int | None = Field(default=None, ge=1)
    section_path: list[str] = Field(default_factory=list)
    sequence_number: int = Field(ge=0)
    bounding_box: BoundingBox | None = None
    spreadsheet_range: SpreadsheetCellRange | None = None
    table: ParsedTable | None = None
    extraction_method: ExtractionMethod = ExtractionMethod.UNKNOWN
    extraction_confidence: float = Field(default=1.0, ge=0, le=1)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_block_content(self) -> "ParsedContentBlock":
        if not self.text and self.table is None:
            if self.block_type not in {
                ContentBlockType.IMAGE,
                ContentBlockType.DIAGRAM,
                ContentBlockType.DRAWING,
                ContentBlockType.PAGE_NUMBER,
            }:
                raise ValueError(
                    "content block must contain text or structured table data"
                )

        return self


class ParsedPage(IngestionBaseModel):
    """Content extracted from one page or page-equivalent unit."""

    page_number: int = Field(ge=1)
    width: float | None = Field(default=None, gt=0)
    height: float | None = Field(default=None, gt=0)
    text: str = ""
    blocks: list[ParsedContentBlock] = Field(default_factory=list)
    extraction_method: ExtractionMethod = ExtractionMethod.UNKNOWN
    extraction_confidence: float = Field(default=1.0, ge=0, le=1)
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_block_page_numbers(self) -> "ParsedPage":
        for block in self.blocks:
            if block.page_number is None:
                object.__setattr__(block, "page_number", self.page_number)
            elif block.page_number != self.page_number:
                raise ValueError(
                    "block page_number must match its containing ParsedPage"
                )

        return self


class ParsedDocument(TimestampedModel):
    """Complete parsed representation of an uploaded document."""

    parsed_document_id: UUID = Field(default_factory=uuid4)
    document_id: UUID
    title: str | None = Field(default=None, max_length=1_000)
    pages: list[ParsedPage] = Field(default_factory=list)
    full_text: str = ""
    page_count: int = Field(default=0, ge=0)
    character_count: int = Field(default=0, ge=0)
    word_count: int = Field(default=0, ge=0)
    parser_name: str = Field(min_length=1, max_length=255)
    parser_version: str = Field(min_length=1, max_length=100)
    extraction_method: ExtractionMethod
    extraction_confidence: float = Field(default=1.0, ge=0, le=1)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    parser_metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def derive_document_statistics(self) -> "ParsedDocument":
        if not self.full_text and self.pages:
            object.__setattr__(
                self,
                "full_text",
                "\n\n".join(
                    page.text for page in self.pages if page.text
                ),
            )

        if self.page_count == 0:
            object.__setattr__(self, "page_count", len(self.pages))

        if self.page_count < len(self.pages):
            raise ValueError(
                "page_count cannot be smaller than the parsed page collection"
            )

        if self.character_count == 0:
            object.__setattr__(self, "character_count", len(self.full_text))

        if self.word_count == 0:
            object.__setattr__(self, "word_count", len(self.full_text.split()))

        page_numbers = [page.page_number for page in self.pages]

        if len(page_numbers) != len(set(page_numbers)):
            raise ValueError("parsed pages must have unique page numbers")

        return self


# ---------------------------------------------------------------------------
# Metadata models
# ---------------------------------------------------------------------------


class ProductReference(IngestionBaseModel):
    """Manufacturer and product identity extracted from a document."""

    manufacturer: str | None = Field(default=None, max_length=255)
    brand: str | None = Field(default=None, max_length=255)
    product_family: str | None = Field(default=None, max_length=255)
    product_series: str | None = Field(default=None, max_length=255)
    model_numbers: list[str] = Field(default_factory=list)
    part_numbers: list[str] = Field(default_factory=list)
    equipment_categories: list[EquipmentCategory] = Field(default_factory=list)


class DocumentRevision(IngestionBaseModel):
    """Revision information for a technical document."""

    revision: str | None = Field(default=None, max_length=100)
    edition: str | None = Field(default=None, max_length=100)
    publication_date: date | None = None
    effective_date: date | None = None
    supersedes_revision: str | None = Field(default=None, max_length=100)
    document_number: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def validate_revision_dates(self) -> "DocumentRevision":
        if (
            self.publication_date is not None
            and self.effective_date is not None
            and self.effective_date < self.publication_date
        ):
            raise ValueError(
                "effective_date cannot be earlier than publication_date"
            )

        return self


class ExtractedDocumentMetadata(TimestampedModel):
    """Structured metadata inferred from a parsed engineering document."""

    metadata_id: UUID = Field(default_factory=uuid4)
    document_id: UUID
    title: str | None = Field(default=None, max_length=1_000)
    document_type: DocumentType = DocumentType.UNKNOWN
    language: DocumentLanguage = DocumentLanguage.UNKNOWN
    revision: DocumentRevision = Field(default_factory=DocumentRevision)
    product_reference: ProductReference = Field(default_factory=ProductReference)
    authors: list[str] = Field(default_factory=list)
    publisher: str | None = Field(default=None, max_length=255)
    applicable_industries: list[str] = Field(default_factory=list)
    applicable_regions: list[str] = Field(default_factory=list)
    standards_referenced: list[str] = Field(default_factory=list)
    hazardous_area_certifications: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    metadata_confidence: float = Field(default=0.0, ge=0, le=1)
    field_confidences: dict[str, float] = Field(default_factory=dict)
    source_block_ids: list[UUID] = Field(default_factory=list)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("field_confidences")
    @classmethod
    def validate_field_confidences(
        cls,
        values: dict[str, float],
    ) -> dict[str, float]:
        invalid = {
            field_name: confidence
            for field_name, confidence in values.items()
            if confidence < 0 or confidence > 1
        }

        if invalid:
            raise ValueError(
                "all field confidence values must be between 0 and 1"
            )

        return values


# ---------------------------------------------------------------------------
# Evidence models
# ---------------------------------------------------------------------------


class EvidenceLocation(IngestionBaseModel):
    """Precise location of supporting evidence within a source document."""

    page_number: int | None = Field(default=None, ge=1)
    section: str | None = Field(default=None, max_length=1_000)
    subsection: str | None = Field(default=None, max_length=1_000)
    paragraph_number: int | None = Field(default=None, ge=1)
    block_id: UUID | None = None
    bounding_box: BoundingBox | None = None
    spreadsheet_range: SpreadsheetCellRange | None = None
    archive_member_path: str | None = Field(default=None, max_length=1_024)


class EvidenceReference(IngestionBaseModel):
    """Traceable evidence supporting an extracted engineering fact."""

    evidence_id: UUID = Field(default_factory=uuid4)
    document_id: UUID
    evidence_type: EvidenceType
    location: EvidenceLocation
    quoted_text: str | None = Field(default=None, max_length=10_000)
    context_before: str | None = Field(default=None, max_length=2_000)
    context_after: str | None = Field(default=None, max_length=2_000)
    source_title: str | None = Field(default=None, max_length=1_000)
    source_revision: str | None = Field(default=None, max_length=100)
    source_document_number: str | None = Field(default=None, max_length=255)
    extraction_confidence: float = Field(default=1.0, ge=0, le=1)
    verified: bool = False
    verification_notes: str | None = Field(default=None, max_length=2_000)

    @model_validator(mode="after")
    def validate_evidence_content(self) -> "EvidenceReference":
        has_location = any(
            (
                self.location.page_number is not None,
                self.location.block_id is not None,
                self.location.bounding_box is not None,
                self.location.spreadsheet_range is not None,
                self.location.archive_member_path is not None,
                self.location.section is not None,
            )
        )

        if not has_location:
            raise ValueError(
                "evidence must include at least one source location"
            )

        return self


# ---------------------------------------------------------------------------
# Engineering knowledge extraction models
# ---------------------------------------------------------------------------


class EngineeringValue(IngestionBaseModel):
    """Engineering value with optional units and operating context."""

    value: str | int | float | bool
    unit: str | None = Field(default=None, max_length=100)
    minimum: float | None = None
    maximum: float | None = None
    nominal: float | None = None
    tolerance: float | None = None
    conditions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_range(self) -> "EngineeringValue":
        if (
            self.minimum is not None
            and self.maximum is not None
            and self.minimum > self.maximum
        ):
            raise ValueError("minimum cannot be greater than maximum")

        if self.nominal is not None:
            if self.minimum is not None and self.nominal < self.minimum:
                raise ValueError("nominal cannot be smaller than minimum")

            if self.maximum is not None and self.nominal > self.maximum:
                raise ValueError("nominal cannot be greater than maximum")

        return self


class SafetyInformation(IngestionBaseModel):
    """Safety context linked to an engineering fact."""

    severity: SafetySeverity
    hazard: str = Field(min_length=1, max_length=2_000)
    consequence: str | None = Field(default=None, max_length=2_000)
    required_actions: list[str] = Field(default_factory=list)
    prohibited_actions: list[str] = Field(default_factory=list)
    required_ppe: list[str] = Field(default_factory=list)
    isolation_requirements: list[str] = Field(default_factory=list)
    permit_requirements: list[str] = Field(default_factory=list)
    escalation_required: bool = False


class ExtractedEngineeringFact(TimestampedModel):
    """A structured engineering fact extracted from source documentation."""

    fact_id: UUID = Field(default_factory=uuid4)
    document_id: UUID
    fact_type: EngineeringFactType
    title: str = Field(min_length=1, max_length=1_000)
    statement: str = Field(min_length=1, max_length=10_000)
    value: EngineeringValue | None = None
    manufacturer: str | None = Field(default=None, max_length=255)
    product_family: str | None = Field(default=None, max_length=255)
    product_series: str | None = Field(default=None, max_length=255)
    model_numbers: list[str] = Field(default_factory=list)
    equipment_categories: list[EquipmentCategory] = Field(default_factory=list)
    operating_conditions: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    required_tools: list[str] = Field(default_factory=list)
    required_parts: list[str] = Field(default_factory=list)
    safety_information: list[SafetyInformation] = Field(default_factory=list)
    standards_referenced: list[str] = Field(default_factory=list)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    extraction_confidence: float = Field(default=0.0, ge=0, le=1)
    confidence_level: ConfidenceLevel = ConfidenceLevel.VERY_LOW
    requires_human_review: bool = True
    review_status: ReviewStatus = ReviewStatus.PENDING
    tags: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def derive_confidence_level(self) -> "ExtractedEngineeringFact":
        confidence = self.extraction_confidence

        if confidence < 0.2:
            object.__setattr__(self, "confidence_level", ConfidenceLevel.VERY_LOW)
        elif confidence < 0.4:
            object.__setattr__(self, "confidence_level", ConfidenceLevel.LOW)
        elif confidence < 0.7:
            object.__setattr__(self, "confidence_level", ConfidenceLevel.MEDIUM)
        elif confidence < 0.9:
            object.__setattr__(self, "confidence_level", ConfidenceLevel.HIGH)
        else:
            object.__setattr__(self, "confidence_level", ConfidenceLevel.VERY_HIGH)

        if not self.requires_human_review:
            object.__setattr__(self, "review_status", ReviewStatus.NOT_REQUIRED)
        elif self.review_status == ReviewStatus.NOT_REQUIRED:
            object.__setattr__(self, "review_status", ReviewStatus.PENDING)

        return self


class EngineeringExtractionResult(TimestampedModel):
    """Result returned by an engineering extraction component."""

    extraction_id: UUID = Field(default_factory=uuid4)
    document_id: UUID
    facts: list[ExtractedEngineeringFact] = Field(default_factory=list)
    extraction_engine: str = Field(min_length=1, max_length=255)
    extraction_engine_version: str = Field(min_length=1, max_length=100)
    extraction_confidence: float = Field(default=0.0, ge=0, le=1)
    processed_block_count: int = Field(default=0, ge=0)
    skipped_block_count: int = Field(default=0, ge=0)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    extraction_metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def fact_count(self) -> int:
        """Return the total number of extracted engineering facts."""

        return len(self.facts)

    @property
    def safety_fact_count(self) -> int:
        """Return the number of safety-related engineering facts."""

        return sum(
            fact.fact_type
            in {
                EngineeringFactType.SAFETY_WARNING,
                EngineeringFactType.SAFETY_REQUIREMENT,
            }
            or bool(fact.safety_information)
            for fact in self.facts
        )


# ---------------------------------------------------------------------------
# Duplicate detection models
# ---------------------------------------------------------------------------


class DuplicateCandidate(IngestionBaseModel):
    """Potential duplicate document found in the repository."""

    candidate_document_id: UUID
    match_type: DuplicateMatchType
    similarity_score: float = Field(ge=0, le=1)
    filename: str | None = Field(default=None, max_length=512)
    title: str | None = Field(default=None, max_length=1_000)
    revision: str | None = Field(default=None, max_length=100)
    checksum_sha256: str | None = None
    matching_reasons: list[str] = Field(default_factory=list)

    @field_validator("checksum_sha256")
    @classmethod
    def validate_optional_sha256(cls, value: str | None) -> str | None:
        if value is None:
            return None

        return DocumentUpload.validate_sha256(value)


class DuplicateDetectionResult(TimestampedModel):
    """Result of checking an uploaded document for duplicates."""

    detection_id: UUID = Field(default_factory=uuid4)
    document_id: UUID
    match_type: DuplicateMatchType = DuplicateMatchType.NONE
    is_duplicate: bool = False
    highest_similarity_score: float = Field(default=0.0, ge=0, le=1)
    candidates: list[DuplicateCandidate] = Field(default_factory=list)
    recommended_action: str | None = Field(default=None, max_length=2_000)

    @model_validator(mode="after")
    def derive_duplicate_state(self) -> "DuplicateDetectionResult":
        if self.candidates:
            candidate_score = max(
                candidate.similarity_score for candidate in self.candidates
            )
            object.__setattr__(
                self,
                "highest_similarity_score",
                max(
                    self.highest_similarity_score,
                    candidate_score,
                ),
            )

            strongest_candidate = max(
                self.candidates,
                key=lambda candidate: candidate.similarity_score,
            )

            if self.match_type == DuplicateMatchType.NONE:
                object.__setattr__(self, "match_type", strongest_candidate.match_type)

        object.__setattr__(
            self,
            "is_duplicate",
            self.match_type
            in {
                DuplicateMatchType.EXACT_FILE,
                DuplicateMatchType.EXACT_CONTENT,
                DuplicateMatchType.SAME_DOCUMENT_REVISION,
            },
        )

        return self


# ---------------------------------------------------------------------------
# Human review models
# ---------------------------------------------------------------------------


class ReviewComment(IngestionBaseModel):
    """Comment recorded during human engineering review."""

    comment_id: UUID = Field(default_factory=uuid4)
    author_id: str = Field(min_length=1, max_length=255)
    comment: str = Field(min_length=1, max_length=5_000)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    resolved: bool = False
    resolved_by: str | None = Field(default=None, max_length=255)
    resolved_at: datetime | None = None

    @model_validator(mode="after")
    def validate_resolution(self) -> "ReviewComment":
        if self.resolved and self.resolved_at is None:
            object.__setattr__(self, "resolved_at", datetime.now(UTC))

        if not self.resolved:
            object.__setattr__(self, "resolved_by", None)
            object.__setattr__(self, "resolved_at", None)

        return self


class FactReview(IngestionBaseModel):
    """Review outcome for one extracted engineering fact."""

    fact_id: UUID
    status: ReviewStatus = ReviewStatus.PENDING
    decision: ReviewDecision | None = None
    reviewer_id: str | None = Field(default=None, max_length=255)
    reviewed_at: datetime | None = None
    comments: list[ReviewComment] = Field(default_factory=list)
    corrected_title: str | None = Field(default=None, max_length=1_000)
    corrected_statement: str | None = Field(default=None, max_length=10_000)
    corrected_attributes: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_review_decision(self) -> "FactReview":
        completed_statuses = {
            ReviewStatus.APPROVED,
            ReviewStatus.REJECTED,
            ReviewStatus.CHANGES_REQUESTED,
        }

        if self.status in completed_statuses:
            if self.decision is None:
                raise ValueError(
                    "a completed review must include a review decision"
                )

            if self.reviewer_id is None:
                raise ValueError(
                    "a completed review must include reviewer_id"
                )

            if self.reviewed_at is None:
                object.__setattr__(self, "reviewed_at", datetime.now(UTC))

        return self


class DocumentReview(TimestampedModel):
    """Human review workflow state for an ingested document."""

    review_id: UUID = Field(default_factory=uuid4)
    document_id: UUID
    status: ReviewStatus = ReviewStatus.PENDING
    assigned_reviewer_ids: list[str] = Field(default_factory=list)
    fact_reviews: list[FactReview] = Field(default_factory=list)
    general_comments: list[ReviewComment] = Field(default_factory=list)
    required_approvals: int = Field(default=1, ge=1)
    approval_count: int = Field(default=0, ge=0)
    rejection_reason: str | None = Field(default=None, max_length=5_000)

    @model_validator(mode="after")
    def validate_review_counts(self) -> "DocumentReview":
        if self.approval_count > len(self.assigned_reviewer_ids):
            raise ValueError(
                "approval_count cannot exceed the number of assigned reviewers"
            )

        if (
            self.status == ReviewStatus.APPROVED
            and self.approval_count < self.required_approvals
        ):
            raise ValueError(
                "approved review must meet the required approval count"
            )

        if self.status == ReviewStatus.REJECTED and not self.rejection_reason:
            raise ValueError(
                "rejected document review must include a rejection reason"
            )

        return self


# ---------------------------------------------------------------------------
# Publication and pipeline models
# ---------------------------------------------------------------------------


class PublicationRecord(TimestampedModel):
    """Repository publication state for extracted engineering knowledge."""

    publication_id: UUID = Field(default_factory=uuid4)
    document_id: UUID
    status: KnowledgePublicationStatus = KnowledgePublicationStatus.NOT_READY
    published_fact_ids: list[UUID] = Field(default_factory=list)
    repository_version: str | None = Field(default=None, max_length=100)
    published_by: str | None = Field(default=None, max_length=255)
    published_at: datetime | None = None
    withdrawn_at: datetime | None = None
    withdrawal_reason: str | None = Field(default=None, max_length=5_000)
    errors: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_publication_state(self) -> "PublicationRecord":
        if self.status == KnowledgePublicationStatus.PUBLISHED:
            if not self.published_fact_ids:
                raise ValueError(
                    "published record must include at least one fact"
                )

            if self.published_at is None:
                object.__setattr__(self, "published_at", datetime.now(UTC))

        if self.status == KnowledgePublicationStatus.WITHDRAWN:
            if self.withdrawn_at is None:
                object.__setattr__(self, "withdrawn_at", datetime.now(UTC))

            if not self.withdrawal_reason:
                raise ValueError(
                    "withdrawn publication must include a reason"
                )

        return self


class IngestionError(IngestionBaseModel):
    """Structured error recorded during ingestion."""

    error_id: UUID = Field(default_factory=uuid4)
    stage: IngestionStatus
    code: str = Field(min_length=1, max_length=100)
    message: str = Field(min_length=1, max_length=5_000)
    recoverable: bool = False
    technical_details: str | None = Field(default=None, max_length=10_000)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class IngestionEvent(IngestionBaseModel):
    """Auditable state transition in the ingestion pipeline."""

    event_id: UUID = Field(default_factory=uuid4)
    status: IngestionStatus
    message: str | None = Field(default=None, max_length=2_000)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    actor_id: str | None = Field(default=None, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IngestionJob(TimestampedModel):
    """Top-level state container for one document-ingestion operation."""

    job_id: UUID = Field(default_factory=uuid4)
    document: DocumentUpload
    status: IngestionStatus = IngestionStatus.RECEIVED
    parsed_document: ParsedDocument | None = None
    extracted_metadata: ExtractedDocumentMetadata | None = None
    extraction_result: EngineeringExtractionResult | None = None
    duplicate_result: DuplicateDetectionResult | None = None
    review: DocumentReview | None = None
    publication: PublicationRecord | None = None
    progress_percent: int = Field(default=0, ge=0, le=100)
    current_stage_message: str | None = Field(default=None, max_length=2_000)
    events: list[IngestionEvent] = Field(default_factory=list)
    errors: list[IngestionError] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_document_relationships(self) -> "IngestionJob":
        document_id = self.document.document_id

        related_objects = (
            self.parsed_document,
            self.extracted_metadata,
            self.extraction_result,
            self.duplicate_result,
            self.review,
            self.publication,
        )

        for related_object in related_objects:
            if (
                related_object is not None
                and related_object.document_id != document_id
            ):
                raise ValueError(
                    "all ingestion job objects must reference the same document_id"
                )

        if self.status == IngestionStatus.PUBLISHED:
            if (
                self.publication is None
                or self.publication.status
                != KnowledgePublicationStatus.PUBLISHED
            ):
                raise ValueError(
                    "published ingestion job requires a published "
                    "PublicationRecord"
                )

            object.__setattr__(self, "progress_percent", 100)

        if self.status == IngestionStatus.FAILED and not self.errors:
            raise ValueError(
                "failed ingestion job must contain at least one error"
            )

        return self

    def transition_to(
        self,
        status: IngestionStatus,
        *,
        message: str | None = None,
        actor_id: str | None = None,
        progress_percent: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Transition the ingestion job to a new status and record an audit event.
        """

        self.status = status
        self.current_stage_message = message
        self.updated_at = datetime.now(UTC)

        if progress_percent is not None:
            if progress_percent < self.progress_percent:
                raise ValueError(
                    "ingestion progress cannot move backwards"
                )

            self.progress_percent = progress_percent

        self.events.append(
            IngestionEvent(
                status=status,
                message=message,
                actor_id=actor_id,
                metadata=metadata or {},
            )
        )

    def add_error(
        self,
        *,
        stage: IngestionStatus,
        code: str,
        message: str,
        recoverable: bool = False,
        technical_details: str | None = None,
    ) -> IngestionError:
        """Add a structured error to the ingestion job."""

        error = IngestionError(
            stage=stage,
            code=code,
            message=message,
            recoverable=recoverable,
            technical_details=technical_details,
        )

        self.errors.append(error)
        self.updated_at = datetime.now(UTC)

        if not recoverable:
            self.transition_to(
                IngestionStatus.FAILED,
                message=message,
                progress_percent=self.progress_percent,
                metadata={"error_code": code},
            )

        return error


__all__ = [
    "BoundingBox",
    "ConfidenceLevel",
    "ContentBlockType",
    "DocumentFormat",
    "DocumentLanguage",
    "DocumentReview",
    "DocumentRevision",
    "DocumentSource",
    "DocumentType",
    "DocumentUpload",
    "DuplicateCandidate",
    "DuplicateDetectionResult",
    "DuplicateMatchType",
    "EngineeringExtractionResult",
    "EngineeringFactType",
    "EngineeringValue",
    "EquipmentCategory",
    "EvidenceLocation",
    "EvidenceReference",
    "EvidenceType",
    "ExtractedDocumentMetadata",
    "ExtractedEngineeringFact",
    "ExtractionMethod",
    "FactReview",
    "IngestionError",
    "IngestionEvent",
    "IngestionJob",
    "IngestionStatus",
    "KnowledgePublicationStatus",
    "ParsedContentBlock",
    "ParsedDocument",
    "ParsedPage",
    "ParsedTable",
    "ProductReference",
    "PublicationRecord",
    "ReviewComment",
    "ReviewDecision",
    "ReviewStatus",
    "SafetyInformation",
    "SafetySeverity",
    "SpreadsheetCellRange",
]