"""
Deterministic engineering knowledge indexing for Engineer4Me.

This module converts extracted engineering facts and document metadata into
normalised, searchable index records.

The index is intentionally persistence-independent. It can be used by:

- an in-memory repository;
- PostgreSQL;
- Elasticsearch or OpenSearch;
- a future vector database;
- API search services;
- document publication workflows.

Phase 5.5.1 provides:

- deterministic keyword extraction;
- manufacturer, product, model, and equipment indexing;
- engineering fact-type indexing;
- safety-priority indexing;
- standards and protocol indexing;
- engineering value and unit indexing;
- evidence and document traceability;
- confidence and review indexing;
- lexical search scoring;
- structured filtering;
- stable deduplication.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.ingestion.document_models import (
    ConfidenceLevel,
    DocumentType,
    EngineeringFactType,
    EquipmentCategory,
    EvidenceReference,
    ExtractedDocumentMetadata,
    ExtractedEngineeringFact,
    ReviewStatus,
    SafetySeverity,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


_TOKEN_PATTERN = re.compile(
    r"""
    [A-Za-z0-9]
    (?:[A-Za-z0-9._:/+\-]*[A-Za-z0-9])?
    """,
    re.VERBOSE,
)

_WHITESPACE_PATTERN = re.compile(r"\s+")
_NON_SEARCHABLE_PATTERN = re.compile(r"[^a-z0-9._:/+\-\s]")

_DEFAULT_STOP_WORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "been",
        "being",
        "by",
        "can",
        "could",
        "do",
        "does",
        "for",
        "from",
        "has",
        "have",
        "if",
        "in",
        "into",
        "is",
        "it",
        "its",
        "may",
        "must",
        "not",
        "of",
        "on",
        "or",
        "shall",
        "should",
        "that",
        "the",
        "then",
        "this",
        "to",
        "use",
        "used",
        "using",
        "was",
        "were",
        "when",
        "where",
        "which",
        "with",
    }
)

_HIGH_PRIORITY_FACT_TYPES = frozenset(
    {
        EngineeringFactType.SAFETY_WARNING,
        EngineeringFactType.SAFETY_REQUIREMENT,
        EngineeringFactType.FAULT_CODE,
        EngineeringFactType.CORRECTIVE_ACTION,
        EngineeringFactType.TROUBLESHOOTING_STEP,
        EngineeringFactType.OPERATING_LIMIT,
        EngineeringFactType.ENVIRONMENTAL_LIMIT,
    }
)

_SAFETY_FACT_TYPES = frozenset(
    {
        EngineeringFactType.SAFETY_WARNING,
        EngineeringFactType.SAFETY_REQUIREMENT,
    }
)

_FAULT_FACT_TYPES = frozenset(
    {
        EngineeringFactType.FAULT_CODE,
        EngineeringFactType.FAILURE_MODE,
        EngineeringFactType.LIKELY_CAUSE,
        EngineeringFactType.CORRECTIVE_ACTION,
        EngineeringFactType.TROUBLESHOOTING_STEP,
        EngineeringFactType.VERIFICATION_STEP,
    }
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class KnowledgeIndexStatus(StrEnum):
    """Lifecycle state of one knowledge index record."""

    ACTIVE = "active"
    PENDING_REVIEW = "pending_review"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"


class SearchMatchType(StrEnum):
    """Highest-value match that contributed to a search result."""

    EXACT_IDENTIFIER = "exact_identifier"
    EXACT_PHRASE = "exact_phrase"
    FIELD_MATCH = "field_match"
    TOKEN_MATCH = "token_match"
    FILTER_MATCH = "filter_match"


# ---------------------------------------------------------------------------
# Shared models
# ---------------------------------------------------------------------------


class KnowledgeIndexBaseModel(BaseModel):
    """Base configuration for knowledge-index models."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )


class IndexedEngineeringValue(KnowledgeIndexBaseModel):
    """Searchable representation of an extracted engineering value."""

    raw_value: str
    unit: str | None = None
    minimum: float | None = None
    maximum: float | None = None
    nominal: float | None = None
    tolerance: float | None = None
    conditions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_range(self) -> "IndexedEngineeringValue":
        if (
            self.minimum is not None
            and self.maximum is not None
            and self.minimum > self.maximum
        ):
            raise ValueError("minimum cannot be greater than maximum")

        return self


class IndexedEvidence(KnowledgeIndexBaseModel):
    """Compact traceable evidence stored with a search index record."""

    evidence_id: UUID
    document_id: UUID
    page_number: int | None = Field(default=None, ge=1)
    section: str | None = None
    block_id: UUID | None = None
    quoted_text: str | None = None
    verified: bool = False
    extraction_confidence: float = Field(ge=0.0, le=1.0)


class KnowledgeIndexRecord(KnowledgeIndexBaseModel):
    """Searchable index representation of one extracted engineering fact."""

    index_id: UUID = Field(default_factory=uuid4)
    fact_id: UUID
    document_id: UUID
    metadata_id: UUID | None = None

    title: str = Field(min_length=1, max_length=1_000)
    statement: str = Field(min_length=1, max_length=10_000)
    fact_type: EngineeringFactType
    document_type: DocumentType = DocumentType.UNKNOWN

    manufacturer: str | None = Field(default=None, max_length=255)
    brand: str | None = Field(default=None, max_length=255)
    product_family: str | None = Field(default=None, max_length=255)
    product_series: str | None = Field(default=None, max_length=255)

    model_numbers: list[str] = Field(default_factory=list)
    part_numbers: list[str] = Field(default_factory=list)
    equipment_categories: list[EquipmentCategory] = Field(default_factory=list)

    standards: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    parts: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    operating_conditions: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    values: list[IndexedEngineeringValue] = Field(default_factory=list)
    evidence: list[IndexedEvidence] = Field(default_factory=list)

    safety_severities: list[SafetySeverity] = Field(default_factory=list)
    hazards: list[str] = Field(default_factory=list)
    required_ppe: list[str] = Field(default_factory=list)
    isolation_requirements: list[str] = Field(default_factory=list)
    permit_requirements: list[str] = Field(default_factory=list)
    safety_blocking: bool = False

    extraction_confidence: float = Field(ge=0.0, le=1.0)
    confidence_level: ConfidenceLevel
    requires_human_review: bool
    review_status: ReviewStatus
    status: KnowledgeIndexStatus

    searchable_text: str
    keywords: list[str] = Field(default_factory=list)
    identifiers: list[str] = Field(default_factory=list)

    source_title: str | None = Field(default=None, max_length=1_000)
    source_revision: str | None = Field(default=None, max_length=100)
    source_document_number: str | None = Field(default=None, max_length=255)

    indexed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    index_version: str = Field(default="1.0.0", max_length=100)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "model_numbers",
        "part_numbers",
        "standards",
        "protocols",
        "tools",
        "parts",
        "actions",
        "verification_steps",
        "operating_conditions",
        "prerequisites",
        "tags",
        "hazards",
        "required_ppe",
        "isolation_requirements",
        "permit_requirements",
        "keywords",
        "identifiers",
    )
    @classmethod
    def remove_blank_strings(cls, values: list[str]) -> list[str]:
        return [value for value in values if value.strip()]

    @property
    def is_safety_related(self) -> bool:
        """Return whether the record contains safety-related knowledge."""

        return (
            self.fact_type in _SAFETY_FACT_TYPES
            or bool(self.safety_severities)
            or bool(self.hazards)
        )

    @property
    def is_fault_related(self) -> bool:
        """Return whether the record supports fault finding."""

        return self.fact_type in _FAULT_FACT_TYPES

    @property
    def verified_evidence_count(self) -> int:
        """Return the number of verified evidence references."""

        return sum(item.verified for item in self.evidence)


class KnowledgeIndexBuildResult(KnowledgeIndexBaseModel):
    """Result produced when engineering facts are indexed."""

    build_id: UUID = Field(default_factory=uuid4)
    document_id: UUID
    records: list[KnowledgeIndexRecord] = Field(default_factory=list)
    indexed_fact_count: int = Field(default=0, ge=0)
    skipped_fact_count: int = Field(default=0, ge=0)
    duplicate_fact_count: int = Field(default=0, ge=0)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    index_engine: str
    index_version: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def derive_indexed_fact_count(self) -> "KnowledgeIndexBuildResult":
        if self.indexed_fact_count == 0 and self.records:
            object.__setattr__(
                self,
                "indexed_fact_count",
                len(self.records),
            )

        return self


class KnowledgeSearchFilters(KnowledgeIndexBaseModel):
    """Structured filters for knowledge-index search."""

    document_ids: list[UUID] = Field(default_factory=list)
    fact_types: list[EngineeringFactType] = Field(default_factory=list)
    document_types: list[DocumentType] = Field(default_factory=list)
    manufacturers: list[str] = Field(default_factory=list)
    brands: list[str] = Field(default_factory=list)
    product_families: list[str] = Field(default_factory=list)
    product_series: list[str] = Field(default_factory=list)
    model_numbers: list[str] = Field(default_factory=list)
    part_numbers: list[str] = Field(default_factory=list)
    equipment_categories: list[EquipmentCategory] = Field(default_factory=list)
    standards: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    safety_severities: list[SafetySeverity] = Field(default_factory=list)
    review_statuses: list[ReviewStatus] = Field(default_factory=list)
    statuses: list[KnowledgeIndexStatus] = Field(default_factory=list)

    minimum_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    verified_evidence_only: bool = False
    safety_only: bool = False
    fault_related_only: bool = False
    human_review_required: bool | None = None


class KnowledgeSearchRequest(KnowledgeIndexBaseModel):
    """Search request accepted by the deterministic knowledge index."""

    text: str | None = Field(default=None, max_length=1_000)
    filters: KnowledgeSearchFilters = Field(
        default_factory=KnowledgeSearchFilters
    )
    limit: int = Field(default=25, ge=1, le=500)
    offset: int = Field(default=0, ge=0)
    require_all_terms: bool = False


class KnowledgeSearchResult(KnowledgeIndexBaseModel):
    """Ranked search result returned from the knowledge index."""

    record: KnowledgeIndexRecord
    score: float = Field(ge=0.0)
    match_type: SearchMatchType
    matched_terms: list[str] = Field(default_factory=list)
    matched_fields: list[str] = Field(default_factory=list)


class KnowledgeSearchResponse(KnowledgeIndexBaseModel):
    """Complete response from a deterministic index search."""

    query: KnowledgeSearchRequest
    results: list[KnowledgeSearchResult] = Field(default_factory=list)
    total_matches: int = Field(default=0, ge=0)
    returned_matches: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def derive_returned_matches(self) -> "KnowledgeSearchResponse":
        object.__setattr__(
            self,
            "returned_matches",
            len(self.results),
        )
        return self


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------


def normalise_search_text(value: str) -> str:
    """Return predictable lowercase searchable text."""

    normalised = unicodedata.normalize("NFKC", value)
    normalised = normalised.casefold()
    normalised = _NON_SEARCHABLE_PATTERN.sub(" ", normalised)
    return _WHITESPACE_PATTERN.sub(" ", normalised).strip()


def normalise_identifier(value: str) -> str:
    """Normalise model, part, fault, and document identifiers."""

    return re.sub(
        r"[^a-z0-9]",
        "",
        unicodedata.normalize("NFKC", value).casefold(),
    )


def unique_strings(
    values: Iterable[str | None],
    *,
    case_sensitive: bool = False,
) -> list[str]:
    """Return stable unique non-empty strings."""

    results: list[str] = []
    seen: set[str] = set()

    for value in values:
        if value is None:
            continue

        cleaned = _WHITESPACE_PATTERN.sub(" ", value).strip()

        if not cleaned:
            continue

        key = cleaned if case_sensitive else cleaned.casefold()

        if key in seen:
            continue

        seen.add(key)
        results.append(cleaned)

    return results


def tokenise(value: str) -> list[str]:
    """Create stable search tokens while preserving technical identifiers."""

    normalised = normalise_search_text(value)
    tokens: list[str] = []

    for match in _TOKEN_PATTERN.finditer(normalised):
        token = match.group(0).strip("._:/+-")

        if not token:
            continue

        if token in _DEFAULT_STOP_WORDS:
            continue

        if len(token) == 1 and not token.isdigit():
            continue

        tokens.append(token)

    return unique_strings(tokens)


def _flatten_strings(values: Iterable[str | None]) -> str:
    return " ".join(value for value in values if value)


def _enum_values(values: Iterable[StrEnum]) -> list[str]:
    return [value.value for value in values]


def _evidence_to_index(evidence: EvidenceReference) -> IndexedEvidence:
    return IndexedEvidence(
        evidence_id=evidence.evidence_id,
        document_id=evidence.document_id,
        page_number=evidence.location.page_number,
        section=evidence.location.section,
        block_id=evidence.location.block_id,
        quoted_text=evidence.quoted_text,
        verified=evidence.verified,
        extraction_confidence=evidence.extraction_confidence,
    )


# ---------------------------------------------------------------------------
# Knowledge index builder
# ---------------------------------------------------------------------------


class EngineeringKnowledgeIndexer:
    """Build deterministic searchable records from extracted facts."""

    ENGINE_NAME = "Engineer4Me deterministic knowledge indexer"
    ENGINE_VERSION = "1.0.0"

    def build(
        self,
        facts: Sequence[ExtractedEngineeringFact],
        *,
        metadata: ExtractedDocumentMetadata | None = None,
    ) -> KnowledgeIndexBuildResult:
        """Build searchable index records for a document."""

        document_id = self._resolve_document_id(facts, metadata)
        records: list[KnowledgeIndexRecord] = []
        warnings: list[str] = []
        errors: list[str] = []
        skipped_fact_count = 0
        duplicate_fact_count = 0
        seen_fact_ids: set[UUID] = set()

        for fact in facts:
            if fact.document_id != document_id:
                errors.append(
                    "Fact "
                    f"{fact.fact_id} references document {fact.document_id}, "
                    f"but the index build is for document {document_id}."
                )
                skipped_fact_count += 1
                continue

            if fact.fact_id in seen_fact_ids:
                duplicate_fact_count += 1
                warnings.append(
                    f"Duplicate fact_id {fact.fact_id} was skipped."
                )
                continue

            seen_fact_ids.add(fact.fact_id)

            try:
                records.append(
                    self.index_fact(
                        fact,
                        metadata=metadata,
                    )
                )
            except (TypeError, ValueError) as error:
                skipped_fact_count += 1
                errors.append(
                    f"Fact {fact.fact_id} could not be indexed: {error}"
                )

        return KnowledgeIndexBuildResult(
            document_id=document_id,
            records=records,
            indexed_fact_count=len(records),
            skipped_fact_count=skipped_fact_count,
            duplicate_fact_count=duplicate_fact_count,
            warnings=warnings,
            errors=errors,
            index_engine=self.ENGINE_NAME,
            index_version=self.ENGINE_VERSION,
        )

    def index_fact(
        self,
        fact: ExtractedEngineeringFact,
        *,
        metadata: ExtractedDocumentMetadata | None = None,
    ) -> KnowledgeIndexRecord:
        """Convert one engineering fact into a searchable index record."""

        if metadata is not None and metadata.document_id != fact.document_id:
            raise ValueError(
                "metadata and engineering fact must reference the same document"
            )

        product_reference = (
            metadata.product_reference if metadata is not None else None
        )

        manufacturer = (
            fact.manufacturer
            or (
                product_reference.manufacturer
                if product_reference is not None
                else None
            )
        )

        brand = (
            product_reference.brand
            if product_reference is not None
            else None
        )

        product_family = (
            fact.product_family
            or (
                product_reference.product_family
                if product_reference is not None
                else None
            )
        )

        product_series = (
            fact.product_series
            or (
                product_reference.product_series
                if product_reference is not None
                else None
            )
        )

        model_numbers = unique_strings(
            [
                *fact.model_numbers,
                *(
                    product_reference.model_numbers
                    if product_reference is not None
                    else []
                ),
            ]
        )

        part_numbers = unique_strings(
            product_reference.part_numbers
            if product_reference is not None
            else []
        )

        equipment_categories = self._unique_enums(
            [
                *fact.equipment_categories,
                *(
                    product_reference.equipment_categories
                    if product_reference is not None
                    else []
                ),
            ]
        )

        standards = unique_strings(
            [
                *fact.standards_referenced,
                *(
                    metadata.standards_referenced
                    if metadata is not None
                    else []
                ),
                *(
                    metadata.hazardous_area_certifications
                    if metadata is not None
                    else []
                ),
            ]
        )

        protocols = unique_strings(
            self._extract_protocols(fact)
        )

        safety_severities = self._unique_enums(
            item.severity for item in fact.safety_information
        )

        hazards = unique_strings(
            item.hazard for item in fact.safety_information
        )

        required_ppe = unique_strings(
            ppe
            for item in fact.safety_information
            for ppe in item.required_ppe
        )

        isolation_requirements = unique_strings(
            requirement
            for item in fact.safety_information
            for requirement in item.isolation_requirements
        )

        permit_requirements = unique_strings(
            requirement
            for item in fact.safety_information
            for requirement in item.permit_requirements
        )

        safety_blocking = any(
            item.escalation_required
            or item.severity
            in {
                SafetySeverity.DANGER,
                SafetySeverity.CRITICAL,
            }
            for item in fact.safety_information
        )

        values = self._build_values(fact)
        evidence = [_evidence_to_index(item) for item in fact.evidence]

        source_title = metadata.title if metadata is not None else None
        source_revision = (
            metadata.revision.revision if metadata is not None else None
        )
        source_document_number = (
            metadata.revision.document_number
            if metadata is not None
            else None
        )

        document_type = (
            metadata.document_type
            if metadata is not None
            else DocumentType.UNKNOWN
        )

        status = self._derive_status(fact)

        searchable_components = [
            fact.title,
            fact.statement,
            manufacturer,
            brand,
            product_family,
            product_series,
            source_title,
            source_revision,
            source_document_number,
            fact.fact_type.value,
            document_type.value,
            *_enum_values(equipment_categories),
            *model_numbers,
            *part_numbers,
            *standards,
            *protocols,
            *fact.required_tools,
            *fact.required_parts,
            *fact.actions,
            *fact.verification_steps,
            *fact.operating_conditions,
            *fact.prerequisites,
            *fact.tags,
            *hazards,
            *required_ppe,
            *isolation_requirements,
            *permit_requirements,
            *(item.raw_value for item in values),
            *(item.unit for item in values),
            *(
                item.quoted_text
                for item in evidence
                if item.quoted_text is not None
            ),
        ]

        searchable_text = normalise_search_text(
            _flatten_strings(searchable_components)
        )

        keywords = self._build_keywords(
            searchable_text=searchable_text,
            metadata=metadata,
            fact=fact,
            standards=standards,
            protocols=protocols,
            hazards=hazards,
        )

        identifiers = self._build_identifiers(
            fact=fact,
            model_numbers=model_numbers,
            part_numbers=part_numbers,
            source_document_number=source_document_number,
        )

        return KnowledgeIndexRecord(
            fact_id=fact.fact_id,
            document_id=fact.document_id,
            metadata_id=metadata.metadata_id if metadata is not None else None,
            title=fact.title,
            statement=fact.statement,
            fact_type=fact.fact_type,
            document_type=document_type,
            manufacturer=manufacturer,
            brand=brand,
            product_family=product_family,
            product_series=product_series,
            model_numbers=model_numbers,
            part_numbers=part_numbers,
            equipment_categories=equipment_categories,
            standards=standards,
            protocols=protocols,
            tools=unique_strings(fact.required_tools),
            parts=unique_strings(fact.required_parts),
            actions=unique_strings(fact.actions),
            verification_steps=unique_strings(fact.verification_steps),
            operating_conditions=unique_strings(fact.operating_conditions),
            prerequisites=unique_strings(fact.prerequisites),
            tags=unique_strings(fact.tags),
            values=values,
            evidence=evidence,
            safety_severities=safety_severities,
            hazards=hazards,
            required_ppe=required_ppe,
            isolation_requirements=isolation_requirements,
            permit_requirements=permit_requirements,
            safety_blocking=safety_blocking,
            extraction_confidence=fact.extraction_confidence,
            confidence_level=fact.confidence_level,
            requires_human_review=fact.requires_human_review,
            review_status=fact.review_status,
            status=status,
            searchable_text=searchable_text,
            keywords=keywords,
            identifiers=identifiers,
            source_title=source_title,
            source_revision=source_revision,
            source_document_number=source_document_number,
            index_version=self.ENGINE_VERSION,
            attributes={
                "is_safety_related": (
                    fact.fact_type in _SAFETY_FACT_TYPES
                    or bool(fact.safety_information)
                ),
                "is_fault_related": fact.fact_type in _FAULT_FACT_TYPES,
                "high_priority_fact": fact.fact_type in _HIGH_PRIORITY_FACT_TYPES,
                "verified_evidence_count": sum(
                    item.verified for item in fact.evidence
                ),
            },
        )

    @staticmethod
    def _resolve_document_id(
        facts: Sequence[ExtractedEngineeringFact],
        metadata: ExtractedDocumentMetadata | None,
    ) -> UUID:
        if metadata is not None:
            return metadata.document_id

        if not facts:
            raise ValueError(
                "metadata or at least one engineering fact is required"
            )

        return facts[0].document_id

    @staticmethod
    def _unique_enums(values: Iterable[Any]) -> list[Any]:
        results: list[Any] = []
        seen: set[Any] = set()

        for value in values:
            if value in seen:
                continue

            seen.add(value)
            results.append(value)

        return results

    @staticmethod
    def _build_values(
        fact: ExtractedEngineeringFact,
    ) -> list[IndexedEngineeringValue]:
        if fact.value is None:
            return []

        return [
            IndexedEngineeringValue(
                raw_value=str(fact.value.value),
                unit=fact.value.unit,
                minimum=fact.value.minimum,
                maximum=fact.value.maximum,
                nominal=fact.value.nominal,
                tolerance=fact.value.tolerance,
                conditions=unique_strings(fact.value.conditions),
            )
        ]

    @staticmethod
    def _extract_protocols(
        fact: ExtractedEngineeringFact,
    ) -> list[str]:
        protocol_values: list[str] = []

        if fact.fact_type == EngineeringFactType.COMMUNICATION_PROTOCOL:
            protocol_values.extend(
                [
                    fact.title,
                    fact.statement,
                    *fact.tags,
                ]
            )

        attribute_protocols = fact.attributes.get("protocols")

        if isinstance(attribute_protocols, str):
            protocol_values.append(attribute_protocols)
        elif isinstance(attribute_protocols, list):
            protocol_values.extend(
                str(value) for value in attribute_protocols
            )

        known_protocols = (
            "hart",
            "foundation fieldbus",
            "profibus",
            "profinet",
            "modbus",
            "ethernet/ip",
            "ethercat",
            "canopen",
            "deviceNet",
            "io-link",
            "opc ua",
            "mqtt",
            "iec 61850",
        )

        source_text = normalise_search_text(
            _flatten_strings(
                [
                    fact.title,
                    fact.statement,
                    *fact.tags,
                    *protocol_values,
                ]
            )
        )

        for protocol in known_protocols:
            if normalise_search_text(protocol) in source_text:
                protocol_values.append(protocol)

        return unique_strings(protocol_values)

    @staticmethod
    def _derive_status(
        fact: ExtractedEngineeringFact,
    ) -> KnowledgeIndexStatus:
        if fact.review_status == ReviewStatus.REJECTED:
            return KnowledgeIndexStatus.REJECTED

        if fact.requires_human_review:
            return KnowledgeIndexStatus.PENDING_REVIEW

        return KnowledgeIndexStatus.ACTIVE

    @staticmethod
    def _build_keywords(
        *,
        searchable_text: str,
        metadata: ExtractedDocumentMetadata | None,
        fact: ExtractedEngineeringFact,
        standards: Sequence[str],
        protocols: Sequence[str],
        hazards: Sequence[str],
    ) -> list[str]:
        explicit_keywords = [
            *fact.tags,
            *standards,
            *protocols,
            *hazards,
        ]

        if metadata is not None:
            explicit_keywords.extend(metadata.keywords)

        generated_tokens = tokenise(searchable_text)

        return unique_strings(
            [
                *explicit_keywords,
                *generated_tokens,
            ]
        )

    @staticmethod
    def _build_identifiers(
        *,
        fact: ExtractedEngineeringFact,
        model_numbers: Sequence[str],
        part_numbers: Sequence[str],
        source_document_number: str | None,
    ) -> list[str]:
        identifier_candidates = [
            *model_numbers,
            *part_numbers,
            source_document_number,
        ]

        fact_code = fact.attributes.get("fault_code")

        if fact_code is not None:
            identifier_candidates.append(str(fact_code))

        if fact.fact_type == EngineeringFactType.FAULT_CODE:
            identifier_candidates.extend(
                [
                    fact.title,
                    *tokenise(fact.statement),
                ]
            )

        return unique_strings(
            normalise_identifier(value)
            for value in identifier_candidates
            if value
            and normalise_identifier(value)
        )


# ---------------------------------------------------------------------------
# Deterministic in-memory search
# ---------------------------------------------------------------------------


class EngineeringKnowledgeIndexSearch:
    """Filter and rank deterministic knowledge-index records."""

    def search(
        self,
        records: Sequence[KnowledgeIndexRecord],
        request: KnowledgeSearchRequest,
    ) -> KnowledgeSearchResponse:
        """Search index records using structured filters and lexical ranking."""

        query_text = normalise_search_text(request.text or "")
        query_tokens = tokenise(query_text)
        query_identifier = normalise_identifier(request.text or "")

        matched_results: list[KnowledgeSearchResult] = []

        for record in records:
            if not self._matches_filters(record, request.filters):
                continue

            scored = self._score_record(
                record=record,
                query_text=query_text,
                query_tokens=query_tokens,
                query_identifier=query_identifier,
                require_all_terms=request.require_all_terms,
            )

            if scored is None:
                continue

            matched_results.append(scored)

        matched_results.sort(
            key=lambda result: (
                -result.score,
                -result.record.extraction_confidence,
                result.record.title.casefold(),
                str(result.record.fact_id),
            )
        )

        total_matches = len(matched_results)
        paginated = matched_results[
            request.offset : request.offset + request.limit
        ]

        return KnowledgeSearchResponse(
            query=request,
            results=paginated,
            total_matches=total_matches,
        )

    def _score_record(
        self,
        *,
        record: KnowledgeIndexRecord,
        query_text: str,
        query_tokens: Sequence[str],
        query_identifier: str,
        require_all_terms: bool,
    ) -> KnowledgeSearchResult | None:
        if not query_text:
            return KnowledgeSearchResult(
                record=record,
                score=self._base_priority_score(record),
                match_type=SearchMatchType.FILTER_MATCH,
            )

        matched_terms: list[str] = []
        matched_fields: list[str] = []
        score = self._base_priority_score(record)
        match_type = SearchMatchType.TOKEN_MATCH

        if query_identifier and query_identifier in record.identifiers:
            score += 120.0
            matched_fields.append("identifiers")
            match_type = SearchMatchType.EXACT_IDENTIFIER

        if query_text == normalise_search_text(record.title):
            score += 100.0
            matched_fields.append("title")
            match_type = SearchMatchType.EXACT_PHRASE
        elif query_text in normalise_search_text(record.title):
            score += 50.0
            matched_fields.append("title")
            match_type = SearchMatchType.FIELD_MATCH

        if query_text in normalise_search_text(record.statement):
            score += 35.0
            matched_fields.append("statement")

            if match_type == SearchMatchType.TOKEN_MATCH:
                match_type = SearchMatchType.EXACT_PHRASE

        field_weights = {
            "manufacturer": 25.0,
            "brand": 25.0,
            "product_family": 22.0,
            "product_series": 22.0,
            "model_numbers": 35.0,
            "part_numbers": 35.0,
            "standards": 20.0,
            "protocols": 20.0,
            "tools": 12.0,
            "parts": 18.0,
            "tags": 10.0,
            "hazards": 20.0,
            "keywords": 8.0,
        }

        searchable_fields: dict[str, list[str]] = {
            "manufacturer": [record.manufacturer or ""],
            "brand": [record.brand or ""],
            "product_family": [record.product_family or ""],
            "product_series": [record.product_series or ""],
            "model_numbers": record.model_numbers,
            "part_numbers": record.part_numbers,
            "standards": record.standards,
            "protocols": record.protocols,
            "tools": record.tools,
            "parts": record.parts,
            "tags": record.tags,
            "hazards": record.hazards,
            "keywords": record.keywords,
        }

        for field_name, field_values in searchable_fields.items():
            normalised_values = [
                normalise_search_text(value)
                for value in field_values
                if value
            ]

            if any(query_text == value for value in normalised_values):
                score += field_weights[field_name]
                matched_fields.append(field_name)

                if match_type == SearchMatchType.TOKEN_MATCH:
                    match_type = SearchMatchType.FIELD_MATCH
            elif any(query_text in value for value in normalised_values):
                score += field_weights[field_name] * 0.6
                matched_fields.append(field_name)

        searchable_token_set = set(tokenise(record.searchable_text))
        query_token_set = set(query_tokens)
        token_matches = query_token_set & searchable_token_set

        if require_all_terms and query_token_set - searchable_token_set:
            return None

        if query_token_set and not token_matches:
            if not matched_fields:
                return None
        else:
            matched_terms.extend(sorted(token_matches))
            score += len(token_matches) * 6.0

            if query_token_set:
                coverage = len(token_matches) / len(query_token_set)
                score += coverage * 15.0

        return KnowledgeSearchResult(
            record=record,
            score=round(score, 4),
            match_type=match_type,
            matched_terms=unique_strings(matched_terms),
            matched_fields=unique_strings(matched_fields),
        )

    @staticmethod
    def _base_priority_score(record: KnowledgeIndexRecord) -> float:
        score = record.extraction_confidence * 10.0
        score += min(record.verified_evidence_count, 5) * 2.0

        if record.fact_type in _HIGH_PRIORITY_FACT_TYPES:
            score += 3.0

        if record.safety_blocking:
            score += 5.0

        if record.status == KnowledgeIndexStatus.ACTIVE:
            score += 2.0

        return score

    def _matches_filters(
        self,
        record: KnowledgeIndexRecord,
        filters: KnowledgeSearchFilters,
    ) -> bool:
        if (
            filters.document_ids
            and record.document_id not in filters.document_ids
        ):
            return False

        if filters.fact_types and record.fact_type not in filters.fact_types:
            return False

        if (
            filters.document_types
            and record.document_type not in filters.document_types
        ):
            return False

        if (
            filters.equipment_categories
            and not set(filters.equipment_categories)
            & set(record.equipment_categories)
        ):
            return False

        if (
            filters.safety_severities
            and not set(filters.safety_severities)
            & set(record.safety_severities)
        ):
            return False

        if (
            filters.review_statuses
            and record.review_status not in filters.review_statuses
        ):
            return False

        if filters.statuses and record.status not in filters.statuses:
            return False

        if record.extraction_confidence < filters.minimum_confidence:
            return False

        if (
            filters.verified_evidence_only
            and record.verified_evidence_count == 0
        ):
            return False

        if filters.safety_only and not record.is_safety_related:
            return False

        if filters.fault_related_only and not record.is_fault_related:
            return False

        if (
            filters.human_review_required is not None
            and record.requires_human_review
            != filters.human_review_required
        ):
            return False

        string_filters = (
            (
                filters.manufacturers,
                [record.manufacturer or ""],
            ),
            (
                filters.brands,
                [record.brand or ""],
            ),
            (
                filters.product_families,
                [record.product_family or ""],
            ),
            (
                filters.product_series,
                [record.product_series or ""],
            ),
            (
                filters.model_numbers,
                record.model_numbers,
            ),
            (
                filters.part_numbers,
                record.part_numbers,
            ),
            (
                filters.standards,
                record.standards,
            ),
            (
                filters.protocols,
                record.protocols,
            ),
        )

        for requested_values, record_values in string_filters:
            if requested_values and not self._matches_any_string(
                requested_values,
                record_values,
            ):
                return False

        return True

    @staticmethod
    def _matches_any_string(
        requested_values: Sequence[str],
        record_values: Sequence[str],
    ) -> bool:
        requested = {
            normalise_search_text(value)
            for value in requested_values
            if value
        }
        available = {
            normalise_search_text(value)
            for value in record_values
            if value
        }

        return bool(requested & available)


__all__ = [
    "EngineeringKnowledgeIndexer",
    "EngineeringKnowledgeIndexSearch",
    "IndexedEngineeringValue",
    "IndexedEvidence",
    "KnowledgeIndexBuildResult",
    "KnowledgeIndexRecord",
    "KnowledgeIndexStatus",
    "KnowledgeSearchFilters",
    "KnowledgeSearchRequest",
    "KnowledgeSearchResponse",
    "KnowledgeSearchResult",
    "SearchMatchType",
    "normalise_identifier",
    "normalise_search_text",
    "tokenise",
    "unique_strings",
]