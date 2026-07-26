"""Adapter between document-ingestion records and controlled knowledge.

This module converts deterministic document-ingestion output into the
vendor-neutral EngineeringKnowledge model used by the Engineer4Me knowledge
service and repository.

The adapter deliberately creates DRAFT knowledge. Extracted document content
must not become published engineering guidance until the required technical,
safety, standards, evidence, and final-approval reviews have been completed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from pydantic import Field

from app.engineering.knowledge_models import (
    EngineeringBaseModel,
    EngineeringDiscipline,
    EngineeringKnowledge,
    EquipmentApplicability,
    EvidenceReference,
    EvidenceStrength,
    EvidenceType,
    HazardCategory,
    HazardControl,
    KnowledgeCategory,
    KnowledgeStatus,
    RevisionMetadata,
    SafetyGuidance,
    SafetySeverity,
    StandardApplicability,
    StandardReference,
    VerificationRequirement,
)
from app.ingestion.knowledge_index import (
    KnowledgeIndexBuildResult,
    KnowledgeIndexRecord,
    KnowledgeIndexStatus,
    unique_strings,
)


class KnowledgeAdapterError(ValueError):
    """Base exception raised by the knowledge adapter."""


class UnsupportedKnowledgeRecordError(KnowledgeAdapterError):
    """Raised when an index record cannot safely be converted."""


class KnowledgeConversionStatus(StrEnum):
    """Outcome assigned to one knowledge-record conversion."""

    CONVERTED = "converted"
    SKIPPED = "skipped"
    FAILED = "failed"


class KnowledgeConversionItem(EngineeringBaseModel):
    """Outcome for one source index record."""

    fact_id: UUID
    index_id: UUID
    status: KnowledgeConversionStatus
    knowledge_id: str | None = None
    message: str | None = None


class KnowledgeConversionResult(EngineeringBaseModel):
    """Complete result of converting an index build."""

    document_id: UUID
    knowledge: list[EngineeringKnowledge] = Field(default_factory=list)
    items: list[KnowledgeConversionItem] = Field(default_factory=list)
    converted_count: int = Field(default=0, ge=0)
    skipped_count: int = Field(default=0, ge=0)
    failed_count: int = Field(default=0, ge=0)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class EngineeringKnowledgeAdapter:
    """Convert deterministic index records into controlled knowledge."""

    ADAPTER_NAME = "Engineer4Me engineering knowledge adapter"
    ADAPTER_VERSION = "1.0.0"

    _CATEGORY_MAP = {
        "operating_principle": KnowledgeCategory.OPERATING_PRINCIPLE,
        "application": KnowledgeCategory.APPLICATION,
        "product_feature": KnowledgeCategory.APPLICATION,
        "selection_guidance": KnowledgeCategory.SELECTION,
        "specification": KnowledgeCategory.SELECTION,
        "sizing_guidance": KnowledgeCategory.SIZING,
        "installation_requirement": KnowledgeCategory.INSTALLATION,
        "configuration_parameter": KnowledgeCategory.CONFIGURATION,
        "calibration_requirement": KnowledgeCategory.CALIBRATION,
        "commissioning_step": KnowledgeCategory.COMMISSIONING,
        "operating_instruction": KnowledgeCategory.OPERATION,
        "inspection_requirement": KnowledgeCategory.INSPECTION,
        "maintenance_requirement": KnowledgeCategory.PREVENTIVE_MAINTENANCE,
        "predictive_indicator": KnowledgeCategory.PREDICTIVE_MAINTENANCE,
        "troubleshooting_step": KnowledgeCategory.TROUBLESHOOTING,
        "fault_code": KnowledgeCategory.FAULT_CODE,
        "failure_mode": KnowledgeCategory.FAILURE_MODE,
        "likely_cause": KnowledgeCategory.ROOT_CAUSE,
        "corrective_action": KnowledgeCategory.CORRECTIVE_ACTION,
        "safety_warning": KnowledgeCategory.SAFETY,
        "safety_requirement": KnowledgeCategory.SAFETY,
        "standard_reference": KnowledgeCategory.STANDARD,
        "formula": KnowledgeCategory.CALCULATION,
        "calculation": KnowledgeCategory.CALCULATION,
        "verification_step": KnowledgeCategory.VERIFICATION,
        "operating_limit": KnowledgeCategory.OPERATION,
        "environmental_limit": KnowledgeCategory.SELECTION,
        "replacement": KnowledgeCategory.REPLACEMENT,
        "obsolescence": KnowledgeCategory.OBSOLESCENCE,
    }

    _DISCIPLINE_MAP = {
        "communication_protocol": EngineeringDiscipline.AUTOMATION_CONTROL,
        "configuration_parameter": EngineeringDiscipline.AUTOMATION_CONTROL,
        "control_strategy": EngineeringDiscipline.AUTOMATION_CONTROL,
        "electrical_requirement": EngineeringDiscipline.ELECTRICAL,
        "wiring_requirement": EngineeringDiscipline.ELECTRICAL,
        "mechanical_requirement": EngineeringDiscipline.MECHANICAL,
        "process_requirement": EngineeringDiscipline.PROCESS,
        "piping_requirement": EngineeringDiscipline.PIPING,
        "safety_warning": EngineeringDiscipline.SAFETY,
        "safety_requirement": EngineeringDiscipline.SAFETY,
        "cybersecurity_requirement": EngineeringDiscipline.INDUSTRIAL_IT,
    }

    _EVIDENCE_TYPE_MAP = {
        "manual": EvidenceType.OEM_MANUAL,
        "installation_manual": EvidenceType.OEM_MANUAL,
        "operation_manual": EvidenceType.OEM_MANUAL,
        "maintenance_manual": EvidenceType.OEM_MANUAL,
        "service_manual": EvidenceType.OEM_MANUAL,
        "datasheet": EvidenceType.OEM_DATASHEET,
        "data_sheet": EvidenceType.OEM_DATASHEET,
        "technical_data": EvidenceType.OEM_DATASHEET,
        "bulletin": EvidenceType.OEM_BULLETIN,
        "standard": EvidenceType.INTERNATIONAL_STANDARD,
        "regulation": EvidenceType.REGULATION,
        "drawing": EvidenceType.DRAWING,
        "test_report": EvidenceType.TEST_RESULT,
        "technical_report": EvidenceType.TECHNICAL_REPORT,
    }

    _SAFETY_SEVERITY_MAP = {
        "information": SafetySeverity.INFORMATION,
        "notice": SafetySeverity.INFORMATION,
        "caution": SafetySeverity.CAUTION,
        "warning": SafetySeverity.WARNING,
        "danger": SafetySeverity.CRITICAL,
        "critical": SafetySeverity.CRITICAL,
    }

    def convert_build(
        self,
        build: KnowledgeIndexBuildResult,
        *,
        created_by: str = "document-ingestion",
    ) -> KnowledgeConversionResult:
        """Convert all eligible records from one index build.

        Rejected and withdrawn records are skipped. A failure converting one
        record does not prevent valid records from being converted.
        """

        knowledge: list[EngineeringKnowledge] = []
        items: list[KnowledgeConversionItem] = []
        warnings = list(build.warnings)
        errors = list(build.errors)

        converted_count = 0
        skipped_count = 0
        failed_count = 0

        for record in build.records:
            if record.status in {
                KnowledgeIndexStatus.REJECTED,
                KnowledgeIndexStatus.WITHDRAWN,
            }:
                skipped_count += 1
                message = (
                    f"Index record {record.index_id} was skipped because its "
                    f"status is {record.status.value}."
                )
                warnings.append(message)
                items.append(
                    KnowledgeConversionItem(
                        fact_id=record.fact_id,
                        index_id=record.index_id,
                        status=KnowledgeConversionStatus.SKIPPED,
                        message=message,
                    )
                )
                continue

            try:
                converted = self.convert_record(
                    record,
                    created_by=created_by,
                )
            except (TypeError, ValueError) as error:
                failed_count += 1
                message = (
                    f"Index record {record.index_id} could not be converted: "
                    f"{error}"
                )
                errors.append(message)
                items.append(
                    KnowledgeConversionItem(
                        fact_id=record.fact_id,
                        index_id=record.index_id,
                        status=KnowledgeConversionStatus.FAILED,
                        message=message,
                    )
                )
                continue

            knowledge.append(converted)
            converted_count += 1
            items.append(
                KnowledgeConversionItem(
                    fact_id=record.fact_id,
                    index_id=record.index_id,
                    status=KnowledgeConversionStatus.CONVERTED,
                    knowledge_id=converted.knowledge_id,
                )
            )

        return KnowledgeConversionResult(
            document_id=build.document_id,
            knowledge=knowledge,
            items=items,
            converted_count=converted_count,
            skipped_count=skipped_count,
            failed_count=failed_count,
            warnings=warnings,
            errors=errors,
        )

    def convert_records(
        self,
        records: Sequence[KnowledgeIndexRecord],
        *,
        created_by: str = "document-ingestion",
    ) -> list[EngineeringKnowledge]:
        """Convert several eligible index records in input order."""

        return [
            self.convert_record(record, created_by=created_by)
            for record in records
            if record.status
            not in {
                KnowledgeIndexStatus.REJECTED,
                KnowledgeIndexStatus.WITHDRAWN,
            }
        ]

    def convert_record(
        self,
        record: KnowledgeIndexRecord,
        *,
        created_by: str = "document-ingestion",
    ) -> EngineeringKnowledge:
        """Convert one index record into draft controlled knowledge."""

        if record.status in {
            KnowledgeIndexStatus.REJECTED,
            KnowledgeIndexStatus.WITHDRAWN,
        }:
            raise UnsupportedKnowledgeRecordError(
                "Rejected or withdrawn index records cannot be converted."
            )

        creator = created_by.strip()

        if not creator:
            raise KnowledgeAdapterError("created_by cannot be empty.")

        knowledge_id = self._build_knowledge_id(record)
        categories = self._build_categories(record)
        discipline = self._derive_discipline(record)
        equipment = self._build_equipment_applicability(record)
        evidence = self._build_evidence(record)
        standards = self._build_standards(record)
        safety = self._build_safety(record)
        verification = self._build_verification_requirements(record)

        limitations = [
            "Automatically extracted document content requires human review "
            "before approval or publication.",
        ]

        if record.requires_human_review:
            limitations.append(
                "The extraction engine explicitly marked this record as "
                "requiring human review."
            )

        if not evidence:
            limitations.append(
                "No traceable source evidence was attached to this extracted "
                "record."
            )

        assumptions = [
            "The source document was parsed and indexed without changing the "
            "technical meaning of the extracted statement.",
        ]

        exclusions = [
            "This draft does not replace site procedures, risk assessments, "
            "legal requirements, OEM instructions, or authorised engineering "
            "approval.",
        ]

        tags = unique_strings(
            [
                *record.tags,
                *record.keywords,
                record.fact_type.value,
                record.document_type.value,
                "document_ingestion",
                "automatically_extracted",
            ]
        )

        confidence_score = round(
            max(0.0, min(100.0, record.extraction_confidence * 100.0)),
            2,
        )

        return EngineeringKnowledge(
            knowledge_id=knowledge_id,
            title=record.title,
            subject=self._build_subject(record),
            summary=self._build_summary(record),
            detailed_guidance=record.statement,
            discipline=discipline,
            categories=categories,
            status=KnowledgeStatus.DRAFT,
            taxonomy_ids=self._build_taxonomy_ids(record),
            semantic_tags=tags,
            equipment_applicability=equipment,
            safety=safety,
            standards=standards,
            evidence=evidence,
            verification_requirements=verification,
            revision_metadata=RevisionMetadata(
                revision="1.0",
                created_by=creator,
                created_at=record.indexed_at,
                change_summary=(
                    "Initial draft created from deterministic document "
                    f"ingestion fact {record.fact_id} using adapter "
                    f"{self.ADAPTER_VERSION}."
                ),
            ),
            confidence_score=confidence_score,
            confidence_explanation=self._build_confidence_explanation(record),
            limitations=unique_strings(limitations),
            assumptions=unique_strings(assumptions),
            exclusions=unique_strings(exclusions),
        )

    @staticmethod
    def _build_knowledge_id(record: KnowledgeIndexRecord) -> str:
        return f"doc-{record.document_id.hex[:12]}-fact-{record.fact_id.hex[:16]}"

    def _build_categories(
        self,
        record: KnowledgeIndexRecord,
    ) -> list[KnowledgeCategory]:
        category = self._CATEGORY_MAP.get(record.fact_type.value)

        if category is None:
            category = KnowledgeCategory.APPLICATION

        categories = [category]

        if record.is_safety_related and KnowledgeCategory.SAFETY not in categories:
            categories.append(KnowledgeCategory.SAFETY)

        if (
            record.is_fault_related
            and KnowledgeCategory.TROUBLESHOOTING not in categories
        ):
            categories.append(KnowledgeCategory.TROUBLESHOOTING)

        return categories

    def _derive_discipline(
        self,
        record: KnowledgeIndexRecord,
    ) -> EngineeringDiscipline:
        mapped = self._DISCIPLINE_MAP.get(record.fact_type.value)

        if mapped is not None:
            return mapped

        equipment_text = " ".join(
            item.value for item in record.equipment_categories
        ).casefold()

        if any(
            term in equipment_text
            for term in (
                "instrument",
                "transmitter",
                "sensor",
                "analyser",
                "analyzer",
                "flow",
                "level",
                "pressure",
                "temperature",
            )
        ):
            return EngineeringDiscipline.INSTRUMENTATION

        if any(
            term in equipment_text
            for term in ("plc", "scada", "controller", "automation", "drive")
        ):
            return EngineeringDiscipline.AUTOMATION_CONTROL

        if any(
            term in equipment_text
            for term in ("motor", "switchgear", "relay", "electrical")
        ):
            return EngineeringDiscipline.ELECTRICAL

        if any(
            term in equipment_text
            for term in ("pump", "compressor", "gearbox", "mechanical")
        ):
            return EngineeringDiscipline.MECHANICAL

        return EngineeringDiscipline.MULTIDISCIPLINARY

    @staticmethod
    def _build_equipment_applicability(
        record: KnowledgeIndexRecord,
    ) -> list[EquipmentApplicability]:
        categories = [
            item.value.replace("_", " ")
            for item in record.equipment_categories
        ]

        if not categories and any(
            (
                record.manufacturer,
                record.product_family,
                record.product_series,
                record.model_numbers,
            )
        ):
            categories = ["industrial equipment"]

        result: list[EquipmentApplicability] = []

        for category in categories:
            result.append(
                EquipmentApplicability(
                    taxonomy_id=None,
                    equipment_category=category,
                    equipment_type=record.product_series,
                    manufacturer=record.manufacturer or record.brand,
                    model_family=record.product_family,
                    models=list(record.model_numbers),
                    components=list(record.parts),
                )
            )

        return result

    def _build_evidence(
        self,
        record: KnowledgeIndexRecord,
    ) -> list[EvidenceReference]:
        evidence_type = self._derive_evidence_type(record)
        result: list[EvidenceReference] = []

        for item in record.evidence:
            location_parts = [f"document:{item.document_id}"]

            if item.page_number is not None:
                location_parts.append(f"page:{item.page_number}")

            if item.section:
                location_parts.append(f"section:{item.section}")

            if item.block_id is not None:
                location_parts.append(f"block:{item.block_id}")

            result.append(
                EvidenceReference(
                    evidence_id=str(item.evidence_id),
                    evidence_type=evidence_type,
                    title=record.source_title or record.title,
                    publisher_or_owner=record.manufacturer or record.brand,
                    document_number=record.source_document_number,
                    revision=record.source_revision,
                    source_location=" | ".join(location_parts),
                    relevant_section=item.section,
                    summary=item.quoted_text,
                    strength=self._derive_evidence_strength(
                        item.extraction_confidence
                    ),
                    verified=item.verified,
                    verified_by=(
                        "document-ingestion-verification"
                        if item.verified
                        else None
                    ),
                    verified_at=record.indexed_at if item.verified else None,
                )
            )

        return result

    def _derive_evidence_type(
        self,
        record: KnowledgeIndexRecord,
    ) -> EvidenceType:
        value = record.document_type.value.casefold()

        if value in self._EVIDENCE_TYPE_MAP:
            return self._EVIDENCE_TYPE_MAP[value]

        for key, evidence_type in self._EVIDENCE_TYPE_MAP.items():
            if key in value:
                return evidence_type

        return EvidenceType.OTHER

    @staticmethod
    def _derive_evidence_strength(confidence: float) -> EvidenceStrength:
        if confidence >= 0.90:
            return EvidenceStrength.VERY_HIGH

        if confidence >= 0.70:
            return EvidenceStrength.HIGH

        if confidence >= 0.40:
            return EvidenceStrength.MODERATE

        if confidence >= 0.20:
            return EvidenceStrength.LOW

        return EvidenceStrength.VERY_LOW

    @staticmethod
    def _build_standards(
        record: KnowledgeIndexRecord,
    ) -> list[StandardReference]:
        result: list[StandardReference] = []

        for standard in unique_strings(record.standards):
            organisation = EngineeringKnowledgeAdapter._standard_organisation(
                standard
            )

            result.append(
                StandardReference(
                    organisation=organisation,
                    standard_number=standard[:150],
                    title=f"Referenced standard: {standard}"[:500],
                    applicability=StandardApplicability.RECOMMENDED,
                    notes=(
                        "Automatically extracted reference. Applicability, "
                        "edition, clauses and jurisdiction require review."
                    ),
                )
            )

        return result

    @staticmethod
    def _standard_organisation(standard: str) -> str:
        match = re.match(r"\s*([A-Za-z][A-Za-z0-9&./-]*)", standard)

        if match is None:
            return "Unknown"

        return match.group(1)[:150]

    def _build_safety(
        self,
        record: KnowledgeIndexRecord,
    ) -> SafetyGuidance | None:
        if not record.is_safety_related:
            return None

        severity = self._derive_safety_severity(record)
        hazards: list[HazardControl] = []

        hazard_names = record.hazards or ["Engineering safety hazard"]

        for position, hazard in enumerate(hazard_names, start=1):
            hazards.append(
                HazardControl(
                    hazard_id=(
                        f"haz-{record.fact_id.hex[:12]}-{position}"
                    ),
                    category=HazardCategory.OTHER,
                    title=hazard[:250],
                    description=record.statement[:2000],
                    severity=severity,
                    possible_consequences=[],
                    preventive_controls=unique_strings(
                        [
                            *record.prerequisites,
                            *record.isolation_requirements,
                            *record.permit_requirements,
                        ]
                    ),
                    detection_controls=[],
                    required_actions=unique_strings(
                        [
                            *record.actions,
                            *record.verification_steps,
                        ]
                    ),
                    stop_work_condition=(
                        "Stop work until the identified safety condition has "
                        "been assessed and controlled."
                        if record.safety_blocking
                        else None
                    ),
                    emergency_response=None,
                    standards=[],
                )
            )

        pre_work_checks = unique_strings(
            [
                *record.prerequisites,
                *(
                    f"Confirm required PPE: {item}"
                    for item in record.required_ppe
                ),
                *(
                    f"Confirm isolation requirement: {item}"
                    for item in record.isolation_requirements
                ),
                *(
                    f"Confirm permit requirement: {item}"
                    for item in record.permit_requirements
                ),
            ]
        )

        return SafetyGuidance(
            safety_summary=record.statement[:3000],
            severity=severity,
            hazards=hazards,
            permit_requirements=list(record.permit_requirements),
            required_site_risk_assessment=True,
            requires_authorised_person=record.safety_blocking,
            blocks_work_until_resolved=record.safety_blocking,
            pre_work_checks=pre_work_checks,
            post_work_checks=list(record.verification_steps),
            emergency_notes=(
                "Follow the site emergency response plan and escalate to an "
                "authorised responsible person."
                if record.safety_blocking
                else None
            ),
        )

    def _derive_safety_severity(
        self,
        record: KnowledgeIndexRecord,
    ) -> SafetySeverity:
        priorities = {
            SafetySeverity.INFORMATION: 1,
            SafetySeverity.CAUTION: 2,
            SafetySeverity.WARNING: 3,
            SafetySeverity.CRITICAL: 4,
        }

        mapped: list[SafetySeverity] = []

        for severity in record.safety_severities:
            converted = self._SAFETY_SEVERITY_MAP.get(severity.value.casefold())

            if converted is not None:
                mapped.append(converted)

        if record.safety_blocking:
            mapped.append(SafetySeverity.CRITICAL)

        if not mapped:
            return SafetySeverity.CAUTION

        return max(mapped, key=lambda item: priorities[item])

    @staticmethod
    def _build_verification_requirements(
        record: KnowledgeIndexRecord,
    ) -> list[VerificationRequirement]:
        result: list[VerificationRequirement] = []

        for position, step in enumerate(
            unique_strings(record.verification_steps),
            start=1,
        ):
            result.append(
                VerificationRequirement(
                    verification_id=(
                        f"ver-{record.fact_id.hex[:12]}-{position}"
                    ),
                    description=step[:2000],
                    method=step[:2000],
                    expected_result=(
                        "The extracted requirement is confirmed against the "
                        "source document and applicable site conditions."
                    ),
                    required_tool=(
                        record.tools[0][:300] if record.tools else None
                    ),
                    evidence_required=[
                        "Record the verification result and supporting evidence."
                    ],
                    independent_verification_required=record.safety_blocking,
                )
            )

        return result

    @staticmethod
    def _build_subject(record: KnowledgeIndexRecord) -> str:
        components = unique_strings(
            [
                record.fact_type.value.replace("_", " "),
                record.manufacturer,
                record.product_family,
                record.product_series,
            ]
        )

        return " - ".join(components)[:300] or record.title[:300]

    @staticmethod
    def _build_summary(record: KnowledgeIndexRecord) -> str:
        source = record.source_title or "an ingested engineering document"

        return (
            f"Draft engineering knowledge extracted from {source}. "
            f"Fact type: {record.fact_type.value}. "
            f"Extraction confidence: "
            f"{record.extraction_confidence * 100:.2f}%. "
            f"Human review required: "
            f"{'yes' if record.requires_human_review else 'no'}."
        )[:3000]

    @staticmethod
    def _build_taxonomy_ids(
        record: KnowledgeIndexRecord,
    ) -> list[str]:
        return unique_strings(
            [
                f"fact-type:{record.fact_type.value}",
                f"document-type:{record.document_type.value}",
                *(
                    f"equipment:{item.value}"
                    for item in record.equipment_categories
                ),
            ]
        )

    @staticmethod
    def _build_confidence_explanation(
        record: KnowledgeIndexRecord,
    ) -> str:
        verified_count = record.verified_evidence_count

        return (
            "Confidence was converted from the deterministic extraction score. "
            f"Source extraction confidence: "
            f"{record.extraction_confidence:.4f}. "
            f"Confidence level: {record.confidence_level.value}. "
            f"Review status: {record.review_status.value}. "
            f"Verified evidence references: {verified_count}. "
            "This confidence score describes extraction reliability and does "
            "not constitute technical approval."
        )


__all__ = [
    "EngineeringKnowledgeAdapter",
    "KnowledgeAdapterError",
    "KnowledgeConversionItem",
    "KnowledgeConversionResult",
    "KnowledgeConversionStatus",
    "UnsupportedKnowledgeRecordError",
]
