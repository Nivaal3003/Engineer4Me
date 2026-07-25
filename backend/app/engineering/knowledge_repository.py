"""Repository services for Engineer4Me engineering knowledge.

This module provides a database-independent repository for storing, retrieving,
filtering, ranking, and versioning controlled engineering knowledge.

The initial implementation uses protected in-memory storage so the knowledge
engine can be developed and tested before PostgreSQL, vector search, and graph
storage adapters are introduced.
"""

from __future__ import annotations

from copy import deepcopy
from enum import StrEnum
from threading import RLock
from typing import Iterable

from pydantic import Field, model_validator

from app.engineering.knowledge_models import (
    EngineeringBaseModel,
    EngineeringDiscipline,
    EngineeringKnowledge,
    EnvironmentCondition,
    EvidenceType,
    IndustrySector,
    KnowledgeCategory,
    KnowledgeStatus,
    SafetySeverity,
)


class KnowledgeRepositoryError(Exception):
    """Base exception raised by the engineering knowledge repository."""


class KnowledgeAlreadyExistsError(KnowledgeRepositoryError):
    """Raised when a knowledge identifier already exists."""


class KnowledgeNotFoundError(KnowledgeRepositoryError):
    """Raised when requested engineering knowledge cannot be found."""


class KnowledgeRevisionError(KnowledgeRepositoryError):
    """Raised when a knowledge update has an invalid revision."""


class SearchSortOrder(StrEnum):
    """Supported result ordering strategies."""

    RELEVANCE = "relevance"
    CONFIDENCE = "confidence"
    TITLE = "title"
    SAFETY_PRIORITY = "safety_priority"


class KnowledgeSearchQuery(EngineeringBaseModel):
    """Structured search request for engineering knowledge."""

    text: str | None = Field(default=None, max_length=500)

    disciplines: list[EngineeringDiscipline] = Field(default_factory=list)
    categories: list[KnowledgeCategory] = Field(default_factory=list)
    statuses: list[KnowledgeStatus] = Field(default_factory=list)

    equipment_categories: list[str] = Field(default_factory=list)
    equipment_types: list[str] = Field(default_factory=list)
    manufacturers: list[str] = Field(default_factory=list)
    model_families: list[str] = Field(default_factory=list)
    models: list[str] = Field(default_factory=list)

    industries: list[IndustrySector] = Field(default_factory=list)
    environmental_conditions: list[EnvironmentCondition] = Field(
        default_factory=list
    )

    standard_numbers: list[str] = Field(default_factory=list)
    evidence_types: list[EvidenceType] = Field(default_factory=list)

    verified_evidence_only: bool = False
    safety_guidance_required: bool = False
    blocking_safety_only: bool = False
    minimum_confidence_score: float = Field(default=0.0, ge=0.0, le=100.0)

    include_unpublished: bool = False
    sort_order: SearchSortOrder = SearchSortOrder.RELEVANCE
    limit: int = Field(default=25, ge=1, le=500)
    @model_validator(mode="after")
    def validate_safety_filters(self) -> "KnowledgeSearchQuery":
        """Normalise dependent safety filters."""

        if self.blocking_safety_only and not self.safety_guidance_required:
            object.__setattr__(
                self,
                "safety_guidance_required",
                True,
            )

        return self
class KnowledgeSearchResult(EngineeringBaseModel):
    """Ranked engineering knowledge search result."""

    knowledge: EngineeringKnowledge
    relevance_score: float = Field(ge=0.0)
    matched_fields: list[str] = Field(default_factory=list)
    safety_priority: int = Field(default=0, ge=0)
    has_verified_evidence: bool = False


class KnowledgeRepository:
    """Thread-safe repository for controlled engineering knowledge."""

    _PUBLIC_STATUSES = {
        KnowledgeStatus.PUBLISHED,
    }

    _SAFETY_PRIORITY = {
        SafetySeverity.CRITICAL: 4,
        SafetySeverity.WARNING: 3,
        SafetySeverity.CAUTION: 2,
        SafetySeverity.INFORMATION: 1,
    }

    def __init__(
        self,
        records: Iterable[EngineeringKnowledge] | None = None,
    ) -> None:
        """Initialise the repository with optional engineering knowledge."""

        self._records: dict[str, EngineeringKnowledge] = {}
        self._history: dict[str, list[EngineeringKnowledge]] = {}
        self._lock = RLock()

        if records is not None:
            for record in records:
                self.add(record)

    def add(self, knowledge: EngineeringKnowledge) -> EngineeringKnowledge:
        """Add a new knowledge record.

        Raises:
            KnowledgeAlreadyExistsError: If the knowledge ID already exists.
        """

        with self._lock:
            if knowledge.knowledge_id in self._records:
                raise KnowledgeAlreadyExistsError(
                    "Engineering knowledge already exists: "
                    f"{knowledge.knowledge_id}."
                )

            stored = deepcopy(knowledge)
            self._records[knowledge.knowledge_id] = stored
            self._history[knowledge.knowledge_id] = []

            return deepcopy(stored)

    def update(self, knowledge: EngineeringKnowledge) -> EngineeringKnowledge:
        """Replace an existing record and preserve its previous revision.

        The revision value must change so that controlled knowledge cannot be
        overwritten without an auditable revision transition.

        Raises:
            KnowledgeNotFoundError: If the knowledge ID does not exist.
            KnowledgeRevisionError: If the revision has not changed.
        """

        with self._lock:
            existing = self._records.get(knowledge.knowledge_id)

            if existing is None:
                raise KnowledgeNotFoundError(
                    "Engineering knowledge was not found: "
                    f"{knowledge.knowledge_id}."
                )

            current_revision = existing.revision_metadata.revision
            new_revision = knowledge.revision_metadata.revision

            if new_revision == current_revision:
                raise KnowledgeRevisionError(
                    "Updated engineering knowledge must use a new revision. "
                    f"Current revision is {current_revision}."
                )

            self._history[knowledge.knowledge_id].append(deepcopy(existing))
            self._records[knowledge.knowledge_id] = deepcopy(knowledge)

            return deepcopy(knowledge)

    def upsert(self, knowledge: EngineeringKnowledge) -> EngineeringKnowledge:
        """Add a new record or update an existing record."""

        with self._lock:
            if knowledge.knowledge_id in self._records:
                return self.update(knowledge)

            return self.add(knowledge)

    def get(
        self,
        knowledge_id: str,
        *,
        include_unpublished: bool = False,
    ) -> EngineeringKnowledge:
        """Return one knowledge record by ID.

        Unpublished knowledge is hidden unless explicitly requested.

        Raises:
            KnowledgeNotFoundError: If the record does not exist or is hidden.
        """

        with self._lock:
            record = self._records.get(knowledge_id)

            if record is None:
                raise KnowledgeNotFoundError(
                    f"Engineering knowledge was not found: {knowledge_id}."
                )

            if (
                not include_unpublished
                and record.status not in self._PUBLIC_STATUSES
            ):
                raise KnowledgeNotFoundError(
                    f"Published engineering knowledge was not found: "
                    f"{knowledge_id}."
                )

            return deepcopy(record)

    def get_history(self, knowledge_id: str) -> list[EngineeringKnowledge]:
        """Return prior revisions in oldest-to-newest order."""

        with self._lock:
            if knowledge_id not in self._records:
                raise KnowledgeNotFoundError(
                    f"Engineering knowledge was not found: {knowledge_id}."
                )

            return deepcopy(self._history.get(knowledge_id, []))

    def list_all(
        self,
        *,
        include_unpublished: bool = False,
    ) -> list[EngineeringKnowledge]:
        """Return all visible knowledge records ordered by title."""

        with self._lock:
            records = [
                deepcopy(record)
                for record in self._records.values()
                if include_unpublished
                or record.status in self._PUBLIC_STATUSES
            ]

        return sorted(
            records,
            key=lambda item: (
                item.title.casefold(),
                item.knowledge_id.casefold(),
            ),
        )

    def delete(self, knowledge_id: str) -> None:
        """Delete a knowledge record and its stored revision history."""

        with self._lock:
            if knowledge_id not in self._records:
                raise KnowledgeNotFoundError(
                    f"Engineering knowledge was not found: {knowledge_id}."
                )

            del self._records[knowledge_id]
            self._history.pop(knowledge_id, None)

    def count(self, *, include_unpublished: bool = False) -> int:
        """Return the number of visible knowledge records."""

        with self._lock:
            if include_unpublished:
                return len(self._records)

            return sum(
                record.status in self._PUBLIC_STATUSES
                for record in self._records.values()
            )

    def search(
        self,
        query: KnowledgeSearchQuery,
    ) -> list[KnowledgeSearchResult]:
        """Search, filter, score, and rank engineering knowledge."""

        with self._lock:
            records = [
                deepcopy(record) for record in self._records.values()
            ]

        results: list[KnowledgeSearchResult] = []

        for knowledge in records:
            if not self._matches_visibility(knowledge, query):
                continue

            if not self._matches_filters(knowledge, query):
                continue

            score, matched_fields = self._calculate_relevance(
                knowledge,
                query.text,
            )

            if query.text and score <= 0.0:
                continue

            results.append(
                KnowledgeSearchResult(
                    knowledge=knowledge,
                    relevance_score=score,
                    matched_fields=matched_fields,
                    safety_priority=self._get_safety_priority(knowledge),
                    has_verified_evidence=any(
                        evidence.verified for evidence in knowledge.evidence
                    ),
                )
            )

        results = self._sort_results(results, query.sort_order)

        return results[: query.limit]

    def search_text(
        self,
        text: str,
        *,
        include_unpublished: bool = False,
        limit: int = 25,
    ) -> list[KnowledgeSearchResult]:
        """Convenience method for general full-text knowledge search."""

        return self.search(
            KnowledgeSearchQuery(
                text=text,
                include_unpublished=include_unpublished,
                limit=limit,
            )
        )

    def _matches_visibility(
        self,
        knowledge: EngineeringKnowledge,
        query: KnowledgeSearchQuery,
    ) -> bool:
        """Return whether a record is visible to the search request."""

        if query.include_unpublished:
            return True

        return knowledge.status in self._PUBLIC_STATUSES

    def _matches_filters(
        self,
        knowledge: EngineeringKnowledge,
        query: KnowledgeSearchQuery,
    ) -> bool:
        """Apply exact structured search filters."""

        if (
            query.disciplines
            and knowledge.discipline not in query.disciplines
        ):
            return False

        if query.categories and not set(query.categories).intersection(
            knowledge.categories
        ):
            return False

        if query.statuses and knowledge.status not in query.statuses:
            return False

        if knowledge.confidence_score < query.minimum_confidence_score:
            return False

        if (
            query.verified_evidence_only
            and not any(item.verified for item in knowledge.evidence)
        ):
            return False

        if query.evidence_types and not any(
            item.evidence_type in query.evidence_types
            for item in knowledge.evidence
        ):
            return False

        if query.safety_guidance_required and knowledge.safety is None:
            return False

        if query.blocking_safety_only and (
            knowledge.safety is None
            or not knowledge.safety.blocks_work_until_resolved
        ):
            return False

        if not self._matches_equipment_filters(knowledge, query):
            return False

        if not self._matches_industry_filters(knowledge, query):
            return False

        if not self._matches_environment_filters(knowledge, query):
            return False

        if not self._matches_standard_filters(knowledge, query):
            return False

        return True

    def _matches_equipment_filters(
        self,
        knowledge: EngineeringKnowledge,
        query: KnowledgeSearchQuery,
    ) -> bool:
        """Match equipment taxonomy, manufacturer, family, and model filters."""

        if not any(
            (
                query.equipment_categories,
                query.equipment_types,
                query.manufacturers,
                query.model_families,
                query.models,
            )
        ):
            return True

        for equipment in knowledge.equipment_applicability:
            if query.equipment_categories and not self._contains_value(
                equipment.equipment_category,
                query.equipment_categories,
            ):
                continue

            if query.equipment_types and not self._contains_value(
                equipment.equipment_type,
                query.equipment_types,
            ):
                continue

            if query.manufacturers and not self._contains_value(
                equipment.manufacturer,
                query.manufacturers,
            ):
                continue

            if query.model_families and not self._contains_value(
                equipment.model_family,
                query.model_families,
            ):
                continue

            if query.models and not self._lists_intersect(
                equipment.models,
                query.models,
            ):
                continue

            return True

        return False

    def _matches_industry_filters(
        self,
        knowledge: EngineeringKnowledge,
        query: KnowledgeSearchQuery,
    ) -> bool:
        """Match industrial sector filters."""

        if not query.industries:
            return True

        return any(
            item.industry in query.industries
            for item in knowledge.industry_applicability
        )

    def _matches_environment_filters(
        self,
        knowledge: EngineeringKnowledge,
        query: KnowledgeSearchQuery,
    ) -> bool:
        """Match environmental operating-condition filters."""

        if not query.environmental_conditions:
            return True

        record_conditions = {
            item.condition for item in knowledge.environmental_constraints
        }

        return bool(
            record_conditions.intersection(query.environmental_conditions)
        )

    def _matches_standard_filters(
        self,
        knowledge: EngineeringKnowledge,
        query: KnowledgeSearchQuery,
    ) -> bool:
        """Match referenced standard numbers."""

        if not query.standard_numbers:
            return True

        requested = {
            value.casefold() for value in query.standard_numbers
        }

        available = {
            standard.standard_number.casefold()
            for standard in knowledge.standards
        }

        for procedure in knowledge.procedures:
            if procedure.safety is None:
                continue

            for hazard in procedure.safety.hazards:
                available.update(
                    standard.standard_number.casefold()
                    for standard in hazard.standards
                )

        return bool(requested.intersection(available))

    def _calculate_relevance(
        self,
        knowledge: EngineeringKnowledge,
        text: str | None,
    ) -> tuple[float, list[str]]:
        """Calculate deterministic keyword relevance for one record."""

        if not text:
            return 0.0, []

        terms = self._normalise_terms(text)

        if not terms:
            return 0.0, []

        fields: list[tuple[str, str, float]] = [
            ("knowledge_id", knowledge.knowledge_id, 10.0),
            ("title", knowledge.title, 9.0),
            ("subject", knowledge.subject, 7.0),
            ("summary", knowledge.summary, 5.0),
            ("detailed_guidance", knowledge.detailed_guidance, 2.0),
            (
                "semantic_tags",
                " ".join(knowledge.semantic_tags),
                7.0,
            ),
            (
                "taxonomy_ids",
                " ".join(knowledge.taxonomy_ids),
                6.0,
            ),
            (
                "categories",
                " ".join(category.value for category in knowledge.categories),
                4.0,
            ),
            ("discipline", knowledge.discipline.value, 4.0),
        ]

        equipment_text = " ".join(
            value
            for item in knowledge.equipment_applicability
            for value in [
                item.equipment_category,
                item.equipment_type or "",
                item.measurement_principle or "",
                item.manufacturer or "",
                item.model_family or "",
                *item.models,
                *item.components,
            ]
            if value
        )

        industry_text = " ".join(
            value
            for item in knowledge.industry_applicability
            for value in [
                item.industry.value,
                item.sub_industry or "",
                item.plant_type or "",
                item.process_area or "",
                item.unit_operation or "",
                *item.typical_process_media,
                *item.typical_equipment,
                *item.common_failure_modes,
            ]
            if value
        )

        standards_text = " ".join(
            value
            for standard in knowledge.standards
            for value in [
                standard.organisation,
                standard.standard_number,
                standard.title,
                standard.clause or "",
            ]
            if value
        )

        evidence_text = " ".join(
            value
            for evidence in knowledge.evidence
            for value in [
                evidence.evidence_id,
                evidence.title,
                evidence.publisher_or_owner or "",
                evidence.document_number or "",
                evidence.summary or "",
            ]
            if value
        )

        fields.extend(
            [
                ("equipment", equipment_text, 7.0),
                ("industry", industry_text, 4.0),
                ("standards", standards_text, 6.0),
                ("evidence", evidence_text, 3.0),
            ]
        )

        score = 0.0
        matched_fields: list[str] = []

        for field_name, field_value, weight in fields:
            normalised_value = field_value.casefold()
            field_score = sum(
                weight for term in terms if term in normalised_value
            )

            if field_score > 0.0:
                score += field_score
                matched_fields.append(field_name)

        normalised_query = text.strip().casefold()

        if normalised_query:
            if normalised_query in knowledge.title.casefold():
                score += 12.0

            if normalised_query in knowledge.subject.casefold():
                score += 8.0

        return score, matched_fields

    def _sort_results(
        self,
        results: list[KnowledgeSearchResult],
        sort_order: SearchSortOrder,
    ) -> list[KnowledgeSearchResult]:
        """Sort search results using the requested strategy."""

        if sort_order == SearchSortOrder.CONFIDENCE:
            return sorted(
                results,
                key=lambda result: (
                    -result.knowledge.confidence_score,
                    -result.safety_priority,
                    -result.relevance_score,
                    result.knowledge.title.casefold(),
                ),
            )

        if sort_order == SearchSortOrder.TITLE:
            return sorted(
                results,
                key=lambda result: (
                    result.knowledge.title.casefold(),
                    result.knowledge.knowledge_id.casefold(),
                ),
            )

        if sort_order == SearchSortOrder.SAFETY_PRIORITY:
            return sorted(
                results,
                key=lambda result: (
                    -result.safety_priority,
                    -result.relevance_score,
                    -result.knowledge.confidence_score,
                    result.knowledge.title.casefold(),
                ),
            )

        return sorted(
            results,
            key=lambda result: (
                -result.relevance_score,
                -result.safety_priority,
                -result.knowledge.confidence_score,
                result.knowledge.title.casefold(),
            ),
        )

    def _get_safety_priority(
        self,
        knowledge: EngineeringKnowledge,
    ) -> int:
        """Return safety ranking, with blocking guidance ranked highest."""

        if knowledge.safety is None:
            return 0

        priority = self._SAFETY_PRIORITY.get(knowledge.safety.severity, 0)

        if knowledge.safety.blocks_work_until_resolved:
            priority += 10

        return priority

    @staticmethod
    def _normalise_terms(text: str) -> list[str]:
        """Return unique case-insensitive search terms."""

        return list(
            dict.fromkeys(
                term
                for term in text.casefold().split()
                if term
            )
        )

    @staticmethod
    def _contains_value(
        value: str | None,
        requested_values: list[str],
    ) -> bool:
        """Return whether one optional value matches requested values."""

        if value is None:
            return False

        normalised_value = value.casefold()

        return any(
            normalised_value == requested.casefold()
            for requested in requested_values
        )

    @staticmethod
    def _lists_intersect(
        available_values: list[str],
        requested_values: list[str],
    ) -> bool:
        """Return whether two string lists intersect case-insensitively."""

        available = {value.casefold() for value in available_values}
        requested = {value.casefold() for value in requested_values}

        return bool(available.intersection(requested))

