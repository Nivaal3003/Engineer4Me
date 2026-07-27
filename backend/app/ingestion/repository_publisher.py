"""Repository publication orchestration for Engineer4Me ingestion.

This module connects deterministic document ingestion to the controlled
engineering knowledge service.

The publication workflow is:

    KnowledgeIndexBuildResult
        -> EngineeringKnowledgeAdapter
        -> EngineeringKnowledgeService
        -> KnowledgeRepository

Automatically extracted records are registered as DRAFT engineering knowledge.
They are not published technical guidance and remain subject to Engineer4Me's
technical, safety, standards, evidence, and final-approval workflows.
"""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import Field

from app.engineering.knowledge_adapter import (
    EngineeringKnowledgeAdapter,
    KnowledgeConversionResult,
    KnowledgeConversionStatus,
)
from app.engineering.knowledge_models import EngineeringBaseModel
from app.engineering.knowledge_repository import (
    KnowledgeAlreadyExistsError,
    KnowledgeRepositoryError,
)
from app.engineering.knowledge_service import (
    EngineeringKnowledgeService,
    KnowledgeServiceError,
)
from app.ingestion.knowledge_index import KnowledgeIndexBuildResult


class RepositoryPublisherError(Exception):
    """Base exception raised by the repository publisher."""


class RepositoryPublicationStatus(StrEnum):
    """Outcome assigned to one repository publication item."""

    REGISTERED = "registered"
    SKIPPED = "skipped"
    FAILED = "failed"


class RepositoryPublicationItem(EngineeringBaseModel):
    """Repository publication outcome for one indexed engineering fact."""

    fact_id: UUID
    index_id: UUID
    knowledge_id: str | None = None
    status: RepositoryPublicationStatus
    message: str | None = None


class RepositoryPublicationResult(EngineeringBaseModel):
    """Complete result of adapting and registering one knowledge-index build."""

    document_id: UUID
    conversion: KnowledgeConversionResult
    items: list[RepositoryPublicationItem] = Field(default_factory=list)

    registered_count: int = Field(default=0, ge=0)
    skipped_count: int = Field(default=0, ge=0)
    failed_count: int = Field(default=0, ge=0)

    registered_knowledge_ids: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @property
    def successful(self) -> bool:
        """Return whether the workflow completed without publication failures."""

        return self.failed_count == 0

    @property
    def processed_count(self) -> int:
        """Return the total number of publication outcomes."""

        return (
            self.registered_count
            + self.skipped_count
            + self.failed_count
        )


class EngineeringKnowledgeRepositoryPublisher:
    """Adapt indexed engineering facts and register controlled knowledge.

    The publisher is an orchestration component only. It delegates:

    - conversion to ``EngineeringKnowledgeAdapter``;
    - business validation to ``EngineeringKnowledgeService``;
    - storage to the service's configured ``KnowledgeRepository``.

    Existing knowledge identifiers are skipped by default. This makes repeated
    ingestion of the same deterministic fact idempotent and prevents an
    unchanged automatically generated revision from overwriting controlled
    knowledge.
    """

    PUBLISHER_NAME = "Engineer4Me engineering knowledge repository publisher"
    PUBLISHER_VERSION = "1.0.0"

    def __init__(
        self,
        *,
        adapter: EngineeringKnowledgeAdapter | None = None,
        service: EngineeringKnowledgeService | None = None,
    ) -> None:
        """Initialise the publisher with optional injected dependencies."""

        self._adapter = adapter or EngineeringKnowledgeAdapter()
        self._service = service or EngineeringKnowledgeService()

    @property
    def adapter(self) -> EngineeringKnowledgeAdapter:
        """Return the configured ingestion-to-knowledge adapter."""

        return self._adapter

    @property
    def service(self) -> EngineeringKnowledgeService:
        """Return the configured controlled knowledge service."""

        return self._service

    def publish_build(
        self,
        build: KnowledgeIndexBuildResult,
        *,
        created_by: str = "document-ingestion",
        skip_existing: bool = True,
    ) -> RepositoryPublicationResult:
        """Convert and register eligible records from one index build.

        Args:
            build:
                Deterministic knowledge-index build to process.
            created_by:
                Responsible ingestion workflow written into revision metadata.
            skip_existing:
                When true, deterministic duplicate knowledge identifiers are
                reported as skipped. When false, they are reported as failed.

        Returns:
            A complete conversion and repository publication result.

        Notes:
            Every converted record is registered independently. A failure for
            one record does not prevent other valid records from being stored.
            All adapter warnings and errors are preserved in the result.
        """

        creator = created_by.strip()

        if not creator:
            raise RepositoryPublisherError("created_by cannot be empty.")

        conversion = self._adapter.convert_build(
            build,
            created_by=creator,
        )

        warnings = list(conversion.warnings)
        errors = list(conversion.errors)
        items: list[RepositoryPublicationItem] = []

        registered_knowledge_ids: list[str] = []
        registered_count = 0
        skipped_count = 0
        failed_count = 0

        knowledge_by_id = {
            knowledge.knowledge_id: knowledge
            for knowledge in conversion.knowledge
        }

        for conversion_item in conversion.items:
            if conversion_item.status == KnowledgeConversionStatus.SKIPPED:
                skipped_count += 1
                items.append(
                    RepositoryPublicationItem(
                        fact_id=conversion_item.fact_id,
                        index_id=conversion_item.index_id,
                        knowledge_id=conversion_item.knowledge_id,
                        status=RepositoryPublicationStatus.SKIPPED,
                        message=conversion_item.message,
                    )
                )
                continue

            if conversion_item.status == KnowledgeConversionStatus.FAILED:
                failed_count += 1
                items.append(
                    RepositoryPublicationItem(
                        fact_id=conversion_item.fact_id,
                        index_id=conversion_item.index_id,
                        knowledge_id=conversion_item.knowledge_id,
                        status=RepositoryPublicationStatus.FAILED,
                        message=conversion_item.message,
                    )
                )
                continue

            knowledge_id = conversion_item.knowledge_id

            if knowledge_id is None:
                failed_count += 1
                message = (
                    f"Converted index record {conversion_item.index_id} did "
                    "not provide a knowledge identifier."
                )
                errors.append(message)
                items.append(
                    RepositoryPublicationItem(
                        fact_id=conversion_item.fact_id,
                        index_id=conversion_item.index_id,
                        status=RepositoryPublicationStatus.FAILED,
                        message=message,
                    )
                )
                continue

            knowledge = knowledge_by_id.get(knowledge_id)

            if knowledge is None:
                failed_count += 1
                message = (
                    f"Converted knowledge {knowledge_id} was not present in "
                    "the adapter conversion payload."
                )
                errors.append(message)
                items.append(
                    RepositoryPublicationItem(
                        fact_id=conversion_item.fact_id,
                        index_id=conversion_item.index_id,
                        knowledge_id=knowledge_id,
                        status=RepositoryPublicationStatus.FAILED,
                        message=message,
                    )
                )
                continue

            try:
                registered = self._service.register(knowledge)
            except KnowledgeAlreadyExistsError as error:
                if skip_existing:
                    skipped_count += 1
                    message = (
                        f"Knowledge {knowledge_id} already exists and was "
                        "skipped."
                    )
                    warnings.append(message)
                    items.append(
                        RepositoryPublicationItem(
                            fact_id=conversion_item.fact_id,
                            index_id=conversion_item.index_id,
                            knowledge_id=knowledge_id,
                            status=RepositoryPublicationStatus.SKIPPED,
                            message=message,
                        )
                    )
                    continue

                failed_count += 1
                message = (
                    f"Knowledge {knowledge_id} could not be registered: "
                    f"{error}"
                )
                errors.append(message)
                items.append(
                    RepositoryPublicationItem(
                        fact_id=conversion_item.fact_id,
                        index_id=conversion_item.index_id,
                        knowledge_id=knowledge_id,
                        status=RepositoryPublicationStatus.FAILED,
                        message=message,
                    )
                )
                continue
            except (
                KnowledgeServiceError,
                KnowledgeRepositoryError,
                TypeError,
                ValueError,
            ) as error:
                failed_count += 1
                message = (
                    f"Knowledge {knowledge_id} could not be registered: "
                    f"{error}"
                )
                errors.append(message)
                items.append(
                    RepositoryPublicationItem(
                        fact_id=conversion_item.fact_id,
                        index_id=conversion_item.index_id,
                        knowledge_id=knowledge_id,
                        status=RepositoryPublicationStatus.FAILED,
                        message=message,
                    )
                )
                continue

            registered_count += 1
            registered_knowledge_ids.append(registered.knowledge_id)
            items.append(
                RepositoryPublicationItem(
                    fact_id=conversion_item.fact_id,
                    index_id=conversion_item.index_id,
                    knowledge_id=registered.knowledge_id,
                    status=RepositoryPublicationStatus.REGISTERED,
                )
            )

        return RepositoryPublicationResult(
            document_id=build.document_id,
            conversion=conversion,
            items=items,
            registered_count=registered_count,
            skipped_count=skipped_count,
            failed_count=failed_count,
            registered_knowledge_ids=registered_knowledge_ids,
            warnings=warnings,
            errors=errors,
        )


__all__ = [
    "EngineeringKnowledgeRepositoryPublisher",
    "RepositoryPublicationItem",
    "RepositoryPublicationResult",
    "RepositoryPublicationStatus",
    "RepositoryPublisherError",
]
