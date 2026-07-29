"""Runtime composition for filesystem-backed document processing.

This module connects the shared ingestion-job lifecycle service to the guarded
filesystem content loader, the complete PDF/Office/OCR-aware parser chain, and
the deterministic document-processing orchestrator. It is transport-neutral:
an API route, queue consumer, or background worker can invoke the same runtime
without duplicating pipeline wiring.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

from app.ingestion.document_processing_orchestrator import (
    DocumentProcessingOrchestrator,
    DocumentProcessingOrchestratorConfig,
)
from app.ingestion.filesystem_document_content_loader import (
    FilesystemDocumentContentLoader,
    FilesystemDocumentContentLoaderConfig,
)
from app.ingestion.ingestion_job_models import IngestionJob
from app.ingestion.ingestion_job_service import IngestionJobService
from app.ingestion.pdf_office_document_parser import (
    PdfOfficeDocumentParser,
    PdfOfficeDocumentParserConfig,
)


@dataclass(frozen=True, slots=True)
class FilesystemDocumentProcessingRuntimeConfig:
    """Validated dependencies and controls for one processing runtime."""

    content_loader_config: FilesystemDocumentContentLoaderConfig
    orchestrator: DocumentProcessingOrchestratorConfig = field(
        default_factory=DocumentProcessingOrchestratorConfig,
    )
    document_parser: PdfOfficeDocumentParserConfig = field(
        default_factory=PdfOfficeDocumentParserConfig,
    )

    def __post_init__(self) -> None:
        """Reject unvalidated or incompatible nested configuration."""

        if not isinstance(
            self.content_loader_config,
            FilesystemDocumentContentLoaderConfig,
        ):
            raise TypeError(
                "content_loader_config must be a "
                "FilesystemDocumentContentLoaderConfig."
            )

        if not isinstance(
            self.orchestrator,
            DocumentProcessingOrchestratorConfig,
        ):
            raise TypeError(
                "orchestrator must be a "
                "DocumentProcessingOrchestratorConfig."
            )

        if not isinstance(
            self.document_parser,
            PdfOfficeDocumentParserConfig,
        ):
            raise TypeError(
                "document_parser must be a "
                "PdfOfficeDocumentParserConfig."
            )


class FilesystemDocumentProcessingRuntime:
    """Run ingestion jobs through one fully composed synchronous pipeline."""

    def __init__(
        self,
        *,
        job_service: IngestionJobService,
        config: FilesystemDocumentProcessingRuntimeConfig,
    ) -> None:
        """Build concrete loader, parser, and orchestrator once for reuse."""

        if not isinstance(job_service, IngestionJobService):
            raise TypeError(
                "job_service must be an IngestionJobService."
            )

        if not isinstance(
            config,
            FilesystemDocumentProcessingRuntimeConfig,
        ):
            raise TypeError(
                "config must be a "
                "FilesystemDocumentProcessingRuntimeConfig."
            )

        content_loader = FilesystemDocumentContentLoader(
            config.content_loader_config,
        )
        document_parser = PdfOfficeDocumentParser(
            config.document_parser,
        )

        self._job_service = job_service
        self._config = config
        self._content_loader = content_loader
        self._document_parser = document_parser
        self._orchestrator = DocumentProcessingOrchestrator(
            job_service=job_service,
            content_loader=content_loader,
            parser=document_parser,
            config=config.orchestrator,
        )

    @property
    def job_service(self) -> IngestionJobService:
        """Return the shared ingestion-job lifecycle service."""

        return self._job_service

    @property
    def config(self) -> FilesystemDocumentProcessingRuntimeConfig:
        """Return the immutable runtime configuration."""

        return self._config

    @property
    def content_loader(self) -> FilesystemDocumentContentLoader:
        """Return the guarded content loader used by this runtime."""

        return self._content_loader

    @property
    def document_parser(self) -> PdfOfficeDocumentParser:
        """Return the complete parser chain used by this runtime."""

        return self._document_parser

    @property
    def orchestrator(self) -> DocumentProcessingOrchestrator:
        """Return the composed document-processing orchestrator."""

        return self._orchestrator

    def process_job(self, job_id: UUID) -> IngestionJob:
        """Process and reconcile one complete ingestion job."""

        return self._orchestrator.process_job(job_id)

    def process_document(
        self,
        job_id: UUID,
        document_id: UUID,
    ) -> IngestionJob:
        """Process one document without finalising its containing job."""

        return self._orchestrator.process_document(
            job_id,
            document_id,
        )


__all__ = [
    "FilesystemDocumentProcessingRuntime",
    "FilesystemDocumentProcessingRuntimeConfig",
]
