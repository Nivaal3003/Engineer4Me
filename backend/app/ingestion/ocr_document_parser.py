"""OCR-aware parsing for native documents and supported raster images.

The parser preserves Engineer4Me's deterministic native parsing for text-based
formats and adds bounded Tesseract OCR for raster images. Image byte, pixel,
frame, format, confidence, and execution-time controls protect the ingestion
pipeline from malformed or unexpectedly expensive inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO
from math import isfinite
from pathlib import Path
import re
from typing import Any
import warnings

from PIL import Image, ImageOps, UnidentifiedImageError
import pytesseract
from pytesseract import Output

from app.ingestion.document_models import (
    BoundingBox,
    ContentBlockType,
    DocumentFormat,
    DocumentUpload,
    ExtractionMethod,
    ParsedContentBlock,
    ParsedDocument,
    ParsedPage,
)
from app.ingestion.document_parser import (
    DocumentParser,
    DocumentParserConfig,
    DocumentParserError,
    DocumentTooLargeError,
    EmptyDocumentError,
    MalformedDocumentError,
)


_IMAGE_FORMATS = frozenset(
    {
        DocumentFormat.JPG,
        DocumentFormat.JPEG,
        DocumentFormat.PNG,
        DocumentFormat.TIFF,
        DocumentFormat.BMP,
        DocumentFormat.WEBP,
    }
)
_IMAGE_SUFFIX_FORMATS = {
    ".jpg": DocumentFormat.JPG,
    ".jpeg": DocumentFormat.JPEG,
    ".png": DocumentFormat.PNG,
    ".tif": DocumentFormat.TIFF,
    ".tiff": DocumentFormat.TIFF,
    ".bmp": DocumentFormat.BMP,
    ".webp": DocumentFormat.WEBP,
}
_PILLOW_FORMATS = {
    DocumentFormat.JPG: frozenset({"JPEG"}),
    DocumentFormat.JPEG: frozenset({"JPEG"}),
    DocumentFormat.PNG: frozenset({"PNG"}),
    DocumentFormat.TIFF: frozenset({"TIFF"}),
    DocumentFormat.BMP: frozenset({"BMP", "DIB"}),
    DocumentFormat.WEBP: frozenset({"WEBP"}),
}
_OCR_LANGUAGE_PATTERN = re.compile(
    r"[A-Za-z0-9_]+(?:\+[A-Za-z0-9_]+)*"
)


@dataclass(frozen=True, slots=True)
class OcrAwareDocumentParserConfig:
    """Validated native-parser and bounded image-OCR controls."""

    standard_parser: DocumentParserConfig = field(
        default_factory=DocumentParserConfig,
    )
    language: str = "eng"
    engine_mode: int = 1
    page_segmentation_mode: int = 3
    timeout_seconds: float = 30.0
    maximum_image_bytes: int = 25 * 1024 * 1024
    maximum_frame_pixels: int = 25_000_000
    maximum_total_pixels: int = 50_000_000
    maximum_frames: int = 16
    minimum_word_confidence: float = 0.0

    def __post_init__(self) -> None:
        """Normalise values and reject unsafe resource controls."""

        if not isinstance(self.standard_parser, DocumentParserConfig):
            raise TypeError(
                "standard_parser must be a DocumentParserConfig."
            )

        if not isinstance(self.language, str):
            raise TypeError("language must be a string.")

        language = self.language.strip()

        if (
            not language
            or _OCR_LANGUAGE_PATTERN.fullmatch(language) is None
        ):
            raise ValueError(
                "language must contain Tesseract language identifiers "
                "separated by '+'."
            )

        if (
            not isinstance(self.engine_mode, int)
            or isinstance(self.engine_mode, bool)
            or self.engine_mode not in range(4)
        ):
            raise ValueError("engine_mode must be between 0 and 3.")

        if (
            not isinstance(self.page_segmentation_mode, int)
            or isinstance(self.page_segmentation_mode, bool)
            or self.page_segmentation_mode not in range(14)
        ):
            raise ValueError(
                "page_segmentation_mode must be between 0 and 13."
            )

        self._require_positive_number(
            self.timeout_seconds,
            field_name="timeout_seconds",
        )

        for field_name in (
            "maximum_image_bytes",
            "maximum_frame_pixels",
            "maximum_total_pixels",
            "maximum_frames",
        ):
            self._require_positive_integer(
                getattr(self, field_name),
                field_name=field_name,
            )

        if self.maximum_total_pixels < self.maximum_frame_pixels:
            raise ValueError(
                "maximum_total_pixels cannot be less than "
                "maximum_frame_pixels."
            )

        if (
            not isinstance(
                self.minimum_word_confidence,
                (int, float),
            )
            or isinstance(self.minimum_word_confidence, bool)
            or not 0.0 <= self.minimum_word_confidence <= 100.0
        ):
            raise ValueError(
                "minimum_word_confidence must be between 0 and 100."
            )

        object.__setattr__(self, "language", language)

    @staticmethod
    def _require_positive_integer(
        value: Any,
        *,
        field_name: str,
    ) -> None:
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value <= 0
        ):
            raise ValueError(
                f"{field_name} must be a positive integer."
            )

    @staticmethod
    def _require_positive_number(
        value: Any,
        *,
        field_name: str,
    ) -> None:
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or value <= 0
        ):
            raise ValueError(
                f"{field_name} must be greater than zero."
            )


class OcrAwareDocumentParser(DocumentParser):
    """Delegate native formats and OCR supported raster images safely."""

    PARSER_NAME = "engineer4me-image-ocr-parser"
    PARSER_VERSION = "1.0.0"

    def __init__(
        self,
        config: OcrAwareDocumentParserConfig | None = None,
    ) -> None:
        self.config = config or OcrAwareDocumentParserConfig()
        self._standard_parser = DocumentParser(
            self.config.standard_parser,
        )

    @property
    def parser_name(self) -> str:
        """Return the stable image-parser identifier."""

        return self.PARSER_NAME

    @property
    def parser_version(self) -> str:
        """Return the image-parser contract version."""

        return self.PARSER_VERSION

    @property
    def standard_parser(self) -> DocumentParser:
        """Return the native parser for non-image documents."""

        return self._standard_parser

    def supports(self, upload: DocumentUpload) -> bool:
        """Return whether native parsing or OCR supports an upload."""

        return (
            self.resolve_document_format(upload) in _IMAGE_FORMATS
            or self._standard_parser.supports(upload)
        )

    def resolve_document_format(
        self,
        upload: DocumentUpload,
    ) -> DocumentFormat:
        """Resolve image suffixes before applying native parser rules."""

        if upload.document_format in _IMAGE_FORMATS:
            return upload.document_format

        if upload.document_format == DocumentFormat.UNKNOWN:
            suffix = Path(upload.filename).suffix.lower()
            image_format = _IMAGE_SUFFIX_FORMATS.get(suffix)

            if image_format is not None:
                return image_format

        return self._standard_parser.resolve_document_format(upload)

    def parse(
        self,
        upload: DocumentUpload,
        content: bytes,
    ) -> ParsedDocument:
        """Parse native documents normally and OCR supported images."""

        effective_format = self.resolve_document_format(upload)

        if effective_format not in _IMAGE_FORMATS:
            return self._standard_parser.parse(upload, content)

        return self._parse_image_document(
            upload=upload,
            content=content,
            effective_format=effective_format,
        )

    def _parse_image_document(
        self,
        *,
        upload: DocumentUpload,
        content: bytes,
        effective_format: DocumentFormat,
    ) -> ParsedDocument:
        self._validate_image_input(upload, content)

        pages: list[ParsedPage] = []
        confidences: list[float] = []
        document_warnings: list[str] = []
        accepted_word_count = 0
        rejected_word_count = 0
        total_pixels = 0
        source_format = ""
        frame_count = 0
        next_sequence_number = 0

        try:
            with warnings.catch_warnings():
                warnings.simplefilter(
                    "error",
                    Image.DecompressionBombWarning,
                )

                with Image.open(BytesIO(content)) as verification_image:
                    source_format = (
                        verification_image.format or ""
                    ).upper()
                    self._validate_source_format(
                        upload,
                        effective_format=effective_format,
                        source_format=source_format,
                    )
                    verification_image.verify()

                with Image.open(BytesIO(content)) as source_image:
                    frame_count = int(
                        getattr(source_image, "n_frames", 1)
                    )

                    if frame_count > self.config.maximum_frames:
                        raise DocumentTooLargeError(
                            f"Image '{upload.filename}' contains "
                            f"{frame_count} frames, which exceeds the "
                            "configured limit of "
                            f"{self.config.maximum_frames}."
                        )

                    for frame_index in range(frame_count):
                        source_image.seek(frame_index)
                        width, height = source_image.size
                        frame_pixels = width * height
                        total_pixels += frame_pixels

                        if (
                            frame_pixels
                            > self.config.maximum_frame_pixels
                        ):
                            raise DocumentTooLargeError(
                                f"Image frame {frame_index + 1} in "
                                f"'{upload.filename}' contains "
                                f"{frame_pixels} pixels, which exceeds "
                                "the configured per-frame limit of "
                                f"{self.config.maximum_frame_pixels}."
                            )

                        if (
                            total_pixels
                            > self.config.maximum_total_pixels
                        ):
                            raise DocumentTooLargeError(
                                f"Image '{upload.filename}' contains "
                                f"{total_pixels} total pixels, which "
                                "exceeds the configured limit of "
                                f"{self.config.maximum_total_pixels}."
                            )

                        (
                            page,
                            page_confidences,
                            page_accepted_words,
                            page_rejected_words,
                        ) = self._ocr_frame(
                            self._prepare_frame(
                                source_image.copy()
                            ),
                            page_number=frame_index + 1,
                            sequence_number=next_sequence_number,
                        )
                        pages.append(page)
                        next_sequence_number += len(page.blocks)
                        confidences.extend(page_confidences)
                        accepted_word_count += page_accepted_words
                        rejected_word_count += page_rejected_words

        except DocumentParserError:
            raise
        except (
            Image.DecompressionBombError,
            Image.DecompressionBombWarning,
        ) as error:
            raise DocumentTooLargeError(
                f"Image '{upload.filename}' exceeds safe Pillow "
                "decompression limits."
            ) from error
        except (
            UnidentifiedImageError,
            EOFError,
            OSError,
            SyntaxError,
        ) as error:
            raise MalformedDocumentError(
                f"Image '{upload.filename}' is malformed or unreadable."
            ) from error

        full_text = "\n\n".join(
            page.text
            for page in pages
            if page.text
        )

        if not full_text.strip():
            raise EmptyDocumentError(
                f"Image '{upload.filename}' contains no readable OCR text."
            )

        if upload.size_bytes != len(content):
            document_warnings.append(
                "Upload metadata size does not match the supplied image "
                "content size."
            )

        for page in pages:
            document_warnings.extend(page.warnings)

        extraction_confidence = (
            sum(confidences) / len(confidences)
            if confidences
            else 0.0
        )
        title = Path(upload.filename).stem.strip() or upload.filename

        return ParsedDocument(
            document_id=upload.document_id,
            title=title[:1000],
            pages=pages,
            full_text=full_text,
            page_count=len(pages),
            character_count=len(full_text),
            word_count=len(full_text.split()),
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            extraction_method=ExtractionMethod.OCR,
            extraction_confidence=extraction_confidence,
            warnings=document_warnings,
            errors=[],
            parser_metadata={
                "source_format": source_format,
                "effective_document_format": effective_format.value,
                "ocr_engine": "tesseract",
                "ocr_language": self.config.language,
                "ocr_engine_mode": self.config.engine_mode,
                "ocr_page_segmentation_mode": (
                    self.config.page_segmentation_mode
                ),
                "ocr_timeout_seconds": self.config.timeout_seconds,
                "frame_count": frame_count,
                "total_pixels": total_pixels,
                "accepted_word_count": accepted_word_count,
                "rejected_word_count": rejected_word_count,
            },
        )

    def _validate_image_input(
        self,
        upload: DocumentUpload,
        content: bytes,
    ) -> None:
        if not isinstance(content, bytes):
            raise TypeError("Document content must be supplied as bytes.")

        if not content:
            raise EmptyDocumentError(
                f"Image '{upload.filename}' contains no data."
            )

        if len(content) > self.config.maximum_image_bytes:
            raise DocumentTooLargeError(
                f"Image '{upload.filename}' is {len(content)} bytes, "
                "which exceeds the configured limit of "
                f"{self.config.maximum_image_bytes} bytes."
            )

    @staticmethod
    def _validate_source_format(
        upload: DocumentUpload,
        *,
        effective_format: DocumentFormat,
        source_format: str,
    ) -> None:
        if source_format not in _PILLOW_FORMATS[effective_format]:
            raise MalformedDocumentError(
                f"Image '{upload.filename}' content format "
                f"'{source_format or 'unknown'}' does not match "
                f"document format '{effective_format.value}'."
            )

    @staticmethod
    def _prepare_frame(frame: Image.Image) -> Image.Image:
        frame = ImageOps.exif_transpose(frame)

        if (
            "A" in frame.getbands()
            or "transparency" in frame.info
        ):
            foreground = frame.convert("RGBA")
            background = Image.new(
                "RGBA",
                foreground.size,
                color=(255, 255, 255, 255),
            )
            background.alpha_composite(foreground)
            frame = background.convert("RGB")
        else:
            frame = frame.convert("RGB")

        return ImageOps.autocontrast(ImageOps.grayscale(frame))

    def _ocr_frame(
        self,
        frame: Image.Image,
        *,
        page_number: int,
        sequence_number: int,
    ) -> tuple[ParsedPage, list[float], int, int]:
        tesseract_config = (
            f"--oem {self.config.engine_mode} "
            f"--psm {self.config.page_segmentation_mode}"
        )

        try:
            data = pytesseract.image_to_data(
                frame,
                lang=self.config.language,
                config=tesseract_config,
                output_type=Output.DICT,
                timeout=self.config.timeout_seconds,
            )
        except Exception as error:
            raise DocumentParserError(
                f"OCR failed for image page {page_number}: {error}"
            ) from error

        (
            text,
            page_confidences,
            accepted_word_count,
            rejected_word_count,
        ) = self._normalise_ocr_data(data)
        page_confidence = (
            sum(page_confidences) / len(page_confidences)
            if page_confidences
            else 0.0
        )
        page_warnings: list[str] = []
        blocks: list[ParsedContentBlock] = []

        if text:
            blocks.append(
                ParsedContentBlock(
                    block_type=ContentBlockType.PARAGRAPH,
                    text=text,
                    page_number=page_number,
                    sequence_number=sequence_number,
                    bounding_box=BoundingBox(
                        x=0.0,
                        y=0.0,
                        width=float(frame.width),
                        height=float(frame.height),
                        page_width=float(frame.width),
                        page_height=float(frame.height),
                    ),
                    extraction_method=ExtractionMethod.OCR,
                    extraction_confidence=page_confidence,
                    attributes={
                        "ocr_engine": "tesseract",
                        "ocr_language": self.config.language,
                        "ocr_word_count": accepted_word_count,
                    },
                )
            )
        else:
            page_warnings.append(
                f"No readable OCR text was detected on page "
                f"{page_number}."
            )

        if rejected_word_count:
            page_warnings.append(
                f"{rejected_word_count} OCR word(s) below the "
                "configured confidence threshold were excluded from "
                f"page {page_number}."
            )

        return (
            ParsedPage(
                page_number=page_number,
                width=float(frame.width),
                height=float(frame.height),
                text=text,
                blocks=blocks,
                extraction_method=ExtractionMethod.OCR,
                extraction_confidence=page_confidence,
                warnings=page_warnings,
            ),
            page_confidences,
            accepted_word_count,
            rejected_word_count,
        )

    def _normalise_ocr_data(
        self,
        data: dict[str, list[Any]],
    ) -> tuple[str, list[float], int, int]:
        required_fields = (
            "text",
            "conf",
            "block_num",
            "par_num",
            "line_num",
        )

        if any(field_name not in data for field_name in required_fields):
            raise DocumentParserError(
                "OCR engine returned incomplete word data."
            )

        item_count = len(data["text"])

        if any(
            len(data[field_name]) != item_count
            for field_name in required_fields
        ):
            raise DocumentParserError(
                "OCR engine returned inconsistent word data."
            )

        lines: dict[tuple[int, int, int], list[str]] = {}
        confidences: list[float] = []
        rejected_word_count = 0

        for item_index in range(item_count):
            text = str(data["text"][item_index]).strip()

            if not text:
                continue

            try:
                confidence_percent = float(
                    data["conf"][item_index]
                )
                line_key = (
                    int(data["block_num"][item_index]),
                    int(data["par_num"][item_index]),
                    int(data["line_num"][item_index]),
                )
            except (TypeError, ValueError) as error:
                raise DocumentParserError(
                    "OCR engine returned invalid word data."
                ) from error

            if not isfinite(confidence_percent):
                raise DocumentParserError(
                    "OCR engine returned non-finite confidence data."
                )

            if confidence_percent < 0:
                continue

            if (
                confidence_percent
                < self.config.minimum_word_confidence
            ):
                rejected_word_count += 1
                continue

            lines.setdefault(line_key, []).append(text)
            confidences.append(
                min(confidence_percent, 100.0) / 100.0
            )

        normalised_text = "\n".join(
            " ".join(words)
            for words in lines.values()
            if words
        )

        return (
            normalised_text,
            confidences,
            len(confidences),
            rejected_word_count,
        )


__all__ = [
    "OcrAwareDocumentParser",
    "OcrAwareDocumentParserConfig",
]
