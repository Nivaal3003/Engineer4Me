"""Tests for bounded OCR-aware engineering document parsing."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from hashlib import sha256
from io import BytesIO
from typing import Any
from unittest.mock import patch

from PIL import Image
import pytest
import pytesseract
from pytesseract import Output

from app.ingestion.document_models import (
    DocumentFormat,
    DocumentSource,
    DocumentUpload,
    ExtractionMethod,
)
from app.ingestion.document_parser import (
    DocumentParser,
    DocumentParserConfig,
    DocumentParserError,
    DocumentTooLargeError,
    EmptyDocumentError,
    MalformedDocumentError,
    UnsupportedDocumentFormatError,
)
from app.ingestion.ocr_document_parser import (
    OcrAwareDocumentParser,
    OcrAwareDocumentParserConfig,
)


def build_upload(
    *,
    filename: str,
    document_format: DocumentFormat,
    media_type: str,
    content: bytes,
    declared_size: int | None = None,
) -> DocumentUpload:
    """Build valid upload metadata for one parser test."""

    return DocumentUpload(
        filename=filename,
        document_format=document_format,
        media_type=media_type,
        size_bytes=(
            len(content)
            if declared_size is None
            else declared_size
        ),
        storage_key=f"uploads/{filename}",
        checksum_sha256=sha256(content).hexdigest(),
        source=DocumentSource(
            source_name="OCR parser test suite",
        ),
    )


def build_image_bytes(
    *,
    image_format: str = "PNG",
    size: tuple[int, int] = (120, 40),
    mode: str = "RGB",
    color: Any = "white",
    frame_count: int = 1,
) -> bytes:
    """Create deterministic single- or multi-frame image bytes."""

    frames = [
        Image.new(
            mode=mode,
            size=size,
            color=color,
        )
        for _ in range(frame_count)
    ]
    buffer = BytesIO()

    if frame_count == 1:
        frames[0].save(buffer, format=image_format)
    else:
        frames[0].save(
            buffer,
            format=image_format,
            save_all=True,
            append_images=frames[1:],
        )

    return buffer.getvalue()


def build_ocr_data(
    *,
    texts: list[str] | None = None,
    confidences: list[Any] | None = None,
    block_numbers: list[Any] | None = None,
    paragraph_numbers: list[Any] | None = None,
    line_numbers: list[Any] | None = None,
) -> dict[str, list[Any]]:
    """Build a Tesseract ``image_to_data`` result."""

    resolved_texts = texts or [
        "",
        "ROSEMOUNT",
        "3051",
        "PRESSURE",
    ]
    item_count = len(resolved_texts)

    return {
        "text": resolved_texts,
        "conf": (
            confidences
            if confidences is not None
            else ["-1", "96", "92", "88"]
        ),
        "block_num": (
            block_numbers
            if block_numbers is not None
            else [0, 1, 1, 1][:item_count]
        ),
        "par_num": (
            paragraph_numbers
            if paragraph_numbers is not None
            else [0, 1, 1, 1][:item_count]
        ),
        "line_num": (
            line_numbers
            if line_numbers is not None
            else [0, 1, 1, 1][:item_count]
        ),
    }


def parse_image(
    *,
    parser: OcrAwareDocumentParser | None = None,
    content: bytes | None = None,
    filename: str = "rosemount_3051_nameplate.png",
    document_format: DocumentFormat = DocumentFormat.PNG,
    media_type: str = "image/png",
    ocr_data: dict[str, list[Any]] | None = None,
    declared_size: int | None = None,
) -> tuple[Any, Any]:
    """Parse one image with deterministic mocked OCR output."""

    resolved_parser = parser or OcrAwareDocumentParser()
    resolved_content = content or build_image_bytes()
    upload = build_upload(
        filename=filename,
        document_format=document_format,
        media_type=media_type,
        content=resolved_content,
        declared_size=declared_size,
    )

    with patch.object(
        pytesseract,
        "image_to_data",
        return_value=ocr_data or build_ocr_data(),
    ) as image_to_data:
        parsed = resolved_parser.parse(
            upload,
            resolved_content,
        )

    return parsed, image_to_data


def test_default_config_uses_bounded_controls_and_is_frozen() -> None:
    """Default OCR controls are conservative and immutable."""

    config = OcrAwareDocumentParserConfig()

    assert isinstance(config.standard_parser, DocumentParserConfig)
    assert config.language == "eng"
    assert config.engine_mode == 1
    assert config.page_segmentation_mode == 3
    assert config.timeout_seconds == 30.0
    assert config.maximum_image_bytes == 25 * 1024 * 1024
    assert config.maximum_frame_pixels == 25_000_000
    assert config.maximum_total_pixels == 50_000_000
    assert config.maximum_frames == 16
    assert config.minimum_word_confidence == 0.0

    with pytest.raises(FrozenInstanceError):
        config.language = "afr"  # type: ignore[misc]


def test_config_preserves_native_parser_controls() -> None:
    """The OCR wrapper receives the exact native-parser configuration."""

    standard = DocumentParserConfig(
        max_document_size_bytes=4096,
    )
    config = OcrAwareDocumentParserConfig(
        standard_parser=standard,
    )
    parser = OcrAwareDocumentParser(config)

    assert config.standard_parser is standard
    assert parser.config is config
    assert parser.standard_parser.config is standard


def test_config_rejects_invalid_native_parser_config() -> None:
    """An unvalidated native-parser dependency is rejected."""

    with pytest.raises(
        TypeError,
        match="standard_parser must be a DocumentParserConfig",
    ):
        OcrAwareDocumentParserConfig(
            standard_parser=object(),  # type: ignore[arg-type]
        )


def test_config_normalises_ocr_language() -> None:
    """Whitespace around a valid Tesseract language string is removed."""

    config = OcrAwareDocumentParserConfig(
        language="  eng+afr  ",
    )

    assert config.language == "eng+afr"


@pytest.mark.parametrize(
    ("language", "expected_exception"),
    [
        (None, TypeError),
        ("", ValueError),
        ("   ", ValueError),
        ("eng+", ValueError),
        ("eng afr", ValueError),
        ("eng;afr", ValueError),
    ],
)
def test_config_rejects_invalid_ocr_language(
    language: Any,
    expected_exception: type[Exception],
) -> None:
    """Only bounded Tesseract language identifiers are accepted."""

    with pytest.raises(expected_exception):
        OcrAwareDocumentParserConfig(language=language)


@pytest.mark.parametrize(
    "engine_mode",
    [-1, 4, True, 1.5, "1"],
)
def test_config_rejects_invalid_engine_mode(
    engine_mode: Any,
) -> None:
    """Tesseract engine modes are limited to integer values zero to three."""

    with pytest.raises(
        ValueError,
        match="engine_mode must be between 0 and 3",
    ):
        OcrAwareDocumentParserConfig(
            engine_mode=engine_mode,
        )


@pytest.mark.parametrize(
    "page_segmentation_mode",
    [-1, 14, True, 3.5, "3"],
)
def test_config_rejects_invalid_page_segmentation_mode(
    page_segmentation_mode: Any,
) -> None:
    """Tesseract page segmentation modes are restricted to 0 through 13."""

    with pytest.raises(
        ValueError,
        match="page_segmentation_mode must be between 0 and 13",
    ):
        OcrAwareDocumentParserConfig(
            page_segmentation_mode=page_segmentation_mode,
        )


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("timeout_seconds", 0),
        ("timeout_seconds", -1),
        ("timeout_seconds", True),
        ("maximum_image_bytes", 0),
        ("maximum_image_bytes", -1),
        ("maximum_image_bytes", 1.5),
        ("maximum_image_bytes", True),
        ("maximum_frame_pixels", 0),
        ("maximum_total_pixels", 0),
        ("maximum_frames", 0),
    ],
)
def test_config_rejects_non_positive_resource_controls(
    field_name: str,
    invalid_value: Any,
) -> None:
    """Resource boundaries must remain positive numeric values."""

    values = {field_name: invalid_value}

    with pytest.raises(ValueError):
        OcrAwareDocumentParserConfig(**values)


def test_config_rejects_total_pixel_limit_below_frame_limit() -> None:
    """The total pixel budget cannot be smaller than one frame budget."""

    with pytest.raises(
        ValueError,
        match=(
            "maximum_total_pixels cannot be less than "
            "maximum_frame_pixels"
        ),
    ):
        OcrAwareDocumentParserConfig(
            maximum_frame_pixels=100,
            maximum_total_pixels=99,
        )


@pytest.mark.parametrize(
    "minimum_word_confidence",
    [-0.1, 100.1, True, "50", None],
)
def test_config_rejects_invalid_confidence_threshold(
    minimum_word_confidence: Any,
) -> None:
    """OCR word confidence must remain within the percentage range."""

    with pytest.raises(
        ValueError,
        match=(
            "minimum_word_confidence must be between 0 and 100"
        ),
    ):
        OcrAwareDocumentParserConfig(
            minimum_word_confidence=minimum_word_confidence,
        )


def test_parser_exposes_stable_identity_and_native_parser() -> None:
    """The wrapper exposes stable versioning and its native delegate."""

    parser = OcrAwareDocumentParser()

    assert parser.parser_name == "engineer4me-image-ocr-parser"
    assert parser.parser_version == "1.0.0"
    assert isinstance(parser.standard_parser, DocumentParser)


@pytest.mark.parametrize(
    ("document_format", "filename", "media_type"),
    [
        (DocumentFormat.JPG, "nameplate.jpg", "image/jpeg"),
        (DocumentFormat.JPEG, "nameplate.jpeg", "image/jpeg"),
        (DocumentFormat.PNG, "nameplate.png", "image/png"),
        (DocumentFormat.TIFF, "nameplate.tiff", "image/tiff"),
        (DocumentFormat.BMP, "nameplate.bmp", "image/bmp"),
        (DocumentFormat.WEBP, "nameplate.webp", "image/webp"),
    ],
)
def test_parser_supports_declared_raster_formats(
    document_format: DocumentFormat,
    filename: str,
    media_type: str,
) -> None:
    """Every declared raster format is routed to bounded OCR."""

    content = build_image_bytes()
    upload = build_upload(
        filename=filename,
        document_format=document_format,
        media_type=media_type,
        content=content,
    )

    assert OcrAwareDocumentParser().supports(upload) is True


@pytest.mark.parametrize(
    ("filename", "expected_format"),
    [
        ("nameplate.jpg", DocumentFormat.JPG),
        ("nameplate.jpeg", DocumentFormat.JPEG),
        ("nameplate.png", DocumentFormat.PNG),
        ("nameplate.tif", DocumentFormat.TIFF),
        ("nameplate.tiff", DocumentFormat.TIFF),
        ("nameplate.bmp", DocumentFormat.BMP),
        ("nameplate.webp", DocumentFormat.WEBP),
    ],
)
def test_parser_resolves_unknown_raster_format_from_suffix(
    filename: str,
    expected_format: DocumentFormat,
) -> None:
    """An unknown upload format is resolved from a supported image suffix."""

    content = build_image_bytes()
    upload = build_upload(
        filename=filename,
        document_format=DocumentFormat.UNKNOWN,
        media_type="application/octet-stream",
        content=content,
    )
    parser = OcrAwareDocumentParser()

    assert parser.resolve_document_format(upload) is expected_format
    assert parser.supports(upload) is True


def test_parser_delegates_native_text_without_ocr() -> None:
    """Existing deterministic native parsing remains unchanged."""

    content = b"Verify process isolation before maintenance."
    upload = build_upload(
        filename="safety-note.txt",
        document_format=DocumentFormat.TXT,
        media_type="text/plain",
        content=content,
    )
    parser = OcrAwareDocumentParser()

    with patch.object(
        pytesseract,
        "image_to_data",
    ) as image_to_data:
        parsed = parser.parse(upload, content)

    image_to_data.assert_not_called()
    assert parsed.extraction_method is ExtractionMethod.NATIVE_TEXT
    assert parsed.full_text == (
        "Verify process isolation before maintenance."
    )


def test_parser_rejects_unknown_non_image_format() -> None:
    """Unsupported binary formats retain the native parser error."""

    content = b"%PDF-unsupported"
    upload = build_upload(
        filename="manual.pdf",
        document_format=DocumentFormat.PDF,
        media_type="application/pdf",
        content=content,
    )

    with pytest.raises(UnsupportedDocumentFormatError):
        OcrAwareDocumentParser().parse(upload, content)


def test_parse_image_builds_normalised_ocr_document() -> None:
    """Raster OCR produces traceable page, block, and document metadata."""

    parser = OcrAwareDocumentParser(
        OcrAwareDocumentParserConfig(
            language="eng",
            engine_mode=1,
            page_segmentation_mode=6,
            timeout_seconds=12.5,
        )
    )
    parsed, image_to_data = parse_image(parser=parser)

    image_to_data.assert_called_once()
    called_frame = image_to_data.call_args.args[0]
    called_options = image_to_data.call_args.kwargs

    assert called_frame.mode == "L"
    assert called_frame.size == (120, 40)
    assert called_options == {
        "lang": "eng",
        "config": "--oem 1 --psm 6",
        "output_type": Output.DICT,
        "timeout": 12.5,
    }

    assert parsed.full_text == "ROSEMOUNT 3051 PRESSURE"
    assert parsed.title == "rosemount_3051_nameplate"
    assert parsed.page_count == 1
    assert parsed.character_count == len(parsed.full_text)
    assert parsed.word_count == 3
    assert parsed.parser_name == "engineer4me-image-ocr-parser"
    assert parsed.parser_version == "1.0.0"
    assert parsed.extraction_method is ExtractionMethod.OCR
    assert parsed.extraction_confidence == pytest.approx(0.92)
    assert parsed.warnings == []
    assert parsed.errors == []

    assert len(parsed.pages) == 1
    page = parsed.pages[0]
    assert page.page_number == 1
    assert page.width == 120.0
    assert page.height == 40.0
    assert page.text == parsed.full_text
    assert page.extraction_method is ExtractionMethod.OCR
    assert page.extraction_confidence == pytest.approx(0.92)
    assert page.warnings == []

    assert len(page.blocks) == 1
    block = page.blocks[0]
    assert block.text == parsed.full_text
    assert block.page_number == 1
    assert block.sequence_number == 0
    assert block.extraction_method is ExtractionMethod.OCR
    assert block.extraction_confidence == pytest.approx(0.92)
    assert block.bounding_box.width == 120.0
    assert block.bounding_box.height == 40.0
    assert block.attributes == {
        "ocr_engine": "tesseract",
        "ocr_language": "eng",
        "ocr_word_count": 3,
    }

    assert parsed.parser_metadata == {
        "source_format": "PNG",
        "effective_document_format": "png",
        "ocr_engine": "tesseract",
        "ocr_language": "eng",
        "ocr_engine_mode": 1,
        "ocr_page_segmentation_mode": 6,
        "ocr_timeout_seconds": 12.5,
        "frame_count": 1,
        "total_pixels": 4_800,
        "accepted_word_count": 3,
        "rejected_word_count": 0,
    }


def test_confidence_threshold_excludes_low_confidence_words() -> None:
    """Low-confidence OCR noise is excluded and recorded as a warning."""

    parser = OcrAwareDocumentParser(
        OcrAwareDocumentParserConfig(
            minimum_word_confidence=50.0,
        )
    )
    ocr_data = build_ocr_data(
        texts=["ROSEMOUNT", "noise", "3051"],
        confidences=["96", "12", "92"],
        block_numbers=[1, 1, 1],
        paragraph_numbers=[1, 1, 1],
        line_numbers=[1, 1, 1],
    )
    parsed, _ = parse_image(
        parser=parser,
        ocr_data=ocr_data,
    )

    assert parsed.full_text == "ROSEMOUNT 3051"
    assert parsed.word_count == 2
    assert parsed.extraction_confidence == pytest.approx(0.94)
    assert parsed.parser_metadata["accepted_word_count"] == 2
    assert parsed.parser_metadata["rejected_word_count"] == 1
    assert parsed.warnings == [
        (
            "1 OCR word(s) below the configured confidence "
            "threshold were excluded from page 1."
        )
    ]


def test_ocr_words_are_grouped_into_detected_lines() -> None:
    """Tesseract block, paragraph, and line keys preserve reading lines."""

    ocr_data = build_ocr_data(
        texts=["ROSEMOUNT", "3051", "PRESSURE"],
        confidences=["96", "92", "88"],
        block_numbers=[1, 1, 1],
        paragraph_numbers=[1, 1, 1],
        line_numbers=[1, 1, 2],
    )
    parsed, _ = parse_image(ocr_data=ocr_data)

    assert parsed.full_text == "ROSEMOUNT 3051\nPRESSURE"
    assert parsed.word_count == 3


def test_negative_confidence_items_are_ignored_without_rejection() -> None:
    """Tesseract structural entries do not count as rejected words."""

    ocr_data = build_ocr_data(
        texts=["layout", "ROSEMOUNT"],
        confidences=["-1", "90"],
        block_numbers=[0, 1],
        paragraph_numbers=[0, 1],
        line_numbers=[0, 1],
    )
    parsed, _ = parse_image(ocr_data=ocr_data)

    assert parsed.full_text == "ROSEMOUNT"
    assert parsed.extraction_confidence == pytest.approx(0.9)
    assert parsed.parser_metadata["accepted_word_count"] == 1
    assert parsed.parser_metadata["rejected_word_count"] == 0


def test_confidence_above_one_hundred_is_clamped() -> None:
    """Unexpected confidence values cannot exceed model bounds."""

    ocr_data = build_ocr_data(
        texts=["ROSEMOUNT"],
        confidences=["123"],
        block_numbers=[1],
        paragraph_numbers=[1],
        line_numbers=[1],
    )
    parsed, _ = parse_image(ocr_data=ocr_data)

    assert parsed.extraction_confidence == 1.0
    assert parsed.pages[0].extraction_confidence == 1.0


def test_upload_size_mismatch_creates_warning() -> None:
    """Transport-size disagreement is retained for evidence and review."""

    content = build_image_bytes()
    parsed, _ = parse_image(
        content=content,
        declared_size=len(content) + 1,
    )

    assert parsed.warnings == [
        (
            "Upload metadata size does not match the supplied "
            "image content size."
        )
    ]


def test_transparent_image_is_flattened_before_ocr() -> None:
    """Transparent pixels are placed on white before grayscale OCR."""

    content = build_image_bytes(
        mode="RGBA",
        color=(0, 0, 0, 0),
    )
    _, image_to_data = parse_image(content=content)
    called_frame = image_to_data.call_args.args[0]

    assert called_frame.mode == "L"
    assert called_frame.getpixel((0, 0)) == 255


def test_ocr_engine_failure_is_normalised() -> None:
    """OCR implementation failures become stable parser diagnostics."""

    content = build_image_bytes()
    upload = build_upload(
        filename="nameplate.png",
        document_format=DocumentFormat.PNG,
        media_type="image/png",
        content=content,
    )

    with (
        patch.object(
            pytesseract,
            "image_to_data",
            side_effect=RuntimeError("engine unavailable"),
        ),
        pytest.raises(
            DocumentParserError,
            match=(
                "OCR failed for image page 1: engine unavailable"
            ),
        ),
    ):
        OcrAwareDocumentParser().parse(upload, content)


@pytest.mark.parametrize(
    ("ocr_data", "expected_message"),
    [
        (
            {
                "text": ["ROSEMOUNT"],
                "conf": ["90"],
            },
            "incomplete word data",
        ),
        (
            {
                "text": ["ROSEMOUNT"],
                "conf": ["90", "80"],
                "block_num": [1],
                "par_num": [1],
                "line_num": [1],
            },
            "inconsistent word data",
        ),
        (
            build_ocr_data(
                texts=["ROSEMOUNT"],
                confidences=["invalid"],
                block_numbers=[1],
                paragraph_numbers=[1],
                line_numbers=[1],
            ),
            "invalid word data",
        ),
        (
            build_ocr_data(
                texts=["ROSEMOUNT"],
                confidences=["nan"],
                block_numbers=[1],
                paragraph_numbers=[1],
                line_numbers=[1],
            ),
            "non-finite confidence data",
        ),
    ],
)
def test_invalid_ocr_word_data_is_rejected(
    ocr_data: dict[str, list[Any]],
    expected_message: str,
) -> None:
    """Malformed OCR engine output cannot enter engineering extraction."""

    with pytest.raises(
        DocumentParserError,
        match=expected_message,
    ):
        parse_image(ocr_data=ocr_data)


def test_image_with_no_accepted_text_is_rejected() -> None:
    """An image without readable OCR text is not treated as parsed."""

    parser = OcrAwareDocumentParser(
        OcrAwareDocumentParserConfig(
            minimum_word_confidence=80.0,
        )
    )
    ocr_data = build_ocr_data(
        texts=["", "noise"],
        confidences=["-1", "12"],
        block_numbers=[0, 1],
        paragraph_numbers=[0, 1],
        line_numbers=[0, 1],
    )

    with pytest.raises(
        EmptyDocumentError,
        match="contains no readable OCR text",
    ):
        parse_image(
            parser=parser,
            ocr_data=ocr_data,
        )


def test_image_parse_requires_bytes() -> None:
    """Raster content cannot bypass the byte-oriented parser boundary."""

    content = build_image_bytes()
    upload = build_upload(
        filename="nameplate.png",
        document_format=DocumentFormat.PNG,
        media_type="image/png",
        content=content,
    )

    with pytest.raises(
        TypeError,
        match="Document content must be supplied as bytes",
    ):
        OcrAwareDocumentParser().parse(
            upload,
            bytearray(content),  # type: ignore[arg-type]
        )


def test_empty_image_bytes_are_rejected() -> None:
    """Empty image content fails before Pillow or Tesseract is invoked."""

    upload = build_upload(
        filename="nameplate.png",
        document_format=DocumentFormat.PNG,
        media_type="image/png",
        content=b"",
    )

    with (
        patch.object(
            pytesseract,
            "image_to_data",
        ) as image_to_data,
        pytest.raises(
            EmptyDocumentError,
            match="contains no data",
        ),
    ):
        OcrAwareDocumentParser().parse(upload, b"")

    image_to_data.assert_not_called()


def test_image_byte_limit_is_enforced_before_decoding() -> None:
    """Oversized image bytes fail before decompression and OCR."""

    content = build_image_bytes()
    parser = OcrAwareDocumentParser(
        OcrAwareDocumentParserConfig(
            maximum_image_bytes=len(content) - 1,
        )
    )
    upload = build_upload(
        filename="nameplate.png",
        document_format=DocumentFormat.PNG,
        media_type="image/png",
        content=content,
    )

    with (
        patch.object(
            pytesseract,
            "image_to_data",
        ) as image_to_data,
        pytest.raises(
            DocumentTooLargeError,
            match="exceeds the configured limit",
        ),
    ):
        parser.parse(upload, content)

    image_to_data.assert_not_called()


def test_malformed_image_bytes_are_rejected() -> None:
    """Unreadable image bytes become a stable malformed-document error."""

    content = b"not-a-real-png"
    upload = build_upload(
        filename="nameplate.png",
        document_format=DocumentFormat.PNG,
        media_type="image/png",
        content=content,
    )

    with pytest.raises(
        MalformedDocumentError,
        match="malformed or unreadable",
    ):
        OcrAwareDocumentParser().parse(upload, content)


def test_declared_format_must_match_image_content() -> None:
    """Filename metadata cannot disguise a different raster encoding."""

    content = build_image_bytes(image_format="PNG")
    upload = build_upload(
        filename="nameplate.jpg",
        document_format=DocumentFormat.JPG,
        media_type="image/jpeg",
        content=content,
    )

    with pytest.raises(
        MalformedDocumentError,
        match=(
            "content format 'PNG' does not match document format 'jpg'"
        ),
    ):
        OcrAwareDocumentParser().parse(upload, content)


def test_frame_pixel_limit_is_enforced_before_ocr() -> None:
    """A single decompressed frame cannot exceed its pixel budget."""

    content = build_image_bytes(size=(20, 20))
    parser = OcrAwareDocumentParser(
        OcrAwareDocumentParserConfig(
            maximum_frame_pixels=399,
            maximum_total_pixels=400,
        )
    )
    upload = build_upload(
        filename="nameplate.png",
        document_format=DocumentFormat.PNG,
        media_type="image/png",
        content=content,
    )

    with (
        patch.object(
            pytesseract,
            "image_to_data",
        ) as image_to_data,
        pytest.raises(
            DocumentTooLargeError,
            match="per-frame limit",
        ),
    ):
        parser.parse(upload, content)

    image_to_data.assert_not_called()


def test_total_pixel_limit_is_enforced_across_frames() -> None:
    """Multi-frame images share one cumulative decompression budget."""

    content = build_image_bytes(
        image_format="TIFF",
        size=(20, 10),
        frame_count=2,
    )
    parser = OcrAwareDocumentParser(
        OcrAwareDocumentParserConfig(
            maximum_frame_pixels=250,
            maximum_total_pixels=300,
        )
    )
    upload = build_upload(
        filename="manual.tiff",
        document_format=DocumentFormat.TIFF,
        media_type="image/tiff",
        content=content,
    )

    with (
        patch.object(
            pytesseract,
            "image_to_data",
            return_value=build_ocr_data(),
        ) as image_to_data,
        pytest.raises(
            DocumentTooLargeError,
            match="configured limit of 300",
        ),
    ):
        parser.parse(upload, content)

    assert image_to_data.call_count == 1


def test_frame_count_limit_is_enforced_before_ocr() -> None:
    """Unexpectedly large animated or multi-page images are bounded."""

    content = build_image_bytes(
        image_format="TIFF",
        frame_count=2,
    )
    parser = OcrAwareDocumentParser(
        OcrAwareDocumentParserConfig(
            maximum_frames=1,
        )
    )
    upload = build_upload(
        filename="manual.tiff",
        document_format=DocumentFormat.TIFF,
        media_type="image/tiff",
        content=content,
    )

    with (
        patch.object(
            pytesseract,
            "image_to_data",
        ) as image_to_data,
        pytest.raises(
            DocumentTooLargeError,
            match="contains 2 frames",
        ),
    ):
        parser.parse(upload, content)

    image_to_data.assert_not_called()


def test_multiframe_tiff_creates_ordered_pages_and_blocks() -> None:
    """Each TIFF frame becomes one ordered OCR page."""

    content = build_image_bytes(
        image_format="TIFF",
        frame_count=2,
    )
    responses = [
        build_ocr_data(
            texts=["ROSEMOUNT", "3051"],
            confidences=["96", "92"],
            block_numbers=[1, 1],
            paragraph_numbers=[1, 1],
            line_numbers=[1, 1],
        ),
        build_ocr_data(
            texts=["PRESSURE", "TRANSMITTER"],
            confidences=["88", "84"],
            block_numbers=[1, 1],
            paragraph_numbers=[1, 1],
            line_numbers=[1, 1],
        ),
    ]
    upload = build_upload(
        filename="manual.tiff",
        document_format=DocumentFormat.TIFF,
        media_type="image/tiff",
        content=content,
    )

    with patch.object(
        pytesseract,
        "image_to_data",
        side_effect=responses,
    ) as image_to_data:
        parsed = OcrAwareDocumentParser().parse(
            upload,
            content,
        )

    assert image_to_data.call_count == 2
    assert parsed.full_text == (
        "ROSEMOUNT 3051\n\nPRESSURE TRANSMITTER"
    )
    assert parsed.page_count == 2
    assert [page.page_number for page in parsed.pages] == [1, 2]
    assert [
        page.blocks[0].sequence_number
        for page in parsed.pages
    ] == [0, 1]
    assert parsed.extraction_confidence == pytest.approx(0.9)
    assert parsed.parser_metadata["source_format"] == "TIFF"
    assert parsed.parser_metadata["frame_count"] == 2
    assert parsed.parser_metadata["total_pixels"] == 9_600
    assert parsed.parser_metadata["accepted_word_count"] == 4
