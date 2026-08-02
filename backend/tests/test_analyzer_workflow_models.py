"""Focused Step 107 tests for analyzer workflow metadata and examples."""

from __future__ import annotations

import ast
import inspect
from types import MappingProxyType
from typing import Any

import pytest
from pydantic import ValidationError

import app.engineering.design.analyzer_workflow_models as workflow_module
from app.engineering.calculations.models import CalculationStatus, ReferenceType
from app.engineering.design.analyzer_assistant import assess_analyzer_application
from app.engineering.design.analyzer_models import (
    ANALYZER_APPLICATION_MODEL_VERSION,
    AnalyzerApplicationAssessment,
    AnalyzerApplicationRequest,
    AnalyzerScenarioDisposition,
    AnalyzerTechnology,
    fingerprint_analyzer_payload,
)
from app.engineering.design.analyzer_workflow_models import (
    ANALYZER_DESIGN_CASE_EXAMPLES,
    ANALYZER_DESIGN_CASE_REGISTRY,
    ANALYZER_KNOWLEDGE_LINKS,
    ANALYZER_KNOWLEDGE_REGISTRY,
    ANALYZER_WORKFLOW_VERSION,
    AnalyzerAssessmentEnvelope,
    AnalyzerDesignCaseExample,
    AnalyzerExpectedScenario,
    AnalyzerKnowledgeLink,
    build_analyzer_example_fingerprint,
    build_analyzer_integration_fingerprint,
    resolve_analyzer_knowledge_links,
    validate_analyzer_design_case_example,
)

EXPECTED_REFERENCE_IDS = (
    "ref.e4m-calc-060",
    "ref.e4m-calc-061",
    "ref.e4m-calc-062",
    "ref.e4m-calc-063",
    "ref.eng-070",
)
EXPECTED_REFERENCE_SOURCE = (
    "docs/07_Engineering/ENG-070_Phase7_Calculation_Engine_Standard.md"
)

# Each tuple pins status, request fingerprint, assessment fingerprint, example
# fingerprint, and the small reviewed scenario assertion set.  These identities
# make the illustrative cases reviewable fixtures rather than drifting demos.
EXPECTED_EXAMPLE_CONTRACTS: dict[
    str,
    tuple[str, str, str, str, tuple[tuple[str, str], ...]],
] = {
    "analyzer-example.corrosive-liquid-blocked": (
        "blocked",
        "e54b9004ba968a37fc1ebb6f13884fd056a18d17311d49e313795ce4ce071c3b",
        "0dbd7f0fad255f09e971999e6f2b634c746724d61fefa6f475e751940b95717d",
        "f4f1fa9f421c580a2d6439260f3bf62cbf2f742cc1fda7f5c6c41c3c6fbabcb1",
        (("conductivity_cell", "blocked"),),
    ),
    "analyzer-example.flammable-point-detection": (
        "completed_with_warnings",
        "add879de43a83f588c3cc9641771c3d697ebe0dccd55f8bfe958cf993db488b4",
        "0593bef4881abc76611669694b0962effffba250099454ab1e0cb36e29b508ab",
        "2e05a42da53b08c40b92f43a9e302fef1af95d3e914a0768c0be7e66d00eb92a",
        (
            ("catalytic_bead_gas_detector", "plausible"),
            ("infrared_point_gas_detector", "plausible"),
        ),
    ),
    "analyzer-example.gas-chromatography": (
        "completed_with_warnings",
        "7c64796abeba3684c182bd6281f5721ccef61f306749511c7017e42649ac194d",
        "5ea8d9c163ffcba69aa264195156d49f582502578670be4fd7a5b1dc44c06e2f",
        "51cbcdd096e7e5e9cec4dbe1c1f5c8ce79c6c3f3cda9b9656e9a6c71c0d931b2",
        (
            ("gas_chromatograph", "plausible"),
            ("mass_spectrometry", "plausible"),
        ),
    ),
    "analyzer-example.insufficient-input": (
        "insufficient_input",
        "d1a4aab29af61040ef75ad6b54f8558901dea897ccbf61e76f2502fcd0d6225b",
        "6757f003dc988c1f0eb33e33b5a1b20a8268a46b4c1db52b66917a945af41d5b",
        "44b62c703419cdae5b5d78e40e713babcb1b7fc8eb774db0de5c7c99027516e4",
        (("ph_electrode", "insufficient_information"),),
    ),
    "analyzer-example.liquid-ph": (
        "completed_with_warnings",
        "0197ffaa733a16c75aea06aa621f947992f9a40e6027c268c5df7a09c0277936",
        "d2d82e1d7b419b38935b8ee301ed491326beb75cb91405c6ba5cab5dcf3c77a1",
        "93bab91684d78cc11860e981e92145590711d82b6acfda4a201e32b775681c91",
        (("ph_electrode", "plausible"),),
    ),
    "analyzer-example.particulate-process-gas": (
        "completed_with_warnings",
        "857b9ad8ba650e8e94fdfb43f7fee6d4e937cad9f8f77eaf4fd8b811bc607cc7",
        "abc624e386f362e2a126ddc17e4e306f57dc8185d91bc46d711115e35ecebbb2",
        "326644944b5c0665b46bab26ba6a4b23412f4b573d6390fca2cbfcb8a67931cf",
        (("ndir_gas", "plausible"),),
    ),
    "analyzer-example.process-gas-oxygen": (
        "completed_with_warnings",
        "c465767f0aec1bd30151c104dd7377c41cd3a120d25d933615fb78d735866b55",
        "fbd73119d07bc3d558299976c0a872cd6fb10afc5e196ab4d041d414da59cc70",
        "ae765c247955b4162148b70b2be8f6eeaf584f55f16b9ed6c6001defe27d21c9",
        (
            ("tunable_diode_laser", "plausible"),
            ("zirconia_oxygen", "plausible"),
        ),
    ),
    "analyzer-example.toxic-extractive": (
        "completed_with_warnings",
        "dcb195024d575b6152d0fbed9ed6a4f26ccd3f33b260287a1384fae307c9a319",
        "990da98dccb9b876e138ecb70f284d5c2dbdcd5a8638ce958e987e1b462a1d4c",
        "ca13ace77a278c0689f1548d577d2c399acd5d18e233f4f75aeb8b408d2b6325",
        (("ndir_gas", "plausible"),),
    ),
    "analyzer-example.wet-condensing-gas": (
        "completed_with_warnings",
        "44d47b9d42e33701e7c2a29e33ec940fd96ddee9edddfa683f0ca978c8f8f1e4",
        "34fc39bf4338b01aea1f499ba0a227e9f5040b007db144f4dbd74a65fb91fa99",
        "5c18e691af53669ba12e63751f3e9d256706e9662c8544c71e0c1bfc0025b0d0",
        (("tunable_diode_laser", "plausible"),),
    ),
}


def _example(example_id: str) -> AnalyzerDesignCaseExample:
    return ANALYZER_DESIGN_CASE_REGISTRY[(example_id, 1)]


def _assessment(
    example_id: str = "analyzer-example.liquid-ph",
) -> AnalyzerApplicationAssessment:
    return assess_analyzer_application(_example(example_id).request)


def _envelope(
    example_id: str = "analyzer-example.liquid-ph",
) -> AnalyzerAssessmentEnvelope:
    assessment = _assessment(example_id)
    links = resolve_analyzer_knowledge_links(assessment)
    return AnalyzerAssessmentEnvelope(
        request_fingerprint=fingerprint_analyzer_payload(assessment.request),
        assessment=assessment,
        knowledge_links=links,
        integration_fingerprint=build_analyzer_integration_fingerprint(
            assessment,
            links,
        ),
    )


def _refingerprint_assessment(
    values: dict[str, Any],
) -> AnalyzerApplicationAssessment:
    values["assessment_fingerprint"] = fingerprint_analyzer_payload(
        {key: value for key, value in values.items() if key != "assessment_fingerprint"}
    )
    return AnalyzerApplicationAssessment.model_validate(values)


def _rebuild_example(
    values: dict[str, Any],
) -> AnalyzerDesignCaseExample:
    request = AnalyzerApplicationRequest.model_validate(values["request"])
    expected_status = CalculationStatus(values["expected_status"])
    expected_scenarios = tuple(
        AnalyzerExpectedScenario.model_validate(item)
        for item in values["expected_scenarios"]
    )
    values["example_fingerprint"] = build_analyzer_example_fingerprint(
        example_id=values["example_id"],
        revision=values["revision"],
        request=request,
        expected_status=expected_status,
        expected_scenarios=expected_scenarios,
        expected_assessment_fingerprint=values["expected_assessment_fingerprint"],
    )
    return AnalyzerDesignCaseExample.model_validate(values)


def test_workflow_version_and_public_surface_are_exact() -> None:
    assert ANALYZER_WORKFLOW_VERSION == "1.0.0"
    assert ANALYZER_APPLICATION_MODEL_VERSION == "1.0.0"
    assert set(workflow_module.__all__) == {
        "ANALYZER_DESIGN_CASE_EXAMPLES",
        "ANALYZER_DESIGN_CASE_REGISTRY",
        "ANALYZER_KNOWLEDGE_LINKS",
        "ANALYZER_KNOWLEDGE_REGISTRY",
        "ANALYZER_WORKFLOW_VERSION",
        "AnalyzerAssessmentEnvelope",
        "AnalyzerDesignCaseExample",
        "AnalyzerExpectedScenario",
        "AnalyzerKnowledgeLink",
        "build_analyzer_example_fingerprint",
        "build_analyzer_integration_fingerprint",
        "resolve_analyzer_knowledge_links",
        "validate_analyzer_design_case_example",
    }


def test_five_knowledge_links_and_registry_are_exact_and_inert() -> None:
    assert isinstance(ANALYZER_KNOWLEDGE_REGISTRY, MappingProxyType)
    assert len(ANALYZER_KNOWLEDGE_LINKS) == 5
    assert tuple(ANALYZER_KNOWLEDGE_REGISTRY) == EXPECTED_REFERENCE_IDS
    assert (
        tuple(item.reference.reference_id for item in ANALYZER_KNOWLEDGE_LINKS)
        == EXPECTED_REFERENCE_IDS
    )
    assert tuple(ANALYZER_KNOWLEDGE_REGISTRY.values()) == (ANALYZER_KNOWLEDGE_LINKS)

    for link in ANALYZER_KNOWLEDGE_LINKS:
        reference = link.reference
        assert reference.reference_type is ReferenceType.ENGINEERING_KNOWLEDGE
        assert reference.publisher_or_owner == "Engineer4Me"
        assert reference.document_number == "ENG-070"
        assert reference.edition_or_revision == "0.1"
        assert reference.source_location == EXPECTED_REFERENCE_SOURCE
        assert reference.verified is False
        assert link.retrieval_mode == "inert_metadata_only"
        assert link.network_access_performed is False
        assert link.protected_content_embedded is False
        assert link.approved_as_equation_or_factor_source is False
        assert link.approved_as_product_or_selection_source is False
        assert link.manufacturer_data_present is False
        assert link.executable is False
        assert link.conformity_evidence is False
        assert link.standards_conformity_claimed is False
        assert link.final_design_approval_granted is False

    with pytest.raises(TypeError):
        ANALYZER_KNOWLEDGE_REGISTRY["ref.new"] = ANALYZER_KNOWLEDGE_LINKS[0]  # type: ignore[index]
    with pytest.raises(ValidationError):
        ANALYZER_KNOWLEDGE_LINKS[0].executable = True  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    (
        ("reference_id", "ref.outside", "allow-list"),
        ("reference_type", ReferenceType.OTHER, "internal engineering knowledge"),
        ("source_location", "docs/drifted.md", "source location drifted"),
    ),
)
def test_knowledge_link_rejects_reference_boundary_drift(
    field_name: str,
    value: object,
    message: str,
) -> None:
    values = ANALYZER_KNOWLEDGE_LINKS[0].model_dump(
        mode="python",
        round_trip=True,
        warnings="error",
    )
    values["reference"][field_name] = value
    with pytest.raises(ValidationError, match=message):
        AnalyzerKnowledgeLink.model_validate(values)


def test_knowledge_link_false_boundaries_cannot_be_enabled() -> None:
    values = ANALYZER_KNOWLEDGE_LINKS[0].model_dump(
        mode="python",
        round_trip=True,
        warnings="error",
    )
    for field_name in (
        "network_access_performed",
        "protected_content_embedded",
        "approved_as_equation_or_factor_source",
        "approved_as_product_or_selection_source",
        "manufacturer_data_present",
        "executable",
        "conformity_evidence",
        "standards_conformity_claimed",
        "final_design_approval_granted",
    ):
        tampered = dict(values)
        tampered[field_name] = True
        with pytest.raises(ValidationError):
            AnalyzerKnowledgeLink.model_validate(tampered)


def test_resolver_requires_exact_reference_closure_and_returns_fresh_links() -> None:
    assessment = _assessment()
    first = resolve_analyzer_knowledge_links(assessment)
    second = resolve_analyzer_knowledge_links(assessment)

    assert first == ANALYZER_KNOWLEDGE_LINKS == second
    assert first is not ANALYZER_KNOWLEDGE_LINKS
    assert first is not second
    assert all(
        resolved is not registered
        for resolved, registered in zip(
            first,
            ANALYZER_KNOWLEDGE_LINKS,
            strict=True,
        )
    )
    with pytest.raises(TypeError, match="AnalyzerApplicationAssessment"):
        resolve_analyzer_knowledge_links(object())  # type: ignore[arg-type]


def test_resolver_rejects_unknown_reference_even_with_valid_assessment_hash() -> None:
    values = _assessment().model_dump(
        mode="json",
        round_trip=True,
        warnings="error",
    )
    values["scenarios"][0]["reference_ids"].append("ref.unknown")
    forged = _refingerprint_assessment(values)

    with pytest.raises(ValueError, match=r"unknown=\['ref\.unknown'\]"):
        resolve_analyzer_knowledge_links(forged)


def test_resolver_rejects_missing_reference_even_with_valid_assessment_hash() -> None:
    values = _assessment().model_dump(
        mode="json",
        round_trip=True,
        warnings="error",
    )
    missing_id = "ref.e4m-calc-062"
    for finding in values["safety_findings"]:
        finding["reference_ids"] = [
            item for item in finding["reference_ids"] if item != missing_id
        ]
    for scenario in values["scenarios"]:
        scenario["reference_ids"] = [
            item for item in scenario["reference_ids"] if item != missing_id
        ]
        for rule in scenario["rule_results"]:
            rule["reference_ids"] = [
                item for item in rule["reference_ids"] if item != missing_id
            ]
    forged = _refingerprint_assessment(values)

    with pytest.raises(
        ValueError,
        match=r"missing=\['ref\.e4m-calc-062'\]",
    ):
        resolve_analyzer_knowledge_links(forged)


def test_envelope_binds_exact_versions_references_and_fingerprints() -> None:
    envelope = _envelope()

    assert envelope.workflow_version == "1.0.0"
    assert envelope.model_version == "1.0.0"
    assert envelope.assistant_version == "1.0.0"
    assert envelope.ruleset_version == "1.0.0"
    assert envelope.taxonomy_version == "1.0.0"
    assert (
        envelope.request_fingerprint
        == _example("analyzer-example.liquid-ph").request_fingerprint
    )
    assert envelope.knowledge_links == ANALYZER_KNOWLEDGE_LINKS
    assert (
        envelope.integration_fingerprint
        == "4cc17461decf932d66cfbd14de2453798bbb65c509e2b5c5dee6e38016ba966d"
    )
    assert envelope.external_knowledge_access_performed is False
    assert envelope.persistence_performed is False
    assert envelope.manufacturer_or_model_selection_performed is False
    assert envelope.standards_conformity_claimed is False
    assert envelope.final_design_approval_granted is False


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    (
        ("request_fingerprint", "0" * 64, "request_fingerprint"),
        ("integration_fingerprint", "f" * 64, "integration_fingerprint"),
        ("workflow_version", "2.0.0", "Input should be '1.0.0'"),
        ("persistence_performed", True, "Input should be False"),
        (
            "manufacturer_or_model_selection_performed",
            True,
            "Input should be False",
        ),
    ),
)
def test_envelope_rejects_tampered_scalar_contracts(
    field_name: str,
    value: object,
    message: str,
) -> None:
    values = _envelope().model_dump(
        mode="python",
        round_trip=True,
        warnings="error",
    )
    values[field_name] = value
    with pytest.raises(ValidationError, match=message):
        AnalyzerAssessmentEnvelope.model_validate(values)


def test_envelope_rejects_reordered_links_and_mismatched_assessment() -> None:
    values = _envelope().model_dump(
        mode="python",
        round_trip=True,
        warnings="error",
    )
    values["knowledge_links"] = tuple(reversed(values["knowledge_links"]))
    with pytest.raises(ValidationError, match="knowledge_links do not match"):
        AnalyzerAssessmentEnvelope.model_validate(values)

    values = _envelope().model_dump(
        mode="python",
        round_trip=True,
        warnings="error",
    )
    values["assessment"] = _assessment("analyzer-example.process-gas-oxygen")
    with pytest.raises(ValidationError, match="request_fingerprint"):
        AnalyzerAssessmentEnvelope.model_validate(values)


def test_integration_fingerprint_is_deterministic_and_order_sensitive() -> None:
    assessment = _assessment()
    links = resolve_analyzer_knowledge_links(assessment)
    expected = build_analyzer_integration_fingerprint(assessment, links)

    assert expected == build_analyzer_integration_fingerprint(assessment, links)
    assert expected != build_analyzer_integration_fingerprint(
        assessment,
        tuple(reversed(links)),
    )
    assert len(expected) == 64
    assert expected == expected.lower()


def test_nine_examples_have_exact_reviewed_identities_and_outcomes() -> None:
    assert isinstance(ANALYZER_DESIGN_CASE_REGISTRY, MappingProxyType)
    assert len(ANALYZER_DESIGN_CASE_EXAMPLES) == 9
    assert tuple(item.example_id for item in ANALYZER_DESIGN_CASE_EXAMPLES) == tuple(
        EXPECTED_EXAMPLE_CONTRACTS
    )
    assert tuple(ANALYZER_DESIGN_CASE_REGISTRY) == tuple(
        (example_id, 1) for example_id in EXPECTED_EXAMPLE_CONTRACTS
    )

    for example in ANALYZER_DESIGN_CASE_EXAMPLES:
        (
            expected_status,
            expected_request_fingerprint,
            expected_assessment_fingerprint,
            expected_example_fingerprint,
            expected_scenarios,
        ) = EXPECTED_EXAMPLE_CONTRACTS[example.example_id]
        assert example.revision == 1
        assert example.request.request_id == example.example_id
        assert example.expected_status.value == expected_status
        assert example.request_fingerprint == expected_request_fingerprint
        assert (
            example.expected_assessment_fingerprint == expected_assessment_fingerprint
        )
        assert example.example_fingerprint == expected_example_fingerprint
        assert (
            tuple(
                (item.technology.value, item.disposition.value)
                for item in example.expected_scenarios
            )
            == expected_scenarios
        )
        assert example.illustrative_only is True
        assert example.persisted is False
        assert example.approved_for_project_use is False
        assert example.manufacturer_or_model_selected is False
        assert example.final_brand_selection == "user_decision_required"
        assert example.standards_conformity_claimed is False
        assert example.final_design_approval_granted is False

    with pytest.raises(TypeError):
        ANALYZER_DESIGN_CASE_REGISTRY[("analyzer-example.new", 1)] = (  # type: ignore[index]
            ANALYZER_DESIGN_CASE_EXAMPLES[0]
        )


def test_all_examples_replay_deterministically_with_exact_reference_closure() -> None:
    for example in ANALYZER_DESIGN_CASE_EXAMPLES:
        first = validate_analyzer_design_case_example(example)
        second = validate_analyzer_design_case_example(example)
        direct = assess_analyzer_application(example.request)

        assert first == second == direct
        assert first is not second
        assert first.request == example.request
        assert first.status is example.expected_status
        assert first.assessment_fingerprint == example.expected_assessment_fingerprint
        assert resolve_analyzer_knowledge_links(first) == ANALYZER_KNOWLEDGE_LINKS


def test_example_rejects_stale_fingerprints_and_revision_drift() -> None:
    example = _example("analyzer-example.liquid-ph")
    for field_name, value, message in (
        ("request_fingerprint", "0" * 64, "request_fingerprint"),
        ("example_fingerprint", "f" * 64, "example_fingerprint"),
        ("revision", 2, "revision 1"),
    ):
        values = example.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )
        values[field_name] = value
        with pytest.raises(ValidationError, match=message):
            AnalyzerDesignCaseExample.model_validate(values)


def test_example_expected_scenarios_require_sorted_unique_technologies() -> None:
    example = _example("analyzer-example.gas-chromatography")
    values = example.model_dump(
        mode="python",
        round_trip=True,
        warnings="error",
    )
    values["expected_scenarios"] = tuple(reversed(values["expected_scenarios"]))
    with pytest.raises(ValidationError, match="ordered by technology"):
        AnalyzerDesignCaseExample.model_validate(values)

    values = example.model_dump(
        mode="python",
        round_trip=True,
        warnings="error",
    )
    values["expected_scenarios"] = (
        values["expected_scenarios"][0],
        values["expected_scenarios"][0],
    )
    with pytest.raises(ValidationError, match="technologies must be unique"):
        AnalyzerDesignCaseExample.model_validate(values)


def test_runtime_replay_rejects_refingerprinted_expected_outcome_drift() -> None:
    example = _example("analyzer-example.liquid-ph")
    values = example.model_dump(
        mode="python",
        round_trip=True,
        warnings="error",
    )
    values["expected_status"] = CalculationStatus.BLOCKED
    forged = _rebuild_example(values)
    with pytest.raises(ValueError, match="status drifted"):
        validate_analyzer_design_case_example(forged)

    values = example.model_dump(
        mode="python",
        round_trip=True,
        warnings="error",
    )
    values["expected_scenarios"] = (
        AnalyzerExpectedScenario(
            technology=AnalyzerTechnology.PH_ELECTRODE,
            disposition=AnalyzerScenarioDisposition.BLOCKED,
        ),
    )
    forged = _rebuild_example(values)
    with pytest.raises(ValueError, match="scenario contract drifted"):
        validate_analyzer_design_case_example(forged)

    values = example.model_dump(
        mode="python",
        round_trip=True,
        warnings="error",
    )
    values["expected_assessment_fingerprint"] = "0" * 64
    forged = _rebuild_example(values)
    with pytest.raises(ValueError, match="assessment fingerprint drifted"):
        validate_analyzer_design_case_example(forged)


def test_negative_zero_has_one_canonical_fingerprint_identity() -> None:
    assert fingerprint_analyzer_payload(
        {"nested": [1, -0.0], "text": "μ"}
    ) == fingerprint_analyzer_payload({"text": "μ", "nested": (1, 0.0)})

    example = _example("analyzer-example.liquid-ph")
    request_values = example.request.model_dump(
        mode="python",
        round_trip=True,
        warnings="error",
    )
    request_values["measurement"]["analytes"][0]["expected_minimum"] = -0.0
    negative_zero_request = AnalyzerApplicationRequest.model_validate(request_values)
    assert fingerprint_analyzer_payload(negative_zero_request) == (
        example.request_fingerprint
    )
    assert (
        build_analyzer_example_fingerprint(
            example_id=example.example_id,
            revision=example.revision,
            request=negative_zero_request,
            expected_status=example.expected_status,
            expected_scenarios=example.expected_scenarios,
            expected_assessment_fingerprint=example.expected_assessment_fingerprint,
        )
        == example.example_fingerprint
    )


def test_workflow_module_has_no_persistence_network_or_repository_imports() -> None:
    tree = ast.parse(inspect.getsource(workflow_module))
    imported_modules: set[str] = set()
    called_names: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called_names.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                called_names.add(node.func.attr)

    forbidden_roots = {
        "aiohttp",
        "alembic",
        "asyncio",
        "boto3",
        "httpx",
        "importlib",
        "os",
        "pathlib",
        "psycopg",
        "redis",
        "requests",
        "socket",
        "sqlalchemy",
        "sqlmodel",
        "subprocess",
        "urllib",
    }
    imported_roots = {module_name.split(".", 1)[0] for module_name in imported_modules}
    assert imported_roots.isdisjoint(forbidden_roots)
    assert not any(
        fragment in module_name.casefold()
        for module_name in imported_modules
        for fragment in ("database", "persistence", "repository")
    )
    assert not any(
        module_name.startswith(prefix)
        for module_name in imported_modules
        for prefix in (
            "app.api",
            "app.db",
            "app.knowledge",
            "app.repositories",
            "app.services",
        )
    )
    assert called_names.isdisjoint(
        {"__import__", "compile", "eval", "exec", "open", "system"}
    )
    assert not any(
        isinstance(node, (ast.AsyncFunctionDef, ast.Await)) for node in ast.walk(tree)
    )
