"""Fail-closed tests for the Step 111 knowledge/calculation adapter."""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.engineering.calculations import (
    ENGINE_VERSION,
    ENGINEERING_METHOD_REGISTRY,
    GENERAL_METHOD_REGISTRATIONS,
)
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.registry import (
    CalculationMethodRegistry,
    MethodRegistration,
)
from app.engineering.knowledge_calculation_adapter import (
    MAX_LINK_IDENTIFIERS,
    ControlledCalculationKnowledgeAdapter,
    KnowledgeCalculationReferenceError,
    KnowledgeMethodBinding,
    fingerprint_knowledge,
    fingerprint_method_definition,
)
from app.engineering.knowledge_models import (
    EngineeringCalculationReference,
    EngineeringDiscipline,
    EngineeringFormula,
    EngineeringKnowledge,
    EvidenceReference,
    EvidenceStrength,
    EvidenceType,
    KnowledgeCategory,
    KnowledgeReview,
    KnowledgeStatus,
    ReviewDecision,
    ReviewType,
    RevisionMetadata,
    SafetyGuidance,
    SafetySeverity,
    StandardApplicability,
    StandardReference,
    VerificationRequirement,
)

FIXED_TIME = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
KNOWLEDGE_ID = "knowledge.pressure-basis"
KNOWLEDGE_REVISION = "1.0"
CALCULATION_REFERENCE_ID = "knowledge.calculation.pressure-basis"
METHOD_ID = "general.pressure.gauge-to-absolute"
METHOD_VERSION = "1.0.0"
CALCULATION_TYPE = "general.pressure.gauge-to-absolute"
BINDING_ID = "binding.knowledge.pressure-basis"


def approved_review(review_type: ReviewType) -> KnowledgeReview:
    """Return one completed review for a published knowledge fixture."""

    return KnowledgeReview(
        review_type=review_type,
        decision=ReviewDecision.APPROVED,
        reviewer_name="Step 111 reviewer",
        reviewer_role="Competent engineering reviewer",
        reviewed_at=FIXED_TIME,
    )


def knowledge_calculation_reference(
    *,
    calculation_id: str = CALCULATION_REFERENCE_ID,
    expression: str = "P_abs = P_gauge + P_atmosphere",
) -> EngineeringCalculationReference:
    """Return inert knowledge metadata for the approved registered method."""

    return EngineeringCalculationReference(
        calculation_id=calculation_id,
        title="Gauge-to-absolute pressure conversion reference",
        purpose=(
            "Describe the controlled conversion without carrying executable "
            "application code."
        ),
        formulas=[
            EngineeringFormula(
                formula_id="knowledge.formula.pressure-basis",
                name="Pressure-basis relationship",
                expression=expression,
                description=(
                    "Knowledge-only formula text requiring a separately "
                    "approved application method."
                ),
                variables={
                    "P_abs": "Absolute pressure",
                    "P_gauge": "Gauge pressure",
                    "P_atmosphere": "Atmospheric absolute pressure",
                },
            )
        ],
        required_inputs=[
            "Gauge pressure",
            "Atmospheric absolute pressure",
        ],
        required_units={
            "Gauge pressure": "pressure",
            "Atmospheric absolute pressure": "pressure",
        },
        validation_rules=["Pressure basis must be explicit."],
        safety_warnings=["Do not substitute differential pressure for gauge pressure."],
        verification_requirements=[
            VerificationRequirement(
                verification_id="verify.knowledge-calculation",
                description="Verify the pressure basis and local atmosphere.",
                method="Independent engineering review",
                expected_result="Both pressure bases are explicit.",
            )
        ],
    )


def published_knowledge(
    *,
    status: KnowledgeStatus = KnowledgeStatus.PUBLISHED,
    calculations: list[EngineeringCalculationReference] | None = None,
    blocking_safety: bool = False,
) -> EngineeringKnowledge:
    """Return a fully reviewed knowledge record with calculation metadata."""

    return EngineeringKnowledge(
        knowledge_id=KNOWLEDGE_ID,
        title="Controlled pressure-basis calculation knowledge",
        subject="Gauge and absolute pressure",
        summary=(
            "A controlled knowledge reference for explicit pressure-basis conversion."
        ),
        detailed_guidance=(
            "Use an approved application calculation method and an explicit "
            "local atmospheric absolute pressure. Formula text in this "
            "record is descriptive metadata only."
        ),
        discipline=EngineeringDiscipline.INSTRUMENTATION,
        categories=[KnowledgeCategory.CALCULATION],
        status=status,
        safety=SafetyGuidance(
            safety_summary=(
                "Confirm the pressure basis before using a pressure result "
                "for design or selection."
            ),
            severity=SafetySeverity.WARNING,
            required_site_risk_assessment=True,
            blocks_work_until_resolved=blocking_safety,
        ),
        standards=[
            StandardReference(
                organisation="BIPM",
                standard_number="SI Brochure",
                title="The International System of Units",
                edition="9",
                publication_year=2019,
                clause="Pressure units",
                applicability=StandardApplicability.INFORMATIVE,
            )
        ],
        evidence=[
            EvidenceReference(
                evidence_id="evidence.pressure-basis",
                evidence_type=EvidenceType.ENGINEERING_TEXTBOOK,
                title="Pressure measurement basis reference",
                strength=EvidenceStrength.HIGH,
                verified=True,
                verified_by="Step 111 reviewer",
                verified_at=FIXED_TIME,
            )
        ],
        calculations=(
            [knowledge_calculation_reference()]
            if calculations is None
            else calculations
        ),
        verification_requirements=[
            VerificationRequirement(
                verification_id="verify.knowledge-record",
                description="Verify the controlled knowledge revision.",
                method="Revision and evidence review",
                expected_result="The intended published revision is used.",
            )
        ],
        reviews=[
            approved_review(ReviewType.TECHNICAL),
            approved_review(ReviewType.SAFETY),
            approved_review(ReviewType.STANDARDS),
            approved_review(ReviewType.FINAL_APPROVAL),
        ],
        revision_metadata=RevisionMetadata(
            revision=KNOWLEDGE_REVISION,
            created_by="Step 111 test suite",
            created_at=FIXED_TIME,
        ),
        confidence_score=95.0,
    )


def knowledge_binding(
    *,
    knowledge: EngineeringKnowledge | None = None,
    **updates: object,
) -> KnowledgeMethodBinding:
    """Return the exact application-owned knowledge/method binding."""

    bound_knowledge = published_knowledge() if knowledge is None else knowledge
    definition = ENGINEERING_METHOD_REGISTRY.resolve(
        METHOD_ID,
        METHOD_VERSION,
        calculation_type=CALCULATION_TYPE,
    )
    values: dict[str, object] = {
        "binding_id": BINDING_ID,
        "knowledge_id": KNOWLEDGE_ID,
        "knowledge_revision": KNOWLEDGE_REVISION,
        "calculation_reference_id": CALCULATION_REFERENCE_ID,
        "method_id": METHOD_ID,
        "method_version": METHOD_VERSION,
        "calculation_type": CALCULATION_TYPE,
        "engine_version": ENGINE_VERSION,
        "knowledge_fingerprint": fingerprint_knowledge(bound_knowledge),
        "method_definition_fingerprint": fingerprint_method_definition(definition),
    }
    values.update(updates)
    return KnowledgeMethodBinding(**values)


def knowledge_adapter(
    *,
    registry: CalculationMethodRegistry = ENGINEERING_METHOD_REGISTRY,
    bindings: tuple[KnowledgeMethodBinding, ...] | None = None,
) -> ControlledCalculationKnowledgeAdapter:
    """Return an adapter using the immutable production calculation registry."""

    return ControlledCalculationKnowledgeAdapter(
        registry=registry,
        bindings=(knowledge_binding(),) if bindings is None else bindings,
    )


def test_published_knowledge_links_only_to_exact_approved_registration() -> None:
    """A published record may link to one exact executable registration."""

    link = knowledge_adapter().resolve_link(
        published_knowledge(),
        CALCULATION_REFERENCE_ID,
    )

    assert link.method_lifecycle_status is MethodLifecycleStatus.APPROVED
    assert link.binding_id == BINDING_ID
    assert link.knowledge_id == KNOWLEDGE_ID
    assert link.knowledge_revision == KNOWLEDGE_REVISION
    assert link.calculation_reference_id == CALCULATION_REFERENCE_ID
    assert link.method_id == METHOD_ID
    assert link.method_version == METHOD_VERSION
    assert link.calculation_type == CALCULATION_TYPE
    assert link.engine_version == ENGINE_VERSION


def test_link_preserves_controlled_knowledge_provenance() -> None:
    """Evidence, standards, safety, and verification links remain visible."""

    link = knowledge_adapter().resolve_link(
        published_knowledge(),
        CALCULATION_REFERENCE_ID,
    )

    assert "evidence.pressure-basis" in link.knowledge_evidence_ids
    assert "evidence.pressure-basis" in link.verified_knowledge_evidence_ids
    assert link.knowledge_standards
    assert link.knowledge_safety is not None
    assert link.knowledge_safety.severity is SafetySeverity.WARNING
    assert link.knowledge_safety.blocks_work_until_resolved is False
    assert {
        "verify.knowledge-calculation",
        "verify.knowledge-record",
    }.issubset(set(link.knowledge_verification_ids))
    assert link.method_reference_ids


def test_link_fingerprints_are_deterministic_and_exact() -> None:
    """Repeated resolution binds the same exact knowledge and method bytes."""

    adapter = knowledge_adapter()
    knowledge = published_knowledge()

    first = adapter.resolve_link(knowledge, CALCULATION_REFERENCE_ID)
    second = adapter.resolve_link(knowledge, CALCULATION_REFERENCE_ID)

    assert first == second
    for fingerprint in (
        first.knowledge_fingerprint,
        first.method_definition_fingerprint,
        first.link_fingerprint,
    ):
        assert len(fingerprint) == 64
        assert fingerprint == fingerprint.lower()
        int(fingerprint, 16)


def test_same_identity_with_modified_knowledge_content_fails_closed() -> None:
    """Matching IDs and revision cannot bypass the content fingerprint."""

    original = published_knowledge()
    payload = original.model_dump(mode="python", round_trip=True)
    payload["summary"] = "Changed after the application binding was approved."
    modified = EngineeringKnowledge.model_validate(payload)

    with pytest.raises(ValueError, match="fingerprint"):
        knowledge_adapter().resolve_link(
            modified,
            CALCULATION_REFERENCE_ID,
        )


def test_changed_method_metadata_fingerprint_fails_at_construction() -> None:
    """The registry method metadata must match the reviewed binding bytes."""

    binding = knowledge_binding().model_copy(
        update={"method_definition_fingerprint": "0" * 64}
    )

    with pytest.raises(ValueError, match="fingerprint"):
        knowledge_adapter(bindings=(binding,))


def test_binding_copy_revalidates_fingerprint_format_and_content_boundary() -> None:
    """Copies validate syntax; adapter resolution validates bound knowledge bytes."""

    binding = knowledge_binding()
    with pytest.raises(ValueError, match="fingerprint|64"):
        binding.model_copy(update={"knowledge_fingerprint": "unchecked"})

    changed = binding.model_copy(update={"knowledge_fingerprint": "0" * 64})
    adapter = knowledge_adapter(bindings=(changed,))
    with pytest.raises(ValueError, match="fingerprint"):
        adapter.resolve_link(
            published_knowledge(),
            CALCULATION_REFERENCE_ID,
        )


@pytest.mark.parametrize(
    "field_name",
    (
        "knowledge_fingerprint",
        "method_definition_fingerprint",
        "link_fingerprint",
    ),
)
def test_link_copy_rejects_fingerprint_changing_updates(field_name: str) -> None:
    """A copied link cannot retain valid provenance after a hash field changes."""

    link = knowledge_adapter().resolve_link(
        published_knowledge(),
        CALCULATION_REFERENCE_ID,
    )

    with pytest.raises(ValueError, match="fingerprint|provenance"):
        link.model_copy(update={field_name: "0" * 64})


@pytest.mark.parametrize(
    "status",
    tuple(
        status for status in KnowledgeStatus if status is not KnowledgeStatus.PUBLISHED
    ),
)
def test_every_unpublished_knowledge_status_is_inert(
    status: KnowledgeStatus,
) -> None:
    """Only published, fully reviewed knowledge may cross the adapter."""

    with pytest.raises(ValueError, match="(?i)published"):
        knowledge_adapter().resolve_link(
            published_knowledge(status=status),
            CALCULATION_REFERENCE_ID,
        )


def test_draft_formula_is_rejected_before_registry_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Draft formula text cannot cause even an approved registry lookup."""

    adapter = knowledge_adapter()
    draft = published_knowledge(status=KnowledgeStatus.DRAFT)

    def unexpected_registry_resolution(*args: object, **kwargs: object) -> None:
        raise AssertionError("draft knowledge reached the execution registry")

    monkeypatch.setattr(
        CalculationMethodRegistry,
        "resolve_for_execution",
        unexpected_registry_resolution,
    )

    with pytest.raises(ValueError, match="(?i)published"):
        adapter.resolve_link(draft, CALCULATION_REFERENCE_ID)


def test_oversized_knowledge_projection_fails_before_fingerprint_or_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bound legacy knowledge collections before hashing or method resolution."""

    payload = published_knowledge().model_dump(mode="python", round_trip=True)
    payload["evidence"] = [
        EvidenceReference(
            evidence_id=f"evidence-{index}",
            evidence_type=EvidenceType.ENGINEERING_TEXTBOOK,
            title=f"Bounded evidence source {index}",
            strength=EvidenceStrength.HIGH,
            verified=index == 0,
            verified_by="Step 113 reviewer" if index == 0 else None,
            verified_at=FIXED_TIME if index == 0 else None,
        )
        for index in range(MAX_LINK_IDENTIFIERS + 1)
    ]
    oversized = EngineeringKnowledge.model_validate(payload)
    adapter = knowledge_adapter(bindings=(knowledge_binding(knowledge=oversized),))

    def unexpected_trusted_resolution(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("oversized knowledge reached trusted resolution")

    monkeypatch.setattr(
        "app.engineering.knowledge_calculation_adapter.fingerprint_knowledge",
        unexpected_trusted_resolution,
    )
    monkeypatch.setattr(
        CalculationMethodRegistry,
        "resolve_for_execution",
        unexpected_trusted_resolution,
    )

    with pytest.raises(KnowledgeCalculationReferenceError, match="bound") as captured:
        adapter.resolve_link(oversized, CALCULATION_REFERENCE_ID)

    assert captured.value.code == "knowledge_calculation_reference_error"


def test_empty_legacy_standard_metadata_uses_owned_adapter_error() -> None:
    """Legacy empty optional strings never leak raw Pydantic validation."""

    payload = published_knowledge().model_dump(mode="python", round_trip=True)
    payload["standards"] = [
        StandardReference(
            organisation="BIPM",
            standard_number="SI Brochure",
            title="The International System of Units",
            edition="",
            clause="",
            jurisdiction="",
            applicability=StandardApplicability.INFORMATIVE,
        )
    ]
    knowledge = EngineeringKnowledge.model_validate(payload)
    adapter = knowledge_adapter(bindings=(knowledge_binding(knowledge=knowledge),))

    with pytest.raises(
        KnowledgeCalculationReferenceError,
        match="standard metadata",
    ) as captured:
        adapter.resolve_link(knowledge, CALCULATION_REFERENCE_ID)

    assert captured.value.code == "knowledge_calculation_reference_error"


def test_method_looking_formula_text_is_never_executed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the configured binding selects code; formula strings stay inert."""

    expression = "__import__('os').system('formula text executed')"
    reference = knowledge_calculation_reference(expression=expression)
    knowledge = published_knowledge(calculations=[reference])

    def unexpected_system_call(*args: object, **kwargs: object) -> None:
        raise AssertionError("knowledge formula text was executed")

    monkeypatch.setattr("os.system", unexpected_system_call)

    link = knowledge_adapter(
        bindings=(knowledge_binding(knowledge=knowledge),)
    ).resolve_link(
        knowledge,
        CALCULATION_REFERENCE_ID,
    )

    assert link.method_id == METHOD_ID
    assert expression not in link.model_dump_json()


def test_unconfigured_knowledge_calculation_cannot_link() -> None:
    """A caller cannot choose an arbitrary calculation reference or method."""

    with pytest.raises(ValueError):
        knowledge_adapter().resolve_link(
            published_knowledge(),
            "knowledge.calculation.unconfigured",
        )


@pytest.mark.parametrize(
    "binding_update",
    (
        {"knowledge_revision": "2.0"},
        {"method_version": "9.9.9"},
        {"calculation_type": "general.pressure.wrong-type"},
        {"engine_version": "99.0.0"},
    ),
)
def test_revision_version_type_and_engine_mismatches_fail_closed(
    binding_update: dict[str, str],
) -> None:
    """No latest-version fallback or type/engine coercion is permitted."""

    binding = knowledge_binding(**binding_update)

    with pytest.raises(ValueError):
        knowledge_adapter(bindings=(binding,)).resolve_link(
            published_knowledge(),
            CALCULATION_REFERENCE_ID,
        )


def test_unapproved_registered_method_cannot_link() -> None:
    """Registration alone is insufficient; the method must be approved."""

    approved = next(
        item for item in GENERAL_METHOD_REGISTRATIONS if item.method_id == METHOD_ID
    )
    draft_definition = approved.definition.model_copy(
        update={"lifecycle_status": MethodLifecycleStatus.DRAFT}
    )
    draft_registration = MethodRegistration(
        definition=draft_definition,
        implementation=approved.implementation,
        input_normalizers=approved.input_normalizers,
        applicability_evaluators=approved.applicability_evaluators,
        safety_evaluator=approved.safety_evaluator,
    )
    registry = CalculationMethodRegistry((draft_registration,))

    with pytest.raises(ValueError, match="approved|execution"):
        knowledge_adapter(registry=registry).resolve_link(
            published_knowledge(),
            CALCULATION_REFERENCE_ID,
        )


def test_case_conflicting_calculation_references_are_rejected() -> None:
    """A case variant cannot create an ambiguous calculation reference."""

    first = knowledge_calculation_reference()
    second = knowledge_calculation_reference(
        calculation_id=CALCULATION_REFERENCE_ID.upper()
    )
    knowledge = published_knowledge(calculations=[first, second])

    with pytest.raises(ValueError, match="unique|ambiguous|calculation"):
        knowledge_adapter(
            bindings=(knowledge_binding(knowledge=knowledge),)
        ).resolve_link(
            knowledge,
            CALCULATION_REFERENCE_ID,
        )


def test_case_conflicting_binding_ids_are_rejected() -> None:
    """Construction rejects ambiguous application-owned binding identities."""

    second = knowledge_binding(
        binding_id=BINDING_ID.upper(),
        knowledge_id="knowledge.other-pressure-basis",
    )

    with pytest.raises(ValueError, match="binding|unique|duplicate"):
        knowledge_adapter(bindings=(knowledge_binding(), second))


def test_same_verification_id_across_scopes_is_rejected() -> None:
    """Equal IDs in distinct scopes cannot collapse into one provenance item."""

    knowledge = published_knowledge()
    payload = knowledge.model_dump(mode="python", round_trip=True)
    payload["verification_requirements"] = [
        VerificationRequirement(
            verification_id="verify.knowledge-calculation",
            description="Conflicting verification identity.",
            method="Independent review",
            expected_result="The duplicate must be rejected.",
        )
    ]
    conflicting = EngineeringKnowledge.model_validate(payload)

    with pytest.raises(ValueError, match="verification|unique"):
        knowledge_adapter(
            bindings=(knowledge_binding(knowledge=conflicting),)
        ).resolve_link(
            conflicting,
            CALCULATION_REFERENCE_ID,
        )


def test_adapter_and_link_are_immutable() -> None:
    """Bindings and resolved provenance cannot be replaced after validation."""

    adapter = knowledge_adapter()
    link = adapter.resolve_link(
        published_knowledge(),
        CALCULATION_REFERENCE_ID,
    )

    with pytest.raises((AttributeError, TypeError, ValueError)):
        adapter.bindings = ()  # type: ignore[attr-defined]

    with pytest.raises((AttributeError, TypeError, ValueError)):
        link.method_id = "general.pressure.untrusted"  # type: ignore[misc]


def test_adapter_source_contains_no_dynamic_execution_boundary() -> None:
    """The adapter source must not evaluate or dynamically import formula text."""

    import app.engineering.knowledge_calculation_adapter as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }.intersection({"eval", "exec", "compile", "__import__"})

    assert forbidden_calls == set()
    assert "importlib" not in source
