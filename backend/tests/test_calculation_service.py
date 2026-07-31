"""Application-service tests for controlled engineering calculations."""

from __future__ import annotations

from datetime import UTC
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import ValidationError
import pytest

from app.engineering.calculations.engine import CalculationEngine
from app.engineering.calculations.engine import CalculationEvidenceError
from app.engineering.calculations.method_models import (
    CalculationMethodDefinition,
)
from app.engineering.calculations.method_models import EngineCompatibility
from app.engineering.calculations.models import CalculationRequest
from app.engineering.calculations.models import CalculationResult
from app.engineering.calculations.models import CalculationStatus
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.registry import (
    CalculationMethodRegistry,
)
from app.engineering.calculations.registry import InvalidMethodLookupError
from app.engineering.calculations.registry import (
    MethodCalculationTypeError,
)
from app.engineering.calculations.registry import MethodRegistration
from app.engineering.calculations.registry import UnknownMethodError
from app.engineering.calculations.registry import (
    UnknownMethodVersionError,
)
from app.engineering.calculations.method_models import (
    TrustedExecutionEvidence,
)
from app.services.calculation_service import CalculationEvidenceResolutionError
from app.services.calculation_service import CalculationService
from app.services.calculation_service import CalculationServiceError
from app.services.calculation_service import DEFAULT_CALCULATION_SERVICE


FIXED_TIME = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
FIXED_CALCULATION_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
FIXED_REQUEST_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")


def fixed_clock() -> datetime:
    """Return one deterministic engine timestamp."""

    return FIXED_TIME


def fixed_id_factory() -> UUID:
    """Return one deterministic engine-owned result identifier."""

    return FIXED_CALCULATION_ID


def draft_executor(context: object, iteration_controller: object) -> object:
    """Fail if a non-executable draft fixture reaches implementation code."""

    del context
    del iteration_controller
    raise AssertionError("A draft method must never execute.")


async def async_evidence_resolver(
    request: CalculationRequest,
    definition: CalculationMethodDefinition,
) -> TrustedExecutionEvidence:
    """Return evidence through a deliberately prohibited async boundary."""

    del request
    del definition
    return TrustedExecutionEvidence()


def generator_evidence_resolver(
    request: CalculationRequest,
    definition: CalculationMethodDefinition,
):
    """Yield evidence through a deliberately prohibited generator."""

    del request
    del definition
    yield TrustedExecutionEvidence()


async def async_generator_evidence_resolver(
    request: CalculationRequest,
    definition: CalculationMethodDefinition,
):
    """Yield evidence through a prohibited async-generator boundary."""

    del request
    del definition
    yield TrustedExecutionEvidence()


def one_argument_evidence_resolver(
    request: CalculationRequest,
) -> TrustedExecutionEvidence:
    """Expose an intentionally incomplete resolver signature."""

    del request
    return TrustedExecutionEvidence()


def make_definition(
    *,
    method_id: str = "fixture.service",
    method_version: str = "1.0.0",
    calculation_type: str = "fixture.service-calculation",
) -> CalculationMethodDefinition:
    """Build compact inert metadata for one discoverable draft method."""

    return CalculationMethodDefinition(
        method_id=method_id,
        method_version=method_version,
        calculation_type=calculation_type,
        title="Calculation service fixture",
        description="Inert draft metadata used only by service tests.",
        implementation_owner="Engineer4Me test engineering",
        lifecycle_status=MethodLifecycleStatus.DRAFT,
        engine_compatibility=EngineCompatibility(
            minimum_version="1.0.0",
            maximum_exclusive_version="2.0.0",
        ),
        required_reviewer_competency="Competent test engineer",
        disclaimer="Engineering decision support requires review.",
    )


def make_registry(
    *definitions: CalculationMethodDefinition,
) -> CalculationMethodRegistry:
    """Register draft fixtures against the unreachable test executor."""

    return CalculationMethodRegistry(
        MethodRegistration(
            definition=definition,
            implementation=draft_executor,
        )
        for definition in definitions
    )


def make_engine(
    *definitions: CalculationMethodDefinition,
) -> CalculationEngine:
    """Build a deterministic calculation engine for service tests."""

    return CalculationEngine(
        registry=make_registry(*definitions),
        clock=fixed_clock,
        id_factory=fixed_id_factory,
    )


def make_request(
    *,
    method_id: str = "fixture.service",
    method_version: str = "1.0.0",
    calculation_type: str = "fixture.service-calculation",
    reference_ids: tuple[str, ...] = (),
) -> CalculationRequest:
    """Build one empty-input request for an inert draft fixture."""

    return CalculationRequest(
        request_id=FIXED_REQUEST_ID,
        calculation_type=calculation_type,
        method_id=method_id,
        method_version=method_version,
        requested_at=FIXED_TIME,
        reference_ids=reference_ids,
    )


@pytest.fixture
def definition() -> CalculationMethodDefinition:
    """Return the primary service-test definition."""

    return make_definition()


@pytest.fixture
def engine(
    definition: CalculationMethodDefinition,
) -> CalculationEngine:
    """Return an engine containing the primary test method."""

    return make_engine(definition)


@pytest.fixture
def service(engine: CalculationEngine) -> CalculationService:
    """Return the default-resolver service under test."""

    return CalculationService(engine=engine)


def test_default_service_uses_empty_production_registry() -> None:
    """The application default must not silently enable a method."""

    assert DEFAULT_CALCULATION_SERVICE.engine_version == "1.0.0"
    assert DEFAULT_CALCULATION_SERVICE.method_count == 0
    assert DEFAULT_CALCULATION_SERVICE.discover_methods() == ()


def test_constructor_rejects_non_engine() -> None:
    """Only the exact immutable calculation-engine type is accepted."""

    with pytest.raises(
        TypeError,
        match="engine must be a CalculationEngine",
    ):
        CalculationService(engine=object())  # type: ignore[arg-type]


def test_constructor_rejects_non_callable_resolver(
    engine: CalculationEngine,
) -> None:
    """Evidence resolution must remain a callable server dependency."""

    with pytest.raises(
        TypeError,
        match="evidence_resolver must be callable",
    ):
        CalculationService(
            engine=engine,
            evidence_resolver=object(),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "resolver",
    (
        async_evidence_resolver,
        generator_evidence_resolver,
        async_generator_evidence_resolver,
    ),
)
def test_constructor_rejects_non_synchronous_resolver(
    engine: CalculationEngine,
    resolver: Any,
) -> None:
    """Async and generator dependencies cannot cross the sync boundary."""

    with pytest.raises(
        TypeError,
        match="must be a synchronous function",
    ):
        CalculationService(
            engine=engine,
            evidence_resolver=resolver,
        )


def test_constructor_rejects_wrong_resolver_signature(
    engine: CalculationEngine,
) -> None:
    """A resolver must accept exactly request and definition."""

    with pytest.raises(
        TypeError,
        match="accept exactly request and definition",
    ):
        CalculationService(
            engine=engine,
            evidence_resolver=one_argument_evidence_resolver,
        )


def test_service_is_immutable(
    service: CalculationService,
    engine: CalculationEngine,
) -> None:
    """Bound engine and evidence dependencies cannot be replaced or removed."""

    with pytest.raises(AttributeError, match="immutable"):
        service._engine = engine  # type: ignore[misc]

    with pytest.raises(AttributeError, match="immutable"):
        del service._evidence_resolver  # type: ignore[misc]

    assert not hasattr(service, "__dict__")


def test_properties_report_bound_engine_state(
    service: CalculationService,
) -> None:
    """Version and count describe exact method registrations."""

    assert service.engine_version == "1.0.0"
    assert service.method_count == 1


def test_discovery_is_sorted_filtered_and_fresh() -> None:
    """Discovery preserves registry ordering and revalidates every model."""

    first = make_definition(
        method_id="fixture.alpha",
        calculation_type="fixture.alpha-calculation",
    )
    second = make_definition(
        method_id="fixture.beta",
        calculation_type="fixture.beta-calculation",
    )
    engine = make_engine(second, first)
    service = CalculationService(engine=engine)

    discovered = service.discover_methods()
    filtered = service.discover_methods("fixture.beta-calculation")

    assert tuple(value.method_id for value in discovered) == (
        "fixture.alpha",
        "fixture.beta",
    )
    assert tuple(value.method_id for value in filtered) == ("fixture.beta",)
    assert all(
        returned is not registered
        for returned, registered in zip(
            discovered,
            engine.registry.definitions,
            strict=True,
        )
    )


def test_discovery_propagates_invalid_lookup(
    service: CalculationService,
) -> None:
    """Registry lookup validation remains a domain error."""

    with pytest.raises(InvalidMethodLookupError):
        service.discover_methods(calculation_type="../not-controlled")


def test_discovery_revalidates_tampered_registry_metadata(
    engine: CalculationEngine,
) -> None:
    """Previously constructed definition instances are never trusted."""

    definition = engine.registry.definitions[0]
    object.__setattr__(definition, "method_id", "x")
    service = CalculationService(engine=engine)

    with pytest.raises(ValidationError):
        service.discover_methods()


def test_available_versions_is_exact_and_deterministic() -> None:
    """Version discovery returns every exact registration without fallback."""

    service = CalculationService(
        engine=make_engine(
            make_definition(method_version="2.0.0"),
            make_definition(method_version="1.0.0"),
        )
    )

    assert service.available_versions("fixture.service") == (
        "1.0.0",
        "2.0.0",
    )


@pytest.mark.parametrize(
    ("method_id", "error_type"),
    (
        ("fixture.unknown", UnknownMethodError),
        ("../bad", InvalidMethodLookupError),
    ),
)
def test_available_versions_propagates_registry_errors(
    service: CalculationService,
    method_id: str,
    error_type: type[Exception],
) -> None:
    """Unknown and malformed lookup identities remain distinguishable."""

    with pytest.raises(error_type):
        service.available_versions(method_id)


def test_get_method_resolves_exact_fresh_metadata(
    engine: CalculationEngine,
) -> None:
    """Exact lookup returns a new validated definition instance."""

    service = CalculationService(engine=engine)
    result = service.get_method(
        "fixture.service",
        "1.0.0",
        "fixture.service-calculation",
    )

    assert result == engine.registry.definitions[0]
    assert result is not engine.registry.definitions[0]


@pytest.mark.parametrize(
    ("method_id", "method_version", "calculation_type", "error_type"),
    (
        (
            "fixture.unknown",
            "1.0.0",
            None,
            UnknownMethodError,
        ),
        (
            "fixture.service",
            "9.0.0",
            None,
            UnknownMethodVersionError,
        ),
        (
            "fixture.service",
            "1.0.0",
            "fixture.other-calculation",
            MethodCalculationTypeError,
        ),
        (
            "x",
            "1.0.0",
            None,
            InvalidMethodLookupError,
        ),
    ),
)
def test_get_method_propagates_registry_errors(
    service: CalculationService,
    method_id: str,
    method_version: str,
    calculation_type: str | None,
    error_type: type[Exception],
) -> None:
    """Exact lookup failures are not rewritten by the service."""

    with pytest.raises(error_type):
        service.get_method(
            method_id,
            method_version,
            calculation_type=calculation_type,
        )


def test_execute_uses_default_empty_evidence(
    service: CalculationService,
) -> None:
    """A method needing no external evidence executes through the boundary."""

    result = service.execute(make_request())

    assert isinstance(result, CalculationResult)
    assert result.calculation_id == FIXED_CALCULATION_ID
    assert result.request_id == FIXED_REQUEST_ID
    assert result.status is CalculationStatus.BLOCKED
    assert result.engine_version == "1.0.0"


def test_execute_passes_fresh_validated_values_to_resolver(
    engine: CalculationEngine,
) -> None:
    """The resolver receives exact metadata and a new validated request."""

    observed: dict[str, Any] = {}

    def resolver(
        request: CalculationRequest,
        definition: CalculationMethodDefinition,
    ) -> TrustedExecutionEvidence:
        observed["request"] = request
        observed["definition"] = definition
        return TrustedExecutionEvidence()

    service = CalculationService(
        engine=engine,
        evidence_resolver=resolver,
    )
    supplied_request = make_request()

    service.execute(supplied_request)

    assert observed["request"] == supplied_request
    assert observed["request"] is not supplied_request
    assert observed["definition"] == engine.registry.definitions[0]
    assert observed["definition"] is not engine.registry.definitions[0]


def test_execute_invokes_resolver_once(
    engine: CalculationEngine,
) -> None:
    """One request performs exactly one server-owned evidence resolution."""

    calls = 0

    def resolver(
        request: CalculationRequest,
        definition: CalculationMethodDefinition,
    ) -> TrustedExecutionEvidence:
        nonlocal calls
        del request
        del definition
        calls += 1
        return TrustedExecutionEvidence()

    service = CalculationService(
        engine=engine,
        evidence_resolver=resolver,
    )

    service.execute(make_request())

    assert calls == 1


def test_execute_accepts_valid_mapping_from_resolver(
    engine: CalculationEngine,
) -> None:
    """Resolver output crosses validation rather than an identity check."""

    def resolver(
        request: CalculationRequest,
        definition: CalculationMethodDefinition,
    ) -> TrustedExecutionEvidence:
        del request
        del definition
        return {}  # type: ignore[return-value]

    result = CalculationService(
        engine=engine,
        evidence_resolver=resolver,
    ).execute(make_request())

    assert result.status is CalculationStatus.BLOCKED


def test_execute_wraps_and_sanitizes_resolver_failure(
    engine: CalculationEngine,
) -> None:
    """Infrastructure details from ordinary resolver errors are not exposed."""

    original_error = RuntimeError(
        "secret database host evidence.internal.example"
    )

    def resolver(
        request: CalculationRequest,
        definition: CalculationMethodDefinition,
    ) -> TrustedExecutionEvidence:
        del request
        del definition
        raise original_error

    service = CalculationService(
        engine=engine,
        evidence_resolver=resolver,
    )

    with pytest.raises(
        CalculationEvidenceResolutionError,
        match="Trusted calculation evidence could not be resolved",
    ) as captured:
        service.execute(make_request())

    assert captured.value.__cause__ is original_error
    assert "secret" not in str(captured.value)
    assert isinstance(captured.value, CalculationServiceError)
    assert (
        captured.value.code
        == "calculation_evidence_resolution_error"
    )


@pytest.mark.parametrize(
    "invalid_evidence",
    (
        object(),
        TrustedExecutionEvidence.model_construct(
            references="not-an-ordered-collection",
        ),
    ),
)
def test_execute_wraps_invalid_resolver_output(
    engine: CalculationEngine,
    invalid_evidence: object,
) -> None:
    """Malformed trusted evidence is a sanitized resolution failure."""

    def resolver(
        request: CalculationRequest,
        definition: CalculationMethodDefinition,
    ) -> TrustedExecutionEvidence:
        del request
        del definition
        return invalid_evidence  # type: ignore[return-value]

    service = CalculationService(
        engine=engine,
        evidence_resolver=resolver,
    )

    with pytest.raises(CalculationEvidenceResolutionError) as captured:
        service.execute(make_request())

    assert captured.value.__cause__ is not None
    assert "not-an-ordered-collection" not in str(captured.value)


@pytest.mark.parametrize("return_kind", ("awaitable", "generator"))
def test_execute_closes_deferred_resolver_output_before_wrapping(
    engine: CalculationEngine,
    return_kind: str,
) -> None:
    """A deceptive sync resolver cannot leak deferred execution or warnings."""

    def resolver(
        request: CalculationRequest,
        definition: CalculationMethodDefinition,
    ) -> Any:
        del request
        del definition
        if return_kind == "awaitable":
            return async_evidence_resolver(
                make_request(),
                make_definition(),
            )
        return generator_evidence_resolver(
            make_request(),
            make_definition(),
        )

    service = CalculationService(
        engine=engine,
        evidence_resolver=resolver,
    )

    with pytest.raises(CalculationEvidenceResolutionError):
        service.execute(make_request())


class ResolverStopSignal(BaseException):
    """Process-control signal used to verify the exception boundary."""


@pytest.mark.parametrize(
    "signal",
    (
        KeyboardInterrupt(),
        SystemExit(3),
        ResolverStopSignal(),
    ),
)
def test_execute_does_not_wrap_process_control(
    engine: CalculationEngine,
    signal: BaseException,
) -> None:
    """BaseException process-control signals must propagate unchanged."""

    def resolver(
        request: CalculationRequest,
        definition: CalculationMethodDefinition,
    ) -> TrustedExecutionEvidence:
        del request
        del definition
        raise signal

    service = CalculationService(
        engine=engine,
        evidence_resolver=resolver,
    )

    with pytest.raises(type(signal)) as captured:
        service.execute(make_request())

    assert captured.value is signal


def test_execute_revalidates_request_before_resolver(
    engine: CalculationEngine,
) -> None:
    """A constructed invalid request cannot cross into dependencies."""

    resolver_called = False

    def resolver(
        request: CalculationRequest,
        definition: CalculationMethodDefinition,
    ) -> TrustedExecutionEvidence:
        nonlocal resolver_called
        del request
        del definition
        resolver_called = True
        return TrustedExecutionEvidence()

    invalid_request = CalculationRequest.model_construct(
        request_id=FIXED_REQUEST_ID,
        calculation_type="fixture.service-calculation",
        method_id="x",
        method_version="1.0.0",
        requested_at=FIXED_TIME,
    )
    service = CalculationService(
        engine=engine,
        evidence_resolver=resolver,
    )

    with pytest.raises(ValidationError):
        service.execute(invalid_request)

    assert resolver_called is False


@pytest.mark.parametrize(
    ("calculation_request", "error_type"),
    (
        (
            make_request(method_id="fixture.unknown"),
            UnknownMethodError,
        ),
        (
            make_request(method_version="9.0.0"),
            UnknownMethodVersionError,
        ),
        (
            make_request(calculation_type="fixture.other-calculation"),
            MethodCalculationTypeError,
        ),
    ),
)
def test_execute_propagates_registry_domain_errors_before_resolution(
    engine: CalculationEngine,
    calculation_request: CalculationRequest,
    error_type: type[Exception],
) -> None:
    """Exact registry failures retain their original domain types."""

    resolver_called = False

    def resolver(
        validated_request: CalculationRequest,
        definition: CalculationMethodDefinition,
    ) -> TrustedExecutionEvidence:
        nonlocal resolver_called
        del validated_request
        del definition
        resolver_called = True
        return TrustedExecutionEvidence()

    service = CalculationService(
        engine=engine,
        evidence_resolver=resolver,
    )

    with pytest.raises(error_type):
        service.execute(calculation_request)

    assert resolver_called is False


def test_execute_propagates_engine_evidence_error_unchanged(
    service: CalculationService,
) -> None:
    """Foundation engine errors are not rewritten as resolver failures."""

    request = make_request(reference_ids=("ref.external",))

    with pytest.raises(CalculationEvidenceError):
        service.execute(request)


def test_execute_revalidates_engine_result(
    engine: CalculationEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid result object cannot escape through the service."""

    def invalid_execute(
        bound_engine: CalculationEngine,
        request: CalculationRequest,
        *,
        evidence: TrustedExecutionEvidence | None = None,
    ) -> CalculationResult:
        del bound_engine
        del request
        del evidence
        return CalculationResult.model_construct()

    monkeypatch.setattr(CalculationEngine, "execute", invalid_execute)
    service = CalculationService(engine=engine)

    with pytest.raises(ValidationError):
        service.execute(make_request())


def test_execute_returns_fresh_result_instance(
    engine: CalculationEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even a valid engine result is copied through model validation."""

    source_result = engine.execute(make_request())

    def captured_execute(
        bound_engine: CalculationEngine,
        request: CalculationRequest,
        *,
        evidence: TrustedExecutionEvidence | None = None,
    ) -> CalculationResult:
        del bound_engine
        del request
        del evidence
        return source_result

    monkeypatch.setattr(CalculationEngine, "execute", captured_execute)
    result = CalculationService(engine=engine).execute(make_request())

    assert result == source_result
    assert result is not source_result
