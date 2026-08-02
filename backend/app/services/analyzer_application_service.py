"""Immutable Step 107 service for analyzer application assessments.

The service revalidates every typed input and output, resolves only the five
compiled ENG-070 metadata links, and binds the assessment to those links in a
deterministic envelope.  It performs no persistence, database or network
access, standards execution, manufacturer lookup, or product selection.
"""

from __future__ import annotations

from collections.abc import Callable
from inspect import (
    Parameter,
    isasyncgenfunction,
    isawaitable,
    iscoroutinefunction,
    isgenerator,
    isgeneratorfunction,
    isroutine,
    signature,
)
from typing import Any, Final

from pydantic import BaseModel

from app.engineering.design.analyzer_assistant import (
    ANALYZER_ASSISTANT_VERSION,
    ANALYZER_RULESET_VERSION,
    ANALYZER_TECHNOLOGY_CATALOGUE,
    ANALYZER_TECHNOLOGY_TAXONOMY_VERSION,
    assess_analyzer_application,
)
from app.engineering.design.analyzer_models import (
    AnalyzerApplicationAssessment,
    AnalyzerApplicationRequest,
    AnalyzerTechnologyDefinition,
    fingerprint_analyzer_payload,
)
from app.engineering.design.analyzer_workflow_models import (
    ANALYZER_DESIGN_CASE_EXAMPLES,
    ANALYZER_KNOWLEDGE_LINKS,
    ANALYZER_WORKFLOW_VERSION,
    AnalyzerAssessmentEnvelope,
    AnalyzerDesignCaseExample,
    AnalyzerKnowledgeLink,
    build_analyzer_integration_fingerprint,
    resolve_analyzer_knowledge_links,
)

AnalyzerApplicationAssessor = Callable[
    [AnalyzerApplicationRequest],
    AnalyzerApplicationAssessment,
]


class AnalyzerApplicationServiceError(RuntimeError):
    """Sanitized trusted-boundary failure."""

    code = "analyzer_service_unavailable"

    def __init__(self) -> None:
        super().__init__("The controlled analyzer application service is unavailable.")


class AnalyzerApplicationInputError(RuntimeError):
    """A typed service input failed strict revalidation."""

    code = "analyzer_input_error"

    def __init__(self) -> None:
        super().__init__("The analyzer application request is invalid.")


def _fresh[ModelT: BaseModel](
    model_type: type[ModelT],
    value: object,
) -> ModelT:
    if not isinstance(value, model_type):
        raise TypeError(f"value must be an instance of {model_type.__name__}")
    return model_type.model_validate(
        value.model_dump(mode="python", round_trip=True, warnings="error")
    )


def _validate_assessor(assessor: object) -> None:
    """Require one inspectable synchronous one-request callable."""

    if not callable(assessor):
        raise TypeError("assessor must be callable")
    callable_target = assessor if isroutine(assessor) else type(assessor).__call__
    if any(
        predicate(assessor) or predicate(callable_target)
        for predicate in (
            iscoroutinefunction,
            isgeneratorfunction,
            isasyncgenfunction,
        )
    ):
        raise TypeError("assessor must be a synchronous non-generator")
    try:
        parameters = tuple(signature(assessor).parameters.values())
    except (TypeError, ValueError) as exc:
        raise TypeError("assessor must have an inspectable signature") from exc
    if (
        len(parameters) != 1
        or parameters[0].kind
        not in {Parameter.POSITIONAL_ONLY, Parameter.POSITIONAL_OR_KEYWORD}
        or parameters[0].default is not Parameter.empty
    ):
        raise TypeError("assessor must accept exactly one request argument")


class AnalyzerApplicationService:
    """Stateless, immutable boundary around the reviewed analyzer assistant."""

    __slots__ = ("_assessor", "_locked")

    def __init__(
        self,
        *,
        assessor: AnalyzerApplicationAssessor = assess_analyzer_application,
    ) -> None:
        object.__setattr__(self, "_locked", False)
        _validate_assessor(assessor)
        object.__setattr__(self, "_assessor", assessor)
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError("AnalyzerApplicationService instances are immutable.")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError("AnalyzerApplicationService instances are immutable.")
        object.__delattr__(self, name)

    @property
    def workflow_version(self) -> str:
        return ANALYZER_WORKFLOW_VERSION

    @property
    def assistant_version(self) -> str:
        return ANALYZER_ASSISTANT_VERSION

    @property
    def ruleset_version(self) -> str:
        return ANALYZER_RULESET_VERSION

    @property
    def taxonomy_version(self) -> str:
        return ANALYZER_TECHNOLOGY_TAXONOMY_VERSION

    def get_catalogue(self) -> tuple[AnalyzerTechnologyDefinition, ...]:
        try:
            return tuple(
                _fresh(AnalyzerTechnologyDefinition, item)
                for item in ANALYZER_TECHNOLOGY_CATALOGUE
            )
        except Exception as exc:
            raise AnalyzerApplicationServiceError() from exc

    def get_knowledge_links(self) -> tuple[AnalyzerKnowledgeLink, ...]:
        try:
            return tuple(
                _fresh(AnalyzerKnowledgeLink, item) for item in ANALYZER_KNOWLEDGE_LINKS
            )
        except Exception as exc:
            raise AnalyzerApplicationServiceError() from exc

    def _assess_validated(
        self,
        request: AnalyzerApplicationRequest,
    ) -> AnalyzerAssessmentEnvelope:
        try:
            assessment = self._assessor(request)
            if isawaitable(assessment):
                close = getattr(assessment, "close", None)
                if callable(close):
                    close()
                raise TypeError("assessor returned an awaitable")
            if isgenerator(assessment):
                assessment.close()
                raise TypeError("assessor returned a generator")
            validated_assessment = _fresh(
                AnalyzerApplicationAssessment,
                assessment,
            )
            if validated_assessment.request != request:
                raise ValueError("assessment request does not match service input")
            links = resolve_analyzer_knowledge_links(validated_assessment)
            envelope = AnalyzerAssessmentEnvelope(
                request_fingerprint=fingerprint_analyzer_payload(request),
                assessment=validated_assessment,
                knowledge_links=links,
                integration_fingerprint=build_analyzer_integration_fingerprint(
                    validated_assessment,
                    links,
                ),
            )
            return _fresh(AnalyzerAssessmentEnvelope, envelope)
        except AnalyzerApplicationServiceError:
            raise
        except Exception as exc:
            raise AnalyzerApplicationServiceError() from exc

    def assess(
        self,
        request: AnalyzerApplicationRequest,
    ) -> AnalyzerAssessmentEnvelope:
        try:
            validated_request = _fresh(AnalyzerApplicationRequest, request)
        except Exception as exc:
            raise AnalyzerApplicationInputError() from exc
        return self._assess_validated(validated_request)

    def get_design_case_examples(self) -> tuple[AnalyzerDesignCaseExample, ...]:
        """Return detached examples after re-running their reviewed contracts."""

        try:
            examples = tuple(
                _fresh(AnalyzerDesignCaseExample, item)
                for item in ANALYZER_DESIGN_CASE_EXAMPLES
            )
            for example in examples:
                outcome = self._assess_validated(
                    _fresh(AnalyzerApplicationRequest, example.request)
                )
                assessment = outcome.assessment
                if (
                    assessment.status is not example.expected_status
                    or assessment.assessment_fingerprint
                    != example.expected_assessment_fingerprint
                ):
                    raise ValueError("analyzer example assessment identity drifted")
                scenarios = {
                    item.technology: item.disposition for item in assessment.scenarios
                }
                if any(
                    scenarios.get(expected.technology) is not expected.disposition
                    for expected in example.expected_scenarios
                ):
                    raise ValueError("analyzer example scenario contract drifted")
            return examples
        except AnalyzerApplicationServiceError:
            raise
        except Exception as exc:
            raise AnalyzerApplicationServiceError() from exc


DEFAULT_ANALYZER_APPLICATION_SERVICE: Final = AnalyzerApplicationService()


__all__ = [
    "DEFAULT_ANALYZER_APPLICATION_SERVICE",
    "AnalyzerApplicationAssessor",
    "AnalyzerApplicationInputError",
    "AnalyzerApplicationService",
    "AnalyzerApplicationServiceError",
]
