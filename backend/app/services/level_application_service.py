"""Immutable service boundary for the Step 96 level application wizard.

The service accepts one already typed application request, revalidates it at
the trust boundary, invokes one synchronous reviewed assessor, and freshly
revalidates the returned assessment.  It has no database, network, dynamic
execution, or calculation-method dispatch path.
"""

from __future__ import annotations

from collections.abc import Callable
from inspect import Parameter
from inspect import isasyncgenfunction
from inspect import isawaitable
from inspect import iscoroutinefunction
from inspect import isgenerator
from inspect import isgeneratorfunction
from inspect import signature
from typing import Any
from typing import Final
from typing import TypeVar

from pydantic import BaseModel

from app.engineering.design.level_application_models import (
    LevelApplicationAssessment,
)
from app.engineering.design.level_application_models import (
    LevelApplicationRequest,
)
from app.engineering.design.level_application_wizard import (
    LEVEL_APPLICATION_WIZARD_VERSION,
)
from app.engineering.design.level_application_wizard import (
    assess_level_application,
)


LevelApplicationAssessor = Callable[
    [LevelApplicationRequest],
    LevelApplicationAssessment,
]

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class LevelApplicationServiceError(RuntimeError):
    """Raised when the controlled wizard boundary cannot return a result."""

    code = "level_application_service_unavailable"

    def __init__(self) -> None:
        super().__init__(
            "The level application assessment service is unavailable."
        )


def _fresh_model(model_type: type[_ModelT], value: object) -> _ModelT:
    """Return a detached, fully revalidated model instance."""

    if not isinstance(value, model_type):
        raise TypeError(
            f"value must be an instance of {model_type.__name__}."
        )
    return model_type.model_validate(
        value.model_dump(
            mode="python",
            round_trip=True,
            warnings="error",
        )
    )


def _validate_assessor(assessor: object) -> None:
    """Require one exact synchronous one-request callable contract."""

    if not callable(assessor):
        raise TypeError("assessor must be callable.")
    callable_target = getattr(assessor, "__call__", assessor)
    if any(
        predicate(assessor) or predicate(callable_target)
        for predicate in (
            iscoroutinefunction,
            isgeneratorfunction,
            isasyncgenfunction,
        )
    ):
        raise TypeError("assessor must be a synchronous non-generator.")

    try:
        parameters = tuple(signature(assessor).parameters.values())
    except (TypeError, ValueError) as exc:
        raise TypeError(
            "assessor must have an inspectable signature."
        ) from exc
    positional_kinds = {
        Parameter.POSITIONAL_ONLY,
        Parameter.POSITIONAL_OR_KEYWORD,
    }
    if (
        len(parameters) != 1
        or parameters[0].kind not in positional_kinds
        or parameters[0].default is not Parameter.empty
    ):
        raise TypeError(
            "assessor must accept exactly one request argument."
        )


class LevelApplicationService:
    """Immutable synchronous boundary around the reviewed level wizard."""

    __slots__ = (
        "_assessor",
        "_locked",
    )

    def __init__(
        self,
        *,
        assessor: LevelApplicationAssessor = assess_level_application,
    ) -> None:
        """Bind one synchronous assessor permanently."""

        object.__setattr__(self, "_locked", False)
        _validate_assessor(assessor)
        object.__setattr__(self, "_assessor", assessor)
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError(
                "LevelApplicationService instances are immutable."
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError(
                "LevelApplicationService instances are immutable."
            )
        object.__delattr__(self, name)

    @property
    def wizard_version(self) -> str:
        """Return the exact reviewed wizard version exposed by the service."""

        return LEVEL_APPLICATION_WIZARD_VERSION

    def assess(
        self,
        request: LevelApplicationRequest,
    ) -> LevelApplicationAssessment:
        """Return one detached assessment or a sanitized service error."""

        try:
            validated_request = _fresh_model(LevelApplicationRequest, request)
            assessment = self._assessor(validated_request)
            if isawaitable(assessment):
                close = getattr(assessment, "close", None)
                if callable(close):
                    close()
                raise TypeError("assessor returned an awaitable.")
            if isgenerator(assessment):
                assessment.close()
                raise TypeError("assessor returned a generator.")
            return _fresh_model(LevelApplicationAssessment, assessment)
        except Exception as exc:
            raise LevelApplicationServiceError() from exc


DEFAULT_LEVEL_APPLICATION_SERVICE: Final = LevelApplicationService()


__all__ = [
    "DEFAULT_LEVEL_APPLICATION_SERVICE",
    "LevelApplicationAssessor",
    "LevelApplicationService",
    "LevelApplicationServiceError",
]
