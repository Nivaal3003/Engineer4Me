"""Bounded method and concrete-path matching for reviewed route security bindings."""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.security.application_route_security_plan import (
    ApplicationRouteSecurityBinding,
    ApplicationRouteSecurityPlan,
)
from app.security.route_policy import RouteHTTPMethod


MAX_CONCRETE_ROUTE_PATH_LENGTH = 2_000
_PATH_PARAMETER = re.compile(r"^\{[A-Za-z_][A-Za-z0-9_]*\}$")


class ApplicationRouteSecurityMatchError(RuntimeError):
    """Sanitized rejection when a concrete request has no unique reviewed binding."""


@dataclass(frozen=True, slots=True)
class _CompiledSecurityBinding:
    binding: ApplicationRouteSecurityBinding
    pattern: re.Pattern[str]
    specificity: tuple[int, int]


def _compile_path_template(path_template: str) -> re.Pattern[str]:
    if path_template == "/":
        return re.compile(r"\A/\Z")
    segments = path_template.split("/")
    if not segments or segments[0] != "":
        raise ApplicationRouteSecurityMatchError(
            "reviewed application route path template is invalid"
        )
    compiled_segments: list[str] = []
    for segment in segments[1:]:
        if _PATH_PARAMETER.fullmatch(segment):
            compiled_segments.append(r"[^/]+")
        elif "{" in segment or "}" in segment:
            raise ApplicationRouteSecurityMatchError(
                "reviewed application route path template is invalid"
            )
        else:
            compiled_segments.append(re.escape(segment))
    return re.compile(r"\A/" + "/".join(compiled_segments) + r"\Z")


def _path_specificity(path_template: str) -> tuple[int, int]:
    literal_segments = tuple(
        segment
        for segment in path_template.split("/")
        if segment and _PATH_PARAMETER.fullmatch(segment) is None
    )
    return (len(literal_segments), sum(len(segment) for segment in literal_segments))


class ApplicationRouteSecurityMatcher:
    """Immutable matcher over one complete deterministic security plan."""

    def __init__(self, plan: ApplicationRouteSecurityPlan) -> None:
        if not isinstance(plan, ApplicationRouteSecurityPlan):
            raise TypeError("application route security matcher requires ApplicationRouteSecurityPlan")
        self._plan = plan
        self._compiled = tuple(
            _CompiledSecurityBinding(
                binding=binding,
                pattern=_compile_path_template(binding.policy.path_template),
                specificity=_path_specificity(binding.policy.path_template),
            )
            for binding in plan.bindings
        )

    @property
    def plan(self) -> ApplicationRouteSecurityPlan:
        return self._plan

    def match(
        self,
        *,
        method: str | RouteHTTPMethod,
        concrete_path: str,
    ) -> ApplicationRouteSecurityBinding:
        try:
            normalized_method = RouteHTTPMethod(method)
        except (TypeError, ValueError) as error:
            raise ApplicationRouteSecurityMatchError(
                "application route security binding is not uniquely matched"
            ) from error
        if (
            not isinstance(concrete_path, str)
            or not concrete_path.startswith("/")
            or len(concrete_path) > MAX_CONCRETE_ROUTE_PATH_LENGTH
            or "?" in concrete_path
            or "#" in concrete_path
            or "\\" in concrete_path
            or any(ord(character) < 32 or ord(character) == 127 for character in concrete_path)
        ):
            raise ApplicationRouteSecurityMatchError(
                "application route security binding is not uniquely matched"
            )
        candidates = tuple(
            item
            for item in self._compiled
            if item.binding.policy.method is normalized_method
            and item.pattern.fullmatch(concrete_path) is not None
        )
        if not candidates:
            raise ApplicationRouteSecurityMatchError(
                "application route security binding is not uniquely matched"
            )
        highest_specificity = max(item.specificity for item in candidates)
        matches = tuple(
            item.binding for item in candidates if item.specificity == highest_specificity
        )
        if len(matches) != 1:
            raise ApplicationRouteSecurityMatchError(
                "application route security binding is not uniquely matched"
            )
        return matches[0]

    def match_protected(
        self,
        *,
        method: str | RouteHTTPMethod,
        concrete_path: str,
    ) -> ApplicationRouteSecurityBinding:
        binding = self.match(method=method, concrete_path=concrete_path)
        if binding.dependency is None:
            raise ApplicationRouteSecurityMatchError(
                "application route security binding is not protected"
            )
        return binding


__all__ = [
    "MAX_CONCRETE_ROUTE_PATH_LENGTH",
    "ApplicationRouteSecurityMatchError",
    "ApplicationRouteSecurityMatcher",
]
