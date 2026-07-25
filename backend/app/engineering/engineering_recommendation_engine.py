"""Safety-first engineering recommendation engine.

This module is separate from the original Phase 2 recommendation engine.

The Phase 2 engine provides lightweight product matching through
SelectionRules. This Phase 3 engine performs deeper engineering evaluation
using EngineeringRuleEngine, mandatory and preferred requirements, safety
findings, suitability scoring, and confidence scoring.
"""

from __future__ import annotations

from app.engineering.engineering_rules import EngineeringRuleEngine
from app.engineering.recommendation_models import (
    EngineeringRequirements,
    ProductEvaluation,
    RecommendationStatus,
    RequirementImportance,
    RuleEvaluation,
    RuleStatus,
    SafetyFinding,
    SafetySeverity,
)
from app.models.product import Product


class EngineeringRecommendationEngine:
    """Evaluate products using explainable, safety-first engineering rules."""

    @staticmethod
    def _is_evaluated_rule(rule: RuleEvaluation) -> bool:
        """Return whether a rule contributed to the engineering evaluation."""

        return rule.status != RuleStatus.NOT_EVALUATED

    @staticmethod
    def _is_missing_data_rule(rule: RuleEvaluation) -> bool:
        """Return whether a rule indicates missing or incomplete product data."""

        return (
            rule.status == RuleStatus.WARNING
            and (
                rule.rule_code.endswith("_DATA_MISSING")
                or rule.rule_code
                in {
                    "PRODUCT_ENGINEERING_DATA_INCOMPLETE",
                    "HAZARDOUS_AREA_DETAILS_INCOMPLETE",
                    "INGRESS_PROTECTION_FORMAT_UNSUPPORTED",
                }
            )
        )

    @classmethod
    def calculate_suitability_score(
        cls,
        rule_evaluations: list[RuleEvaluation],
    ) -> float:
        """Calculate the weighted product suitability percentage.

        Only rules with a positive maximum score contribute to suitability.
        Rules marked as not evaluated are excluded from the denominator.
        """

        scored_rules = [
            rule
            for rule in rule_evaluations
            if cls._is_evaluated_rule(rule) and rule.maximum_score > 0
        ]

        maximum_score = sum(rule.maximum_score for rule in scored_rules)

        if maximum_score <= 0:
            return 0.0

        awarded_score = sum(rule.score_awarded for rule in scored_rules)

        return round(
            min(max(awarded_score / maximum_score * 100.0, 0.0), 100.0),
            2,
        )

    @classmethod
    def calculate_confidence_score(
        cls,
        rule_evaluations: list[RuleEvaluation],
    ) -> float:
        """Calculate confidence based on engineering-data completeness.

        Confidence measures how much of the requested evaluation could be
        completed using available and interpretable product data.

        It is intentionally separate from suitability. A product can have a
        high suitability score but a lower confidence score when important
        product information is missing.
        """

        applicable_rules = [
            rule
            for rule in rule_evaluations
            if cls._is_evaluated_rule(rule)
            and rule.category.value != "data_completeness"
        ]

        if not applicable_rules:
            return 0.0

        confirmed_rules = [
            rule
            for rule in applicable_rules
            if not cls._is_missing_data_rule(rule)
        ]

        confidence = len(confirmed_rules) / len(applicable_rules) * 100.0

        return round(
            min(max(confidence, 0.0), 100.0),
            2,
        )

    @staticmethod
    def count_rule_results(
        rule_evaluations: list[RuleEvaluation],
    ) -> dict[str, int]:
        """Count passed and failed mandatory and preferred rules."""

        counts = {
            "mandatory_rules_passed": 0,
            "mandatory_rules_failed": 0,
            "preferred_rules_passed": 0,
            "preferred_rules_failed": 0,
        }

        for rule in rule_evaluations:
            if rule.status == RuleStatus.NOT_EVALUATED:
                continue

            if rule.importance == RequirementImportance.MANDATORY:
                if rule.status == RuleStatus.PASSED:
                    counts["mandatory_rules_passed"] += 1
                elif rule.status == RuleStatus.FAILED:
                    counts["mandatory_rules_failed"] += 1

            elif rule.importance == RequirementImportance.PREFERRED:
                if rule.status == RuleStatus.PASSED:
                    counts["preferred_rules_passed"] += 1
                elif rule.status == RuleStatus.FAILED:
                    counts["preferred_rules_failed"] += 1

        return counts

    @classmethod
    def collect_missing_information(
        cls,
        rule_evaluations: list[RuleEvaluation],
    ) -> list[str]:
        """Collect clear descriptions of missing engineering information."""

        missing_information: list[str] = []

        for rule in rule_evaluations:
            if not cls._is_missing_data_rule(rule):
                continue

            if rule.rule_code == "PRODUCT_ENGINEERING_DATA_INCOMPLETE":
                product_value = rule.product_value

                if isinstance(product_value, dict):
                    missing_fields = product_value.get("missing_fields", [])

                    if isinstance(missing_fields, list):
                        for field in missing_fields:
                            description = str(field).strip()

                            if (
                                description
                                and description not in missing_information
                            ):
                                missing_information.append(description)

                    continue

            description = rule.title.strip()

            if description and description not in missing_information:
                missing_information.append(description)

        return missing_information

    @staticmethod
    def build_recommendation_reasons(
        rule_evaluations: list[RuleEvaluation],
    ) -> list[str]:
        """Build concise reasons supporting a product recommendation."""

        reasons: list[str] = []

        for rule in rule_evaluations:
            if rule.status != RuleStatus.PASSED:
                continue

            if rule.maximum_score <= 0:
                continue

            reason = rule.explanation.strip()

            if reason and reason not in reasons:
                reasons.append(reason)

        return reasons

    @staticmethod
    def build_rejection_reasons(
        rule_evaluations: list[RuleEvaluation],
    ) -> list[str]:
        """Build concise reasons explaining why a product was rejected."""

        reasons: list[str] = []

        for rule in rule_evaluations:
            if rule.status != RuleStatus.FAILED:
                continue

            if rule.importance != RequirementImportance.MANDATORY:
                continue

            reason = rule.explanation.strip()

            if reason and reason not in reasons:
                reasons.append(reason)

        return reasons

    @staticmethod
    def build_safety_findings(
        rule_evaluations: list[RuleEvaluation],
    ) -> list[SafetyFinding]:
        """Convert safety-relevant rule failures into safety findings."""

        findings: list[SafetyFinding] = []

        safety_rule_codes: dict[str, tuple[SafetySeverity, str, str]] = {
            "PROCESS_TEMPERATURE_OUTSIDE_LIMITS": (
                SafetySeverity.CRITICAL,
                "Process temperature exceeds product limits",
                (
                    "Select equipment rated for the complete expected process "
                    "temperature range, including abnormal and start-up "
                    "conditions."
                ),
            ),
            "PROCESS_PRESSURE_OUTSIDE_LIMITS": (
                SafetySeverity.CRITICAL,
                "Process pressure exceeds product limits",
                (
                    "Select equipment with a verified pressure rating suitable "
                    "for the maximum operating and upset pressure."
                ),
            ),
            "AMBIENT_TEMPERATURE_OUTSIDE_LIMITS": (
                SafetySeverity.WARNING,
                "Ambient temperature exceeds product limits",
                (
                    "Select equipment rated for the installation environment "
                    "or provide an approved environmental protection solution."
                ),
            ),
            "INGRESS_PROTECTION_DOES_NOT_MEET_REQUIREMENT": (
                SafetySeverity.WARNING,
                "Enclosure protection is insufficient",
                (
                    "Select equipment with an enclosure rating appropriate for "
                    "dust, water, washdown and installation conditions."
                ),
            ),
            "HAZARDOUS_AREA_APPROVALS_MISSING": (
                SafetySeverity.CRITICAL,
                "Hazardous-area approval is missing",
                (
                    "Do not install the product in the classified area. Select "
                    "equipment with certification matching the complete site "
                    "hazardous-area classification."
                ),
            ),
            "HAZARDOUS_AREA_APPROVALS_DO_NOT_MATCH": (
                SafetySeverity.CRITICAL,
                "Hazardous-area approval does not match",
                (
                    "Verify zone or division, equipment protection level, gas "
                    "or dust group, temperature class and protection concept "
                    "before selecting equipment."
                ),
            ),
            "WETTED_MATERIAL_NO_MATCH": (
                SafetySeverity.CRITICAL,
                "Wetted material requirement is not satisfied",
                (
                    "Complete a documented chemical compatibility assessment "
                    "and select suitable wetted materials before installation."
                ),
            ),
            "PROCESS_CONNECTION_NO_MATCH": (
                SafetySeverity.WARNING,
                "Process connection does not match",
                (
                    "Select the correct process connection or use only an "
                    "engineered and approved adaptor arrangement."
                ),
            ),
        }

        for rule in rule_evaluations:
            safety_definition = safety_rule_codes.get(rule.rule_code)

            if safety_definition is None:
                continue

            severity, title, required_action = safety_definition

            findings.append(
                SafetyFinding(
                    code=f"SAFETY_{rule.rule_code}",
                    severity=severity,
                    title=title,
                    message=rule.explanation,
                    required_action=required_action,
                    verification_step=(
                        "Verify the final selection against the current "
                        "manufacturer datasheet, site specifications, risk "
                        "assessment and authorised plant procedures."
                    ),
                    reference=rule.engineering_reference,
                    blocks_recommendation=(
                        rule.status == RuleStatus.FAILED
                        and rule.importance
                        == RequirementImportance.MANDATORY
                    ),
                )
            )

        return findings

    @staticmethod
    def determine_recommendation_status(
        *,
        mandatory_rules_failed: int,
        preferred_rules_failed: int,
        missing_information: list[str],
        safety_findings: list[SafetyFinding],
    ) -> RecommendationStatus:
        """Determine overall product recommendation status."""

        has_blocking_safety_finding = any(
            finding.blocks_recommendation
            for finding in safety_findings
        )

        if mandatory_rules_failed > 0 or has_blocking_safety_finding:
            return RecommendationStatus.NOT_RECOMMENDED

        if missing_information:
            return RecommendationStatus.INSUFFICIENT_INFORMATION

        if preferred_rules_failed > 0:
            return RecommendationStatus.CONDITIONALLY_RECOMMENDED

        return RecommendationStatus.RECOMMENDED

    @staticmethod
    def _get_product_name(product: Product) -> str:
        """Return a stable display name for a product."""

        for attribute_name in ("name", "model", "model_number"):
            value = getattr(product, attribute_name, None)

            if value is not None and str(value).strip():
                return str(value).strip()

        return f"Product {product.id}"

    @staticmethod
    def _get_model_number(product: Product) -> str | None:
        """Return the product model number when available."""

        for attribute_name in ("model_number", "model"):
            value = getattr(product, attribute_name, None)

            if value is not None and str(value).strip():
                return str(value).strip()

        return None

    @staticmethod
    def _get_manufacturer_name(product: Product) -> str | None:
        """Return the related manufacturer name safely."""

        manufacturer = getattr(product, "manufacturer", None)

        if manufacturer is None:
            return None

        name = getattr(manufacturer, "name", None)

        if name is None or not str(name).strip():
            return None

        return str(name).strip()

    @classmethod
    def evaluate_product(
        cls,
        product: Product,
        requirements: EngineeringRequirements,
    ) -> ProductEvaluation:
        """Evaluate one product against the supplied requirements."""

        rule_evaluations = EngineeringRuleEngine.evaluate_all_rules(
            requirements,
            product,
        )

        counts = cls.count_rule_results(rule_evaluations)
        missing_information = cls.collect_missing_information(
            rule_evaluations
        )
        safety_findings = cls.build_safety_findings(rule_evaluations)

        status = cls.determine_recommendation_status(
            mandatory_rules_failed=counts["mandatory_rules_failed"],
            preferred_rules_failed=counts["preferred_rules_failed"],
            missing_information=missing_information,
            safety_findings=safety_findings,
        )

        return ProductEvaluation(
            product_id=product.id,
            manufacturer_name=cls._get_manufacturer_name(product),
            product_name=cls._get_product_name(product),
            model_number=cls._get_model_number(product),
            status=status,
            suitability_score=cls.calculate_suitability_score(
                rule_evaluations
            ),
            confidence_score=cls.calculate_confidence_score(
                rule_evaluations
            ),
            mandatory_rules_passed=counts["mandatory_rules_passed"],
            mandatory_rules_failed=counts["mandatory_rules_failed"],
            preferred_rules_passed=counts["preferred_rules_passed"],
            preferred_rules_failed=counts["preferred_rules_failed"],
            rule_evaluations=rule_evaluations,
            safety_findings=safety_findings,
            recommendation_reasons=cls.build_recommendation_reasons(
                rule_evaluations
            ),
            rejection_reasons=cls.build_rejection_reasons(
                rule_evaluations
            ),
            missing_information=missing_information,
        )