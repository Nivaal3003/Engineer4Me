"""Safety-first engineering recommendation engine.

This module is separate from the original Phase 2 recommendation engine.

The Phase 2 engine provides lightweight product matching through
SelectionRules. This Phase 3 engine performs deeper engineering evaluation
using EngineeringRuleEngine, mandatory and preferred requirements, safety
findings, suitability scoring, confidence scoring, catalogue evaluation,
product ranking, and explainable recommendation responses.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.engineering.engineering_rules import EngineeringRuleEngine
from app.engineering.recommendation_models import (
    EngineeringRecommendationResponse,
    EngineeringRequirements,
    ProductEvaluation,
    RankedRecommendation,
    RecommendationStatus,
    RecommendationSummary,
    RequirementImportance,
    RuleEvaluation,
    RuleStatus,
    SafetyFinding,
    SafetySeverity,
)
from app.models.product import Product


class EngineeringRecommendationEngine:
    """Evaluate and rank products using safety-first engineering rules."""

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
            min(
                max(
                    awarded_score / maximum_score * 100.0,
                    0.0,
                ),
                100.0,
            ),
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
            min(
                max(confidence, 0.0),
                100.0,
            ),
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
                    missing_fields = product_value.get(
                        "missing_fields",
                        [],
                    )

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

        safety_rule_codes: dict[
            str,
            tuple[SafetySeverity, str, str],
        ] = {
            "PROCESS_TEMPERATURE_OUTSIDE_LIMITS": (
                SafetySeverity.CRITICAL,
                "Process temperature exceeds product limits",
                (
                    "Select equipment rated for the complete expected process "
                    "temperature range, including abnormal, start-up and "
                    "shutdown conditions."
                ),
            ),
            "PROCESS_PRESSURE_OUTSIDE_LIMITS": (
                SafetySeverity.CRITICAL,
                "Process pressure exceeds product limits",
                (
                    "Select equipment with a verified pressure rating suitable "
                    "for the maximum operating, start-up and upset pressure."
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
        """Determine the overall product recommendation status."""

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

        for attribute_name in (
            "name",
            "model",
            "model_number",
        ):
            value = getattr(product, attribute_name, None)

            if value is not None and str(value).strip():
                return str(value).strip()

        return f"Product {product.id}"

    @staticmethod
    def _get_model_number(product: Product) -> str | None:
        """Return the product model number when available."""

        for attribute_name in (
            "model_number",
            "model",
        ):
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

        safety_findings = cls.build_safety_findings(
            rule_evaluations
        )

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
            mandatory_rules_passed=counts[
                "mandatory_rules_passed"
            ],
            mandatory_rules_failed=counts[
                "mandatory_rules_failed"
            ],
            preferred_rules_passed=counts[
                "preferred_rules_passed"
            ],
            preferred_rules_failed=counts[
                "preferred_rules_failed"
            ],
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

    @classmethod
    def evaluate_products(
        cls,
        products: Sequence[Product],
        requirements: EngineeringRequirements,
    ) -> list[ProductEvaluation]:
        """Evaluate every candidate product against the requirements.

        Products are evaluated independently so that one invalid or unsuitable
        product cannot affect another product's result.
        """

        return [
            cls.evaluate_product(
                product=product,
                requirements=requirements,
            )
            for product in products
        ]

    @staticmethod
    def _recommendation_status_priority(
        status: RecommendationStatus,
    ) -> int:
        """Return the ranking priority for a recommendation status."""

        priorities = {
            RecommendationStatus.RECOMMENDED: 0,
            RecommendationStatus.CONDITIONALLY_RECOMMENDED: 1,
            RecommendationStatus.INSUFFICIENT_INFORMATION: 2,
            RecommendationStatus.NOT_RECOMMENDED: 3,
        }

        return priorities[status]

    @classmethod
    def rank_products(
        cls,
        evaluations: Sequence[ProductEvaluation],
    ) -> list[RankedRecommendation]:
        """Rank products that are eligible for recommendation.

        Products that are not recommended or have insufficient information are
        excluded from the ranked recommendation list.

        Ranking order:

        1. Recommended products before conditionally recommended products.
        2. Higher suitability score.
        3. Higher confidence score.
        4. Fewer preferred-rule failures.
        5. Manufacturer name.
        6. Product name.
        7. Model number.
        8. Product identifier.
        """

        eligible_evaluations = [
            evaluation
            for evaluation in evaluations
            if evaluation.status
            in {
                RecommendationStatus.RECOMMENDED,
                RecommendationStatus.CONDITIONALLY_RECOMMENDED,
            }
        ]

        sorted_evaluations = sorted(
            eligible_evaluations,
            key=lambda evaluation: (
                cls._recommendation_status_priority(
                    evaluation.status
                ),
                -evaluation.suitability_score,
                -evaluation.confidence_score,
                evaluation.preferred_rules_failed,
                (evaluation.manufacturer_name or "").casefold(),
                evaluation.product_name.casefold(),
                (evaluation.model_number or "").casefold(),
                evaluation.product_id,
            ),
        )

        return [
            RankedRecommendation(
                rank=index,
                evaluation=evaluation,
            )
            for index, evaluation in enumerate(
                sorted_evaluations,
                start=1,
            )
        ]

    @staticmethod
    def build_summary(
        evaluations: Sequence[ProductEvaluation],
    ) -> RecommendationSummary:
        """Build recommendation statistics for all evaluated products."""

        return RecommendationSummary(
            products_evaluated=len(evaluations),
            products_recommended=sum(
                evaluation.status == RecommendationStatus.RECOMMENDED
                for evaluation in evaluations
            ),
            products_conditionally_recommended=sum(
                evaluation.status
                == RecommendationStatus.CONDITIONALLY_RECOMMENDED
                for evaluation in evaluations
            ),
            products_not_recommended=sum(
                evaluation.status
                == RecommendationStatus.NOT_RECOMMENDED
                for evaluation in evaluations
            ),
            products_with_insufficient_information=sum(
                evaluation.status
                == RecommendationStatus.INSUFFICIENT_INFORMATION
                for evaluation in evaluations
            ),
        )

    @staticmethod
    def collect_missing_request_information(
        requirements: EngineeringRequirements,
    ) -> list[str]:
        """Identify important request information not supplied by the user.

        Missing request information does not automatically prevent evaluation.
        It is reported transparently so that the user can improve the quality
        and confidence of the recommendation.
        """

        missing_information: list[str] = []

        if requirements.measurement_type is None:
            missing_information.append("measurement type")

        if requirements.process_temperature_c is None:
            missing_information.append("process temperature")

        if requirements.process_pressure_bar is None:
            missing_information.append("process pressure")

        if requirements.ambient_temperature_c is None:
            missing_information.append("ambient temperature")

        if requirements.required_accuracy_percent is None:
            missing_information.append("required accuracy")

        if requirements.required_ingress_protection_rating is None:
            missing_information.append(
                "required ingress protection rating"
            )

        if requirements.process_medium is None:
            missing_information.append("process medium")

        if not requirements.required_wetted_materials:
            missing_information.append("required wetted materials")

        if not requirements.required_process_connections:
            missing_information.append(
                "required process connection"
            )

        if not requirements.required_protocols:
            missing_information.append(
                "required communication protocol"
            )

        if (
            requirements.hazardous_area_required
            and not requirements.required_hazardous_area_approvals
        ):
            missing_information.append(
                "hazardous-area certification details"
            )

        if not requirements.installation_environment:
            missing_information.append(
                "installation environment conditions"
            )

        return missing_information

    @staticmethod
    def build_general_safety_findings(
        requirements: EngineeringRequirements,
    ) -> list[SafetyFinding]:
        """Build request-level safety findings and verification reminders."""

        findings: list[SafetyFinding] = [
            SafetyFinding(
                code="GENERAL_ENGINEERING_VERIFICATION_REQUIRED",
                severity=SafetySeverity.INFORMATION,
                title="Final engineering verification required",
                message=(
                    "The recommendation is based on the engineering data "
                    "provided to Engineer4Me and the product information "
                    "available during evaluation."
                ),
                required_action=(
                    "Confirm the final selection against the latest "
                    "manufacturer documentation, approved site standards, "
                    "applicable legislation and project specifications."
                ),
                verification_step=(
                    "Record the final engineering review and approval before "
                    "procurement, installation or commissioning."
                ),
                blocks_recommendation=False,
            )
        ]

        if requirements.hazardous_area_required:
            findings.append(
                SafetyFinding(
                    code="GENERAL_HAZARDOUS_AREA_VERIFICATION_REQUIRED",
                    severity=SafetySeverity.CRITICAL,
                    title="Hazardous-area certification must be verified",
                    message=(
                        "Hazardous-area suitability cannot be confirmed using "
                        "a certificate name alone. The complete certification "
                        "and installation conditions must match the site."
                    ),
                    required_action=(
                        "Verify the area classification, zone or division, "
                        "equipment protection level, gas or dust group, "
                        "temperature class, ambient range, protection concept "
                        "and certificate conditions."
                    ),
                    verification_step=(
                        "Have an authorised hazardous-area competent person "
                        "approve the selected equipment and installation "
                        "method before work begins."
                    ),
                    reference=(
                        "Applicable hazardous-area legislation, site standards "
                        "and current product certification."
                    ),
                    blocks_recommendation=False,
                )
            )

        if requirements.process_medium:
            findings.append(
                SafetyFinding(
                    code="GENERAL_PROCESS_COMPATIBILITY_VERIFICATION_REQUIRED",
                    severity=SafetySeverity.WARNING,
                    title="Process compatibility must be verified",
                    message=(
                        "Material suitability may depend on concentration, "
                        "temperature, pressure, contamination, cleaning media, "
                        "velocity, erosion and process-specific conditions."
                    ),
                    required_action=(
                        "Complete a documented material compatibility and "
                        "process-risk assessment for all pressure-retaining, "
                        "wetted and sealing materials."
                    ),
                    verification_step=(
                        "Confirm compatibility using approved engineering "
                        "references and current manufacturer guidance."
                    ),
                    blocks_recommendation=False,
                )
            )

        return findings

    @staticmethod
    def collect_excluded_products(
        evaluations: Sequence[ProductEvaluation],
    ) -> list[ProductEvaluation]:
        """Return products not eligible for the ranked recommendation list."""

        return [
            evaluation
            for evaluation in evaluations
            if evaluation.status
            in {
                RecommendationStatus.NOT_RECOMMENDED,
                RecommendationStatus.INSUFFICIENT_INFORMATION,
            }
        ]

    @classmethod
    def recommend_products(
        cls,
        products: Sequence[Product],
        requirements: EngineeringRequirements,
    ) -> EngineeringRecommendationResponse:
        """Evaluate and rank a complete catalogue of candidate products."""

        evaluations = cls.evaluate_products(
            products=products,
            requirements=requirements,
        )

        recommendations = cls.rank_products(evaluations)

        excluded_products = cls.collect_excluded_products(
            evaluations
        )

        summary = cls.build_summary(evaluations)

        general_safety_findings = cls.build_general_safety_findings(
            requirements
        )

        missing_request_information = (
            cls.collect_missing_request_information(requirements)
        )

        return EngineeringRecommendationResponse(
            requirements=requirements,
            summary=summary,
            recommendations=recommendations,
            excluded_products=excluded_products,
            general_safety_findings=general_safety_findings,
            missing_request_information=missing_request_information,
        )