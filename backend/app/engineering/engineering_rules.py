"""Vendor-neutral engineering rules for product recommendation.

The rule engine evaluates a product against user-supplied engineering
requirements. Each rule returns an explainable RuleEvaluation rather than
only returning True or False.

Mandatory failures may disqualify a product. Preferred failures reduce the
eventual suitability score but do not automatically reject the product.
"""

from collections.abc import Iterable
from typing import Any

from app.engineering.recommendation_models import (
    EngineeringRequirements,
    RequirementImportance,
    RuleCategory,
    RuleEvaluation,
    RuleStatus,
)
from app.models.product import Product


class EngineeringRuleEngine:
    """Evaluate product engineering data against application requirements."""

    RULE_WEIGHTS: dict[RuleCategory, float] = {
        RuleCategory.PROCESS_TEMPERATURE: 15.0,
        RuleCategory.PROCESS_PRESSURE: 15.0,
        RuleCategory.AMBIENT_TEMPERATURE: 10.0,
        RuleCategory.ACCURACY: 10.0,
        RuleCategory.INGRESS_PROTECTION: 10.0,
        RuleCategory.HAZARDOUS_AREA: 15.0,
        RuleCategory.WETTED_MATERIAL: 10.0,
        RuleCategory.PROCESS_CONNECTION: 7.5,
        RuleCategory.COMMUNICATION_PROTOCOL: 7.5,
        RuleCategory.DATA_COMPLETENESS: 0.0,
    }

    @staticmethod
    def _normalise_text(value: str) -> str:
        """Normalise text for case-insensitive engineering comparisons."""

        return " ".join(value.strip().lower().split())

    @classmethod
    def _normalise_collection(
        cls,
        values: Iterable[Any] | None,
    ) -> list[str]:
        """Return a clean, lower-case list of textual values."""

        if values is None:
            return []

        normalised: list[str] = []

        for value in values:
            if value is None:
                continue

            if hasattr(value, "name"):
                text_value = str(value.name)
            else:
                text_value = str(value)

            cleaned_value = cls._normalise_text(text_value)

            if cleaned_value and cleaned_value not in normalised:
                normalised.append(cleaned_value)

        return normalised

    @classmethod
    def _collections_overlap(
        cls,
        required_values: Iterable[Any] | None,
        product_values: Iterable[Any] | None,
    ) -> bool:
        """Return whether at least one required value matches a product value."""

        required = set(cls._normalise_collection(required_values))
        available = set(cls._normalise_collection(product_values))

        return bool(required.intersection(available))

    @classmethod
    def _all_values_supported(
        cls,
        required_values: Iterable[Any] | None,
        product_values: Iterable[Any] | None,
    ) -> bool:
        """Return whether every required value exists in product data."""

        required = set(cls._normalise_collection(required_values))
        available = set(cls._normalise_collection(product_values))

        return required.issubset(available)

    @classmethod
    def _build_not_required_result(
        cls,
        *,
        rule_code: str,
        category: RuleCategory,
        title: str,
        importance: RequirementImportance,
        explanation: str,
    ) -> RuleEvaluation:
        """Create a rule result for a requirement that was not supplied."""

        return RuleEvaluation(
            rule_code=rule_code,
            category=category,
            title=title,
            status=RuleStatus.NOT_EVALUATED,
            importance=importance,
            explanation=explanation,
            score_awarded=0.0,
            maximum_score=cls.RULE_WEIGHTS[category],
        )

    @classmethod
    def _build_missing_product_data_result(
        cls,
        *,
        rule_code: str,
        category: RuleCategory,
        title: str,
        importance: RequirementImportance,
        requirement_value: Any,
        explanation: str,
    ) -> RuleEvaluation:
        """Create a warning when product engineering data is unavailable."""

        return RuleEvaluation(
            rule_code=rule_code,
            category=category,
            title=title,
            status=RuleStatus.WARNING,
            importance=importance,
            requirement_value=requirement_value,
            product_value=None,
            explanation=explanation,
            score_awarded=0.0,
            maximum_score=cls.RULE_WEIGHTS[category],
        )

    @classmethod
    def evaluate_process_temperature(
        cls,
        requirements: EngineeringRequirements,
        product: Product,
    ) -> RuleEvaluation:
        """Evaluate required process temperature against product limits."""

        required_temperature = requirements.process_temperature_c
        importance = requirements.process_temperature_importance
        maximum_score = cls.RULE_WEIGHTS[RuleCategory.PROCESS_TEMPERATURE]

        if required_temperature is None:
            return cls._build_not_required_result(
                rule_code="PROCESS_TEMPERATURE_NOT_SUPPLIED",
                category=RuleCategory.PROCESS_TEMPERATURE,
                title="Process temperature suitability",
                importance=importance,
                explanation=(
                    "A process temperature requirement was not supplied, "
                    "so product temperature suitability was not evaluated."
                ),
            )

        minimum = product.minimum_process_temperature_c
        maximum = product.maximum_process_temperature_c

        if minimum is None or maximum is None:
            return cls._build_missing_product_data_result(
                rule_code="PROCESS_TEMPERATURE_DATA_MISSING",
                category=RuleCategory.PROCESS_TEMPERATURE,
                title="Process temperature suitability",
                importance=importance,
                requirement_value=required_temperature,
                explanation=(
                    "The product does not have complete process temperature "
                    "limits. Suitability must be verified against current "
                    "manufacturer documentation."
                ),
            )

        passed = minimum <= required_temperature <= maximum

        return RuleEvaluation(
            rule_code=(
                "PROCESS_TEMPERATURE_WITHIN_LIMITS"
                if passed
                else "PROCESS_TEMPERATURE_OUTSIDE_LIMITS"
            ),
            category=RuleCategory.PROCESS_TEMPERATURE,
            title="Process temperature suitability",
            status=RuleStatus.PASSED if passed else RuleStatus.FAILED,
            importance=importance,
            requirement_value=required_temperature,
            product_value={
                "minimum_process_temperature_c": minimum,
                "maximum_process_temperature_c": maximum,
            },
            explanation=(
                f"The required process temperature of {required_temperature} °C "
                f"is within the product operating range of {minimum} °C to "
                f"{maximum} °C."
                if passed
                else (
                    f"The required process temperature of "
                    f"{required_temperature} °C is outside the product "
                    f"operating range of {minimum} °C to {maximum} °C."
                )
            ),
            score_awarded=maximum_score if passed else 0.0,
            maximum_score=maximum_score,
        )

    @classmethod
    def evaluate_process_pressure(
        cls,
        requirements: EngineeringRequirements,
        product: Product,
    ) -> RuleEvaluation:
        """Evaluate required process pressure against product limits."""

        required_pressure = requirements.process_pressure_bar
        importance = requirements.process_pressure_importance
        maximum_score = cls.RULE_WEIGHTS[RuleCategory.PROCESS_PRESSURE]

        if required_pressure is None:
            return cls._build_not_required_result(
                rule_code="PROCESS_PRESSURE_NOT_SUPPLIED",
                category=RuleCategory.PROCESS_PRESSURE,
                title="Process pressure suitability",
                importance=importance,
                explanation=(
                    "A process pressure requirement was not supplied, "
                    "so product pressure suitability was not evaluated."
                ),
            )

        minimum = product.minimum_process_pressure_bar
        maximum = product.maximum_process_pressure_bar

        if minimum is None or maximum is None:
            return cls._build_missing_product_data_result(
                rule_code="PROCESS_PRESSURE_DATA_MISSING",
                category=RuleCategory.PROCESS_PRESSURE,
                title="Process pressure suitability",
                importance=importance,
                requirement_value=required_pressure,
                explanation=(
                    "The product does not have complete process pressure "
                    "limits. The pressure rating must be verified before use."
                ),
            )

        passed = minimum <= required_pressure <= maximum

        return RuleEvaluation(
            rule_code=(
                "PROCESS_PRESSURE_WITHIN_LIMITS"
                if passed
                else "PROCESS_PRESSURE_OUTSIDE_LIMITS"
            ),
            category=RuleCategory.PROCESS_PRESSURE,
            title="Process pressure suitability",
            status=RuleStatus.PASSED if passed else RuleStatus.FAILED,
            importance=importance,
            requirement_value=required_pressure,
            product_value={
                "minimum_process_pressure_bar": minimum,
                "maximum_process_pressure_bar": maximum,
            },
            explanation=(
                f"The required process pressure of {required_pressure} bar "
                f"is within the product range of {minimum} bar to "
                f"{maximum} bar."
                if passed
                else (
                    f"The required process pressure of {required_pressure} bar "
                    f"is outside the product range of {minimum} bar to "
                    f"{maximum} bar."
                )
            ),
            score_awarded=maximum_score if passed else 0.0,
            maximum_score=maximum_score,
        )

    @classmethod
    def evaluate_ambient_temperature(
        cls,
        requirements: EngineeringRequirements,
        product: Product,
    ) -> RuleEvaluation:
        """Evaluate expected ambient temperature against product limits."""

        required_temperature = requirements.ambient_temperature_c
        importance = requirements.ambient_temperature_importance
        maximum_score = cls.RULE_WEIGHTS[RuleCategory.AMBIENT_TEMPERATURE]

        if required_temperature is None:
            return cls._build_not_required_result(
                rule_code="AMBIENT_TEMPERATURE_NOT_SUPPLIED",
                category=RuleCategory.AMBIENT_TEMPERATURE,
                title="Ambient temperature suitability",
                importance=importance,
                explanation=(
                    "An ambient temperature requirement was not supplied, "
                    "so environmental temperature suitability was not evaluated."
                ),
            )

        minimum = product.minimum_ambient_temperature_c
        maximum = product.maximum_ambient_temperature_c

        if minimum is None or maximum is None:
            return cls._build_missing_product_data_result(
                rule_code="AMBIENT_TEMPERATURE_DATA_MISSING",
                category=RuleCategory.AMBIENT_TEMPERATURE,
                title="Ambient temperature suitability",
                importance=importance,
                requirement_value=required_temperature,
                explanation=(
                    "The product does not have complete ambient temperature "
                    "limits. Installation suitability must be verified."
                ),
            )

        passed = minimum <= required_temperature <= maximum

        return RuleEvaluation(
            rule_code=(
                "AMBIENT_TEMPERATURE_WITHIN_LIMITS"
                if passed
                else "AMBIENT_TEMPERATURE_OUTSIDE_LIMITS"
            ),
            category=RuleCategory.AMBIENT_TEMPERATURE,
            title="Ambient temperature suitability",
            status=RuleStatus.PASSED if passed else RuleStatus.FAILED,
            importance=importance,
            requirement_value=required_temperature,
            product_value={
                "minimum_ambient_temperature_c": minimum,
                "maximum_ambient_temperature_c": maximum,
            },
            explanation=(
                f"The expected ambient temperature of "
                f"{required_temperature} °C is within the product range of "
                f"{minimum} °C to {maximum} °C."
                if passed
                else (
                    f"The expected ambient temperature of "
                    f"{required_temperature} °C is outside the product range "
                    f"of {minimum} °C to {maximum} °C."
                )
            ),
            score_awarded=maximum_score if passed else 0.0,
            maximum_score=maximum_score,
        )

    @classmethod
    def evaluate_accuracy(
        cls,
        requirements: EngineeringRequirements,
        product: Product,
    ) -> RuleEvaluation:
        """Evaluate whether product accuracy meets the required accuracy."""

        required_accuracy = requirements.required_accuracy_percent
        importance = requirements.accuracy_importance
        maximum_score = cls.RULE_WEIGHTS[RuleCategory.ACCURACY]

        if required_accuracy is None:
            return cls._build_not_required_result(
                rule_code="ACCURACY_NOT_SUPPLIED",
                category=RuleCategory.ACCURACY,
                title="Measurement accuracy suitability",
                importance=importance,
                explanation=(
                    "An accuracy requirement was not supplied, so product "
                    "accuracy was not evaluated."
                ),
            )

        product_accuracy = product.accuracy_percent

        if product_accuracy is None:
            return cls._build_missing_product_data_result(
                rule_code="ACCURACY_DATA_MISSING",
                category=RuleCategory.ACCURACY,
                title="Measurement accuracy suitability",
                importance=importance,
                requirement_value=required_accuracy,
                explanation=(
                    "The product accuracy is not recorded. Accuracy must be "
                    "confirmed using current manufacturer documentation."
                ),
            )

        passed = product_accuracy <= required_accuracy

        return RuleEvaluation(
            rule_code=(
                "ACCURACY_MEETS_REQUIREMENT"
                if passed
                else "ACCURACY_DOES_NOT_MEET_REQUIREMENT"
            ),
            category=RuleCategory.ACCURACY,
            title="Measurement accuracy suitability",
            status=RuleStatus.PASSED if passed else RuleStatus.FAILED,
            importance=importance,
            requirement_value=required_accuracy,
            product_value=product_accuracy,
            explanation=(
                f"The product accuracy of ±{product_accuracy}% meets the "
                f"maximum acceptable error of ±{required_accuracy}%."
                if passed
                else (
                    f"The product accuracy of ±{product_accuracy}% does not "
                    f"meet the maximum acceptable error of "
                    f"±{required_accuracy}%."
                )
            ),
            score_awarded=maximum_score if passed else 0.0,
            maximum_score=maximum_score,
        )

    @staticmethod
    def _parse_ip_rating(value: str | None) -> tuple[int, int] | None:
        """Parse a two-digit IP rating such as IP65 or IP66."""

        if value is None:
            return None

        cleaned = value.strip().upper().replace(" ", "")

        if not cleaned.startswith("IP"):
            return None

        digits = cleaned[2:]

        if len(digits) < 2 or not digits[:2].isdigit():
            return None

        return int(digits[0]), int(digits[1])

    @classmethod
    def evaluate_ingress_protection(
        cls,
        requirements: EngineeringRequirements,
        product: Product,
    ) -> RuleEvaluation:
        """Evaluate product IP rating against the required IP rating."""

        required_rating = requirements.required_ingress_protection_rating
        importance = requirements.ingress_protection_importance
        maximum_score = cls.RULE_WEIGHTS[RuleCategory.INGRESS_PROTECTION]

        if required_rating is None:
            return cls._build_not_required_result(
                rule_code="INGRESS_PROTECTION_NOT_SUPPLIED",
                category=RuleCategory.INGRESS_PROTECTION,
                title="Ingress protection suitability",
                importance=importance,
                explanation=(
                    "An ingress protection requirement was not supplied, "
                    "so the product enclosure rating was not evaluated."
                ),
            )

        product_rating = product.ingress_protection_rating

        if product_rating is None:
            return cls._build_missing_product_data_result(
                rule_code="INGRESS_PROTECTION_DATA_MISSING",
                category=RuleCategory.INGRESS_PROTECTION,
                title="Ingress protection suitability",
                importance=importance,
                requirement_value=required_rating,
                explanation=(
                    "The product ingress protection rating is not recorded. "
                    "The enclosure rating must be confirmed before installation."
                ),
            )

        required_parsed = cls._parse_ip_rating(required_rating)
        product_parsed = cls._parse_ip_rating(product_rating)

        if required_parsed is None or product_parsed is None:
            return RuleEvaluation(
                rule_code="INGRESS_PROTECTION_FORMAT_UNSUPPORTED",
                category=RuleCategory.INGRESS_PROTECTION,
                title="Ingress protection suitability",
                status=RuleStatus.WARNING,
                importance=importance,
                requirement_value=required_rating,
                product_value=product_rating,
                explanation=(
                    "The ingress protection ratings could not be compared "
                    "automatically. Confirm the complete IP classification "
                    "using product documentation."
                ),
                score_awarded=0.0,
                maximum_score=maximum_score,
            )

        passed = (
            product_parsed[0] >= required_parsed[0]
            and product_parsed[1] >= required_parsed[1]
        )

        return RuleEvaluation(
            rule_code=(
                "INGRESS_PROTECTION_MEETS_REQUIREMENT"
                if passed
                else "INGRESS_PROTECTION_DOES_NOT_MEET_REQUIREMENT"
            ),
            category=RuleCategory.INGRESS_PROTECTION,
            title="Ingress protection suitability",
            status=RuleStatus.PASSED if passed else RuleStatus.FAILED,
            importance=importance,
            requirement_value=required_rating,
            product_value=product_rating,
            explanation=(
                f"The product rating {product_rating} meets or exceeds the "
                f"required rating {required_rating}."
                if passed
                else (
                    f"The product rating {product_rating} does not meet the "
                    f"required rating {required_rating}."
                )
            ),
            score_awarded=maximum_score if passed else 0.0,
            maximum_score=maximum_score,
        )

    @classmethod
    def evaluate_hazardous_area(
        cls,
        requirements: EngineeringRequirements,
        product: Product,
    ) -> RuleEvaluation:
        """Evaluate hazardous-area approval requirements."""

        importance = requirements.hazardous_area_importance
        required_approvals = requirements.required_hazardous_area_approvals
        product_approvals = product.hazardous_area_approvals or []
        maximum_score = cls.RULE_WEIGHTS[RuleCategory.HAZARDOUS_AREA]

        if not requirements.hazardous_area_required:
            return cls._build_not_required_result(
                rule_code="HAZARDOUS_AREA_NOT_REQUIRED",
                category=RuleCategory.HAZARDOUS_AREA,
                title="Hazardous-area approval suitability",
                importance=importance,
                explanation=(
                    "Hazardous-area certification was not identified as an "
                    "application requirement."
                ),
            )

        if not product_approvals:
            return RuleEvaluation(
                rule_code="HAZARDOUS_AREA_APPROVALS_MISSING",
                category=RuleCategory.HAZARDOUS_AREA,
                title="Hazardous-area approval suitability",
                status=RuleStatus.FAILED,
                importance=importance,
                requirement_value=required_approvals,
                product_value=[],
                explanation=(
                    "Hazardous-area equipment is required, but no verified "
                    "hazardous-area approvals are recorded for the product."
                ),
                score_awarded=0.0,
                maximum_score=maximum_score,
            )

        if not required_approvals:
            return RuleEvaluation(
                rule_code="HAZARDOUS_AREA_DETAILS_INCOMPLETE",
                category=RuleCategory.HAZARDOUS_AREA,
                title="Hazardous-area approval suitability",
                status=RuleStatus.WARNING,
                importance=importance,
                requirement_value=[],
                product_value=product_approvals,
                explanation=(
                    "The product has hazardous-area approvals, but the required "
                    "site certification, zone, gas group, temperature class, "
                    "and protection concept were not specified."
                ),
                score_awarded=maximum_score * 0.5,
                maximum_score=maximum_score,
            )

        passed = cls._all_values_supported(
            required_approvals,
            product_approvals,
        )

        return RuleEvaluation(
            rule_code=(
                "HAZARDOUS_AREA_APPROVALS_MATCH"
                if passed
                else "HAZARDOUS_AREA_APPROVALS_DO_NOT_MATCH"
            ),
            category=RuleCategory.HAZARDOUS_AREA,
            title="Hazardous-area approval suitability",
            status=RuleStatus.PASSED if passed else RuleStatus.FAILED,
            importance=importance,
            requirement_value=required_approvals,
            product_value=product_approvals,
            explanation=(
                "The product includes all specified hazardous-area approvals."
                if passed
                else (
                    "The product does not include every specified hazardous-"
                    "area approval. Certification must match the complete site "
                    "classification."
                )
            ),
            score_awarded=maximum_score if passed else 0.0,
            maximum_score=maximum_score,
        )

    @classmethod
    def evaluate_wetted_material(
        cls,
        requirements: EngineeringRequirements,
        product: Product,
    ) -> RuleEvaluation:
        """Evaluate required wetted materials against product materials."""

        required_materials = requirements.required_wetted_materials
        importance = requirements.wetted_material_importance
        product_materials = product.wetted_materials or []
        maximum_score = cls.RULE_WEIGHTS[RuleCategory.WETTED_MATERIAL]

        if not required_materials:
            return cls._build_not_required_result(
                rule_code="WETTED_MATERIAL_NOT_SUPPLIED",
                category=RuleCategory.WETTED_MATERIAL,
                title="Wetted material suitability",
                importance=importance,
                explanation=(
                    "Acceptable wetted materials were not supplied. Chemical "
                    "compatibility was therefore not confirmed."
                ),
            )

        if not product_materials:
            return cls._build_missing_product_data_result(
                rule_code="WETTED_MATERIAL_DATA_MISSING",
                category=RuleCategory.WETTED_MATERIAL,
                title="Wetted material suitability",
                importance=importance,
                requirement_value=required_materials,
                explanation=(
                    "The product wetted materials are not recorded. Material "
                    "compatibility must be confirmed before selection."
                ),
            )

        passed = cls._collections_overlap(
            required_materials,
            product_materials,
        )

        return RuleEvaluation(
            rule_code=(
                "WETTED_MATERIAL_MATCH"
                if passed
                else "WETTED_MATERIAL_NO_MATCH"
            ),
            category=RuleCategory.WETTED_MATERIAL,
            title="Wetted material suitability",
            status=RuleStatus.PASSED if passed else RuleStatus.FAILED,
            importance=importance,
            requirement_value=required_materials,
            product_value=product_materials,
            explanation=(
                "At least one product wetted material matches the acceptable "
                "material list."
                if passed
                else (
                    "None of the recorded product wetted materials match the "
                    "acceptable material list."
                )
            ),
            score_awarded=maximum_score if passed else 0.0,
            maximum_score=maximum_score,
        )

    @classmethod
    def evaluate_process_connection(
        cls,
        requirements: EngineeringRequirements,
        product: Product,
    ) -> RuleEvaluation:
        """Evaluate process connection requirements."""

        required_connections = requirements.required_process_connections
        importance = requirements.process_connection_importance
        product_connections = product.process_connections or []
        maximum_score = cls.RULE_WEIGHTS[RuleCategory.PROCESS_CONNECTION]

        if not required_connections:
            return cls._build_not_required_result(
                rule_code="PROCESS_CONNECTION_NOT_SUPPLIED",
                category=RuleCategory.PROCESS_CONNECTION,
                title="Process connection suitability",
                importance=importance,
                explanation=(
                    "A process connection requirement was not supplied."
                ),
            )

        if not product_connections:
            return cls._build_missing_product_data_result(
                rule_code="PROCESS_CONNECTION_DATA_MISSING",
                category=RuleCategory.PROCESS_CONNECTION,
                title="Process connection suitability",
                importance=importance,
                requirement_value=required_connections,
                explanation=(
                    "The available product process connections are not recorded."
                ),
            )

        passed = cls._collections_overlap(
            required_connections,
            product_connections,
        )

        return RuleEvaluation(
            rule_code=(
                "PROCESS_CONNECTION_MATCH"
                if passed
                else "PROCESS_CONNECTION_NO_MATCH"
            ),
            category=RuleCategory.PROCESS_CONNECTION,
            title="Process connection suitability",
            status=RuleStatus.PASSED if passed else RuleStatus.FAILED,
            importance=importance,
            requirement_value=required_connections,
            product_value=product_connections,
            explanation=(
                "At least one available product process connection matches "
                "the acceptable connection list."
                if passed
                else (
                    "None of the available product process connections match "
                    "the acceptable connection list."
                )
            ),
            score_awarded=maximum_score if passed else 0.0,
            maximum_score=maximum_score,
        )

    @classmethod
    def evaluate_protocol(
        cls,
        requirements: EngineeringRequirements,
        product: Product,
    ) -> RuleEvaluation:
        """Evaluate communication protocol requirements."""

        required_protocols = requirements.required_protocols
        importance = requirements.communication_protocol_importance
        product_protocols = product.protocols or []
        maximum_score = cls.RULE_WEIGHTS[
            RuleCategory.COMMUNICATION_PROTOCOL
        ]

        if not required_protocols:
            return cls._build_not_required_result(
                rule_code="COMMUNICATION_PROTOCOL_NOT_SUPPLIED",
                category=RuleCategory.COMMUNICATION_PROTOCOL,
                title="Communication protocol suitability",
                importance=importance,
                explanation=(
                    "A communication protocol requirement was not supplied."
                ),
            )

        if not product_protocols:
            return cls._build_missing_product_data_result(
                rule_code="COMMUNICATION_PROTOCOL_DATA_MISSING",
                category=RuleCategory.COMMUNICATION_PROTOCOL,
                title="Communication protocol suitability",
                importance=importance,
                requirement_value=required_protocols,
                explanation=(
                    "No communication protocols are recorded for the product."
                ),
            )

        product_protocol_names = [
            protocol.name
            for protocol in product_protocols
            if getattr(protocol, "name", None)
        ]

        passed = cls._collections_overlap(
            required_protocols,
            product_protocol_names,
        )

        return RuleEvaluation(
            rule_code=(
                "COMMUNICATION_PROTOCOL_MATCH"
                if passed
                else "COMMUNICATION_PROTOCOL_NO_MATCH"
            ),
            category=RuleCategory.COMMUNICATION_PROTOCOL,
            title="Communication protocol suitability",
            status=RuleStatus.PASSED if passed else RuleStatus.FAILED,
            importance=importance,
            requirement_value=required_protocols,
            product_value=product_protocol_names,
            explanation=(
                "At least one product communication protocol matches the "
                "acceptable protocol list."
                if passed
                else (
                    "None of the product communication protocols match the "
                    "acceptable protocol list."
                )
            ),
            score_awarded=maximum_score if passed else 0.0,
            maximum_score=maximum_score,
        )

    @classmethod
    def evaluate_data_completeness(
        cls,
        requirements: EngineeringRequirements,
        product: Product,
    ) -> RuleEvaluation:
        """Identify missing product data needed by supplied requirements."""

        missing_fields: list[str] = []

        if requirements.process_temperature_c is not None:
            if (
                product.minimum_process_temperature_c is None
                or product.maximum_process_temperature_c is None
            ):
                missing_fields.append("process temperature limits")

        if requirements.process_pressure_bar is not None:
            if (
                product.minimum_process_pressure_bar is None
                or product.maximum_process_pressure_bar is None
            ):
                missing_fields.append("process pressure limits")

        if requirements.ambient_temperature_c is not None:
            if (
                product.minimum_ambient_temperature_c is None
                or product.maximum_ambient_temperature_c is None
            ):
                missing_fields.append("ambient temperature limits")

        if (
            requirements.required_accuracy_percent is not None
            and product.accuracy_percent is None
        ):
            missing_fields.append("accuracy")

        if (
            requirements.required_ingress_protection_rating is not None
            and product.ingress_protection_rating is None
        ):
            missing_fields.append("ingress protection rating")

        if (
            requirements.hazardous_area_required
            and not product.hazardous_area_approvals
        ):
            missing_fields.append("hazardous-area approvals")

        if (
            requirements.required_wetted_materials
            and not product.wetted_materials
        ):
            missing_fields.append("wetted materials")

        if (
            requirements.required_process_connections
            and not product.process_connections
        ):
            missing_fields.append("process connections")

        if requirements.required_protocols and not product.protocols:
            missing_fields.append("communication protocols")

        if not missing_fields:
            return RuleEvaluation(
                rule_code="PRODUCT_ENGINEERING_DATA_COMPLETE",
                category=RuleCategory.DATA_COMPLETENESS,
                title="Product engineering data completeness",
                status=RuleStatus.PASSED,
                importance=RequirementImportance.MANDATORY,
                requirement_value="Data required for supplied requirements",
                product_value="Complete",
                explanation=(
                    "The product contains the engineering data required to "
                    "evaluate the supplied application requirements."
                ),
                score_awarded=0.0,
                maximum_score=0.0,
            )

        return RuleEvaluation(
            rule_code="PRODUCT_ENGINEERING_DATA_INCOMPLETE",
            category=RuleCategory.DATA_COMPLETENESS,
            title="Product engineering data completeness",
            status=RuleStatus.WARNING,
            importance=RequirementImportance.MANDATORY,
            requirement_value="Data required for supplied requirements",
            product_value={"missing_fields": missing_fields},
            explanation=(
                "The product is missing engineering data required for a "
                "complete evaluation: "
                + ", ".join(missing_fields)
                + "."
            ),
            score_awarded=0.0,
            maximum_score=0.0,
        )

    @classmethod
    def evaluate_all_rules(
        cls,
        requirements: EngineeringRequirements,
        product: Product,
    ) -> list[RuleEvaluation]:
        """Evaluate every supported engineering rule for one product."""

        return [
            cls.evaluate_process_temperature(requirements, product),
            cls.evaluate_process_pressure(requirements, product),
            cls.evaluate_ambient_temperature(requirements, product),
            cls.evaluate_accuracy(requirements, product),
            cls.evaluate_ingress_protection(requirements, product),
            cls.evaluate_hazardous_area(requirements, product),
            cls.evaluate_wetted_material(requirements, product),
            cls.evaluate_process_connection(requirements, product),
            cls.evaluate_protocol(requirements, product),
            cls.evaluate_data_completeness(requirements, product),
        ]