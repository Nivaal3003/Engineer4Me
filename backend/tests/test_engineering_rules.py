"""Tests for the Phase 3 engineering rule engine."""

from types import SimpleNamespace

from app.engineering.engineering_rules import EngineeringRuleEngine
from app.engineering.recommendation_models import (
    EngineeringRequirements,
    RequirementImportance,
    RuleStatus,
)


def build_product(**overrides):
    """Create a lightweight product object for isolated rule testing."""

    defaults = {
        "minimum_process_temperature_c": -40.0,
        "maximum_process_temperature_c": 200.0,
        "minimum_process_pressure_bar": 0.0,
        "maximum_process_pressure_bar": 100.0,
        "minimum_ambient_temperature_c": -20.0,
        "maximum_ambient_temperature_c": 70.0,
        "accuracy_percent": 0.1,
        "ingress_protection_rating": "IP66",
        "hazardous_area_approvals": ["ATEX", "IECEx"],
        "wetted_materials": ["316L Stainless Steel", "Hastelloy C-276"],
        "process_connections": ["1/2 NPT", "G1/2"],
        "protocols": [
            SimpleNamespace(name="HART"),
            SimpleNamespace(name="Modbus"),
        ],
    }

    defaults.update(overrides)

    return SimpleNamespace(**defaults)


def test_process_temperature_passes_within_limits() -> None:
    requirements = EngineeringRequirements(
        process_temperature_c=120.0,
    )
    product = build_product()

    result = EngineeringRuleEngine.evaluate_process_temperature(
        requirements,
        product,
    )

    assert result.status == RuleStatus.PASSED
    assert result.rule_code == "PROCESS_TEMPERATURE_WITHIN_LIMITS"
    assert result.score_awarded == 15.0


def test_process_temperature_fails_outside_limits() -> None:
    requirements = EngineeringRequirements(
        process_temperature_c=250.0,
    )
    product = build_product()

    result = EngineeringRuleEngine.evaluate_process_temperature(
        requirements,
        product,
    )

    assert result.status == RuleStatus.FAILED
    assert result.rule_code == "PROCESS_TEMPERATURE_OUTSIDE_LIMITS"
    assert result.score_awarded == 0.0


def test_missing_process_temperature_data_returns_warning() -> None:
    requirements = EngineeringRequirements(
        process_temperature_c=100.0,
    )
    product = build_product(
        minimum_process_temperature_c=None,
        maximum_process_temperature_c=None,
    )

    result = EngineeringRuleEngine.evaluate_process_temperature(
        requirements,
        product,
    )

    assert result.status == RuleStatus.WARNING
    assert result.rule_code == "PROCESS_TEMPERATURE_DATA_MISSING"


def test_process_pressure_passes_within_limits() -> None:
    requirements = EngineeringRequirements(
        process_pressure_bar=40.0,
    )
    product = build_product()

    result = EngineeringRuleEngine.evaluate_process_pressure(
        requirements,
        product,
    )

    assert result.status == RuleStatus.PASSED
    assert result.rule_code == "PROCESS_PRESSURE_WITHIN_LIMITS"
    assert result.score_awarded == 15.0


def test_process_pressure_fails_outside_limits() -> None:
    requirements = EngineeringRequirements(
        process_pressure_bar=150.0,
    )
    product = build_product()

    result = EngineeringRuleEngine.evaluate_process_pressure(
        requirements,
        product,
    )

    assert result.status == RuleStatus.FAILED
    assert result.rule_code == "PROCESS_PRESSURE_OUTSIDE_LIMITS"


def test_ambient_temperature_fails_outside_limits() -> None:
    requirements = EngineeringRequirements(
        ambient_temperature_c=80.0,
    )
    product = build_product()

    result = EngineeringRuleEngine.evaluate_ambient_temperature(
        requirements,
        product,
    )

    assert result.status == RuleStatus.FAILED
    assert result.rule_code == "AMBIENT_TEMPERATURE_OUTSIDE_LIMITS"


def test_accuracy_passes_when_product_is_more_accurate() -> None:
    requirements = EngineeringRequirements(
        required_accuracy_percent=0.25,
    )
    product = build_product(accuracy_percent=0.1)

    result = EngineeringRuleEngine.evaluate_accuracy(
        requirements,
        product,
    )

    assert result.status == RuleStatus.PASSED
    assert result.rule_code == "ACCURACY_MEETS_REQUIREMENT"
    assert result.score_awarded == 10.0


def test_accuracy_fails_when_product_is_less_accurate() -> None:
    requirements = EngineeringRequirements(
        required_accuracy_percent=0.05,
    )
    product = build_product(accuracy_percent=0.1)

    result = EngineeringRuleEngine.evaluate_accuracy(
        requirements,
        product,
    )

    assert result.status == RuleStatus.FAILED
    assert result.rule_code == "ACCURACY_DOES_NOT_MEET_REQUIREMENT"


def test_ingress_protection_passes_when_product_rating_is_higher() -> None:
    requirements = EngineeringRequirements(
        required_ingress_protection_rating="IP65",
    )
    product = build_product(
        ingress_protection_rating="IP66",
    )

    result = EngineeringRuleEngine.evaluate_ingress_protection(
        requirements,
        product,
    )

    assert result.status == RuleStatus.PASSED
    assert result.rule_code == "INGRESS_PROTECTION_MEETS_REQUIREMENT"


def test_ingress_protection_fails_when_product_rating_is_lower() -> None:
    requirements = EngineeringRequirements(
        required_ingress_protection_rating="IP67",
    )
    product = build_product(
        ingress_protection_rating="IP65",
    )

    result = EngineeringRuleEngine.evaluate_ingress_protection(
        requirements,
        product,
    )

    assert result.status == RuleStatus.FAILED
    assert result.rule_code == (
        "INGRESS_PROTECTION_DOES_NOT_MEET_REQUIREMENT"
    )


def test_unsupported_ip_format_returns_warning() -> None:
    requirements = EngineeringRequirements(
        required_ingress_protection_rating="NEMA 4X",
    )
    product = build_product(
        ingress_protection_rating="IP66",
    )

    result = EngineeringRuleEngine.evaluate_ingress_protection(
        requirements,
        product,
    )

    assert result.status == RuleStatus.WARNING
    assert result.rule_code == "INGRESS_PROTECTION_FORMAT_UNSUPPORTED"


def test_hazardous_area_approval_passes_when_all_approvals_match() -> None:
    requirements = EngineeringRequirements(
        hazardous_area_required=True,
        required_hazardous_area_approvals=["ATEX", "IECEx"],
    )
    product = build_product()

    result = EngineeringRuleEngine.evaluate_hazardous_area(
        requirements,
        product,
    )

    assert result.status == RuleStatus.PASSED
    assert result.rule_code == "HAZARDOUS_AREA_APPROVALS_MATCH"
    assert result.score_awarded == 15.0


def test_hazardous_area_approval_fails_when_product_has_no_approval() -> None:
    requirements = EngineeringRequirements(
        hazardous_area_required=True,
        required_hazardous_area_approvals=["IECEx"],
    )
    product = build_product(
        hazardous_area_approvals=[],
    )

    result = EngineeringRuleEngine.evaluate_hazardous_area(
        requirements,
        product,
    )

    assert result.status == RuleStatus.FAILED
    assert result.rule_code == "HAZARDOUS_AREA_APPROVALS_MISSING"


def test_hazardous_area_without_site_details_returns_warning() -> None:
    requirements = EngineeringRequirements(
        hazardous_area_required=True,
    )
    product = build_product()

    result = EngineeringRuleEngine.evaluate_hazardous_area(
        requirements,
        product,
    )

    assert result.status == RuleStatus.WARNING
    assert result.rule_code == "HAZARDOUS_AREA_DETAILS_INCOMPLETE"
    assert result.score_awarded == 7.5


def test_wetted_material_passes_when_one_acceptable_material_matches() -> None:
    requirements = EngineeringRequirements(
        required_wetted_materials=["Hastelloy C-276"],
    )
    product = build_product()

    result = EngineeringRuleEngine.evaluate_wetted_material(
        requirements,
        product,
    )

    assert result.status == RuleStatus.PASSED
    assert result.rule_code == "WETTED_MATERIAL_MATCH"


def test_wetted_material_fails_when_no_material_matches() -> None:
    requirements = EngineeringRequirements(
        required_wetted_materials=["Tantalum"],
    )
    product = build_product()

    result = EngineeringRuleEngine.evaluate_wetted_material(
        requirements,
        product,
    )

    assert result.status == RuleStatus.FAILED
    assert result.rule_code == "WETTED_MATERIAL_NO_MATCH"


def test_process_connection_passes_when_one_connection_matches() -> None:
    requirements = EngineeringRequirements(
        required_process_connections=["1/2 NPT"],
    )
    product = build_product()

    result = EngineeringRuleEngine.evaluate_process_connection(
        requirements,
        product,
    )

    assert result.status == RuleStatus.PASSED
    assert result.rule_code == "PROCESS_CONNECTION_MATCH"


def test_protocol_passes_when_one_protocol_matches() -> None:
    requirements = EngineeringRequirements(
        required_protocols=["HART"],
    )
    product = build_product()

    result = EngineeringRuleEngine.evaluate_protocol(
        requirements,
        product,
    )

    assert result.status == RuleStatus.PASSED
    assert result.rule_code == "COMMUNICATION_PROTOCOL_MATCH"


def test_protocol_fails_when_no_protocol_matches() -> None:
    requirements = EngineeringRequirements(
        required_protocols=["PROFINET"],
    )
    product = build_product()

    result = EngineeringRuleEngine.evaluate_protocol(
        requirements,
        product,
    )

    assert result.status == RuleStatus.FAILED
    assert result.rule_code == "COMMUNICATION_PROTOCOL_NO_MATCH"


def test_data_completeness_reports_missing_required_product_data() -> None:
    requirements = EngineeringRequirements(
        process_temperature_c=100.0,
        process_pressure_bar=10.0,
        required_protocols=["HART"],
    )
    product = build_product(
        minimum_process_temperature_c=None,
        maximum_process_temperature_c=None,
        protocols=[],
    )

    result = EngineeringRuleEngine.evaluate_data_completeness(
        requirements,
        product,
    )

    assert result.status == RuleStatus.WARNING
    assert result.rule_code == "PRODUCT_ENGINEERING_DATA_INCOMPLETE"
    assert "process temperature limits" in result.product_value["missing_fields"]
    assert "communication protocols" in result.product_value["missing_fields"]


def test_evaluate_all_rules_returns_all_supported_rule_results() -> None:
    requirements = EngineeringRequirements(
        process_temperature_c=100.0,
        process_pressure_bar=20.0,
        ambient_temperature_c=40.0,
        required_accuracy_percent=0.25,
        required_ingress_protection_rating="IP65",
        hazardous_area_required=True,
        required_hazardous_area_approvals=["ATEX"],
        required_wetted_materials=["316L Stainless Steel"],
        required_process_connections=["1/2 NPT"],
        required_protocols=["HART"],
    )
    product = build_product()

    results = EngineeringRuleEngine.evaluate_all_rules(
        requirements,
        product,
    )

    assert len(results) == 10
    assert all(result.status == RuleStatus.PASSED for result in results)


def test_preferred_rule_failure_retains_preferred_importance() -> None:
    requirements = EngineeringRequirements(
        required_protocols=["PROFINET"],
        communication_protocol_importance=RequirementImportance.PREFERRED,
    )
    product = build_product()

    result = EngineeringRuleEngine.evaluate_protocol(
        requirements,
        product,
    )

    assert result.status == RuleStatus.FAILED
    assert result.importance == RequirementImportance.PREFERRED