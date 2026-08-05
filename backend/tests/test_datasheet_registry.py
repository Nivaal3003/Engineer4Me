"""Step 109 controlled datasheet-template registry tests."""

from __future__ import annotations

import pytest
from app.engineering.calculations.units import DEFAULT_UNIT_REGISTRY
from app.engineering.design.datasheet_models import (
    DATASHEET_MODEL_VERSION,
    DatasheetFieldOrigin,
    DatasheetFieldRequirement,
    DatasheetTemplateLifecycleStatus,
    DatasheetValueKind,
    build_datasheet_template_fingerprint,
)
from app.engineering.design.datasheet_registry import (
    CONTROL_VALVE_TEMPLATE,
    DATASHEET_TEMPLATE_REGISTRY_VERSION,
    DATASHEET_TEMPLATE_VERSION,
    DATASHEET_TEMPLATES,
    DEFAULT_DATASHEET_TEMPLATE_REGISTRY,
    DP_FLOW_TEMPLATE,
    PRESSURE_RELIEF_TEMPLATE,
    DatasheetTemplateRegistry,
    DuplicateDatasheetTemplateRegistrationError,
    InvalidDatasheetTemplateLookupError,
    InvalidDatasheetTemplateRegistrationError,
    UnknownDatasheetTemplateError,
    UnknownDatasheetTemplateVersionError,
)
from pydantic import ValidationError

EXPECTED_TEMPLATES = {
    "analyzer.process": (
        30,
        "887c58a5be14c31c837ee0957c2d7ee8da96f66037f53e890e815173d0d9ccee",
    ),
    "instrument.dp-flow": (
        27,
        "a8a5576237cf9d9f83c777c58b4a4920483437b3c936bb73b9c11aec972d1678",
    ),
    "instrument.level-transmitter": (
        26,
        "0bd8e46b7281f139f67aadbc8526fb658b4d9e5dee921c988dd0fce015ce5cf5",
    ),
    "instrument.pressure-transmitter": (
        25,
        "ca748e7b81f04d11e3e9dd76454f6eed5de4441c8f2793f59e98ebe1aba3e97c",
    ),
    "valve.control": (
        33,
        "d605427362268538de47c0c6f268990fc1a33eb21dd5b689d20ef68b0d84de43",
    ),
    "valve.pressure-relief": (
        32,
        "b9e7532e6b802f7f7d3fea0b6e2d9cd2735bf4cd1f2a636e43caff8216160d94",
    ),
}


def test_default_registry_contains_exact_six_controlled_templates() -> None:
    assert DATASHEET_MODEL_VERSION == "1.0.0"
    assert DATASHEET_TEMPLATE_REGISTRY_VERSION == "1.0.0"
    assert DATASHEET_TEMPLATE_VERSION == "1.0.0"
    assert len(DATASHEET_TEMPLATES) == 6
    assert DEFAULT_DATASHEET_TEMPLATE_REGISTRY.templates == tuple(
        sorted(DATASHEET_TEMPLATES, key=lambda item: item.template_id)
    )
    assert set(DEFAULT_DATASHEET_TEMPLATE_REGISTRY.template_ids) == set(
        EXPECTED_TEMPLATES
    )


@pytest.mark.parametrize("template", DATASHEET_TEMPLATES)
def test_template_identity_and_fingerprint_are_golden(template) -> None:
    expected_count, expected_fingerprint = EXPECTED_TEMPLATES[template.template_id]
    assert template.template_version == "1.0.0"
    assert len(template.sections) == 5
    assert len(template.fields) == expected_count
    assert template.template_fingerprint == expected_fingerprint
    assert template.template_fingerprint == build_datasheet_template_fingerprint(
        template_id=template.template_id,
        template_version=template.template_version,
        title=template.title,
        discipline=template.discipline,
        sections=template.sections,
        fields=template.fields,
    )
    assert template.lifecycle_status is DatasheetTemplateLifecycleStatus.CONTROLLED
    assert template.vendor_neutral is True
    assert template.standards_conformity_claimed is False
    assert template.final_design_approval_granted is False


@pytest.mark.parametrize("template", DATASHEET_TEMPLATES)
def test_each_template_exercises_all_presence_rules(template) -> None:
    requirements = {field.requirement for field in template.fields}
    assert requirements == set(DatasheetFieldRequirement)
    assert any(field.safety_critical for field in template.fields)
    assert len({field.field_id.casefold() for field in template.fields}) == len(
        template.fields
    )


@pytest.mark.parametrize("template", DATASHEET_TEMPLATES)
def test_template_conditions_close_and_use_typed_values(template) -> None:
    fields = {field.field_id: field for field in template.fields}
    for field in template.fields:
        if field.condition is None:
            assert field.requirement is not DatasheetFieldRequirement.CONDITIONAL
            continue
        dependency = fields[field.condition.depends_on_field_id]
        assert field.requirement is DatasheetFieldRequirement.CONDITIONAL
        if dependency.value_kind is DatasheetValueKind.BOOLEAN:
            assert all(type(value) is bool for value in field.condition.expected_values)
        elif dependency.value_kind is DatasheetValueKind.NUMBER:
            assert all(
                type(value) in {int, float} for value in field.condition.expected_values
            )
        else:
            assert all(type(value) is str for value in field.condition.expected_values)


@pytest.mark.parametrize("template", DATASHEET_TEMPLATES)
def test_template_quantities_have_registered_dimensionally_compatible_units(
    template,
) -> None:
    for field in template.fields:
        if field.value_kind is not DatasheetValueKind.QUANTITY:
            continue
        expected_dimension = DEFAULT_UNIT_REGISTRY.dimension_for(field.quantity_kind)
        unit = DEFAULT_UNIT_REGISTRY.resolve_unit(field.preferred_unit)
        assert unit.dimension is expected_dimension


def test_registry_resolves_only_an_exact_explicit_version() -> None:
    for template in DATASHEET_TEMPLATES:
        assert (
            DEFAULT_DATASHEET_TEMPLATE_REGISTRY.resolve(
                template.template_id,
                template.template_version,
            )
            == template
        )
        assert DEFAULT_DATASHEET_TEMPLATE_REGISTRY.available_versions(
            template.template_id
        ) == ("1.0.0",)
    with pytest.raises(UnknownDatasheetTemplateVersionError):
        DEFAULT_DATASHEET_TEMPLATE_REGISTRY.resolve(
            "instrument.dp-flow",
            "1.0.1",
        )
    with pytest.raises(UnknownDatasheetTemplateError):
        DEFAULT_DATASHEET_TEMPLATE_REGISTRY.resolve(
            "instrument.not-registered",
            "1.0.0",
        )


@pytest.mark.parametrize(
    ("template_id", "version"),
    (
        ("", "1.0.0"),
        ("x", "1.0.0"),
        ("../instrument.dp-flow", "1.0.0"),
        ("instrument.dp-flow", "latest"),
        ("instrument.dp-flow", ""),
    ),
)
def test_registry_rejects_uncontrolled_lookup_components(
    template_id: str,
    version: str,
) -> None:
    with pytest.raises(InvalidDatasheetTemplateLookupError):
        DEFAULT_DATASHEET_TEMPLATE_REGISTRY.resolve(template_id, version)


def test_registry_rejects_empty_and_duplicate_inputs() -> None:
    with pytest.raises(InvalidDatasheetTemplateRegistrationError):
        DatasheetTemplateRegistry(())
    with pytest.raises(DuplicateDatasheetTemplateRegistrationError):
        DatasheetTemplateRegistry((DP_FLOW_TEMPLATE, DP_FLOW_TEMPLATE))


def test_registry_and_pydantic_templates_are_immutable() -> None:
    with pytest.raises(AttributeError):
        DEFAULT_DATASHEET_TEMPLATE_REGISTRY._templates = ()
    with pytest.raises(ValidationError):
        CONTROL_VALVE_TEMPLATE.title = "Changed"


def test_discovery_is_deterministic_and_does_not_choose_a_version() -> None:
    expected = tuple(sorted(DATASHEET_TEMPLATES, key=lambda item: item.template_id))
    assert DEFAULT_DATASHEET_TEMPLATE_REGISTRY.discover() == expected
    assert (
        DEFAULT_DATASHEET_TEMPLATE_REGISTRY.discover(
            discipline="instrumentation-control"
        )
        == expected
    )
    assert DEFAULT_DATASHEET_TEMPLATE_REGISTRY.discover(discipline="process") == ()


def test_dp_flow_template_has_no_proprietary_annubar_family() -> None:
    family = next(
        field
        for field in DP_FLOW_TEMPLATE.fields
        if field.field_id == "primary_element_family"
    )
    assert "annubar" not in {value.casefold() for value in family.allowed_values}
    assert "averaging_pitot" in family.allowed_values


def test_pressure_relief_template_remains_preliminary_and_unapproved() -> None:
    assert "Preliminary" in PRESSURE_RELIEF_TEMPLATE.title
    assert PRESSURE_RELIEF_TEMPLATE.standards_conformity_claimed is False
    assert PRESSURE_RELIEF_TEMPLATE.final_design_approval_granted is False


def test_relief_and_control_valve_templates_close_review_readiness_gaps() -> None:
    relief_fields = {field.field_id: field for field in PRESSURE_RELIEF_TEMPLATE.fields}
    affirmative = {
        "governing_scenario_confirmed",
        "inlet_piping_verified",
        "outlet_piping_verified",
        "competent_review_completed",
    }
    assert all(
        relief_fields[field_id].required_boolean_value is True
        and set(relief_fields[field_id].allowed_origins)
        == {
            DatasheetFieldOrigin.USER_SUPPLIED,
            DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
        }
        for field_id in affirmative
    )
    assert "two_phase" not in relief_fields["fluid_phase"].allowed_values
    assert {
        "backpressure_basis",
        "backpressure_gauge",
        "backpressure_absolute",
        "atmospheric_pressure",
        "steam_specific_volume_m3_kg",
        "steam_specific_volume_basis",
        "steam_eligibility_confirmed",
        "required_area_basis_verified",
    }.issubset(relief_fields)
    assert relief_fields["preliminary_required_area"].positive_value_required
    assert (
        DatasheetFieldOrigin.SELECTED
        not in relief_fields["preliminary_required_area"].allowed_origins
    )

    valve_fields = {field.field_id: field for field in CONTROL_VALVE_TEMPLATE.fields}
    assert {
        "steam_state_basis",
        "steam_eligibility_confirmed",
    }.issubset(valve_fields)
    assert valve_fields["steam_eligibility_confirmed"].required_boolean_value
    assert set(valve_fields["steam_state_basis"].allowed_values) == {
        "dry_saturated",
        "superheated",
    }
    assert valve_fields["required_flow_coefficient"].positive_value_required
    assert set(valve_fields["required_flow_coefficient"].allowed_origins) == {
        DatasheetFieldOrigin.USER_SUPPLIED,
        DatasheetFieldOrigin.DOCUMENT_EXTRACTED,
    }


def test_number_fields_never_promise_unrepresentable_calculated_outputs() -> None:
    for template in DATASHEET_TEMPLATES:
        for field in template.fields:
            if field.value_kind is DatasheetValueKind.NUMBER:
                assert DatasheetFieldOrigin.CALCULATED not in field.allowed_origins


def test_templates_contain_no_executable_metadata_fields() -> None:
    forbidden = {"callable", "expression", "formula", "import_path", "python"}
    for template in DATASHEET_TEMPLATES:
        dumped = template.model_dump(mode="json", warnings="error")
        assert forbidden.isdisjoint(dumped)
        for field in template.fields:
            assert forbidden.isdisjoint(field.model_dump(mode="json"))


def test_design_package_exports_complete_step109_boundary() -> None:
    import app.engineering.design as design_package
    from app.engineering.design import (
        datasheet_models,
        datasheet_registry,
        datasheet_service,
    )

    expected = set(datasheet_models.__all__)
    expected.update(datasheet_registry.__all__)
    expected.update(datasheet_service.__all__)

    assert design_package.FOUNDATION_VERSION == "0.2.0"
    assert design_package.VOICE_FUNCTIONALITY_ENABLED is False
    assert expected.issubset(design_package.__all__)
    assert len(design_package.__all__) == len(set(design_package.__all__))
    assert all(hasattr(design_package, name) for name in design_package.__all__)
