"""Tests for the deterministic Phase 7 engineering unit subsystem."""

from __future__ import annotations

import ast
from decimal import Decimal
from enum import StrEnum
from inspect import Parameter
from inspect import signature
from math import inf
from math import nan
from math import nextafter
from pathlib import Path
from types import MappingProxyType

import pytest
from pydantic import ValidationError

import app.engineering.calculations as calculation_package
import app.engineering.calculations.units as units_module
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.units import CompressibilityTreatment
from app.engineering.calculations.units import DEFAULT_UNIT_REGISTRY
from app.engineering.calculations.units import FlowReferenceBasis
from app.engineering.calculations.units import IncompatibleUnitError
from app.engineering.calculations.units import PhysicalDimension
from app.engineering.calculations.units import PresentationRoundingError
from app.engineering.calculations.units import PresentationRoundingMode
from app.engineering.calculations.units import PressureBasisError
from app.engineering.calculations.units import QuantityKind
from app.engineering.calculations.units import ReferenceConditionError
from app.engineering.calculations.units import ReferenceConditions
from app.engineering.calculations.units import ReferencedVolumetricFlow
from app.engineering.calculations.units import UnitConversionError
from app.engineering.calculations.units import UnitDefinition
from app.engineering.calculations.units import UnitRegistry
from app.engineering.calculations.units import UnitRegistryError
from app.engineering.calculations.units import UnknownQuantityKindError
from app.engineering.calculations.units import UnknownUnitError
from app.engineering.calculations.units import convert_pressure_basis
from app.engineering.calculations.units import (
    convert_referenced_volumetric_flow,
)
from app.engineering.calculations.units import format_quantity_value
from app.engineering.calculations.units import presentation_value
from app.engineering.calculations.units import round_decimal_places
from app.engineering.calculations.units import round_significant_figures


REGISTRY = DEFAULT_UNIT_REGISTRY


KIND_BY_DIMENSION = {
    PhysicalDimension.DIMENSIONLESS: QuantityKind.RATIO,
    PhysicalDimension.ANGLE: QuantityKind.ANGLE,
    PhysicalDimension.LENGTH: QuantityKind.LENGTH,
    PhysicalDimension.AREA: QuantityKind.AREA,
    PhysicalDimension.VOLUME: QuantityKind.VOLUME,
    PhysicalDimension.TIME: QuantityKind.TIME,
    PhysicalDimension.MASS: QuantityKind.MASS,
    PhysicalDimension.ABSOLUTE_TEMPERATURE: (
        QuantityKind.ABSOLUTE_TEMPERATURE
    ),
    PhysicalDimension.TEMPERATURE_DIFFERENCE: (
        QuantityKind.TEMPERATURE_DIFFERENCE
    ),
    PhysicalDimension.PRESSURE: QuantityKind.ABSOLUTE_PRESSURE,
    PhysicalDimension.DENSITY: QuantityKind.DENSITY,
    PhysicalDimension.DYNAMIC_VISCOSITY: (
        QuantityKind.DYNAMIC_VISCOSITY
    ),
    PhysicalDimension.KINEMATIC_VISCOSITY: (
        QuantityKind.KINEMATIC_VISCOSITY
    ),
    PhysicalDimension.VELOCITY: QuantityKind.VELOCITY,
    PhysicalDimension.ACCELERATION: QuantityKind.ACCELERATION,
    PhysicalDimension.VOLUMETRIC_FLOW: (
        QuantityKind.ACTUAL_VOLUMETRIC_FLOW
    ),
    PhysicalDimension.MASS_FLOW: QuantityKind.MASS_FLOW,
    PhysicalDimension.FORCE: QuantityKind.FORCE,
    PhysicalDimension.ENERGY: QuantityKind.ENERGY,
    PhysicalDimension.POWER: QuantityKind.POWER,
    PhysicalDimension.ELECTRIC_CURRENT: QuantityKind.ELECTRIC_CURRENT,
    PhysicalDimension.ELECTRIC_POTENTIAL: (
        QuantityKind.ELECTRIC_POTENTIAL
    ),
    PhysicalDimension.ELECTRICAL_RESISTANCE: (
        QuantityKind.ELECTRICAL_RESISTANCE
    ),
    PhysicalDimension.FREQUENCY: QuantityKind.FREQUENCY,
}


def quantity(
    quantity_kind: QuantityKind | str,
    value: float,
    unit: str,
    **kwargs: object,
) -> EngineeringQuantity:
    """Build one strict engineering quantity for a test."""

    kind_value = (
        quantity_kind.value
        if isinstance(quantity_kind, QuantityKind)
        else quantity_kind
    )
    return EngineeringQuantity(
        quantity_kind=kind_value,
        value=value,
        unit=unit,
        **kwargs,
    )


def reference_conditions(
    *,
    reference_id: str,
    basis: FlowReferenceBasis,
    pressure: float = 101_325.0,
    pressure_unit: str = "Pa",
    temperature: float = 273.15,
    temperature_unit: str = "K",
    treatment: CompressibilityTreatment = (
        CompressibilityTreatment.IDEAL_GAS
    ),
    compressibility_factor: float | None = None,
) -> ReferenceConditions:
    """Build explicit reference conditions without hidden defaults."""

    return ReferenceConditions(
        reference_id=reference_id,
        basis=basis,
        absolute_pressure=quantity(
            QuantityKind.ABSOLUTE_PRESSURE,
            pressure,
            pressure_unit,
        ),
        absolute_temperature=quantity(
            QuantityKind.ABSOLUTE_TEMPERATURE,
            temperature,
            temperature_unit,
        ),
        compressibility_treatment=treatment,
        compressibility_factor=compressibility_factor,
    )


def referenced_flow(
    *,
    value: float,
    unit: str,
    conditions: ReferenceConditions,
    uncertainty: float | None = None,
    uncertainty_basis: str | None = None,
    significant_figures: int | None = None,
    decimal_places: int | None = None,
) -> ReferencedVolumetricFlow:
    """Build a flow whose quantity kind matches the explicit basis."""

    kinds = {
        FlowReferenceBasis.ACTUAL: QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
        FlowReferenceBasis.STANDARD: (
            QuantityKind.STANDARD_VOLUMETRIC_FLOW
        ),
        FlowReferenceBasis.NORMAL: QuantityKind.NORMAL_VOLUMETRIC_FLOW,
        FlowReferenceBasis.CUSTOM: (
            QuantityKind.REFERENCE_VOLUMETRIC_FLOW
        ),
    }
    return ReferencedVolumetricFlow(
        quantity=quantity(
            kinds[conditions.basis],
            value,
            unit,
            uncertainty=uncertainty,
            uncertainty_basis=uncertainty_basis,
            significant_figures=significant_figures,
            decimal_places=decimal_places,
        ),
        reference_conditions=conditions,
    )


def small_length_registry(
    definitions: tuple[UnitDefinition, ...] | None = None,
    *,
    quantity_dimensions: dict[
        QuantityKind | str,
        PhysicalDimension | str,
    ]
    | None = None,
    canonical_units: dict[PhysicalDimension | str, str] | None = None,
) -> UnitRegistry:
    """Build a minimal registry for registry-integrity tests."""

    metre = UnitDefinition(
        symbol="m",
        name="metre",
        dimension=PhysicalDimension.LENGTH,
        scale_to_canonical=Decimal("1"),
    )
    return UnitRegistry(
        (metre,) if definitions is None else definitions,
        quantity_dimensions=(
            {QuantityKind.LENGTH: PhysicalDimension.LENGTH}
            if quantity_dimensions is None
            else quantity_dimensions
        ),
        canonical_units=(
            {PhysicalDimension.LENGTH: "m"}
            if canonical_units is None
            else canonical_units
        ),
    )


def test_default_registry_is_immutable_and_complete() -> None:
    assert isinstance(REGISTRY.definitions, tuple)
    assert isinstance(REGISTRY.aliases, MappingProxyType)
    assert isinstance(REGISTRY.quantity_dimensions, MappingProxyType)
    assert isinstance(REGISTRY.canonical_units, MappingProxyType)
    assert len(REGISTRY.definitions) == 106
    assert set(REGISTRY.quantity_dimensions) == set(QuantityKind)
    assert set(REGISTRY.canonical_units) == set(PhysicalDimension)

    with pytest.raises(TypeError):
        REGISTRY.aliases["new"] = REGISTRY.definitions[0]  # type: ignore[index]

    with pytest.raises(TypeError):
        REGISTRY.quantity_dimensions[QuantityKind.LENGTH] = (  # type: ignore[index]
            PhysicalDimension.MASS
        )

    with pytest.raises(TypeError):
        REGISTRY.canonical_units[PhysicalDimension.LENGTH] = "ft"  # type: ignore[index]

    with pytest.raises(AttributeError):
        REGISTRY._definitions = ()  # type: ignore[misc]

    for attribute_name in UnitRegistry.__slots__:
        with pytest.raises(AttributeError):
            REGISTRY.__delattr__(attribute_name)


@pytest.mark.parametrize(
    "definition",
    REGISTRY.definitions,
    ids=lambda definition: definition.symbol,
)
def test_every_canonical_symbol_resolves_exactly(
    definition: UnitDefinition,
) -> None:
    resolved = REGISTRY.resolve_unit(definition.symbol)
    assert resolved is definition
    assert resolved.symbol == definition.symbol


ALIAS_CASES = tuple(
    (alias, definition)
    for definition in REGISTRY.definitions
    for alias in definition.aliases
)


@pytest.mark.parametrize(
    ("alias", "definition"),
    ALIAS_CASES,
    ids=lambda value: (
        value.symbol
        if isinstance(value, UnitDefinition)
        else value
    ),
)
def test_every_alias_resolves_to_its_canonical_definition(
    alias: str,
    definition: UnitDefinition,
) -> None:
    resolved = REGISTRY.resolve_unit(alias)
    assert resolved is definition
    assert resolved.symbol == definition.symbol


@pytest.mark.parametrize(
    "definition",
    REGISTRY.definitions,
    ids=lambda definition: definition.symbol,
)
def test_every_registered_unit_round_trips_through_canonical(
    definition: UnitDefinition,
) -> None:
    kind = KIND_BY_DIMENSION[definition.dimension]
    canonical_unit = REGISTRY.canonical_unit_for(kind)
    converted = REGISTRY.convert_value(
        2.5,
        canonical_unit,
        definition.symbol,
        quantity_kind=kind,
    )
    restored = REGISTRY.convert_value(
        converted,
        definition.symbol,
        canonical_unit,
        quantity_kind=kind,
    )
    assert restored == pytest.approx(2.5, rel=1e-14, abs=1e-14)


@pytest.mark.parametrize(
    ("quantity_kind", "expected_dimension", "expected_unit"),
    [
        (
            kind,
            dimension,
            REGISTRY.canonical_units[dimension],
        )
        for kind, dimension in REGISTRY.quantity_dimensions.items()
    ],
    ids=lambda value: value.value if isinstance(value, StrEnum) else value,
)
def test_every_quantity_kind_has_one_dimension_and_canonical_unit(
    quantity_kind: QuantityKind,
    expected_dimension: PhysicalDimension,
    expected_unit: str,
) -> None:
    assert REGISTRY.dimension_for(quantity_kind) is expected_dimension
    assert REGISTRY.dimension_for(quantity_kind.value) is expected_dimension
    assert REGISTRY.canonical_unit_for(quantity_kind) == expected_unit
    definition = REGISTRY.resolve_unit(expected_unit)
    assert definition.dimension is expected_dimension
    assert definition.scale_to_canonical == 1
    assert definition.offset_to_canonical == 0


def test_unit_symbols_are_case_sensitive() -> None:
    assert REGISTRY.resolve_unit("MPa").scale_to_canonical == Decimal(
        "1000000"
    )
    assert REGISTRY.resolve_unit("mPa").scale_to_canonical == Decimal(
        "0.001"
    )
    assert REGISTRY.convert_value(
        1.0,
        "MPa",
        "mPa",
        quantity_kind=QuantityKind.ABSOLUTE_PRESSURE,
    ) == 1_000_000_000.0

    with pytest.raises(UnknownUnitError):
        REGISTRY.resolve_unit("mpa")


@pytest.mark.parametrize(
    "unsupported_symbol",
    (
        "",
        "   ",
        "unknown",
        "PSI",
        "barg",
        "bar(g)",
        "psig",
        "psia",
        "scfm",
        "Nm3/h",
        "normal m3/h",
        "gal",
        "ton",
        "x" * 41,
    ),
)
def test_unsupported_or_semantically_ambiguous_units_are_rejected(
    unsupported_symbol: str,
) -> None:
    with pytest.raises(UnknownUnitError):
        REGISTRY.resolve_unit(unsupported_symbol)


@pytest.mark.parametrize("unsupported_symbol", (None, 1, 1.0, True))
def test_non_string_unit_symbols_are_rejected(
    unsupported_symbol: object,
) -> None:
    with pytest.raises(UnknownUnitError):
        REGISTRY.resolve_unit(unsupported_symbol)  # type: ignore[arg-type]


def test_resolve_unit_strips_only_surrounding_whitespace() -> None:
    assert REGISTRY.resolve_unit("  kPa  ").symbol == "kPa"

    with pytest.raises(UnknownUnitError):
        REGISTRY.resolve_unit("k Pa")


def test_unit_definition_requires_decimal_constants() -> None:
    with pytest.raises(ValidationError):
        UnitDefinition(
            symbol="x",
            name="test unit",
            dimension=PhysicalDimension.LENGTH,
            scale_to_canonical=1.0,  # type: ignore[arg-type]
        )

    with pytest.raises(ValidationError):
        UnitDefinition(
            symbol="x",
            name="test unit",
            dimension=PhysicalDimension.LENGTH,
            scale_to_canonical=Decimal("NaN"),
        )


def test_unit_definition_round_trips_through_json() -> None:
    definition = UnitDefinition(
        symbol="json_u",
        name="JSON test unit",
        dimension=PhysicalDimension.LENGTH,
        scale_to_canonical=Decimal("1.25"),
        aliases=("json unit",),
    )
    restored = UnitDefinition.model_validate_json(
        definition.model_dump_json()
    )
    assert restored == definition


def test_unit_definition_rejects_python_decimal_strings() -> None:
    with pytest.raises(ValidationError):
        UnitDefinition.model_validate(
            {
                "symbol": "python_u",
                "name": "Python test unit",
                "dimension": PhysicalDimension.LENGTH,
                "scale_to_canonical": "1.25",
            }
        )


def test_unit_definition_rejects_json_binary_float_constants() -> None:
    with pytest.raises(ValidationError):
        UnitDefinition.model_validate_json(
            """
            {
                "symbol": "float_u",
                "name": "Float test unit",
                "dimension": "length",
                "scale_to_canonical": 1.25
            }
            """
        )


@pytest.mark.parametrize(
    "scale",
    (Decimal("0"), Decimal("-1"), Decimal("-0.001")),
)
def test_unit_definition_requires_positive_scale(
    scale: Decimal,
) -> None:
    with pytest.raises(ValidationError):
        UnitDefinition(
            symbol="x",
            name="test unit",
            dimension=PhysicalDimension.LENGTH,
            scale_to_canonical=scale,
        )


def test_non_temperature_unit_cannot_have_affine_offset() -> None:
    with pytest.raises(ValidationError):
        UnitDefinition(
            symbol="offset_m",
            name="offset metre",
            dimension=PhysicalDimension.LENGTH,
            scale_to_canonical=Decimal("1"),
            offset_to_canonical=Decimal("2"),
        )


def test_absolute_temperature_unit_may_have_affine_offset() -> None:
    definition = UnitDefinition(
        symbol="test_C",
        name="test Celsius",
        dimension=PhysicalDimension.ABSOLUTE_TEMPERATURE,
        scale_to_canonical=Decimal("1"),
        offset_to_canonical=Decimal("273.15"),
    )
    assert definition.offset_to_canonical == Decimal("273.15")


@pytest.mark.parametrize(
    "aliases",
    (
        ("duplicate", "duplicate"),
        ("x", "x"),
    ),
)
def test_unit_definition_rejects_duplicate_aliases(
    aliases: tuple[str, str],
) -> None:
    with pytest.raises(ValidationError):
        UnitDefinition(
            symbol="x",
            name="test unit",
            dimension=PhysicalDimension.LENGTH,
            scale_to_canonical=Decimal("1"),
            aliases=aliases,
        )


def test_registry_rejects_duplicate_symbols() -> None:
    metre = UnitDefinition(
        symbol="m",
        name="metre",
        dimension=PhysicalDimension.LENGTH,
        scale_to_canonical=Decimal("1"),
    )

    with pytest.raises(UnitRegistryError, match="Duplicate"):
        small_length_registry((metre, metre))


def test_registry_rejects_alias_collisions() -> None:
    metre = UnitDefinition(
        symbol="m",
        name="metre",
        dimension=PhysicalDimension.LENGTH,
        scale_to_canonical=Decimal("1"),
        aliases=("metre",),
    )
    other = UnitDefinition(
        symbol="metre",
        name="other metre",
        dimension=PhysicalDimension.LENGTH,
        scale_to_canonical=Decimal("2"),
    )

    with pytest.raises(UnitRegistryError, match="Duplicate"):
        small_length_registry((metre, other))


def test_registry_rejects_empty_definitions() -> None:
    with pytest.raises(UnitRegistryError, match="at least one"):
        small_length_registry(())


def test_registry_rejects_empty_quantity_kind_mapping() -> None:
    with pytest.raises(UnitRegistryError, match="quantity-kind"):
        small_length_registry(quantity_dimensions={})


def test_registry_rejects_unknown_quantity_kind_mapping() -> None:
    with pytest.raises(UnitRegistryError, match="Unsupported quantity"):
        small_length_registry(
            quantity_dimensions={"custom.length": PhysicalDimension.LENGTH}
        )


def test_registry_rejects_unknown_dimension_mapping() -> None:
    with pytest.raises(UnitRegistryError, match="Unsupported physical"):
        small_length_registry(
            quantity_dimensions={QuantityKind.LENGTH: "imaginary"}
        )


def test_registry_requires_canonical_unit_for_every_dimension() -> None:
    with pytest.raises(UnitRegistryError, match="missing"):
        small_length_registry(canonical_units={})


def test_registry_canonical_unit_must_be_registered_symbol_not_alias() -> None:
    metre = UnitDefinition(
        symbol="m",
        name="metre",
        dimension=PhysicalDimension.LENGTH,
        scale_to_canonical=Decimal("1"),
        aliases=("metre",),
    )

    with pytest.raises(UnitRegistryError, match="registered symbol"):
        small_length_registry(
            (metre,),
            canonical_units={PhysicalDimension.LENGTH: "metre"},
        )


def test_registry_canonical_unit_must_have_matching_dimension() -> None:
    second = UnitDefinition(
        symbol="s",
        name="second",
        dimension=PhysicalDimension.TIME,
        scale_to_canonical=Decimal("1"),
    )

    with pytest.raises(UnitRegistryError, match="wrong dimension"):
        small_length_registry(
            (second,),
            canonical_units={PhysicalDimension.LENGTH: "s"},
        )


def test_registry_canonical_unit_must_have_unit_scale_and_zero_offset() -> None:
    centimetre = UnitDefinition(
        symbol="cm",
        name="centimetre",
        dimension=PhysicalDimension.LENGTH,
        scale_to_canonical=Decimal("0.01"),
    )

    with pytest.raises(UnitRegistryError, match="scale 1"):
        small_length_registry(
            (centimetre,),
            canonical_units={PhysicalDimension.LENGTH: "cm"},
        )


@pytest.mark.parametrize(
    ("scale", "value"),
    (
        (Decimal("1E+1000000"), Decimal("1E+300")),
        (Decimal("1E-999999"), Decimal("1E-300")),
    ),
)
def test_extreme_custom_scales_raise_controlled_conversion_error(
    scale: Decimal,
    value: Decimal,
) -> None:
    metre = UnitDefinition(
        symbol="m",
        name="metre",
        dimension=PhysicalDimension.LENGTH,
        scale_to_canonical=Decimal("1"),
    )
    extreme = UnitDefinition(
        symbol="extreme",
        name="extreme unit",
        dimension=PhysicalDimension.LENGTH,
        scale_to_canonical=scale,
    )
    registry = small_length_registry((metre, extreme))

    with pytest.raises(UnitConversionError):
        registry.convert_value(
            value,
            "extreme",
            "m",
            quantity_kind=QuantityKind.LENGTH,
        )


def test_extreme_custom_scale_uncertainty_raises_controlled_error() -> None:
    metre = UnitDefinition(
        symbol="m",
        name="metre",
        dimension=PhysicalDimension.LENGTH,
        scale_to_canonical=Decimal("1"),
    )
    tiny = UnitDefinition(
        symbol="tiny",
        name="tiny unit",
        dimension=PhysicalDimension.LENGTH,
        scale_to_canonical=Decimal("1E-999999"),
    )
    registry = small_length_registry((metre, tiny))
    source = quantity(
        QuantityKind.LENGTH,
        0.0,
        "m",
        uncertainty=1.0e300,
        uncertainty_basis="Extreme uncertainty vector.",
    )

    with pytest.raises(UnitConversionError):
        registry.convert_quantity(source, "tiny")


INDEPENDENT_CONVERSION_VECTORS = (
    (50.0, "%", "1", QuantityKind.RATIO, 0.5),
    (1.0, "in", "m", QuantityKind.LENGTH, 0.0254),
    (1.0, "ft", "m", QuantityKind.LENGTH, 0.3048),
    (1.0, "ft2", "m2", QuantityKind.AREA, 0.09290304),
    (1.0, "in2", "m2", QuantityKind.AREA, 0.00064516),
    (1.0, "ft3", "m3", QuantityKind.VOLUME, 0.028316846592),
    (1.0, "US gal", "m3", QuantityKind.VOLUME, 0.003785411784),
    (1.0, "Imp gal", "m3", QuantityKind.VOLUME, 0.00454609),
    (1.0, "lb", "kg", QuantityKind.MASS, 0.45359237),
    (1.0, "oz", "kg", QuantityKind.MASS, 0.028349523125),
    (1.0, "h", "s", QuantityKind.TIME, 3600.0),
    (1.0, "d", "h", QuantityKind.TIME, 24.0),
    (1.0, "bar", "Pa", QuantityKind.ABSOLUTE_PRESSURE, 100_000.0),
    (
        1.0,
        "psi",
        "Pa",
        QuantityKind.ABSOLUTE_PRESSURE,
        6894.757293168361,
    ),
    (1.0, "atm", "Pa", QuantityKind.ABSOLUTE_PRESSURE, 101_325.0),
    (0.0, "degC", "K", QuantityKind.ABSOLUTE_TEMPERATURE, 273.15),
    (32.0, "degF", "K", QuantityKind.ABSOLUTE_TEMPERATURE, 273.15),
    (
        100.0,
        "degC",
        "degF",
        QuantityKind.ABSOLUTE_TEMPERATURE,
        212.0,
    ),
    (
        -40.0,
        "degC",
        "degF",
        QuantityKind.ABSOLUTE_TEMPERATURE,
        -40.0,
    ),
    (
        1.0,
        "delta_degF",
        "delta_K",
        QuantityKind.TEMPERATURE_DIFFERENCE,
        5.0 / 9.0,
    ),
    (
        1.0,
        "delta_degR",
        "delta_K",
        QuantityKind.TEMPERATURE_DIFFERENCE,
        5.0 / 9.0,
    ),
    (
        491.67,
        "degR",
        "K",
        QuantityKind.ABSOLUTE_TEMPERATURE,
        273.15,
    ),
    (180.0, "deg", "rad", QuantityKind.ANGLE, 3.141592653589793),
    (1.0, "rad", "deg", QuantityKind.ANGLE, 57.29577951308232),
    (1.0, "yd", "m", QuantityKind.LENGTH, 0.9144),
    (1.0, "mm2", "m2", QuantityKind.AREA, 0.000001),
    (1.0, "in3", "m3", QuantityKind.VOLUME, 0.000016387064),
    (1.0, "mL", "m3", QuantityKind.VOLUME, 0.000001),
    (760.0, "torr", "Pa", QuantityKind.ABSOLUTE_PRESSURE, 101_325.0),
    (1.0, "g/cm3", "kg/m3", QuantityKind.DENSITY, 1000.0),
    (1.0, "kg/L", "kg/m3", QuantityKind.DENSITY, 1000.0),
    (
        1.0,
        "lb/ft3",
        "kg/m3",
        QuantityKind.DENSITY,
        16.018463373960138,
    ),
    (
        1.0,
        "cP",
        "Pa.s",
        QuantityKind.DYNAMIC_VISCOSITY,
        0.001,
    ),
    (
        1.0,
        "cSt",
        "m2/s",
        QuantityKind.KINEMATIC_VISCOSITY,
        0.000001,
    ),
    (1.0, "P", "Pa.s", QuantityKind.DYNAMIC_VISCOSITY, 0.1),
    (
        1.0,
        "St",
        "m2/s",
        QuantityKind.KINEMATIC_VISCOSITY,
        0.0001,
    ),
    (36.0, "km/h", "m/s", QuantityKind.VELOCITY, 10.0),
    (1.0, "mph", "m/s", QuantityKind.VELOCITY, 0.44704),
    (
        1.0,
        "m3/h",
        "m3/s",
        QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
        1.0 / 3600.0,
    ),
    (
        1.0,
        "ft3/min",
        "m3/s",
        QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
        0.0004719474432,
    ),
    (
        1.0,
        "US gal/min",
        "m3/s",
        QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
        0.0000630901964,
    ),
    (
        1.0,
        "L/min",
        "m3/s",
        QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
        1.0 / 60_000.0,
    ),
    (1.0, "kg/h", "kg/s", QuantityKind.MASS_FLOW, 1.0 / 3600.0),
    (
        1.0,
        "lb/h",
        "kg/s",
        QuantityKind.MASS_FLOW,
        0.00012599788055555556,
    ),
    (1.0, "lbf", "N", QuantityKind.FORCE, 4.4482216152605),
    (1.0, "kN", "N", QuantityKind.FORCE, 1000.0),
    (1.0, "Wh", "J", QuantityKind.ENERGY, 3600.0),
    (1.0, "kJ", "J", QuantityKind.ENERGY, 1000.0),
    (1.0, "kWh", "J", QuantityKind.ENERGY, 3_600_000.0),
    (1.0, "hp", "W", QuantityKind.POWER, 745.69987158227022),
    (20.0, "mA", "A", QuantityKind.ELECTRIC_CURRENT, 0.02),
    (1.0, "uA", "A", QuantityKind.ELECTRIC_CURRENT, 0.000001),
    (1.0, "mV", "V", QuantityKind.ELECTRIC_POTENTIAL, 0.001),
    (1.0, "kV", "V", QuantityKind.ELECTRIC_POTENTIAL, 1000.0),
    (1.0, "kohm", "ohm", QuantityKind.ELECTRICAL_RESISTANCE, 1000.0),
    (1.0, "Mohm", "ohm", QuantityKind.ELECTRICAL_RESISTANCE, 1_000_000.0),
    (1.0, "kHz", "Hz", QuantityKind.FREQUENCY, 1000.0),
    (1.0, "MHz", "Hz", QuantityKind.FREQUENCY, 1_000_000.0),
    (1.0, "g0", "m/s2", QuantityKind.ACCELERATION, 9.80665),
)


@pytest.mark.parametrize(
    ("value", "from_unit", "to_unit", "kind", "expected"),
    INDEPENDENT_CONVERSION_VECTORS,
)
def test_independent_conversion_vectors(
    value: float,
    from_unit: str,
    to_unit: str,
    kind: QuantityKind,
    expected: float,
) -> None:
    converted = REGISTRY.convert_value(
        value,
        from_unit,
        to_unit,
        quantity_kind=kind,
    )
    assert converted == pytest.approx(expected, rel=1e-14, abs=1e-14)


@pytest.mark.parametrize(
    "value",
    (0.0, 1.23456789, -1.23456789, 1.0e-120, 1.0e120),
)
def test_repeated_conversion_is_deterministic(value: float) -> None:
    first = REGISTRY.convert_value(
        value,
        "m",
        "in",
        quantity_kind=QuantityKind.LENGTH,
    )
    second = REGISTRY.convert_value(
        value,
        "m",
        "in",
        quantity_kind=QuantityKind.LENGTH,
    )
    assert first == second


@pytest.mark.parametrize(
    ("kind", "from_unit", "to_unit"),
    (
        (QuantityKind.LENGTH, "m", "kg"),
        (QuantityKind.LENGTH, "m2", "m"),
        (QuantityKind.AREA, "m2", "m"),
        (QuantityKind.VOLUME, "m3", "m2"),
        (QuantityKind.ABSOLUTE_PRESSURE, "Pa", "K"),
        (QuantityKind.DENSITY, "kg/m3", "kg"),
        (QuantityKind.MASS_FLOW, "kg/s", "m3/s"),
        (QuantityKind.ACTUAL_VOLUMETRIC_FLOW, "m3/s", "kg/s"),
        (QuantityKind.DYNAMIC_VISCOSITY, "Pa.s", "m2/s"),
        (QuantityKind.KINEMATIC_VISCOSITY, "m2/s", "Pa.s"),
        (
            QuantityKind.ABSOLUTE_TEMPERATURE,
            "K",
            "delta_K",
        ),
        (
            QuantityKind.TEMPERATURE_DIFFERENCE,
            "delta_K",
            "K",
        ),
    ),
)
def test_incompatible_dimensions_are_rejected(
    kind: QuantityKind,
    from_unit: str,
    to_unit: str,
) -> None:
    with pytest.raises(IncompatibleUnitError):
        REGISTRY.convert_value(
            1.0,
            from_unit,
            to_unit,
            quantity_kind=kind,
        )


def test_unknown_quantity_kind_is_rejected_even_for_identity_conversion() -> None:
    with pytest.raises(UnknownQuantityKindError):
        REGISTRY.convert_value(
            1.0,
            "m",
            "m",
            quantity_kind="custom.length",
        )

    invalid = quantity("custom.length", 1.0, "m")

    with pytest.raises(UnknownQuantityKindError):
        REGISTRY.validate_quantity(invalid)


def test_wrong_source_dimension_is_rejected_even_for_identity_conversion() -> None:
    invalid = quantity(QuantityKind.LENGTH, 1.0, "kg")

    with pytest.raises(IncompatibleUnitError):
        REGISTRY.validate_quantity(invalid)

    with pytest.raises(IncompatibleUnitError):
        REGISTRY.convert_quantity(invalid, "kg")


@pytest.mark.parametrize(
    "reference_kind",
    (
        QuantityKind.STANDARD_VOLUMETRIC_FLOW,
        QuantityKind.NORMAL_VOLUMETRIC_FLOW,
        QuantityKind.REFERENCE_VOLUMETRIC_FLOW,
    ),
)
def test_reference_qualified_flow_cannot_use_detached_public_conversion(
    reference_kind: QuantityKind,
) -> None:
    detached = quantity(reference_kind, 100.0, "m3/h")

    with pytest.raises(ReferenceConditionError):
        REGISTRY.convert_value(
            100.0,
            "m3/h",
            "m3/s",
            quantity_kind=reference_kind,
        )

    with pytest.raises(ReferenceConditionError):
        REGISTRY.validate_quantity(detached)

    with pytest.raises(ReferenceConditionError):
        REGISTRY.convert_quantity(detached, "m3/s")

    with pytest.raises(ReferenceConditionError):
        REGISTRY.canonicalize_quantity(detached)


@pytest.mark.parametrize("bad_value", (nan, inf, -inf))
def test_direct_conversion_rejects_non_finite_values(
    bad_value: float,
) -> None:
    with pytest.raises(UnitConversionError):
        REGISTRY.convert_value(
            bad_value,
            "m",
            "m",
            quantity_kind=QuantityKind.LENGTH,
        )


@pytest.mark.parametrize("bad_value", (True, False, "1", None))
def test_direct_conversion_rejects_non_numeric_or_boolean_values(
    bad_value: object,
) -> None:
    with pytest.raises(UnitConversionError):
        REGISTRY.convert_value(
            bad_value,  # type: ignore[arg-type]
            "m",
            "m",
            quantity_kind=QuantityKind.LENGTH,
        )


def test_conversion_rejects_supported_magnitude_overflow() -> None:
    with pytest.raises(UnitConversionError, match="magnitude"):
        REGISTRY.convert_value(
            1.0e300,
            "km",
            "m",
            quantity_kind=QuantityKind.LENGTH,
        )


def test_conversion_rejects_huge_integer_without_string_conversion_leak() -> None:
    with pytest.raises(UnitConversionError, match="magnitude"):
        REGISTRY.convert_value(
            10**5000,
            "m",
            "m",
            quantity_kind=QuantityKind.LENGTH,
        )


def test_conversion_rejects_nonzero_float_underflow() -> None:
    with pytest.raises(UnitConversionError, match="underflow"):
        REGISTRY.convert_value(
            5.0e-324,
            "mm",
            "km",
            quantity_kind=QuantityKind.LENGTH,
        )


def test_conversion_rejects_decimal_below_public_float_boundary() -> None:
    with pytest.raises(UnitConversionError, match="too small"):
        REGISTRY.convert_value(
            Decimal("1e-1000127"),
            "m",
            "m",
            quantity_kind=QuantityKind.LENGTH,
        )


def test_negative_zero_is_normalized() -> None:
    converted = REGISTRY.convert_value(
        -0.0,
        "m",
        "mm",
        quantity_kind=QuantityKind.LENGTH,
    )
    assert converted == 0.0
    assert str(converted) == "0.0"


@pytest.mark.parametrize(
    "zero",
    (
        Decimal("0E-10000000"),
        Decimal("0E+10000000"),
        Decimal("-0E-10000000"),
    ),
)
def test_extreme_decimal_zero_exponents_are_normalized(
    zero: Decimal,
) -> None:
    converted = REGISTRY.convert_value(
        zero,
        "m",
        "mm",
        quantity_kind=QuantityKind.LENGTH,
    )
    assert converted == 0.0
    assert str(converted) == "0.0"


def test_quantity_conversion_preserves_kind_metadata_and_input() -> None:
    source = quantity(
        QuantityKind.LENGTH,
        1.23456,
        "metre",
        uncertainty=0.01,
        uncertainty_basis="Independent measurement standard deviation.",
        significant_figures=2,
    )
    original = source.model_dump(mode="json")
    converted = REGISTRY.convert_quantity(source, "millimetre")

    assert converted.quantity_kind == QuantityKind.LENGTH.value
    assert converted.value == pytest.approx(1234.56)
    assert converted.unit == "mm"
    assert converted.uncertainty == pytest.approx(10.0)
    assert converted.uncertainty_basis == source.uncertainty_basis
    assert converted.significant_figures == 2
    assert converted.decimal_places is None
    assert source.model_dump(mode="json") == original
    assert presentation_value(converted) == Decimal("1.2E+3")


def test_unit_change_clears_unit_dependent_decimal_places() -> None:
    source = quantity(
        QuantityKind.LENGTH,
        1.23,
        "m",
        decimal_places=2,
    )
    converted = REGISTRY.convert_quantity(source, "mm")
    assert converted.value == pytest.approx(1230.0)
    assert converted.decimal_places is None
    assert source.decimal_places == 2


def test_identity_unit_conversion_retains_decimal_places() -> None:
    source = quantity(
        QuantityKind.LENGTH,
        1.23,
        "metre",
        decimal_places=2,
    )
    converted = REGISTRY.convert_quantity(source, "m")
    assert converted.unit == "m"
    assert converted.decimal_places == 2


def test_temperature_uncertainty_uses_scale_without_offset() -> None:
    source = quantity(
        QuantityKind.ABSOLUTE_TEMPERATURE,
        32.0,
        "degF",
        uncertainty=1.8,
        uncertainty_basis="Instrument tolerance.",
    )
    converted = REGISTRY.convert_quantity(source, "K")
    assert converted.value == pytest.approx(273.15)
    assert converted.uncertainty == pytest.approx(1.0)


def test_quantity_conversion_rejects_uncertainty_overflow() -> None:
    source = quantity(
        QuantityKind.LENGTH,
        1.0,
        "km",
        uncertainty=1.0e300,
        uncertainty_basis="Stress vector.",
    )

    with pytest.raises(UnitConversionError, match="magnitude"):
        REGISTRY.convert_quantity(source, "m")


def test_quantity_conversion_rejects_uncertainty_underflow() -> None:
    source = quantity(
        QuantityKind.ABSOLUTE_PRESSURE,
        1.0,
        "Pa",
        uncertainty=5.0e-324,
        uncertainty_basis="Subnormal uncertainty vector.",
    )

    with pytest.raises(UnitConversionError, match="underflow"):
        REGISTRY.convert_quantity(source, "MPa")


def test_target_alias_produces_canonical_output_symbol() -> None:
    source = quantity(QuantityKind.LENGTH, 1.0, "ft")
    converted = REGISTRY.convert_quantity(source, "metre")
    assert converted.unit == "m"


def test_canonicalize_quantity_uses_kind_canonical_unit() -> None:
    source = quantity(QuantityKind.GAUGE_PRESSURE, 1.0, "bar")
    converted = REGISTRY.canonicalize_quantity(source)
    assert converted.quantity_kind == QuantityKind.GAUGE_PRESSURE.value
    assert converted.unit == "Pa"
    assert converted.value == 100_000.0


def test_bypass_constructed_invalid_quantity_is_revalidated() -> None:
    bypassed = EngineeringQuantity.model_construct(
        quantity_kind=QuantityKind.LENGTH.value,
        value=nan,
        unit="m",
    )

    with pytest.raises(UnitConversionError):
        REGISTRY.validate_quantity(bypassed)

    with pytest.raises(UnitConversionError):
        REGISTRY.convert_quantity(bypassed, "mm")


ABSOLUTE_ZERO_VECTORS = (
    (0.0, "K"),
    (0.0, "degR"),
    (-273.15, "degC"),
    (-459.67, "degF"),
)


@pytest.mark.parametrize(("value", "unit"), ABSOLUTE_ZERO_VECTORS)
def test_absolute_zero_is_valid(value: float, unit: str) -> None:
    converted = REGISTRY.convert_value(
        value,
        unit,
        "K",
        quantity_kind=QuantityKind.ABSOLUTE_TEMPERATURE,
    )
    assert converted == pytest.approx(0.0, abs=1e-13)


@pytest.mark.parametrize(
    ("value", "unit"),
    (
        (nextafter(0.0, -inf), "K"),
        (nextafter(0.0, -inf), "degR"),
        (nextafter(-273.15, -inf), "degC"),
        (nextafter(-459.67, -inf), "degF"),
    ),
)
def test_value_below_absolute_zero_is_rejected(
    value: float,
    unit: str,
) -> None:
    with pytest.raises(UnitConversionError, match="0 K"):
        REGISTRY.convert_value(
            value,
            unit,
            unit,
            quantity_kind=QuantityKind.ABSOLUTE_TEMPERATURE,
        )


def test_negative_temperature_differences_are_valid_and_linear() -> None:
    converted = REGISTRY.convert_value(
        -18.0,
        "delta_degF",
        "delta_degC",
        quantity_kind=QuantityKind.TEMPERATURE_DIFFERENCE,
    )
    assert converted == pytest.approx(-10.0)


def test_absolute_temperature_unit_cannot_be_used_as_difference() -> None:
    with pytest.raises(IncompatibleUnitError):
        REGISTRY.convert_value(
            10.0,
            "degC",
            "degF",
            quantity_kind=QuantityKind.TEMPERATURE_DIFFERENCE,
        )


def test_temperature_difference_unit_cannot_be_used_as_absolute() -> None:
    with pytest.raises(IncompatibleUnitError):
        REGISTRY.convert_value(
            10.0,
            "delta_degC",
            "delta_degF",
            quantity_kind=QuantityKind.ABSOLUTE_TEMPERATURE,
        )


def test_zero_absolute_pressure_is_valid_for_unit_representation() -> None:
    converted = REGISTRY.convert_value(
        0.0,
        "Pa",
        "bar",
        quantity_kind=QuantityKind.ABSOLUTE_PRESSURE,
    )
    assert converted == 0.0


def test_negative_absolute_pressure_is_rejected() -> None:
    with pytest.raises(UnitConversionError, match="0 Pa"):
        REGISTRY.convert_value(
            -1.0,
            "Pa",
            "Pa",
            quantity_kind=QuantityKind.ABSOLUTE_PRESSURE,
        )


@pytest.mark.parametrize(
    "kind",
    (QuantityKind.GAUGE_PRESSURE, QuantityKind.DIFFERENTIAL_PRESSURE),
)
def test_signed_non_absolute_pressure_is_valid(kind: QuantityKind) -> None:
    converted = REGISTRY.convert_value(
        -25.0,
        "kPa",
        "Pa",
        quantity_kind=kind,
    )
    assert converted == -25_000.0


PRESSURE_BASIS_VECTORS = (
    (
        QuantityKind.GAUGE_PRESSURE,
        0.0,
        "bar",
        QuantityKind.ABSOLUTE_PRESSURE,
        101.325,
        "kPa",
        "kPa",
        101.325,
    ),
    (
        QuantityKind.ABSOLUTE_PRESSURE,
        250.0,
        "kPa",
        QuantityKind.GAUGE_PRESSURE,
        101.325,
        "kPa",
        "kPa",
        148.675,
    ),
    (
        QuantityKind.ABSOLUTE_PRESSURE,
        50.0,
        "kPa",
        QuantityKind.GAUGE_PRESSURE,
        101.325,
        "kPa",
        "kPa",
        -51.325,
    ),
    (
        QuantityKind.GAUGE_PRESSURE,
        -100.0,
        "kPa",
        QuantityKind.ABSOLUTE_PRESSURE,
        101.325,
        "kPa",
        "kPa",
        1.325,
    ),
    (
        QuantityKind.GAUGE_PRESSURE,
        1.0,
        "bar",
        QuantityKind.ABSOLUTE_PRESSURE,
        1.0,
        "atm",
        "bar",
        2.01325,
    ),
)


@pytest.mark.parametrize(
    (
        "source_kind",
        "source_value",
        "source_unit",
        "target_kind",
        "atmosphere_value",
        "atmosphere_unit",
        "target_unit",
        "expected",
    ),
    PRESSURE_BASIS_VECTORS,
)
def test_explicit_pressure_basis_vectors(
    source_kind: QuantityKind,
    source_value: float,
    source_unit: str,
    target_kind: QuantityKind,
    atmosphere_value: float,
    atmosphere_unit: str,
    target_unit: str,
    expected: float,
) -> None:
    source = quantity(source_kind, source_value, source_unit)
    atmosphere = quantity(
        QuantityKind.ABSOLUTE_PRESSURE,
        atmosphere_value,
        atmosphere_unit,
    )
    converted = convert_pressure_basis(
        source,
        target_kind,
        atmospheric_pressure=atmosphere,
        target_unit=target_unit,
    )
    assert converted.quantity_kind == target_kind.value
    assert converted.unit == target_unit
    assert converted.value == pytest.approx(expected, abs=1e-12)


def test_pressure_basis_uses_source_unit_when_target_unit_is_omitted() -> None:
    source = quantity(QuantityKind.GAUGE_PRESSURE, 0.0, "bar")
    atmosphere = quantity(
        QuantityKind.ABSOLUTE_PRESSURE,
        101.325,
        "kPa",
    )
    converted = convert_pressure_basis(
        source,
        QuantityKind.ABSOLUTE_PRESSURE,
        atmospheric_pressure=atmosphere,
    )
    assert converted.unit == "bar"
    assert converted.value == pytest.approx(1.01325)


def test_pressure_basis_preserves_source_uncertainty_and_precision() -> None:
    source = quantity(
        QuantityKind.GAUGE_PRESSURE,
        1.0,
        "bar",
        uncertainty=0.01,
        uncertainty_basis="Transmitter accuracy.",
        significant_figures=4,
    )
    atmosphere = quantity(
        QuantityKind.ABSOLUTE_PRESSURE,
        101.325,
        "kPa",
    )
    converted = convert_pressure_basis(
        source,
        QuantityKind.ABSOLUTE_PRESSURE,
        atmospheric_pressure=atmosphere,
        target_unit="kPa",
    )
    assert converted.uncertainty == pytest.approx(1.0)
    assert converted.uncertainty_basis == source.uncertainty_basis
    assert converted.significant_figures == 4
    assert converted.value == pytest.approx(201.325)


def test_pressure_basis_change_clears_decimal_place_metadata() -> None:
    source = quantity(
        QuantityKind.GAUGE_PRESSURE,
        1.25,
        "bar",
        decimal_places=2,
    )
    atmosphere = quantity(
        QuantityKind.ABSOLUTE_PRESSURE,
        1.0,
        "bar",
    )
    converted = convert_pressure_basis(
        source,
        QuantityKind.ABSOLUTE_PRESSURE,
        atmospheric_pressure=atmosphere,
    )
    assert converted.value == pytest.approx(2.25)
    assert converted.decimal_places is None


def test_zero_absolute_pressure_boundary_can_result_from_gauge_conversion() -> None:
    atmosphere = quantity(
        QuantityKind.ABSOLUTE_PRESSURE,
        101.325,
        "kPa",
    )
    converted = convert_pressure_basis(
        quantity(QuantityKind.GAUGE_PRESSURE, -101.325, "kPa"),
        QuantityKind.ABSOLUTE_PRESSURE,
        atmospheric_pressure=atmosphere,
    )
    assert converted.value == 0.0


def test_pressure_basis_rejects_negative_absolute_result() -> None:
    atmosphere = quantity(
        QuantityKind.ABSOLUTE_PRESSURE,
        101.325,
        "kPa",
    )

    with pytest.raises(PressureBasisError, match="below"):
        convert_pressure_basis(
            quantity(QuantityKind.GAUGE_PRESSURE, -102.0, "kPa"),
            QuantityKind.ABSOLUTE_PRESSURE,
            atmospheric_pressure=atmosphere,
        )


@pytest.mark.parametrize(
    ("source_kind", "target_kind"),
    (
        (
            QuantityKind.DIFFERENTIAL_PRESSURE,
            QuantityKind.ABSOLUTE_PRESSURE,
        ),
        (
            QuantityKind.DIFFERENTIAL_PRESSURE,
            QuantityKind.GAUGE_PRESSURE,
        ),
        (
            QuantityKind.GAUGE_PRESSURE,
            QuantityKind.DIFFERENTIAL_PRESSURE,
        ),
        (
            QuantityKind.ABSOLUTE_PRESSURE,
            QuantityKind.DIFFERENTIAL_PRESSURE,
        ),
    ),
)
def test_differential_pressure_cannot_change_basis(
    source_kind: QuantityKind,
    target_kind: QuantityKind,
) -> None:
    atmosphere = quantity(
        QuantityKind.ABSOLUTE_PRESSURE,
        101_325.0,
        "Pa",
    )

    with pytest.raises(PressureBasisError):
        convert_pressure_basis(
            quantity(source_kind, 10.0, "kPa"),
            target_kind,
            atmospheric_pressure=atmosphere,
        )


@pytest.mark.parametrize(
    "source_kind",
    (QuantityKind.ABSOLUTE_PRESSURE, QuantityKind.GAUGE_PRESSURE),
)
def test_pressure_basis_requires_different_source_and_target(
    source_kind: QuantityKind,
) -> None:
    atmosphere = quantity(
        QuantityKind.ABSOLUTE_PRESSURE,
        101_325.0,
        "Pa",
    )

    with pytest.raises(PressureBasisError, match="must differ"):
        convert_pressure_basis(
            quantity(source_kind, 10.0, "kPa"),
            source_kind,
            atmospheric_pressure=atmosphere,
        )


def test_pressure_basis_rejects_unknown_target_kind() -> None:
    atmosphere = quantity(
        QuantityKind.ABSOLUTE_PRESSURE,
        101_325.0,
        "Pa",
    )

    with pytest.raises(PressureBasisError):
        convert_pressure_basis(
            quantity(QuantityKind.GAUGE_PRESSURE, 0.0, "Pa"),
            "pressure.vacuum",
            atmospheric_pressure=atmosphere,
        )


def test_pressure_basis_requires_absolute_atmospheric_kind() -> None:
    with pytest.raises(PressureBasisError, match="pressure.absolute"):
        convert_pressure_basis(
            quantity(QuantityKind.GAUGE_PRESSURE, 0.0, "Pa"),
            QuantityKind.ABSOLUTE_PRESSURE,
            atmospheric_pressure=quantity(
                QuantityKind.GAUGE_PRESSURE,
                101_325.0,
                "Pa",
            ),
        )


@pytest.mark.parametrize("atmosphere_value", (0.0, -1.0))
def test_pressure_basis_requires_positive_atmospheric_pressure(
    atmosphere_value: float,
) -> None:
    with pytest.raises(PressureBasisError):
        convert_pressure_basis(
            quantity(QuantityKind.GAUGE_PRESSURE, 0.0, "Pa"),
            QuantityKind.ABSOLUTE_PRESSURE,
            atmospheric_pressure=quantity(
                QuantityKind.ABSOLUTE_PRESSURE,
                atmosphere_value,
                "Pa",
            ),
        )


def test_pressure_basis_rejects_uncertain_atmospheric_pressure() -> None:
    atmosphere = quantity(
        QuantityKind.ABSOLUTE_PRESSURE,
        101_325.0,
        "Pa",
        uncertainty=10.0,
        uncertainty_basis="Weather-station uncertainty.",
    )

    with pytest.raises(PressureBasisError, match="uncertainty"):
        convert_pressure_basis(
            quantity(QuantityKind.GAUGE_PRESSURE, 0.0, "Pa"),
            QuantityKind.ABSOLUTE_PRESSURE,
            atmospheric_pressure=atmosphere,
        )


def test_pressure_basis_rejects_incompatible_target_unit() -> None:
    atmosphere = quantity(
        QuantityKind.ABSOLUTE_PRESSURE,
        101_325.0,
        "Pa",
    )

    with pytest.raises(PressureBasisError):
        convert_pressure_basis(
            quantity(QuantityKind.GAUGE_PRESSURE, 0.0, "Pa"),
            QuantityKind.ABSOLUTE_PRESSURE,
            atmospheric_pressure=atmosphere,
            target_unit="K",
        )


@pytest.mark.parametrize(
    "basis",
    tuple(FlowReferenceBasis),
)
def test_reference_conditions_require_all_explicit_state_values(
    basis: FlowReferenceBasis,
) -> None:
    conditions = reference_conditions(
        reference_id=f"{basis.value}.conditions",
        basis=basis,
    )
    assert conditions.basis is basis
    assert conditions.absolute_pressure.quantity_kind == (
        QuantityKind.ABSOLUTE_PRESSURE.value
    )
    assert conditions.absolute_temperature.quantity_kind == (
        QuantityKind.ABSOLUTE_TEMPERATURE.value
    )
    assert conditions.effective_compressibility_factor == 1.0


@pytest.mark.parametrize(
    "required_field",
    (
        "reference_id",
        "basis",
        "absolute_pressure",
        "absolute_temperature",
        "compressibility_treatment",
    ),
)
def test_reference_condition_fields_are_structurally_required(
    required_field: str,
) -> None:
    conditions = reference_conditions(
        reference_id="required.conditions",
        basis=FlowReferenceBasis.STANDARD,
    )
    assert ReferenceConditions.model_fields[
        required_field
    ].is_required()
    payload = conditions.model_dump(mode="python")
    payload.pop(required_field)

    with pytest.raises(ValidationError):
        ReferenceConditions.model_validate(payload)


def test_atmospheric_pressure_is_a_required_keyword_only_argument() -> None:
    parameter = signature(convert_pressure_basis).parameters[
        "atmospheric_pressure"
    ]
    assert parameter.kind is Parameter.KEYWORD_ONLY
    assert parameter.default is Parameter.empty
    assert "registry" not in signature(convert_pressure_basis).parameters
    assert (
        "registry"
        not in signature(
            convert_referenced_volumetric_flow
        ).parameters
    )


def test_reference_conditions_are_strict_and_frozen() -> None:
    conditions = reference_conditions(
        reference_id="frozen.conditions",
        basis=FlowReferenceBasis.CUSTOM,
    )

    with pytest.raises(ValidationError):
        conditions.reference_id = "changed"  # type: ignore[misc]

    with pytest.raises(ValidationError):
        ReferenceConditions(
            reference_id="extra.conditions",
            basis=FlowReferenceBasis.CUSTOM,
            absolute_pressure=conditions.absolute_pressure,
            absolute_temperature=conditions.absolute_temperature,
            compressibility_treatment=CompressibilityTreatment.IDEAL_GAS,
            unexpected=True,  # type: ignore[call-arg]
        )


def test_reference_conditions_require_absolute_pressure_kind() -> None:
    with pytest.raises(ValidationError, match="pressure.absolute"):
        ReferenceConditions(
            reference_id="wrong.pressure",
            basis=FlowReferenceBasis.STANDARD,
            absolute_pressure=quantity(
                QuantityKind.GAUGE_PRESSURE,
                101_325.0,
                "Pa",
            ),
            absolute_temperature=quantity(
                QuantityKind.ABSOLUTE_TEMPERATURE,
                273.15,
                "K",
            ),
            compressibility_treatment=CompressibilityTreatment.IDEAL_GAS,
        )


def test_reference_conditions_require_absolute_temperature_kind() -> None:
    with pytest.raises(ValidationError, match="temperature.absolute"):
        ReferenceConditions(
            reference_id="wrong.temperature",
            basis=FlowReferenceBasis.NORMAL,
            absolute_pressure=quantity(
                QuantityKind.ABSOLUTE_PRESSURE,
                101_325.0,
                "Pa",
            ),
            absolute_temperature=quantity(
                QuantityKind.TEMPERATURE_DIFFERENCE,
                273.15,
                "delta_K",
            ),
            compressibility_treatment=CompressibilityTreatment.IDEAL_GAS,
        )


@pytest.mark.parametrize(
    ("pressure", "temperature"),
    (
        (0.0, 273.15),
        (-1.0, 273.15),
        (101_325.0, 0.0),
        (101_325.0, -1.0),
    ),
)
def test_reference_conditions_require_strictly_positive_pressure_and_temperature(
    pressure: float,
    temperature: float,
) -> None:
    with pytest.raises(ValidationError):
        reference_conditions(
            reference_id="nonpositive.conditions",
            basis=FlowReferenceBasis.STANDARD,
            pressure=pressure,
            temperature=temperature,
        )


@pytest.mark.parametrize(
    ("field_name", "quantity_kind", "value", "unit"),
    (
        (
            "absolute_pressure",
            QuantityKind.ABSOLUTE_PRESSURE,
            101_325.0,
            "Pa",
        ),
        (
            "absolute_temperature",
            QuantityKind.ABSOLUTE_TEMPERATURE,
            273.15,
            "K",
        ),
    ),
)
def test_reference_conditions_reject_uncertain_state_inputs(
    field_name: str,
    quantity_kind: QuantityKind,
    value: float,
    unit: str,
) -> None:
    values = {
        "reference_id": "uncertain.conditions",
        "basis": FlowReferenceBasis.STANDARD,
        "absolute_pressure": quantity(
            QuantityKind.ABSOLUTE_PRESSURE,
            101_325.0,
            "Pa",
        ),
        "absolute_temperature": quantity(
            QuantityKind.ABSOLUTE_TEMPERATURE,
            273.15,
            "K",
        ),
        "compressibility_treatment": CompressibilityTreatment.IDEAL_GAS,
    }
    values[field_name] = quantity(
        quantity_kind,
        value,
        unit,
        uncertainty=0.1,
        uncertainty_basis="Reference uncertainty.",
    )

    with pytest.raises(ValidationError, match="uncertainty"):
        ReferenceConditions.model_validate(values)


def test_ideal_gas_treatment_requires_factor_omission() -> None:
    with pytest.raises(ValidationError, match="omitted"):
        reference_conditions(
            reference_id="ideal.with.factor",
            basis=FlowReferenceBasis.STANDARD,
            treatment=CompressibilityTreatment.IDEAL_GAS,
            compressibility_factor=1.0,
        )


def test_specified_factor_treatment_requires_positive_factor() -> None:
    with pytest.raises(ValidationError, match="requires"):
        reference_conditions(
            reference_id="factor.missing",
            basis=FlowReferenceBasis.STANDARD,
            treatment=CompressibilityTreatment.SPECIFIED_FACTOR,
        )

    for value in (0.0, -1.0, nan, inf, -inf):
        with pytest.raises(ValidationError):
            reference_conditions(
                reference_id="factor.invalid",
                basis=FlowReferenceBasis.STANDARD,
                treatment=CompressibilityTreatment.SPECIFIED_FACTOR,
                compressibility_factor=value,
            )


def test_specified_factor_is_explicit_and_serializable() -> None:
    conditions = reference_conditions(
        reference_id="factor.valid",
        basis=FlowReferenceBasis.STANDARD,
        treatment=CompressibilityTreatment.SPECIFIED_FACTOR,
        compressibility_factor=0.92,
    )
    assert conditions.effective_compressibility_factor == 0.92
    restored = ReferenceConditions.model_validate_json(
        conditions.model_dump_json()
    )
    assert restored == conditions


@pytest.mark.parametrize(
    ("basis", "wrong_kind"),
    (
        (
            FlowReferenceBasis.ACTUAL,
            QuantityKind.STANDARD_VOLUMETRIC_FLOW,
        ),
        (
            FlowReferenceBasis.STANDARD,
            QuantityKind.NORMAL_VOLUMETRIC_FLOW,
        ),
        (
            FlowReferenceBasis.NORMAL,
            QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
        ),
        (
            FlowReferenceBasis.CUSTOM,
            QuantityKind.STANDARD_VOLUMETRIC_FLOW,
        ),
    ),
)
def test_referenced_flow_quantity_kind_must_match_basis(
    basis: FlowReferenceBasis,
    wrong_kind: QuantityKind,
) -> None:
    conditions = reference_conditions(
        reference_id=f"{basis.value}.mismatch",
        basis=basis,
    )

    with pytest.raises(ValidationError, match="requires quantity kind"):
        ReferencedVolumetricFlow(
            quantity=quantity(wrong_kind, 100.0, "m3/h"),
            reference_conditions=conditions,
        )


def test_referenced_flow_rejects_mass_flow_dimension() -> None:
    conditions = reference_conditions(
        reference_id="mass.flow",
        basis=FlowReferenceBasis.STANDARD,
    )

    with pytest.raises(ValidationError):
        ReferencedVolumetricFlow(
            quantity=quantity(
                QuantityKind.STANDARD_VOLUMETRIC_FLOW,
                100.0,
                "kg/h",
            ),
            reference_conditions=conditions,
        )


REFERENCE_FLOW_VECTORS = (
    (
        100.0,
        101_325.0,
        273.15,
        1.0,
        101_325.0,
        288.15,
        1.0,
        105.49148819330038,
    ),
    (
        100.0,
        100_000.0,
        300.0,
        1.0,
        200_000.0,
        300.0,
        1.0,
        50.0,
    ),
    (
        100.0,
        100_000.0,
        300.0,
        0.9,
        100_000.0,
        300.0,
        1.1,
        122.22222222222223,
    ),
    (
        120.0,
        100_000.0,
        300.0,
        0.9,
        200_000.0,
        250.0,
        1.05,
        58.33333333333333,
    ),
)


@pytest.mark.parametrize(
    (
        "flow_value",
        "pressure_1",
        "temperature_1",
        "z_1",
        "pressure_2",
        "temperature_2",
        "z_2",
        "expected",
    ),
    REFERENCE_FLOW_VECTORS,
)
def test_reference_flow_independent_vectors(
    flow_value: float,
    pressure_1: float,
    temperature_1: float,
    z_1: float,
    pressure_2: float,
    temperature_2: float,
    z_2: float,
    expected: float,
) -> None:
    source_conditions = reference_conditions(
        reference_id="source.vector",
        basis=FlowReferenceBasis.STANDARD,
        pressure=pressure_1,
        temperature=temperature_1,
        treatment=CompressibilityTreatment.SPECIFIED_FACTOR,
        compressibility_factor=z_1,
    )
    target_conditions = reference_conditions(
        reference_id="target.vector",
        basis=FlowReferenceBasis.NORMAL,
        pressure=pressure_2,
        temperature=temperature_2,
        treatment=CompressibilityTreatment.SPECIFIED_FACTOR,
        compressibility_factor=z_2,
    )
    source = referenced_flow(
        value=flow_value,
        unit="m3/h",
        conditions=source_conditions,
    )
    converted = convert_referenced_volumetric_flow(
        source,
        target_conditions,
    )
    assert converted.quantity.value == pytest.approx(
        expected,
        rel=1e-14,
        abs=1e-12,
    )
    assert converted.quantity.unit == "m3/h"
    assert converted.quantity.quantity_kind == (
        QuantityKind.NORMAL_VOLUMETRIC_FLOW.value
    )
    assert converted.reference_conditions == target_conditions


@pytest.mark.parametrize(
    "vector",
    REFERENCE_FLOW_VECTORS,
)
def test_reference_flow_vectors_round_trip(
    vector: tuple[float, float, float, float, float, float, float, float],
) -> None:
    (
        flow_value,
        pressure_1,
        temperature_1,
        z_1,
        pressure_2,
        temperature_2,
        z_2,
        _,
    ) = vector
    source_conditions = reference_conditions(
        reference_id="roundtrip.source",
        basis=FlowReferenceBasis.STANDARD,
        pressure=pressure_1,
        temperature=temperature_1,
        treatment=CompressibilityTreatment.SPECIFIED_FACTOR,
        compressibility_factor=z_1,
    )
    target_conditions = reference_conditions(
        reference_id="roundtrip.target",
        basis=FlowReferenceBasis.NORMAL,
        pressure=pressure_2,
        temperature=temperature_2,
        treatment=CompressibilityTreatment.SPECIFIED_FACTOR,
        compressibility_factor=z_2,
    )
    source = referenced_flow(
        value=flow_value,
        unit="m3/h",
        conditions=source_conditions,
    )
    forward = convert_referenced_volumetric_flow(
        source,
        target_conditions,
        target_unit="ft3/min",
    )
    restored = convert_referenced_volumetric_flow(
        forward,
        source_conditions,
        target_unit="m3/h",
    )
    assert restored.quantity.value == pytest.approx(
        flow_value,
        rel=1e-14,
        abs=1e-12,
    )
    assert restored.reference_conditions == source_conditions


def test_reference_flow_mixed_units_match_si_result() -> None:
    source_conditions = reference_conditions(
        reference_id="mixed.source",
        basis=FlowReferenceBasis.ACTUAL,
        pressure=1.0,
        pressure_unit="bar",
        temperature=80.33,
        temperature_unit="degF",
    )
    target_conditions = reference_conditions(
        reference_id="mixed.target",
        basis=FlowReferenceBasis.CUSTOM,
        pressure=200.0,
        pressure_unit="kPa",
        temperature=250.0,
        temperature_unit="K",
    )
    source = referenced_flow(
        value=58.857,
        unit="ft3/min",
        conditions=source_conditions,
    )
    mixed = convert_referenced_volumetric_flow(
        source,
        target_conditions,
        target_unit="L/min",
    )

    si_source_conditions = reference_conditions(
        reference_id="si.source",
        basis=FlowReferenceBasis.ACTUAL,
        pressure=100_000.0,
        temperature=300.0,
    )
    si_target_conditions = reference_conditions(
        reference_id="si.target",
        basis=FlowReferenceBasis.CUSTOM,
        pressure=200_000.0,
        temperature=250.0,
    )
    si_source = referenced_flow(
        value=REGISTRY.convert_value(
            58.857,
            "ft3/min",
            "m3/s",
            quantity_kind=QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
        ),
        unit="m3/s",
        conditions=si_source_conditions,
    )
    si = convert_referenced_volumetric_flow(
        si_source,
        si_target_conditions,
        target_unit="L/min",
    )
    assert mixed.quantity.value == pytest.approx(
        694.43526661056,
        rel=1e-14,
    )
    assert mixed.quantity.value == pytest.approx(
        si.quantity.value,
        rel=1e-12,
    )


def test_reference_labels_do_not_select_hidden_conditions() -> None:
    source_conditions = reference_conditions(
        reference_id="same.label.source",
        basis=FlowReferenceBasis.STANDARD,
        pressure=101_325.0,
        temperature=273.15,
    )
    same_label_different_values = reference_conditions(
        reference_id="same.label.target",
        basis=FlowReferenceBasis.STANDARD,
        pressure=200_000.0,
        temperature=300.0,
    )
    source = referenced_flow(
        value=100.0,
        unit="m3/h",
        conditions=source_conditions,
    )
    converted = convert_referenced_volumetric_flow(
        source,
        same_label_different_values,
    )
    expected = (
        100.0
        * (101_325.0 / 200_000.0)
        * (300.0 / 273.15)
    )
    assert converted.quantity.value == pytest.approx(expected)
    assert converted.quantity.value != pytest.approx(100.0)


def test_reference_flow_uncertainty_scales_with_exact_state_factor() -> None:
    source_conditions = reference_conditions(
        reference_id="uncertainty.source",
        basis=FlowReferenceBasis.STANDARD,
        pressure=100_000.0,
        temperature=300.0,
    )
    target_conditions = reference_conditions(
        reference_id="uncertainty.target",
        basis=FlowReferenceBasis.NORMAL,
        pressure=200_000.0,
        temperature=300.0,
    )
    source = referenced_flow(
        value=100.0,
        unit="m3/h",
        conditions=source_conditions,
        uncertainty=2.0,
        uncertainty_basis="Meter standard deviation.",
        significant_figures=5,
    )
    converted = convert_referenced_volumetric_flow(
        source,
        target_conditions,
        target_unit="L/min",
    )
    assert converted.quantity.value == pytest.approx(
        833.3333333333333
    )
    assert converted.quantity.uncertainty == pytest.approx(
        16.666666666666668
    )
    assert converted.quantity.uncertainty_basis == (
        "Meter standard deviation."
    )
    assert converted.quantity.significant_figures == 5


def test_reference_flow_change_clears_decimal_place_metadata() -> None:
    source_conditions = reference_conditions(
        reference_id="decimal.source",
        basis=FlowReferenceBasis.STANDARD,
    )
    target_conditions = reference_conditions(
        reference_id="decimal.target",
        basis=FlowReferenceBasis.NORMAL,
        temperature=288.15,
    )
    source = referenced_flow(
        value=100.0,
        unit="m3/h",
        conditions=source_conditions,
        decimal_places=2,
    )
    converted = convert_referenced_volumetric_flow(
        source,
        target_conditions,
        target_unit="m3/h",
    )
    assert converted.quantity.decimal_places is None


def test_reference_flow_preserves_signed_flow_direction() -> None:
    source_conditions = reference_conditions(
        reference_id="signed.source",
        basis=FlowReferenceBasis.ACTUAL,
    )
    target_conditions = reference_conditions(
        reference_id="signed.target",
        basis=FlowReferenceBasis.CUSTOM,
        pressure=202_650.0,
    )
    source = referenced_flow(
        value=-100.0,
        unit="m3/h",
        conditions=source_conditions,
    )
    converted = convert_referenced_volumetric_flow(
        source,
        target_conditions,
    )
    assert converted.quantity.value == pytest.approx(-50.0)


def test_reference_flow_rejects_incompatible_target_unit() -> None:
    source_conditions = reference_conditions(
        reference_id="bad.target.source",
        basis=FlowReferenceBasis.STANDARD,
    )
    target_conditions = reference_conditions(
        reference_id="bad.target.target",
        basis=FlowReferenceBasis.NORMAL,
    )
    source = referenced_flow(
        value=100.0,
        unit="m3/h",
        conditions=source_conditions,
    )

    with pytest.raises(ReferenceConditionError):
        convert_referenced_volumetric_flow(
            source,
            target_conditions,
            target_unit="kg/h",
        )


def test_reference_flow_revalidates_bypass_constructed_source() -> None:
    conditions = reference_conditions(
        reference_id="bypass.conditions",
        basis=FlowReferenceBasis.STANDARD,
    )
    bypassed_quantity = EngineeringQuantity.model_construct(
        quantity_kind=QuantityKind.STANDARD_VOLUMETRIC_FLOW.value,
        value=nan,
        unit="m3/h",
    )
    bypassed_flow = ReferencedVolumetricFlow.model_construct(
        quantity=bypassed_quantity,
        reference_conditions=conditions,
    )

    with pytest.raises(ReferenceConditionError):
        convert_referenced_volumetric_flow(
            bypassed_flow,
            conditions,
        )


def test_reference_flow_revalidates_bypass_constructed_target() -> None:
    source_conditions = reference_conditions(
        reference_id="valid.source",
        basis=FlowReferenceBasis.STANDARD,
    )
    source = referenced_flow(
        value=100.0,
        unit="m3/h",
        conditions=source_conditions,
    )
    bypassed_target = ReferenceConditions.model_construct(
        reference_id="invalid.target",
        basis=FlowReferenceBasis.NORMAL,
        absolute_pressure=quantity(
            QuantityKind.ABSOLUTE_PRESSURE,
            0.0,
            "Pa",
        ),
        absolute_temperature=quantity(
            QuantityKind.ABSOLUTE_TEMPERATURE,
            273.15,
            "K",
        ),
        compressibility_treatment=CompressibilityTreatment.IDEAL_GAS,
        compressibility_factor=None,
    )

    with pytest.raises(ReferenceConditionError):
        convert_referenced_volumetric_flow(
            source,
            bypassed_target,
        )


DECIMAL_PLACE_VECTORS = (
    ("2.5", 0, PresentationRoundingMode.HALF_EVEN, "2"),
    ("3.5", 0, PresentationRoundingMode.HALF_EVEN, "4"),
    ("-2.5", 0, PresentationRoundingMode.HALF_EVEN, "-2"),
    ("-3.5", 0, PresentationRoundingMode.HALF_EVEN, "-4"),
    ("1.225", 2, PresentationRoundingMode.HALF_EVEN, "1.22"),
    ("1.235", 2, PresentationRoundingMode.HALF_EVEN, "1.24"),
    ("2.5", 0, PresentationRoundingMode.HALF_UP, "3"),
    ("-2.5", 0, PresentationRoundingMode.HALF_UP, "-3"),
    ("2.5", 0, PresentationRoundingMode.HALF_DOWN, "2"),
    ("-2.5", 0, PresentationRoundingMode.HALF_DOWN, "-2"),
    ("1.23456789", 5, PresentationRoundingMode.HALF_EVEN, "1.23457"),
    ("0", 3, PresentationRoundingMode.HALF_EVEN, "0.000"),
)


@pytest.mark.parametrize(
    ("value", "places", "mode", "expected"),
    DECIMAL_PLACE_VECTORS,
)
def test_decimal_place_rounding_vectors(
    value: str,
    places: int,
    mode: PresentationRoundingMode,
    expected: str,
) -> None:
    rounded = round_decimal_places(
        Decimal(value),
        places,
        mode=mode,
    )
    assert str(rounded) == expected


SIGNIFICANT_FIGURE_VECTORS = (
    ("1234.567", 3, PresentationRoundingMode.HALF_EVEN, "1.23E+3"),
    ("0.012345", 3, PresentationRoundingMode.HALF_EVEN, "0.0123"),
    ("1.225", 3, PresentationRoundingMode.HALF_EVEN, "1.22"),
    ("1.235", 3, PresentationRoundingMode.HALF_EVEN, "1.24"),
    ("-1234.567", 3, PresentationRoundingMode.HALF_EVEN, "-1.23E+3"),
    ("9.995", 3, PresentationRoundingMode.HALF_UP, "10.0"),
    ("0.09995", 3, PresentationRoundingMode.HALF_UP, "0.100"),
    ("9.995", 3, PresentationRoundingMode.HALF_EVEN, "10.0"),
    ("-9.995", 3, PresentationRoundingMode.HALF_EVEN, "-10.0"),
    ("999.5", 3, PresentationRoundingMode.HALF_UP, "1.00E+3"),
    ("-999.5", 3, PresentationRoundingMode.HALF_UP, "-1.00E+3"),
    ("9.985", 3, PresentationRoundingMode.HALF_EVEN, "9.98"),
    ("0", 1, PresentationRoundingMode.HALF_EVEN, "0"),
    ("0", 3, PresentationRoundingMode.HALF_EVEN, "0.00"),
    ("1.234567890123456", 15, PresentationRoundingMode.HALF_EVEN, (
        "1.23456789012346"
    )),
)


@pytest.mark.parametrize(
    ("value", "figures", "mode", "expected"),
    SIGNIFICANT_FIGURE_VECTORS,
)
def test_significant_figure_rounding_vectors(
    value: str,
    figures: int,
    mode: PresentationRoundingMode,
    expected: str,
) -> None:
    rounded = round_significant_figures(
        Decimal(value),
        figures,
        mode=mode,
    )
    assert str(rounded) == expected


@pytest.mark.parametrize(
    ("value", "expected_significant"),
    (
        (
            Decimal("1E+300"),
            "1.00000000000000E+300",
        ),
        (
            Decimal("-1E+300"),
            "-1.00000000000000E+300",
        ),
        (
            Decimal("1E-300"),
            "1.00000000000000E-300",
        ),
        (
            Decimal("-1E-300"),
            "-1.00000000000000E-300",
        ),
    ),
)
def test_rounding_handles_supported_extreme_exponents(
    value: Decimal,
    expected_significant: str,
) -> None:
    decimal_result = round_decimal_places(value, 15)
    significant_result = round_significant_figures(value, 15)
    assert str(significant_result) == expected_significant

    if abs(value) < 1:
        assert str(decimal_result) == "0E-15"
    else:
        assert decimal_result == value
        assert decimal_result.as_tuple().exponent == -15


@pytest.mark.parametrize("places", (-1, 16, True, False, 1.0, "1"))
def test_decimal_place_precision_is_strict(
    places: object,
) -> None:
    with pytest.raises(PresentationRoundingError):
        round_decimal_places(
            Decimal("1.23"),
            places,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("figures", (0, -1, 16, True, False, 1.0, "1"))
def test_significant_figure_precision_is_strict(
    figures: object,
) -> None:
    with pytest.raises(PresentationRoundingError):
        round_significant_figures(
            Decimal("1.23"),
            figures,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "bad_value",
    (
        Decimal("NaN"),
        Decimal("Infinity"),
        Decimal("-Infinity"),
        nan,
        inf,
        -inf,
        True,
        False,
        "1.23",
        None,
    ),
)
def test_rounding_rejects_invalid_values(bad_value: object) -> None:
    with pytest.raises(PresentationRoundingError):
        round_decimal_places(
            bad_value,  # type: ignore[arg-type]
            2,
        )

    with pytest.raises(PresentationRoundingError):
        round_significant_figures(
            bad_value,  # type: ignore[arg-type]
            2,
        )


@pytest.mark.parametrize(
    "mode",
    ("bankers", "", None, 1, True),
)
def test_rounding_rejects_unknown_modes(mode: object) -> None:
    with pytest.raises(PresentationRoundingError):
        round_decimal_places(
            Decimal("1.25"),
            1,
            mode=mode,  # type: ignore[arg-type]
        )


def test_presentation_value_uses_decimal_places_without_mutation() -> None:
    source = quantity(
        QuantityKind.LENGTH,
        1.235,
        "m",
        decimal_places=2,
    )
    original = source.model_dump(mode="json")
    assert presentation_value(source) == Decimal("1.24")
    assert presentation_value(source) == Decimal("1.24")
    assert source.value == 1.235
    assert source.model_dump(mode="json") == original


def test_presentation_value_uses_significant_figures_without_mutation() -> None:
    source = quantity(
        QuantityKind.LENGTH,
        1234.567,
        "m",
        significant_figures=3,
    )
    original = source.model_dump(mode="json")
    assert presentation_value(source) == Decimal("1.23E+3")
    assert source.value == 1234.567
    assert source.model_dump(mode="json") == original


def test_presentation_value_without_precision_preserves_unrounded_value() -> None:
    source = quantity(QuantityKind.LENGTH, 1.23456789, "m")
    assert presentation_value(source) == Decimal("1.23456789")


def test_presentation_value_validates_mode_even_without_precision() -> None:
    source = quantity(QuantityKind.LENGTH, 1.23456789, "m")

    with pytest.raises(PresentationRoundingError):
        presentation_value(source, mode="unsupported")


@pytest.mark.parametrize(
    ("value", "precision_field", "precision", "expected"),
    (
        (1.2, "significant_figures", 3, "1.20"),
        (0.0, "significant_figures", 3, "0.00"),
        (1234.567, "significant_figures", 3, "1230"),
        (1.2, "decimal_places", 3, "1.200"),
        (-0.0, "decimal_places", 2, "0.00"),
    ),
)
def test_format_quantity_value_retains_trailing_zeros_and_is_locale_independent(
    value: float,
    precision_field: str,
    precision: int,
    expected: str,
) -> None:
    source = quantity(
        QuantityKind.LENGTH,
        value,
        "m",
        **{precision_field: precision},
    )
    rendered = format_quantity_value(source)
    assert rendered == expected
    assert "," not in rendered


def test_presentation_helpers_revalidate_bypass_constructed_quantity() -> None:
    bypassed = EngineeringQuantity.model_construct(
        quantity_kind=QuantityKind.LENGTH.value,
        value=nan,
        unit="m",
        significant_figures=3,
    )

    with pytest.raises(PresentationRoundingError):
        presentation_value(bypassed)

    with pytest.raises(PresentationRoundingError):
        format_quantity_value(bypassed)


def test_conversion_never_applies_presentation_rounding() -> None:
    source = quantity(
        QuantityKind.LENGTH,
        1.23456,
        "m",
        significant_figures=2,
    )
    converted = REGISTRY.convert_quantity(source, "mm")
    assert converted.value == pytest.approx(1234.56)
    assert presentation_value(converted) == Decimal("1.2E+3")


def test_public_unit_exports_are_exact_and_available_from_package() -> None:
    expected_unit_exports = {
        "CompressibilityTreatment",
        "DEFAULT_UNIT_REGISTRY",
        "FlowReferenceBasis",
        "IncompatibleUnitError",
        "PhysicalDimension",
        "PresentationRoundingError",
        "PresentationRoundingMode",
        "PressureBasisError",
        "QuantityKind",
        "ReferenceConditionError",
        "ReferenceConditions",
        "ReferencedVolumetricFlow",
        "UnitConversionError",
        "UnitDefinition",
        "UnitRegistry",
        "UnitRegistryError",
        "UnitSystemError",
        "UnknownQuantityKindError",
        "UnknownUnitError",
        "convert_pressure_basis",
        "convert_referenced_volumetric_flow",
        "format_quantity_value",
        "presentation_value",
        "round_decimal_places",
        "round_significant_figures",
    }
    assert set(units_module.__all__) == expected_unit_exports
    assert len(units_module.__all__) == len(set(units_module.__all__))

    for public_name in expected_unit_exports:
        assert getattr(calculation_package, public_name) is getattr(
            units_module,
            public_name,
        )
        assert public_name in calculation_package.__all__


def test_step_91_package_boundary_and_version() -> None:
    assert calculation_package.PHASE_NUMBER == 7
    assert calculation_package.PACKAGE_NAME == "engineering_calculations"
    assert calculation_package.FOUNDATION_VERSION == "0.4.0"
    assert calculation_package.EXECUTABLE_METHODS_ENABLED is False
    assert not any(
        "voice" in public_name.casefold()
        for public_name in calculation_package.__all__
    )


def test_unit_module_contains_no_dynamic_execution_or_process_calls() -> None:
    source_path = Path(units_module.__file__)
    parsed = ast.parse(source_path.read_text(encoding="utf-8"))
    forbidden_names = {
        "__import__",
        "compile",
        "eval",
        "exec",
        "popen",
        "run",
        "system",
    }
    forbidden_modules = {
        "importlib",
        "os",
        "subprocess",
    }

    for node in ast.walk(parsed):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imported_modules = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            assert not any(
                module.split(".")[0] in forbidden_modules
                for module in imported_modules
            )

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                assert node.func.id not in forbidden_names
            elif isinstance(node.func, ast.Attribute):
                assert node.func.attr not in forbidden_names


def test_models_and_reference_states_round_trip_through_json() -> None:
    conditions = reference_conditions(
        reference_id="json.conditions",
        basis=FlowReferenceBasis.STANDARD,
        treatment=CompressibilityTreatment.SPECIFIED_FACTOR,
        compressibility_factor=0.98,
    )
    source = referenced_flow(
        value=123.456,
        unit="m3/h",
        conditions=conditions,
        uncertainty=0.25,
        uncertainty_basis="Reference meter uncertainty.",
        decimal_places=2,
    )
    restored = ReferencedVolumetricFlow.model_validate_json(
        source.model_dump_json()
    )
    assert restored == source
