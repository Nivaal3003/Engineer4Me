"""Deterministic unit handling for Engineer4Me calculations.

This module provides the reviewed Phase 7 unit boundary.  It contains an
immutable allow-listed unit registry, dimensional validation, explicit
pressure-basis conversion, explicit volumetric-flow reference conditions, and
presentation-only rounding helpers.

Unit symbols are case-sensitive.  Compound units are registered literals; the
module does not parse or execute arbitrary expressions.  Pressure basis and
flow reference basis are quantity semantics rather than unit-name suffixes, so
aliases such as ``psig``, ``barg``, ``scfm``, and ``Nm3/h`` are deliberately
absent.
"""

from __future__ import annotations

from collections.abc import Iterable
from collections.abc import Mapping
from decimal import Clamped
from decimal import Context
from decimal import Decimal
from decimal import DecimalException
from decimal import Overflow
from decimal import ROUND_HALF_DOWN
from decimal import ROUND_HALF_EVEN
from decimal import ROUND_HALF_UP
from decimal import Underflow
from decimal import localcontext
from enum import StrEnum
from math import isfinite
from types import MappingProxyType
from typing import Annotated
from typing import Any
from typing import Self

from pydantic import Field
from pydantic import StrictFloat
from pydantic import StringConstraints
from pydantic import ValidationInfo
from pydantic import field_validator
from pydantic import model_validator

from app.engineering.calculations.models import CalculationModel
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import MAX_ABSOLUTE_OPTION_NUMBER


_CONVERSION_CONTEXT = Context(
    prec=128,
    Emin=-999_999,
    Emax=999_999,
)
_ROUNDING_CONTEXT = Context(
    prec=384,
    Emin=-999_999,
    Emax=999_999,
)
_MAXIMUM_DECIMAL = Decimal(str(MAX_ABSOLUTE_OPTION_NUMBER))


UnitText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=40,
    ),
]

UnitName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=2,
        max_length=100,
    ),
]

ReferenceIdentifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=2,
        max_length=100,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$",
    ),
]


class UnitSystemError(ValueError):
    """Base error for deterministic unit-system operations."""


class UnitRegistryError(UnitSystemError):
    """Raised when a unit registry definition is inconsistent."""


class UnknownUnitError(UnitSystemError):
    """Raised when a unit symbol or alias is not allow-listed."""


class UnknownQuantityKindError(UnitSystemError):
    """Raised when a quantity kind has no controlled dimension mapping."""


class IncompatibleUnitError(UnitSystemError):
    """Raised when a unit is incompatible with a quantity kind or target."""


class UnitConversionError(UnitSystemError):
    """Raised when a numerical unit conversion cannot be represented safely."""


class PressureBasisError(UnitSystemError):
    """Raised when pressure-basis conversion rules are not satisfied."""


class ReferenceConditionError(UnitSystemError):
    """Raised when volumetric-flow reference conditions are invalid."""


class PresentationRoundingError(UnitSystemError):
    """Raised when a presentation precision request is invalid."""


class PhysicalDimension(StrEnum):
    """Controlled physical dimensions supported by the Phase 7 registry."""

    DIMENSIONLESS = "dimensionless"
    ANGLE = "angle"
    LENGTH = "length"
    AREA = "area"
    VOLUME = "volume"
    TIME = "time"
    MASS = "mass"
    ABSOLUTE_TEMPERATURE = "temperature.absolute"
    TEMPERATURE_DIFFERENCE = "temperature.difference"
    PRESSURE = "pressure"
    DENSITY = "density"
    DYNAMIC_VISCOSITY = "viscosity.dynamic"
    KINEMATIC_VISCOSITY = "viscosity.kinematic"
    VELOCITY = "velocity"
    ACCELERATION = "acceleration"
    VOLUMETRIC_FLOW = "flow.volumetric"
    MASS_FLOW = "flow.mass"
    FORCE = "force"
    ENERGY = "energy"
    POWER = "power"
    ELECTRIC_CURRENT = "electrical.current"
    ELECTRIC_POTENTIAL = "electrical.potential"
    ELECTRICAL_RESISTANCE = "electrical.resistance"
    FREQUENCY = "frequency"


class QuantityKind(StrEnum):
    """Allow-listed quantity semantics understood by unit operations."""

    DIMENSIONLESS = "dimensionless"
    RATIO = "ratio"
    SPECIFIC_GRAVITY = "specific_gravity"
    ANGLE = "angle"
    LENGTH = "length"
    AREA = "area"
    VOLUME = "volume"
    TIME = "time"
    MASS = "mass"
    ABSOLUTE_TEMPERATURE = "temperature.absolute"
    TEMPERATURE_DIFFERENCE = "temperature.difference"
    ABSOLUTE_PRESSURE = "pressure.absolute"
    GAUGE_PRESSURE = "pressure.gauge"
    DIFFERENTIAL_PRESSURE = "pressure.differential"
    DENSITY = "density"
    DYNAMIC_VISCOSITY = "viscosity.dynamic"
    KINEMATIC_VISCOSITY = "viscosity.kinematic"
    VELOCITY = "velocity"
    ACCELERATION = "acceleration"
    ACTUAL_VOLUMETRIC_FLOW = "flow.volumetric.actual"
    STANDARD_VOLUMETRIC_FLOW = "flow.volumetric.standard"
    NORMAL_VOLUMETRIC_FLOW = "flow.volumetric.normal"
    REFERENCE_VOLUMETRIC_FLOW = "flow.volumetric.reference"
    MASS_FLOW = "flow.mass"
    FORCE = "force"
    ENERGY = "energy"
    POWER = "power"
    ELECTRIC_CURRENT = "electrical.current"
    ELECTRIC_POTENTIAL = "electrical.potential"
    ELECTRICAL_RESISTANCE = "electrical.resistance"
    FREQUENCY = "frequency"


_REFERENCE_CONDITION_QUANTITY_KINDS = frozenset(
    {
        QuantityKind.STANDARD_VOLUMETRIC_FLOW,
        QuantityKind.NORMAL_VOLUMETRIC_FLOW,
        QuantityKind.REFERENCE_VOLUMETRIC_FLOW,
    }
)


class CompressibilityTreatment(StrEnum):
    """How a flow reference state treats gas compressibility."""

    IDEAL_GAS = "ideal_gas"
    SPECIFIED_FACTOR = "specified_factor"


class FlowReferenceBasis(StrEnum):
    """Meaning assigned to an explicitly described volumetric-flow state."""

    ACTUAL = "actual"
    STANDARD = "standard"
    NORMAL = "normal"
    CUSTOM = "custom"


class PresentationRoundingMode(StrEnum):
    """Supported deterministic presentation rounding modes."""

    HALF_EVEN = "half_even"
    HALF_UP = "half_up"
    HALF_DOWN = "half_down"


class UnitDefinition(CalculationModel):
    """One immutable unit and its affine conversion to a canonical unit.

    The canonical value is calculated as:

    ``canonical = value * scale_to_canonical + offset_to_canonical``.

    Non-zero offsets are restricted to absolute-temperature units.  Difference
    temperatures use a separate dimension and therefore can never inherit an
    absolute-temperature offset.
    """

    symbol: UnitText
    name: UnitName
    dimension: PhysicalDimension
    scale_to_canonical: Decimal
    offset_to_canonical: Decimal = Decimal("0")
    aliases: tuple[UnitText, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )

    @field_validator(
        "scale_to_canonical",
        "offset_to_canonical",
        mode="before",
    )
    @classmethod
    def require_decimal_constants(
        cls,
        value: Any,
        info: ValidationInfo,
    ) -> Decimal:
        """Require reviewed decimal constants rather than binary floats."""

        if isinstance(value, Decimal):
            decimal_value = value
        elif info.mode == "json" and isinstance(value, str):
            try:
                decimal_value = Decimal(value)
            except DecimalException as exc:
                raise ValueError(
                    "Unit conversion constants must be valid decimals."
                ) from exc
        else:
            raise ValueError(
                "Unit conversion constants must be Decimal instances."
            )

        if not decimal_value.is_finite():
            raise ValueError("Unit conversion constants must be finite.")

        return decimal_value

    @model_validator(mode="after")
    def validate_definition(self) -> Self:
        """Validate scale, offset, and alias invariants."""

        if self.scale_to_canonical <= 0:
            raise ValueError("scale_to_canonical must be greater than zero.")

        if (
            self.offset_to_canonical != 0
            and self.dimension is not PhysicalDimension.ABSOLUTE_TEMPERATURE
        ):
            raise ValueError(
                "Only absolute-temperature units may have a non-zero offset."
            )

        if self.symbol in self.aliases:
            raise ValueError("A unit alias cannot duplicate its symbol.")

        if len(self.aliases) != len(set(self.aliases)):
            raise ValueError("Unit aliases must be unique.")

        return self


def _decimal_ratio(
    numerator: str,
    denominator: str,
) -> Decimal:
    """Create a high-precision deterministic decimal ratio."""

    with localcontext(_CONVERSION_CONTEXT):
        return Decimal(numerator) / Decimal(denominator)


_FIVE_NINTHS = _decimal_ratio("5", "9")
with localcontext(_CONVERSION_CONTEXT):
    _FAHRENHEIT_OFFSET = Decimal("459.67") * _FIVE_NINTHS
    _DEGREE_TO_RADIAN = (
        Decimal(
            "3.1415926535897932384626433832795028841971693993751"
        )
        / Decimal("180")
    )


def _unit(
    symbol: str,
    name: str,
    dimension: PhysicalDimension,
    scale: str | Decimal,
    *,
    offset: str | Decimal = "0",
    aliases: tuple[str, ...] = (),
) -> UnitDefinition:
    """Build one reviewed default-registry definition."""

    scale_value = (
        scale
        if isinstance(scale, Decimal)
        else Decimal(scale)
    )
    offset_value = (
        offset
        if isinstance(offset, Decimal)
        else Decimal(offset)
    )

    return UnitDefinition(
        symbol=symbol,
        name=name,
        dimension=dimension,
        scale_to_canonical=scale_value,
        offset_to_canonical=offset_value,
        aliases=aliases,
    )


_DEFAULT_UNIT_DEFINITIONS = (
    _unit(
        "1",
        "unity",
        PhysicalDimension.DIMENSIONLESS,
        "1",
        aliases=("ratio",),
    ),
    _unit(
        "%",
        "percent",
        PhysicalDimension.DIMENSIONLESS,
        "0.01",
        aliases=("percent",),
    ),
    _unit(
        "rad",
        "radian",
        PhysicalDimension.ANGLE,
        "1",
        aliases=("radian", "radians"),
    ),
    _unit(
        "deg",
        "degree",
        PhysicalDimension.ANGLE,
        _DEGREE_TO_RADIAN,
        aliases=("degree", "degrees", "°"),
    ),
    _unit(
        "m",
        "metre",
        PhysicalDimension.LENGTH,
        "1",
        aliases=("metre", "meter", "metres", "meters"),
    ),
    _unit(
        "mm",
        "millimetre",
        PhysicalDimension.LENGTH,
        "0.001",
        aliases=("millimetre", "millimeter"),
    ),
    _unit(
        "cm",
        "centimetre",
        PhysicalDimension.LENGTH,
        "0.01",
        aliases=("centimetre", "centimeter"),
    ),
    _unit(
        "km",
        "kilometre",
        PhysicalDimension.LENGTH,
        "1000",
        aliases=("kilometre", "kilometer"),
    ),
    _unit(
        "in",
        "inch",
        PhysicalDimension.LENGTH,
        "0.0254",
        aliases=("inch", "inches"),
    ),
    _unit(
        "ft",
        "foot",
        PhysicalDimension.LENGTH,
        "0.3048",
        aliases=("foot", "feet"),
    ),
    _unit(
        "yd",
        "yard",
        PhysicalDimension.LENGTH,
        "0.9144",
        aliases=("yard", "yards"),
    ),
    _unit(
        "m2",
        "square metre",
        PhysicalDimension.AREA,
        "1",
        aliases=("m^2", "m²"),
    ),
    _unit(
        "mm2",
        "square millimetre",
        PhysicalDimension.AREA,
        "0.000001",
        aliases=("mm^2", "mm²"),
    ),
    _unit(
        "cm2",
        "square centimetre",
        PhysicalDimension.AREA,
        "0.0001",
        aliases=("cm^2", "cm²"),
    ),
    _unit(
        "in2",
        "square inch",
        PhysicalDimension.AREA,
        "0.00064516",
        aliases=("in^2", "in²"),
    ),
    _unit(
        "ft2",
        "square foot",
        PhysicalDimension.AREA,
        "0.09290304",
        aliases=("ft^2", "ft²"),
    ),
    _unit(
        "m3",
        "cubic metre",
        PhysicalDimension.VOLUME,
        "1",
        aliases=("m^3", "m³"),
    ),
    _unit(
        "L",
        "litre",
        PhysicalDimension.VOLUME,
        "0.001",
        aliases=("litre", "liter", "litres", "liters"),
    ),
    _unit(
        "mL",
        "millilitre",
        PhysicalDimension.VOLUME,
        "0.000001",
        aliases=("millilitre", "milliliter"),
    ),
    _unit(
        "cm3",
        "cubic centimetre",
        PhysicalDimension.VOLUME,
        "0.000001",
        aliases=("cm^3", "cm³", "cc"),
    ),
    _unit(
        "in3",
        "cubic inch",
        PhysicalDimension.VOLUME,
        "0.000016387064",
        aliases=("in^3", "in³"),
    ),
    _unit(
        "ft3",
        "cubic foot",
        PhysicalDimension.VOLUME,
        "0.028316846592",
        aliases=("ft^3", "ft³"),
    ),
    _unit(
        "US gal",
        "US liquid gallon",
        PhysicalDimension.VOLUME,
        "0.003785411784",
        aliases=("US gallon", "US gallons"),
    ),
    _unit(
        "Imp gal",
        "imperial gallon",
        PhysicalDimension.VOLUME,
        "0.00454609",
        aliases=("imperial gallon", "imperial gallons"),
    ),
    _unit(
        "s",
        "second",
        PhysicalDimension.TIME,
        "1",
        aliases=("second", "seconds"),
    ),
    _unit(
        "min",
        "minute",
        PhysicalDimension.TIME,
        "60",
        aliases=("minute", "minutes"),
    ),
    _unit(
        "h",
        "hour",
        PhysicalDimension.TIME,
        "3600",
        aliases=("hour", "hours", "hr"),
    ),
    _unit(
        "d",
        "day",
        PhysicalDimension.TIME,
        "86400",
        aliases=("day", "days"),
    ),
    _unit(
        "kg",
        "kilogram",
        PhysicalDimension.MASS,
        "1",
        aliases=("kilogram", "kilograms"),
    ),
    _unit(
        "g",
        "gram",
        PhysicalDimension.MASS,
        "0.001",
        aliases=("gram", "grams"),
    ),
    _unit(
        "mg",
        "milligram",
        PhysicalDimension.MASS,
        "0.000001",
        aliases=("milligram", "milligrams"),
    ),
    _unit(
        "t",
        "metric tonne",
        PhysicalDimension.MASS,
        "1000",
        aliases=("tonne", "tonnes"),
    ),
    _unit(
        "lb",
        "pound mass",
        PhysicalDimension.MASS,
        "0.45359237",
        aliases=("lbm", "pound", "pounds"),
    ),
    _unit(
        "oz",
        "ounce mass",
        PhysicalDimension.MASS,
        "0.028349523125",
        aliases=("ounce", "ounces"),
    ),
    _unit(
        "K",
        "kelvin",
        PhysicalDimension.ABSOLUTE_TEMPERATURE,
        "1",
        aliases=("kelvin",),
    ),
    _unit(
        "degC",
        "degree Celsius",
        PhysicalDimension.ABSOLUTE_TEMPERATURE,
        "1",
        offset="273.15",
        aliases=("°C", "Celsius"),
    ),
    _unit(
        "degF",
        "degree Fahrenheit",
        PhysicalDimension.ABSOLUTE_TEMPERATURE,
        _FIVE_NINTHS,
        offset=_FAHRENHEIT_OFFSET,
        aliases=("°F", "Fahrenheit"),
    ),
    _unit(
        "degR",
        "degree Rankine",
        PhysicalDimension.ABSOLUTE_TEMPERATURE,
        _FIVE_NINTHS,
        aliases=("°R", "Rankine"),
    ),
    _unit(
        "delta_K",
        "kelvin difference",
        PhysicalDimension.TEMPERATURE_DIFFERENCE,
        "1",
        aliases=("delta kelvin",),
    ),
    _unit(
        "delta_degC",
        "degree Celsius difference",
        PhysicalDimension.TEMPERATURE_DIFFERENCE,
        "1",
        aliases=("delta °C",),
    ),
    _unit(
        "delta_degF",
        "degree Fahrenheit difference",
        PhysicalDimension.TEMPERATURE_DIFFERENCE,
        _FIVE_NINTHS,
        aliases=("delta °F",),
    ),
    _unit(
        "delta_degR",
        "degree Rankine difference",
        PhysicalDimension.TEMPERATURE_DIFFERENCE,
        _FIVE_NINTHS,
        aliases=("delta °R",),
    ),
    _unit(
        "Pa",
        "pascal",
        PhysicalDimension.PRESSURE,
        "1",
        aliases=("pascal", "pascals"),
    ),
    _unit(
        "mPa",
        "millipascal",
        PhysicalDimension.PRESSURE,
        "0.001",
        aliases=("millipascal",),
    ),
    _unit(
        "kPa",
        "kilopascal",
        PhysicalDimension.PRESSURE,
        "1000",
        aliases=("kilopascal",),
    ),
    _unit(
        "MPa",
        "megapascal",
        PhysicalDimension.PRESSURE,
        "1000000",
        aliases=("megapascal",),
    ),
    _unit(
        "bar",
        "bar",
        PhysicalDimension.PRESSURE,
        "100000",
    ),
    _unit(
        "mbar",
        "millibar",
        PhysicalDimension.PRESSURE,
        "100",
        aliases=("millibar",),
    ),
    _unit(
        "psi",
        "pound-force per square inch",
        PhysicalDimension.PRESSURE,
        "6894.757293168361",
    ),
    _unit(
        "atm",
        "standard atmosphere",
        PhysicalDimension.PRESSURE,
        "101325",
        aliases=("atmosphere",),
    ),
    _unit(
        "torr",
        "torr",
        PhysicalDimension.PRESSURE,
        "133.32236842105263157894736842105263157894736842105",
    ),
    _unit(
        "kg/m3",
        "kilogram per cubic metre",
        PhysicalDimension.DENSITY,
        "1",
        aliases=("kg/m^3", "kg/m³"),
    ),
    _unit(
        "g/cm3",
        "gram per cubic centimetre",
        PhysicalDimension.DENSITY,
        "1000",
        aliases=("g/cm^3", "g/cm³"),
    ),
    _unit(
        "kg/L",
        "kilogram per litre",
        PhysicalDimension.DENSITY,
        "1000",
    ),
    _unit(
        "g/L",
        "gram per litre",
        PhysicalDimension.DENSITY,
        "1",
    ),
    _unit(
        "lb/ft3",
        "pound mass per cubic foot",
        PhysicalDimension.DENSITY,
        "16.018463373960138",
        aliases=("lb/ft^3", "lb/ft³"),
    ),
    _unit(
        "Pa.s",
        "pascal second",
        PhysicalDimension.DYNAMIC_VISCOSITY,
        "1",
        aliases=("Pa*s",),
    ),
    _unit(
        "mPa.s",
        "millipascal second",
        PhysicalDimension.DYNAMIC_VISCOSITY,
        "0.001",
        aliases=("mPa*s", "cP"),
    ),
    _unit(
        "P",
        "poise",
        PhysicalDimension.DYNAMIC_VISCOSITY,
        "0.1",
        aliases=("poise",),
    ),
    _unit(
        "m2/s",
        "square metre per second",
        PhysicalDimension.KINEMATIC_VISCOSITY,
        "1",
        aliases=("m^2/s", "m²/s"),
    ),
    _unit(
        "mm2/s",
        "square millimetre per second",
        PhysicalDimension.KINEMATIC_VISCOSITY,
        "0.000001",
        aliases=("mm^2/s", "mm²/s", "cSt"),
    ),
    _unit(
        "St",
        "stokes",
        PhysicalDimension.KINEMATIC_VISCOSITY,
        "0.0001",
        aliases=("stokes",),
    ),
    _unit(
        "m/s",
        "metre per second",
        PhysicalDimension.VELOCITY,
        "1",
    ),
    _unit(
        "km/h",
        "kilometre per hour",
        PhysicalDimension.VELOCITY,
        "0.27777777777777777777777777777777777777777777777778",
    ),
    _unit(
        "ft/s",
        "foot per second",
        PhysicalDimension.VELOCITY,
        "0.3048",
    ),
    _unit(
        "mph",
        "mile per hour",
        PhysicalDimension.VELOCITY,
        "0.44704",
    ),
    _unit(
        "m/s2",
        "metre per second squared",
        PhysicalDimension.ACCELERATION,
        "1",
        aliases=("m/s^2", "m/s²"),
    ),
    _unit(
        "ft/s2",
        "foot per second squared",
        PhysicalDimension.ACCELERATION,
        "0.3048",
        aliases=("ft/s^2", "ft/s²"),
    ),
    _unit(
        "g0",
        "standard gravity",
        PhysicalDimension.ACCELERATION,
        "9.80665",
        aliases=("standard gravity",),
    ),
    _unit(
        "m3/s",
        "cubic metre per second",
        PhysicalDimension.VOLUMETRIC_FLOW,
        "1",
        aliases=("m^3/s", "m³/s"),
    ),
    _unit(
        "m3/h",
        "cubic metre per hour",
        PhysicalDimension.VOLUMETRIC_FLOW,
        "0.00027777777777777777777777777777777777777777777778",
        aliases=("m^3/h", "m³/h"),
    ),
    _unit(
        "L/s",
        "litre per second",
        PhysicalDimension.VOLUMETRIC_FLOW,
        "0.001",
    ),
    _unit(
        "L/min",
        "litre per minute",
        PhysicalDimension.VOLUMETRIC_FLOW,
        "0.000016666666666666666666666666666666666666666666666667",
    ),
    _unit(
        "ft3/s",
        "cubic foot per second",
        PhysicalDimension.VOLUMETRIC_FLOW,
        "0.028316846592",
        aliases=("ft^3/s", "ft³/s"),
    ),
    _unit(
        "ft3/min",
        "cubic foot per minute",
        PhysicalDimension.VOLUMETRIC_FLOW,
        "0.0004719474432",
        aliases=("ft^3/min", "ft³/min", "cfm"),
    ),
    _unit(
        "US gal/min",
        "US gallon per minute",
        PhysicalDimension.VOLUMETRIC_FLOW,
        "0.0000630901964",
        aliases=("US gpm",),
    ),
    _unit(
        "kg/s",
        "kilogram per second",
        PhysicalDimension.MASS_FLOW,
        "1",
    ),
    _unit(
        "kg/h",
        "kilogram per hour",
        PhysicalDimension.MASS_FLOW,
        "0.00027777777777777777777777777777777777777777777778",
    ),
    _unit(
        "g/s",
        "gram per second",
        PhysicalDimension.MASS_FLOW,
        "0.001",
    ),
    _unit(
        "t/h",
        "metric tonne per hour",
        PhysicalDimension.MASS_FLOW,
        "0.27777777777777777777777777777777777777777777777778",
    ),
    _unit(
        "lb/s",
        "pound mass per second",
        PhysicalDimension.MASS_FLOW,
        "0.45359237",
    ),
    _unit(
        "lb/h",
        "pound mass per hour",
        PhysicalDimension.MASS_FLOW,
        "0.00012599788055555555555555555555555555555555555555556",
    ),
    _unit(
        "N",
        "newton",
        PhysicalDimension.FORCE,
        "1",
        aliases=("newton",),
    ),
    _unit(
        "kN",
        "kilonewton",
        PhysicalDimension.FORCE,
        "1000",
    ),
    _unit(
        "lbf",
        "pound force",
        PhysicalDimension.FORCE,
        "4.4482216152605",
    ),
    _unit(
        "J",
        "joule",
        PhysicalDimension.ENERGY,
        "1",
        aliases=("joule",),
    ),
    _unit(
        "kJ",
        "kilojoule",
        PhysicalDimension.ENERGY,
        "1000",
    ),
    _unit(
        "MJ",
        "megajoule",
        PhysicalDimension.ENERGY,
        "1000000",
    ),
    _unit(
        "Wh",
        "watt hour",
        PhysicalDimension.ENERGY,
        "3600",
    ),
    _unit(
        "kWh",
        "kilowatt hour",
        PhysicalDimension.ENERGY,
        "3600000",
    ),
    _unit(
        "W",
        "watt",
        PhysicalDimension.POWER,
        "1",
        aliases=("watt",),
    ),
    _unit(
        "kW",
        "kilowatt",
        PhysicalDimension.POWER,
        "1000",
    ),
    _unit(
        "MW",
        "megawatt",
        PhysicalDimension.POWER,
        "1000000",
    ),
    _unit(
        "hp",
        "mechanical horsepower",
        PhysicalDimension.POWER,
        "745.69987158227022",
    ),
    _unit(
        "A",
        "ampere",
        PhysicalDimension.ELECTRIC_CURRENT,
        "1",
        aliases=("ampere", "amp"),
    ),
    _unit(
        "mA",
        "milliampere",
        PhysicalDimension.ELECTRIC_CURRENT,
        "0.001",
        aliases=("milliampere",),
    ),
    _unit(
        "uA",
        "microampere",
        PhysicalDimension.ELECTRIC_CURRENT,
        "0.000001",
        aliases=("µA", "microampere"),
    ),
    _unit(
        "V",
        "volt",
        PhysicalDimension.ELECTRIC_POTENTIAL,
        "1",
        aliases=("volt",),
    ),
    _unit(
        "mV",
        "millivolt",
        PhysicalDimension.ELECTRIC_POTENTIAL,
        "0.001",
    ),
    _unit(
        "kV",
        "kilovolt",
        PhysicalDimension.ELECTRIC_POTENTIAL,
        "1000",
    ),
    _unit(
        "ohm",
        "ohm",
        PhysicalDimension.ELECTRICAL_RESISTANCE,
        "1",
        aliases=("Ω",),
    ),
    _unit(
        "kohm",
        "kiloohm",
        PhysicalDimension.ELECTRICAL_RESISTANCE,
        "1000",
        aliases=("kΩ",),
    ),
    _unit(
        "Mohm",
        "megaohm",
        PhysicalDimension.ELECTRICAL_RESISTANCE,
        "1000000",
        aliases=("MΩ",),
    ),
    _unit(
        "Hz",
        "hertz",
        PhysicalDimension.FREQUENCY,
        "1",
        aliases=("hertz",),
    ),
    _unit(
        "kHz",
        "kilohertz",
        PhysicalDimension.FREQUENCY,
        "1000",
    ),
    _unit(
        "MHz",
        "megahertz",
        PhysicalDimension.FREQUENCY,
        "1000000",
    ),
)


_DEFAULT_QUANTITY_DIMENSIONS = {
    QuantityKind.DIMENSIONLESS: PhysicalDimension.DIMENSIONLESS,
    QuantityKind.RATIO: PhysicalDimension.DIMENSIONLESS,
    QuantityKind.SPECIFIC_GRAVITY: PhysicalDimension.DIMENSIONLESS,
    QuantityKind.ANGLE: PhysicalDimension.ANGLE,
    QuantityKind.LENGTH: PhysicalDimension.LENGTH,
    QuantityKind.AREA: PhysicalDimension.AREA,
    QuantityKind.VOLUME: PhysicalDimension.VOLUME,
    QuantityKind.TIME: PhysicalDimension.TIME,
    QuantityKind.MASS: PhysicalDimension.MASS,
    QuantityKind.ABSOLUTE_TEMPERATURE: (
        PhysicalDimension.ABSOLUTE_TEMPERATURE
    ),
    QuantityKind.TEMPERATURE_DIFFERENCE: (
        PhysicalDimension.TEMPERATURE_DIFFERENCE
    ),
    QuantityKind.ABSOLUTE_PRESSURE: PhysicalDimension.PRESSURE,
    QuantityKind.GAUGE_PRESSURE: PhysicalDimension.PRESSURE,
    QuantityKind.DIFFERENTIAL_PRESSURE: PhysicalDimension.PRESSURE,
    QuantityKind.DENSITY: PhysicalDimension.DENSITY,
    QuantityKind.DYNAMIC_VISCOSITY: PhysicalDimension.DYNAMIC_VISCOSITY,
    QuantityKind.KINEMATIC_VISCOSITY: (
        PhysicalDimension.KINEMATIC_VISCOSITY
    ),
    QuantityKind.VELOCITY: PhysicalDimension.VELOCITY,
    QuantityKind.ACCELERATION: PhysicalDimension.ACCELERATION,
    QuantityKind.ACTUAL_VOLUMETRIC_FLOW: PhysicalDimension.VOLUMETRIC_FLOW,
    QuantityKind.STANDARD_VOLUMETRIC_FLOW: (
        PhysicalDimension.VOLUMETRIC_FLOW
    ),
    QuantityKind.NORMAL_VOLUMETRIC_FLOW: PhysicalDimension.VOLUMETRIC_FLOW,
    QuantityKind.REFERENCE_VOLUMETRIC_FLOW: (
        PhysicalDimension.VOLUMETRIC_FLOW
    ),
    QuantityKind.MASS_FLOW: PhysicalDimension.MASS_FLOW,
    QuantityKind.FORCE: PhysicalDimension.FORCE,
    QuantityKind.ENERGY: PhysicalDimension.ENERGY,
    QuantityKind.POWER: PhysicalDimension.POWER,
    QuantityKind.ELECTRIC_CURRENT: PhysicalDimension.ELECTRIC_CURRENT,
    QuantityKind.ELECTRIC_POTENTIAL: PhysicalDimension.ELECTRIC_POTENTIAL,
    QuantityKind.ELECTRICAL_RESISTANCE: (
        PhysicalDimension.ELECTRICAL_RESISTANCE
    ),
    QuantityKind.FREQUENCY: PhysicalDimension.FREQUENCY,
}


_DEFAULT_CANONICAL_UNITS = {
    PhysicalDimension.DIMENSIONLESS: "1",
    PhysicalDimension.ANGLE: "rad",
    PhysicalDimension.LENGTH: "m",
    PhysicalDimension.AREA: "m2",
    PhysicalDimension.VOLUME: "m3",
    PhysicalDimension.TIME: "s",
    PhysicalDimension.MASS: "kg",
    PhysicalDimension.ABSOLUTE_TEMPERATURE: "K",
    PhysicalDimension.TEMPERATURE_DIFFERENCE: "delta_K",
    PhysicalDimension.PRESSURE: "Pa",
    PhysicalDimension.DENSITY: "kg/m3",
    PhysicalDimension.DYNAMIC_VISCOSITY: "Pa.s",
    PhysicalDimension.KINEMATIC_VISCOSITY: "m2/s",
    PhysicalDimension.VELOCITY: "m/s",
    PhysicalDimension.ACCELERATION: "m/s2",
    PhysicalDimension.VOLUMETRIC_FLOW: "m3/s",
    PhysicalDimension.MASS_FLOW: "kg/s",
    PhysicalDimension.FORCE: "N",
    PhysicalDimension.ENERGY: "J",
    PhysicalDimension.POWER: "W",
    PhysicalDimension.ELECTRIC_CURRENT: "A",
    PhysicalDimension.ELECTRIC_POTENTIAL: "V",
    PhysicalDimension.ELECTRICAL_RESISTANCE: "ohm",
    PhysicalDimension.FREQUENCY: "Hz",
}


def _coerce_dimension(value: PhysicalDimension | str) -> PhysicalDimension:
    """Return a controlled physical dimension."""

    try:
        return (
            value
            if isinstance(value, PhysicalDimension)
            else PhysicalDimension(value)
        )
    except (TypeError, ValueError) as exc:
        raise UnitRegistryError(
            f"Unsupported physical dimension: {value!r}."
        ) from exc


def _decimal_from_number(
    value: int | float | Decimal,
    *,
    field_name: str,
    error_type: type[UnitSystemError] = UnitConversionError,
) -> Decimal:
    """Validate and convert a finite public numerical input to Decimal."""

    if isinstance(value, bool) or not isinstance(
        value,
        (int, float, Decimal),
    ):
        raise error_type(f"{field_name} must be a finite number.")

    if isinstance(value, float) and not isfinite(value):
        raise error_type(f"{field_name} must be finite.")

    if isinstance(value, Decimal):
        decimal_value = value
    elif isinstance(value, int):
        decimal_value = Decimal(value)
    else:
        decimal_value = Decimal(str(value))

    if not decimal_value.is_finite():
        raise error_type(f"{field_name} must be finite.")

    if abs(decimal_value) > _MAXIMUM_DECIMAL:
        raise error_type(
            f"{field_name} exceeds the supported numerical magnitude."
        )

    if decimal_value.is_zero():
        return Decimal("0")

    if decimal_value != 0 and float(decimal_value) == 0.0:
        raise error_type(
            f"{field_name} is too small for the public float boundary."
        )

    return decimal_value


def _float_from_decimal(
    value: Decimal,
    *,
    field_name: str,
    error_type: type[UnitSystemError] = UnitConversionError,
) -> float:
    """Convert a Decimal to a safe finite EngineeringQuantity float."""

    if not value.is_finite() or abs(value) > _MAXIMUM_DECIMAL:
        raise error_type(
            f"{field_name} exceeds the supported numerical magnitude."
        )

    float_value = float(value)

    if not isfinite(float_value):
        raise error_type(f"{field_name} cannot be represented as a float.")

    if value != 0 and float_value == 0.0:
        raise error_type(
            f"{field_name} would underflow to zero during conversion."
        )

    if float_value == 0.0:
        return 0.0

    return float_value


class UnitRegistry:
    """Immutable, allow-listed registry of dimensions and unit definitions."""

    __slots__ = (
        "_aliases",
        "_canonical_units",
        "_definitions",
        "_locked",
        "_quantity_dimensions",
        "_units_by_symbol",
    )

    def __init__(
        self,
        definitions: Iterable[UnitDefinition],
        *,
        quantity_dimensions: Mapping[
            QuantityKind | str,
            PhysicalDimension | str,
        ],
        canonical_units: Mapping[PhysicalDimension | str, str],
    ) -> None:
        """Build and validate an immutable registry."""

        object.__setattr__(self, "_locked", False)

        definition_values = tuple(
            UnitDefinition.model_validate(
                definition.model_dump(
                    mode="python",
                    round_trip=True,
                )
            )
            if isinstance(definition, UnitDefinition)
            else UnitDefinition.model_validate(definition)
            for definition in definitions
        )

        if not definition_values:
            raise UnitRegistryError(
                "A unit registry requires at least one definition."
            )

        units_by_symbol: dict[str, UnitDefinition] = {}
        aliases: dict[str, UnitDefinition] = {}

        for definition in definition_values:
            if (
                definition.symbol in units_by_symbol
                or definition.symbol in aliases
            ):
                raise UnitRegistryError(
                    f"Duplicate unit symbol or alias: "
                    f"{definition.symbol!r}."
                )

            units_by_symbol[definition.symbol] = definition

            for alias in definition.aliases:
                if alias in units_by_symbol or alias in aliases:
                    raise UnitRegistryError(
                        f"Duplicate unit symbol or alias: {alias!r}."
                    )

                aliases[alias] = definition

        quantity_dimension_values: dict[
            QuantityKind,
            PhysicalDimension,
        ] = {}

        for raw_kind, raw_dimension in quantity_dimensions.items():
            try:
                kind = (
                    raw_kind
                    if isinstance(raw_kind, QuantityKind)
                    else QuantityKind(raw_kind)
                )
            except (TypeError, ValueError) as exc:
                raise UnitRegistryError(
                    f"Unsupported quantity kind: {raw_kind!r}."
                ) from exc

            if kind in quantity_dimension_values:
                raise UnitRegistryError(
                    f"Duplicate quantity-kind mapping: {kind.value!r}."
                )

            quantity_dimension_values[kind] = _coerce_dimension(
                raw_dimension
            )

        if not quantity_dimension_values:
            raise UnitRegistryError(
                "A unit registry requires quantity-kind mappings."
            )

        canonical_unit_values: dict[PhysicalDimension, str] = {}

        for raw_dimension, raw_symbol in canonical_units.items():
            dimension = _coerce_dimension(raw_dimension)

            if dimension in canonical_unit_values:
                raise UnitRegistryError(
                    f"Duplicate canonical dimension: {dimension.value!r}."
                )

            if not isinstance(raw_symbol, str):
                raise UnitRegistryError(
                    "Canonical unit symbols must be strings."
                )

            symbol = raw_symbol.strip()

            if symbol not in units_by_symbol:
                raise UnitRegistryError(
                    f"Canonical unit {symbol!r} must be a registered symbol."
                )

            definition = units_by_symbol[symbol]

            if definition.dimension is not dimension:
                raise UnitRegistryError(
                    f"Canonical unit {symbol!r} has the wrong dimension."
                )

            if (
                definition.scale_to_canonical != 1
                or definition.offset_to_canonical != 0
            ):
                raise UnitRegistryError(
                    f"Canonical unit {symbol!r} must have scale 1 "
                    "and offset 0."
                )

            canonical_unit_values[dimension] = symbol

        required_dimensions = (
            {definition.dimension for definition in definition_values}
            | set(quantity_dimension_values.values())
        )
        missing_dimensions = (
            required_dimensions - set(canonical_unit_values)
        )

        if missing_dimensions:
            missing_values = ", ".join(
                sorted(
                    dimension.value
                    for dimension in missing_dimensions
                )
            )
            raise UnitRegistryError(
                "Canonical units are missing for: "
                f"{missing_values}."
            )

        object.__setattr__(self, "_definitions", definition_values)
        object.__setattr__(
            self,
            "_units_by_symbol",
            MappingProxyType(units_by_symbol),
        )
        object.__setattr__(
            self,
            "_aliases",
            MappingProxyType(aliases),
        )
        object.__setattr__(
            self,
            "_quantity_dimensions",
            MappingProxyType(quantity_dimension_values),
        )
        object.__setattr__(
            self,
            "_canonical_units",
            MappingProxyType(canonical_unit_values),
        )
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: Any) -> None:
        """Prevent registry mutation after validated construction."""

        if getattr(self, "_locked", False):
            raise AttributeError("UnitRegistry instances are immutable.")

        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """Prevent registry attribute deletion after construction."""

        if getattr(self, "_locked", False):
            raise AttributeError("UnitRegistry instances are immutable.")

        object.__delattr__(self, name)

    @property
    def definitions(self) -> tuple[UnitDefinition, ...]:
        """Return the ordered immutable unit definitions."""

        return self._definitions

    @property
    def aliases(self) -> Mapping[str, UnitDefinition]:
        """Return the read-only alias map."""

        return self._aliases

    @property
    def quantity_dimensions(
        self,
    ) -> Mapping[QuantityKind, PhysicalDimension]:
        """Return the read-only quantity-kind dimension map."""

        return self._quantity_dimensions

    @property
    def canonical_units(self) -> Mapping[PhysicalDimension, str]:
        """Return the read-only canonical-unit map."""

        return self._canonical_units

    def resolve_unit(self, symbol: str) -> UnitDefinition:
        """Resolve one exact, case-sensitive unit symbol or alias."""

        if not isinstance(symbol, str):
            raise UnknownUnitError("A unit symbol must be a string.")

        normalized_symbol = symbol.strip()

        if not normalized_symbol or len(normalized_symbol) > 40:
            raise UnknownUnitError(
                f"Unsupported unit symbol or alias: {symbol!r}."
            )

        definition = self._units_by_symbol.get(normalized_symbol)

        if definition is None:
            definition = self._aliases.get(normalized_symbol)

        if definition is None:
            raise UnknownUnitError(
                f"Unsupported unit symbol or alias: "
                f"{normalized_symbol!r}."
            )

        return definition

    def _coerce_quantity_kind(
        self,
        quantity_kind: QuantityKind | str,
    ) -> QuantityKind:
        """Return a supported controlled quantity kind."""

        try:
            kind = (
                quantity_kind
                if isinstance(quantity_kind, QuantityKind)
                else QuantityKind(quantity_kind)
            )
        except (TypeError, ValueError) as exc:
            raise UnknownQuantityKindError(
                f"Unsupported quantity kind: {quantity_kind!r}."
            ) from exc

        if kind not in self._quantity_dimensions:
            raise UnknownQuantityKindError(
                f"Unsupported quantity kind: {kind.value!r}."
            )

        return kind

    def dimension_for(
        self,
        quantity_kind: QuantityKind | str,
    ) -> PhysicalDimension:
        """Return the registered physical dimension for a quantity kind."""

        kind = self._coerce_quantity_kind(quantity_kind)
        return self._quantity_dimensions[kind]

    def canonical_unit_for(
        self,
        quantity_kind: QuantityKind | str,
    ) -> str:
        """Return the canonical unit symbol for a quantity kind."""

        dimension = self.dimension_for(quantity_kind)
        return self._canonical_units[dimension]

    def _validate_unit_pair(
        self,
        *,
        from_unit: str,
        to_unit: str,
        quantity_kind: QuantityKind | str,
    ) -> tuple[QuantityKind, UnitDefinition, UnitDefinition]:
        """Resolve and dimension-check one conversion pair."""

        kind = self._coerce_quantity_kind(quantity_kind)
        expected_dimension = self._quantity_dimensions[kind]
        source_definition = self.resolve_unit(from_unit)
        target_definition = self.resolve_unit(to_unit)

        if source_definition.dimension is not expected_dimension:
            raise IncompatibleUnitError(
                f"Unit {source_definition.symbol!r} has dimension "
                f"{source_definition.dimension.value!r}, not the "
                f"{expected_dimension.value!r} required by "
                f"{kind.value!r}."
            )

        if target_definition.dimension is not expected_dimension:
            raise IncompatibleUnitError(
                f"Unit {target_definition.symbol!r} has dimension "
                f"{target_definition.dimension.value!r}, not the "
                f"{expected_dimension.value!r} required by "
                f"{kind.value!r}."
            )

        return kind, source_definition, target_definition

    @staticmethod
    def _validate_canonical_domain(
        kind: QuantityKind,
        canonical_value: Decimal,
    ) -> None:
        """Apply domain rules intrinsic to quantity representation."""

        if (
            kind is QuantityKind.ABSOLUTE_TEMPERATURE
            and canonical_value < 0
        ):
            raise UnitConversionError(
                "Absolute temperature cannot be below 0 K."
            )

        if (
            kind is QuantityKind.ABSOLUTE_PRESSURE
            and canonical_value < 0
        ):
            raise UnitConversionError(
                "Absolute pressure cannot be below 0 Pa."
            )

    def _convert_decimal(
        self,
        value: Decimal,
        *,
        from_unit: str,
        to_unit: str,
        quantity_kind: QuantityKind | str,
        allow_reference_conditions: bool = False,
    ) -> tuple[Decimal, QuantityKind, UnitDefinition, UnitDefinition]:
        """Convert a validated Decimal without presentation rounding."""

        (
            kind,
            source_definition,
            target_definition,
        ) = self._validate_unit_pair(
            from_unit=from_unit,
            to_unit=to_unit,
            quantity_kind=quantity_kind,
        )

        if (
            kind in _REFERENCE_CONDITION_QUANTITY_KINDS
            and not allow_reference_conditions
        ):
            raise ReferenceConditionError(
                f"Quantity kind {kind.value!r} requires an explicit "
                "ReferencedVolumetricFlow with reference conditions."
            )

        try:
            with localcontext(_CONVERSION_CONTEXT) as context:
                context.clear_flags()
                canonical_value = (
                    value * source_definition.scale_to_canonical
                    + source_definition.offset_to_canonical
                )
                self._validate_canonical_domain(kind, canonical_value)
                converted_value = (
                    canonical_value
                    - target_definition.offset_to_canonical
                ) / target_definition.scale_to_canonical
                unsafe_decimal_result = any(
                    context.flags[signal]
                    for signal in (Clamped, Overflow, Underflow)
                )
        except DecimalException as exc:
            raise UnitConversionError(
                "Unit conversion exceeded the supported Decimal range."
            ) from exc

        if unsafe_decimal_result:
            raise UnitConversionError(
                "Unit conversion overflowed, underflowed, or was clamped."
            )

        if converted_value == 0:
            converted_value = abs(converted_value)

        return (
            converted_value,
            kind,
            source_definition,
            target_definition,
        )

    def convert_value(
        self,
        value: int | float | Decimal,
        from_unit: str,
        to_unit: str,
        *,
        quantity_kind: QuantityKind | str,
    ) -> float:
        """Convert one finite value using an explicit quantity kind."""

        decimal_value = _decimal_from_number(
            value,
            field_name="value",
        )
        converted_value, _, _, _ = self._convert_decimal(
            decimal_value,
            from_unit=from_unit,
            to_unit=to_unit,
            quantity_kind=quantity_kind,
        )

        return _float_from_decimal(
            converted_value,
            field_name="converted value",
        )

    def validate_quantity(
        self,
        quantity: EngineeringQuantity,
    ) -> EngineeringQuantity:
        """Revalidate and dimension-check an engineering quantity."""

        return self._validate_quantity(
            quantity,
            allow_reference_conditions=False,
        )

    def _validate_quantity(
        self,
        quantity: EngineeringQuantity,
        *,
        allow_reference_conditions: bool,
    ) -> EngineeringQuantity:
        """Internal quantity validation with an explicit reference guard."""

        if not isinstance(quantity, EngineeringQuantity):
            raise UnitConversionError(
                "quantity must be an EngineeringQuantity."
            )

        try:
            validated_quantity = EngineeringQuantity.model_validate(
                quantity.model_dump(
                    mode="python",
                    round_trip=True,
                )
            )
        except Exception as exc:
            raise UnitConversionError(
                "quantity failed EngineeringQuantity validation."
            ) from exc

        decimal_value = _decimal_from_number(
            validated_quantity.value,
            field_name="quantity value",
        )
        self._convert_decimal(
            decimal_value,
            from_unit=validated_quantity.unit,
            to_unit=validated_quantity.unit,
            quantity_kind=validated_quantity.quantity_kind,
            allow_reference_conditions=allow_reference_conditions,
        )

        return validated_quantity

    def convert_quantity(
        self,
        quantity: EngineeringQuantity,
        to_unit: str,
    ) -> EngineeringQuantity:
        """Convert a quantity without changing its kind or rounding its value."""

        return self._convert_quantity(
            quantity,
            to_unit,
            allow_reference_conditions=False,
        )

    def _convert_quantity(
        self,
        quantity: EngineeringQuantity,
        to_unit: str,
        *,
        allow_reference_conditions: bool,
    ) -> EngineeringQuantity:
        """Internal quantity conversion with an explicit reference guard.

        Significant figures are unit-invariant and are retained. Decimal
        places describe the displayed numerical scale, so they are retained
        only when the canonical source and target symbols are the same.
        """

        validated_quantity = self._validate_quantity(
            quantity,
            allow_reference_conditions=allow_reference_conditions,
        )
        decimal_value = _decimal_from_number(
            validated_quantity.value,
            field_name="quantity value",
        )
        (
            converted_value,
            kind,
            source_definition,
            target_definition,
        ) = self._convert_decimal(
            decimal_value,
            from_unit=validated_quantity.unit,
            to_unit=to_unit,
            quantity_kind=validated_quantity.quantity_kind,
            allow_reference_conditions=allow_reference_conditions,
        )
        converted_float = _float_from_decimal(
            converted_value,
            field_name="converted value",
        )

        converted_uncertainty: float | None = None

        if validated_quantity.uncertainty is not None:
            uncertainty_value = _decimal_from_number(
                validated_quantity.uncertainty,
                field_name="quantity uncertainty",
            )

            try:
                with localcontext(_CONVERSION_CONTEXT) as context:
                    context.clear_flags()
                    target_uncertainty = (
                        uncertainty_value
                        * source_definition.scale_to_canonical
                        / target_definition.scale_to_canonical
                    )
                    unsafe_uncertainty = any(
                        context.flags[signal]
                        for signal in (Clamped, Overflow, Underflow)
                    )
            except DecimalException as exc:
                raise UnitConversionError(
                    "Uncertainty conversion exceeded the supported "
                    "Decimal range."
                ) from exc

            if unsafe_uncertainty:
                raise UnitConversionError(
                    "Uncertainty conversion overflowed, underflowed, "
                    "or was clamped."
                )

            converted_uncertainty = _float_from_decimal(
                abs(target_uncertainty),
                field_name="converted uncertainty",
            )

        return EngineeringQuantity(
            quantity_kind=kind.value,
            value=converted_float,
            unit=target_definition.symbol,
            uncertainty=converted_uncertainty,
            uncertainty_basis=validated_quantity.uncertainty_basis,
            significant_figures=validated_quantity.significant_figures,
            decimal_places=(
                validated_quantity.decimal_places
                if source_definition.symbol == target_definition.symbol
                else None
            ),
        )

    def canonicalize_quantity(
        self,
        quantity: EngineeringQuantity,
    ) -> EngineeringQuantity:
        """Return a validated quantity in its canonical unit.

        Zero absolute pressure is representable at the unit layer.  Equations
        that divide by pressure, including reference-flow normalization, impose
        the stricter positive-pressure rule at their own public boundary.
        """

        validated_quantity = self.validate_quantity(quantity)
        canonical_unit = self.canonical_unit_for(
            validated_quantity.quantity_kind
        )
        return self.convert_quantity(validated_quantity, canonical_unit)


DEFAULT_UNIT_REGISTRY = UnitRegistry(
    _DEFAULT_UNIT_DEFINITIONS,
    quantity_dimensions=_DEFAULT_QUANTITY_DIMENSIONS,
    canonical_units=_DEFAULT_CANONICAL_UNITS,
)


_FLOW_KIND_BY_BASIS = MappingProxyType(
    {
        FlowReferenceBasis.ACTUAL: QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
        FlowReferenceBasis.STANDARD: (
            QuantityKind.STANDARD_VOLUMETRIC_FLOW
        ),
        FlowReferenceBasis.NORMAL: QuantityKind.NORMAL_VOLUMETRIC_FLOW,
        FlowReferenceBasis.CUSTOM: (
            QuantityKind.REFERENCE_VOLUMETRIC_FLOW
        ),
    }
)


class ReferenceConditions(CalculationModel):
    """Explicit pressure, temperature, and compressibility reference state."""

    reference_id: ReferenceIdentifier
    basis: FlowReferenceBasis
    absolute_pressure: EngineeringQuantity
    absolute_temperature: EngineeringQuantity
    compressibility_treatment: CompressibilityTreatment
    compressibility_factor: StrictFloat | None = Field(
        default=None,
        gt=0.0,
        le=MAX_ABSOLUTE_OPTION_NUMBER,
    )

    @model_validator(mode="after")
    def validate_reference_conditions(self) -> Self:
        """Require positive absolute state values and explicit Z treatment."""

        try:
            pressure = DEFAULT_UNIT_REGISTRY.canonicalize_quantity(
                self.absolute_pressure
            )
            temperature = DEFAULT_UNIT_REGISTRY.canonicalize_quantity(
                self.absolute_temperature
            )
        except UnitSystemError as exc:
            raise ValueError(
                "Reference pressure or temperature is invalid."
            ) from exc

        if (
            pressure.quantity_kind
            != QuantityKind.ABSOLUTE_PRESSURE.value
        ):
            raise ValueError(
                "Reference pressure must use quantity kind "
                "'pressure.absolute'."
            )

        if (
            temperature.quantity_kind
            != QuantityKind.ABSOLUTE_TEMPERATURE.value
        ):
            raise ValueError(
                "Reference temperature must use quantity kind "
                "'temperature.absolute'."
            )

        if pressure.value <= 0.0:
            raise ValueError(
                "Reference absolute pressure must be greater than zero."
            )

        if temperature.value <= 0.0:
            raise ValueError(
                "Reference absolute temperature must be greater than zero."
            )

        if (
            self.absolute_pressure.uncertainty is not None
            or self.absolute_temperature.uncertainty is not None
        ):
            raise ValueError(
                "Reference pressure and temperature uncertainty propagation "
                "is outside the Step 91 unit-conversion boundary."
            )

        if (
            self.compressibility_treatment
            is CompressibilityTreatment.IDEAL_GAS
        ):
            if self.compressibility_factor is not None:
                raise ValueError(
                    "ideal_gas treatment requires the factor to be omitted."
                )
        elif self.compressibility_factor is None:
            raise ValueError(
                "specified_factor treatment requires a positive "
                "compressibility_factor."
            )

        return self

    @property
    def effective_compressibility_factor(self) -> float:
        """Return the explicit effective compressibility factor."""

        if (
            self.compressibility_treatment
            is CompressibilityTreatment.IDEAL_GAS
        ):
            return 1.0

        if self.compressibility_factor is None:
            raise ReferenceConditionError(
                "A specified compressibility factor is missing."
            )

        return self.compressibility_factor


class ReferencedVolumetricFlow(CalculationModel):
    """A volumetric flow inseparably bound to explicit state conditions."""

    quantity: EngineeringQuantity
    reference_conditions: ReferenceConditions

    @model_validator(mode="after")
    def validate_flow_basis(self) -> Self:
        """Require the flow quantity kind to match its reference basis."""

        try:
            flow_quantity = DEFAULT_UNIT_REGISTRY._validate_quantity(
                self.quantity,
                allow_reference_conditions=True,
            )
        except UnitSystemError as exc:
            raise ValueError(
                "Referenced volumetric flow quantity is invalid."
            ) from exc

        expected_kind = _FLOW_KIND_BY_BASIS[
            self.reference_conditions.basis
        ]

        if flow_quantity.quantity_kind != expected_kind.value:
            raise ValueError(
                f"Flow basis {self.reference_conditions.basis.value!r} "
                f"requires quantity kind {expected_kind.value!r}."
            )

        return self


def convert_pressure_basis(
    quantity: EngineeringQuantity,
    target_kind: QuantityKind | str,
    *,
    atmospheric_pressure: EngineeringQuantity,
    target_unit: str | None = None,
) -> EngineeringQuantity:
    """Explicitly convert gauge pressure to or from absolute pressure.

    Differential pressure is never a pressure-basis conversion.  The caller
    must supply a finite, strictly positive atmospheric absolute pressure.
    Atmospheric-pressure uncertainty is rejected because combining independent
    uncertainties belongs to a reviewed calculation method rather than the
    unit layer.
    """

    registry = DEFAULT_UNIT_REGISTRY

    try:
        source = registry.validate_quantity(quantity)
        atmosphere = registry.validate_quantity(atmospheric_pressure)
        target = registry._coerce_quantity_kind(target_kind)
    except UnitSystemError as exc:
        raise PressureBasisError(str(exc)) from exc

    supported_kinds = {
        QuantityKind.ABSOLUTE_PRESSURE,
        QuantityKind.GAUGE_PRESSURE,
    }

    try:
        source_kind = QuantityKind(source.quantity_kind)
    except ValueError as exc:
        raise PressureBasisError(
            f"Unsupported source pressure kind: "
            f"{source.quantity_kind!r}."
        ) from exc

    if source_kind not in supported_kinds:
        raise PressureBasisError(
            "Only gauge and absolute pressure can change basis."
        )

    if target not in supported_kinds:
        raise PressureBasisError(
            "Target pressure kind must be gauge or absolute."
        )

    if source_kind is target:
        raise PressureBasisError(
            "Source and target pressure basis must differ; use ordinary "
            "unit conversion for same-basis scaling."
        )

    if atmosphere.quantity_kind != QuantityKind.ABSOLUTE_PRESSURE.value:
        raise PressureBasisError(
            "atmospheric_pressure must use quantity kind "
            "'pressure.absolute'."
        )

    if atmosphere.uncertainty is not None:
        raise PressureBasisError(
            "Atmospheric-pressure uncertainty propagation is outside the "
            "Step 91 unit-conversion boundary."
        )

    try:
        source_canonical = registry.convert_quantity(quantity, "Pa")
        atmosphere_canonical = registry.convert_quantity(
            atmospheric_pressure,
            "Pa",
        )
    except UnitSystemError as exc:
        raise PressureBasisError(str(exc)) from exc

    if atmosphere_canonical.value <= 0.0:
        raise PressureBasisError(
            "Atmospheric absolute pressure must be greater than zero."
        )

    source_value = _decimal_from_number(
        source_canonical.value,
        field_name="source pressure",
        error_type=PressureBasisError,
    )
    atmosphere_value = _decimal_from_number(
        atmosphere_canonical.value,
        field_name="atmospheric pressure",
        error_type=PressureBasisError,
    )

    with localcontext(_CONVERSION_CONTEXT):
        if source_kind is QuantityKind.GAUGE_PRESSURE:
            result_value = source_value + atmosphere_value
        else:
            result_value = source_value - atmosphere_value

    if target is QuantityKind.ABSOLUTE_PRESSURE and result_value < 0:
        raise PressureBasisError(
            "The converted absolute pressure cannot be below 0 Pa."
        )

    result_uncertainty = source_canonical.uncertainty
    canonical_result = EngineeringQuantity(
        quantity_kind=target.value,
        value=_float_from_decimal(
            result_value,
            field_name="converted pressure",
            error_type=PressureBasisError,
        ),
        unit="Pa",
        uncertainty=result_uncertainty,
        uncertainty_basis=source.uncertainty_basis,
        significant_figures=source.significant_figures,
        decimal_places=None,
    )

    output_unit = source.unit if target_unit is None else target_unit

    try:
        return registry.convert_quantity(canonical_result, output_unit)
    except UnitSystemError as exc:
        raise PressureBasisError(str(exc)) from exc


def _revalidate_reference_conditions(
    conditions: ReferenceConditions,
) -> ReferenceConditions:
    """Revalidate a reference-condition instance, including constructed data."""

    if not isinstance(conditions, ReferenceConditions):
        raise ReferenceConditionError(
            "reference conditions must be a ReferenceConditions instance."
        )

    try:
        return ReferenceConditions.model_validate(
            conditions.model_dump(
                mode="python",
                round_trip=True,
            )
        )
    except Exception as exc:
        raise ReferenceConditionError(
            "Reference conditions failed validation."
        ) from exc


def _revalidate_referenced_flow(
    flow: ReferencedVolumetricFlow,
) -> ReferencedVolumetricFlow:
    """Revalidate a referenced-flow instance, including constructed data."""

    if not isinstance(flow, ReferencedVolumetricFlow):
        raise ReferenceConditionError(
            "source flow must be a ReferencedVolumetricFlow instance."
        )

    try:
        return ReferencedVolumetricFlow.model_validate(
            flow.model_dump(
                mode="python",
                round_trip=True,
            )
        )
    except Exception as exc:
        raise ReferenceConditionError(
            "Referenced volumetric flow failed validation."
        ) from exc


def convert_referenced_volumetric_flow(
    source: ReferencedVolumetricFlow,
    target_conditions: ReferenceConditions,
    *,
    target_unit: str | None = None,
) -> ReferencedVolumetricFlow:
    """Convert volumetric flow between two explicit gas reference states.

    For fixed molar flow, the conversion is:

    ``Q2 = Q1 * (P1/P2) * (T2/T1) * (Z2/Z1)``.

    The target conditions are returned with the converted quantity so standard
    or normal semantics cannot be detached from their explicit pressure,
    temperature, and compressibility treatment.
    """

    registry = DEFAULT_UNIT_REGISTRY
    source_flow = _revalidate_referenced_flow(source)
    target_state = _revalidate_reference_conditions(target_conditions)
    source_state = source_flow.reference_conditions

    try:
        canonical_flow = registry._convert_quantity(
            source_flow.quantity,
            "m3/s",
            allow_reference_conditions=True,
        )
        source_pressure = registry.convert_quantity(
            source_state.absolute_pressure,
            "Pa",
        )
        target_pressure = registry.convert_quantity(
            target_state.absolute_pressure,
            "Pa",
        )
        source_temperature = registry.convert_quantity(
            source_state.absolute_temperature,
            "K",
        )
        target_temperature = registry.convert_quantity(
            target_state.absolute_temperature,
            "K",
        )
    except UnitSystemError as exc:
        raise ReferenceConditionError(str(exc)) from exc

    flow_value = _decimal_from_number(
        canonical_flow.value,
        field_name="source volumetric flow",
        error_type=ReferenceConditionError,
    )
    pressure_1 = _decimal_from_number(
        source_pressure.value,
        field_name="source reference pressure",
        error_type=ReferenceConditionError,
    )
    pressure_2 = _decimal_from_number(
        target_pressure.value,
        field_name="target reference pressure",
        error_type=ReferenceConditionError,
    )
    temperature_1 = _decimal_from_number(
        source_temperature.value,
        field_name="source reference temperature",
        error_type=ReferenceConditionError,
    )
    temperature_2 = _decimal_from_number(
        target_temperature.value,
        field_name="target reference temperature",
        error_type=ReferenceConditionError,
    )
    compressibility_1 = _decimal_from_number(
        source_state.effective_compressibility_factor,
        field_name="source compressibility factor",
        error_type=ReferenceConditionError,
    )
    compressibility_2 = _decimal_from_number(
        target_state.effective_compressibility_factor,
        field_name="target compressibility factor",
        error_type=ReferenceConditionError,
    )

    with localcontext(_CONVERSION_CONTEXT):
        conversion_factor = (
            (pressure_1 / pressure_2)
            * (temperature_2 / temperature_1)
            * (compressibility_2 / compressibility_1)
        )
        target_flow_value = flow_value * conversion_factor

    target_uncertainty: float | None = None

    if canonical_flow.uncertainty is not None:
        uncertainty = _decimal_from_number(
            canonical_flow.uncertainty,
            field_name="source flow uncertainty",
            error_type=ReferenceConditionError,
        )
        with localcontext(_CONVERSION_CONTEXT):
            converted_uncertainty = abs(uncertainty * conversion_factor)
        target_uncertainty = _float_from_decimal(
            converted_uncertainty,
            field_name="converted flow uncertainty",
            error_type=ReferenceConditionError,
        )

    target_kind = _FLOW_KIND_BY_BASIS[target_state.basis]
    canonical_target_quantity = EngineeringQuantity(
        quantity_kind=target_kind.value,
        value=_float_from_decimal(
            target_flow_value,
            field_name="converted volumetric flow",
            error_type=ReferenceConditionError,
        ),
        unit="m3/s",
        uncertainty=target_uncertainty,
        uncertainty_basis=canonical_flow.uncertainty_basis,
        significant_figures=canonical_flow.significant_figures,
        decimal_places=None,
    )
    output_unit = (
        source_flow.quantity.unit
        if target_unit is None
        else target_unit
    )

    try:
        converted_quantity = registry._convert_quantity(
            canonical_target_quantity,
            output_unit,
            allow_reference_conditions=True,
        )
    except UnitSystemError as exc:
        raise ReferenceConditionError(str(exc)) from exc

    return ReferencedVolumetricFlow(
        quantity=converted_quantity,
        reference_conditions=target_state,
    )


_ROUNDING_MODES = MappingProxyType(
    {
        PresentationRoundingMode.HALF_EVEN: ROUND_HALF_EVEN,
        PresentationRoundingMode.HALF_UP: ROUND_HALF_UP,
        PresentationRoundingMode.HALF_DOWN: ROUND_HALF_DOWN,
    }
)


def _coerce_rounding_mode(
    mode: PresentationRoundingMode | str,
) -> PresentationRoundingMode:
    """Return a supported presentation rounding mode."""

    try:
        return (
            mode
            if isinstance(mode, PresentationRoundingMode)
            else PresentationRoundingMode(mode)
        )
    except (TypeError, ValueError) as exc:
        raise PresentationRoundingError(
            f"Unsupported presentation rounding mode: {mode!r}."
        ) from exc


def _validate_precision(
    value: int,
    *,
    field_name: str,
    minimum: int,
) -> int:
    """Validate one strict presentation precision integer."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise PresentationRoundingError(
            f"{field_name} must be an integer."
        )

    if value < minimum or value > 15:
        raise PresentationRoundingError(
            f"{field_name} must be between {minimum} and 15."
        )

    return value


def round_decimal_places(
    value: int | float | Decimal,
    decimal_places: int,
    *,
    mode: PresentationRoundingMode | str = (
        PresentationRoundingMode.HALF_EVEN
    ),
) -> Decimal:
    """Return a Decimal rounded only for presentation decimal places."""

    decimal_value = _decimal_from_number(
        value,
        field_name="value",
        error_type=PresentationRoundingError,
    )
    places = _validate_precision(
        decimal_places,
        field_name="decimal_places",
        minimum=0,
    )
    rounding_mode = _coerce_rounding_mode(mode)
    quantum = Decimal("1").scaleb(-places)

    try:
        with localcontext(_ROUNDING_CONTEXT):
            rounded_value = decimal_value.quantize(
                quantum,
                rounding=_ROUNDING_MODES[rounding_mode],
            )
    except Exception as exc:
        raise PresentationRoundingError(
            "The value cannot be rounded to the requested decimal places."
        ) from exc

    if rounded_value.is_zero():
        return rounded_value.copy_abs()

    return rounded_value


def round_significant_figures(
    value: int | float | Decimal,
    significant_figures: int,
    *,
    mode: PresentationRoundingMode | str = (
        PresentationRoundingMode.HALF_EVEN
    ),
) -> Decimal:
    """Return a Decimal rounded only for presentation significant figures."""

    decimal_value = _decimal_from_number(
        value,
        field_name="value",
        error_type=PresentationRoundingError,
    )
    figures = _validate_precision(
        significant_figures,
        field_name="significant_figures",
        minimum=1,
    )
    rounding_mode = _coerce_rounding_mode(mode)

    if decimal_value.is_zero():
        quantum = Decimal("1").scaleb(-(figures - 1))
    else:
        quantum = Decimal("1").scaleb(
            decimal_value.copy_abs().adjusted() - figures + 1
        )

    try:
        with localcontext(_ROUNDING_CONTEXT):
            rounded_value = decimal_value.quantize(
                quantum,
                rounding=_ROUNDING_MODES[rounding_mode],
            )

            if rounded_value != 0:
                carried_quantum = Decimal("1").scaleb(
                    rounded_value.copy_abs().adjusted() - figures + 1
                )

                if carried_quantum != quantum:
                    rounded_value = rounded_value.quantize(
                        carried_quantum,
                        rounding=_ROUNDING_MODES[rounding_mode],
                    )
    except Exception as exc:
        raise PresentationRoundingError(
            "The value cannot be rounded to the requested significant "
            "figures."
        ) from exc

    if rounded_value.is_zero():
        return rounded_value.copy_abs()

    return rounded_value


def presentation_value(
    quantity: EngineeringQuantity,
    *,
    mode: PresentationRoundingMode | str = (
        PresentationRoundingMode.HALF_EVEN
    ),
    registry: UnitRegistry = DEFAULT_UNIT_REGISTRY,
) -> Decimal:
    """Return a presentation Decimal without changing the stored quantity."""

    rounding_mode = _coerce_rounding_mode(mode)

    try:
        validated_quantity = registry.validate_quantity(quantity)
    except UnitSystemError as exc:
        raise PresentationRoundingError(str(exc)) from exc

    if validated_quantity.significant_figures is not None:
        return round_significant_figures(
            validated_quantity.value,
            validated_quantity.significant_figures,
            mode=rounding_mode,
        )

    if validated_quantity.decimal_places is not None:
        return round_decimal_places(
            validated_quantity.value,
            validated_quantity.decimal_places,
            mode=rounding_mode,
        )

    decimal_value = _decimal_from_number(
        validated_quantity.value,
        field_name="quantity value",
        error_type=PresentationRoundingError,
    )

    if decimal_value.is_zero():
        return decimal_value.copy_abs()

    return decimal_value


def format_quantity_value(
    quantity: EngineeringQuantity,
    *,
    mode: PresentationRoundingMode | str = (
        PresentationRoundingMode.HALF_EVEN
    ),
    registry: UnitRegistry = DEFAULT_UNIT_REGISTRY,
) -> str:
    """Render a locale-independent value while retaining trailing zeros."""

    value = presentation_value(
        quantity,
        mode=mode,
        registry=registry,
    )

    if (
        quantity.significant_figures is not None
        or quantity.decimal_places is not None
    ):
        return format(value, "f")

    return str(value)


__all__ = [
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
]
