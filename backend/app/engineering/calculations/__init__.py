"""Engineer4Me Phase 7 engineering-calculation foundation and general pack.

Steps 90 through 92 provide immutable shared calculation contracts, the
deterministic unit subsystem, versioned method metadata, an exact allow-listed
registry, fail-closed validation and safety boundaries, bounded iteration, and
deterministic result fingerprinting.

Step 94 adds seventeen reviewed general methods.  Step 95 adds nine reviewed
pressure and level methods and composes both immutable catalogues into the
production engine.  The Step 92 default registry and engine remain empty
foundation fixtures. Uploaded, extracted, or AI-generated formula text remains
inert and cannot be resolved as code.

Pressure basis and volumetric-flow reference conditions remain explicit.
Voice functionality is outside Phase 7 and remains scheduled for Phase 10.
"""

from __future__ import annotations

from app.engineering.calculations.engine import ATTEMPT_FINGERPRINT_SCHEMA
from app.engineering.calculations.engine import CalculationEngine
from app.engineering.calculations.engine import CalculationEngineError
from app.engineering.calculations.engine import CalculationEvidenceError
from app.engineering.calculations.engine import (
    CalculationExecutionContractError,
)
from app.engineering.calculations.engine import DEFAULT_CALCULATION_ENGINE
from app.engineering.calculations.engine import (
    ENGINE_COMPATIBILITY_FINDING_ID,
)
from app.engineering.calculations.engine import ENGINE_EXECUTION_FINDING_ID
from app.engineering.calculations.engine import ENGINE_LIFECYCLE_FINDING_ID
from app.engineering.calculations.engine import ENGINE_NONCONVERGENCE_FINDING_ID
from app.engineering.calculations.engine import (
    ENGINE_PRE_EXECUTION_RESULT_FINDING_ID,
)
from app.engineering.calculations.engine import ENGINE_RESULT_FINDING_ID
from app.engineering.calculations.engine import ENGINE_VERSION
from app.engineering.calculations.engine import FINGERPRINT_SCHEMA
from app.engineering.calculations.engine import IterationControlError
from app.engineering.calculations.engine import IterationController
from app.engineering.calculations.engine import IterationLimitExceededError
from app.engineering.calculations.engine import IterationStateError
from app.engineering.calculations.engine import NonFiniteIterationError
from app.engineering.calculations.engine import (
    build_attempt_fingerprint_payload,
)
from app.engineering.calculations.engine import build_fingerprint_payload
from app.engineering.calculations.engine import canonical_fingerprint_bytes
from app.engineering.calculations.engine import fingerprint_payload
from app.engineering.calculations.method_models import ApplicabilityRule
from app.engineering.calculations.method_models import (
    CalculationMethodDefinition,
)
from app.engineering.calculations.method_models import EngineCompatibility
from app.engineering.calculations.method_models import FormulaMetadata
from app.engineering.calculations.method_models import InputNormalizationMode
from app.engineering.calculations.method_models import InputPresence
from app.engineering.calculations.method_models import InputValueType
from app.engineering.calculations.method_models import IterationLimits
from app.engineering.calculations.method_models import IterationOutcome
from app.engineering.calculations.method_models import (
    IterationTerminationReason,
)
from app.engineering.calculations.method_models import MAX_ENGINE_ITERATIONS
from app.engineering.calculations.method_models import MethodExecutionContext
from app.engineering.calculations.method_models import MethodExecutionOutcome
from app.engineering.calculations.method_models import (
    MethodInputSpecification,
)
from app.engineering.calculations.method_models import (
    MethodOptionSpecification,
)
from app.engineering.calculations.method_models import MethodOptionValueType
from app.engineering.calculations.method_models import MethodReviewRecord
from app.engineering.calculations.method_models import MethodReviewType
from app.engineering.calculations.method_models import (
    NumericApplicabilityRange,
)
from app.engineering.calculations.method_models import SafetyRequirement
from app.engineering.calculations.method_models import TrustedExecutionEvidence
from app.engineering.calculations.models import CalculationAssumption
from app.engineering.calculations.models import CalculationFinding
from app.engineering.calculations.models import CalculationInput
from app.engineering.calculations.models import CalculationModel
from app.engineering.calculations.models import CalculationOption
from app.engineering.calculations.models import CalculationOutput
from app.engineering.calculations.models import CalculationReference
from app.engineering.calculations.models import CalculationRequest
from app.engineering.calculations.models import CalculationResult
from app.engineering.calculations.models import CalculationStatus
from app.engineering.calculations.models import CalculationTraceStep
from app.engineering.calculations.models import CalculationTraceValue
from app.engineering.calculations.models import EngineeringQuantity
from app.engineering.calculations.models import FindingCategory
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.models import InputOrigin
from app.engineering.calculations.models import MethodLifecycleStatus
from app.engineering.calculations.models import MissingCalculationInput
from app.engineering.calculations.models import ReferenceType
from app.engineering.calculations.models import TraceStepKind
from app.engineering.calculations.models import TraceStepStatus
from app.engineering.calculations.models import VerificationRequirement
from app.engineering.calculations.registry import ApplicabilityEvaluator
from app.engineering.calculations.registry import CalculationMethodRegistry
from app.engineering.calculations.registry import DEFAULT_METHOD_REGISTRY
from app.engineering.calculations.registry import (
    DuplicateMethodRegistrationError,
)
from app.engineering.calculations.registry import InvalidMethodLookupError
from app.engineering.calculations.registry import (
    InvalidMethodRegistrationError,
)
from app.engineering.calculations.registry import MAX_REGISTERED_METHODS
from app.engineering.calculations.registry import (
    MethodCalculationTypeError,
)
from app.engineering.calculations.registry import (
    MethodEngineCompatibilityError,
)
from app.engineering.calculations.registry import (
    MethodExecutionNotAllowedError,
)
from app.engineering.calculations.registry import MethodImplementation
from app.engineering.calculations.registry import MethodRegistration
from app.engineering.calculations.registry import MethodRegistryError
from app.engineering.calculations.registry import MethodSpecificNormalizer
from app.engineering.calculations.registry import UnknownMethodError
from app.engineering.calculations.registry import UnknownMethodVersionError
from app.engineering.calculations.safety import CalculationSafetyEngine
from app.engineering.calculations.safety import DEFAULT_SAFETY_ENGINE
from app.engineering.calculations.safety import MAX_SAFETY_TRIGGERS
from app.engineering.calculations.safety import MethodSafetyExtension
from app.engineering.calculations.safety import (
    SAFETY_EVALUATION_FAILED_FINDING_ID,
)
from app.engineering.calculations.safety import (
    SAFETY_EVALUATION_FAILED_VERIFICATION_ID,
)
from app.engineering.calculations.safety import SafetyEvaluationContext
from app.engineering.calculations.safety import SafetyEvaluationError
from app.engineering.calculations.safety import SafetyEvaluator
from app.engineering.calculations.safety import SafetyReport
from app.engineering.calculations.safety import SafetyTrigger
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
from app.engineering.calculations.units import UnitSystemError
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
from app.engineering.calculations.validation import (
    CalculationValidationEngine,
)
from app.engineering.calculations.validation import (
    CalculationValidationError,
)
from app.engineering.calculations.validation import (
    CalculationValidationReport,
)
from app.engineering.calculations.validation import (
    DEFAULT_CALCULATION_VALIDATION_ENGINE,
)
from app.engineering.calculations.validation import DEFAULT_VALIDATION_ENGINE
from app.engineering.calculations.validation import (
    InvalidValidationContractError,
)
from app.engineering.calculations.general import (
    GENERAL_CALCULATION_ENGINE,
)
from app.engineering.calculations.general import (
    GENERAL_CALCULATION_TYPE_PREFIX,
)
from app.engineering.calculations.general import GENERAL_CALCULATORS_VERSION
from app.engineering.calculations.general import GENERAL_METHOD_IDS
from app.engineering.calculations.general import GENERAL_METHOD_REGISTRATIONS
from app.engineering.calculations.general import GENERAL_METHOD_REGISTRY
from app.engineering.calculations.general import GENERAL_METHOD_VERSION
from app.engineering.calculations.general import GeneralCalculationDomainError
from app.engineering.calculations.general import GeneralCalculationError
from app.engineering.calculations.general import GeneralCalculationInputError
from app.engineering.calculations.general import LoopVoltageBudgetResult
from app.engineering.calculations.general import PipeFlowResult
from app.engineering.calculations.general import TransmitterRangeResult
from app.engineering.calculations.general import actual_volume_from_mass_flow
from app.engineering.calculations.general import assess_dp_transmitter_range
from app.engineering.calculations.general import (
    combine_independent_standard_uncertainties,
)
from app.engineering.calculations.general import convert_pressure
from app.engineering.calculations.general import (
    convert_referenced_gas_volume,
)
from app.engineering.calculations.general import current_from_linear_fraction
from app.engineering.calculations.general import (
    current_from_square_root_flow_fraction,
)
from app.engineering.calculations.general import dc_loop_voltage_budget
from app.engineering.calculations.general import (
    density_from_specific_gravity,
)
from app.engineering.calculations.general import (
    dynamic_viscosity_from_kinematic,
)
from app.engineering.calculations.general import (
    flow_fraction_from_square_root_signal,
)
from app.engineering.calculations.general import hydrostatic_pressure
from app.engineering.calculations.general import (
    kinematic_viscosity_from_dynamic,
)
from app.engineering.calculations.general import linear_fraction_from_current
from app.engineering.calculations.general import mass_flow_from_actual_volume
from app.engineering.calculations.general import (
    pipe_area_velocity_reynolds,
)
from app.engineering.calculations.general import pressure_head
from app.engineering.calculations.general import (
    propagate_independent_uncertainty,
)
from app.engineering.calculations.general import (
    specific_gravity_from_density,
)
from app.engineering.calculations.general import (
    square_root_flow_fraction_from_current,
)
from app.engineering.calculations.general import (
    square_root_signal_fraction_from_flow,
)
from app.engineering.calculations.general import transmitter_linear_fraction
from app.engineering.calculations.general import (
    transmitter_value_from_fraction,
)
from app.engineering.calculations.level import ENGINEERING_CALCULATION_ENGINE
from app.engineering.calculations.level import ENGINEERING_METHOD_IDS
from app.engineering.calculations.level import (
    ENGINEERING_METHOD_REGISTRATIONS,
)
from app.engineering.calculations.level import ENGINEERING_METHOD_REGISTRY
from app.engineering.calculations.level import LEVEL_CALCULATION_ENGINE
from app.engineering.calculations.level import (
    LEVEL_CALCULATION_TYPE_PREFIX,
)
from app.engineering.calculations.level import LEVEL_CALCULATORS_VERSION
from app.engineering.calculations.level import LEVEL_METHOD_IDS
from app.engineering.calculations.level import LEVEL_METHOD_REGISTRATIONS
from app.engineering.calculations.level import LEVEL_METHOD_REGISTRY
from app.engineering.calculations.level import LEVEL_METHOD_VERSION
from app.engineering.calculations.level import LevelCalculationDomainError
from app.engineering.calculations.level import LevelCalculationError
from app.engineering.calculations.level import LevelCalculationInputError
from app.engineering.calculations.level import LevelRangeResult
from app.engineering.calculations.level import LevelTransmitterRangeResult
from app.engineering.calculations.level import PressureLevelRangeResult
from app.engineering.calculations.level import PressureLimitScreenResult
from app.engineering.calculations.level import TankVolumeResult
from app.engineering.calculations.level import dry_leg_dp_range
from app.engineering.calculations.level import (
    horizontal_cylindrical_tank_volume,
)
from app.engineering.calculations.level import interface_dp_range
from app.engineering.calculations.level import liquid_column_pressure
from app.engineering.calculations.level import liquid_head_from_pressure
from app.engineering.calculations.level import open_vessel_dp_range
from app.engineering.calculations.level import remote_seal_dp_range
from app.engineering.calculations.level import (
    screen_level_transmitter_range,
)
from app.engineering.calculations.level import screen_pressure_limits
from app.engineering.calculations.level import (
    vertical_cylindrical_tank_volume,
)
from app.engineering.calculations.level import wet_leg_dp_range


PHASE_NUMBER = 7
PACKAGE_NAME = "engineering_calculations"
FOUNDATION_VERSION = "0.6.0"
EXECUTABLE_METHODS_ENABLED = True


__all__ = [
    "ATTEMPT_FINGERPRINT_SCHEMA",
    "ApplicabilityEvaluator",
    "ApplicabilityRule",
    "CalculationAssumption",
    "CalculationEngine",
    "CalculationEngineError",
    "CalculationEvidenceError",
    "CalculationExecutionContractError",
    "CalculationFinding",
    "CalculationInput",
    "CalculationMethodDefinition",
    "CalculationMethodRegistry",
    "CalculationModel",
    "CalculationOption",
    "CalculationOutput",
    "CalculationReference",
    "CalculationRequest",
    "CalculationResult",
    "CalculationSafetyEngine",
    "CalculationStatus",
    "CalculationTraceStep",
    "CalculationTraceValue",
    "CalculationValidationEngine",
    "CalculationValidationError",
    "CalculationValidationReport",
    "CompressibilityTreatment",
    "DEFAULT_CALCULATION_ENGINE",
    "DEFAULT_CALCULATION_VALIDATION_ENGINE",
    "DEFAULT_METHOD_REGISTRY",
    "DEFAULT_SAFETY_ENGINE",
    "DEFAULT_UNIT_REGISTRY",
    "DEFAULT_VALIDATION_ENGINE",
    "DuplicateMethodRegistrationError",
    "ENGINE_COMPATIBILITY_FINDING_ID",
    "ENGINE_EXECUTION_FINDING_ID",
    "ENGINE_LIFECYCLE_FINDING_ID",
    "ENGINE_NONCONVERGENCE_FINDING_ID",
    "ENGINE_PRE_EXECUTION_RESULT_FINDING_ID",
    "ENGINE_RESULT_FINDING_ID",
    "ENGINE_VERSION",
    "ENGINEERING_CALCULATION_ENGINE",
    "ENGINEERING_METHOD_IDS",
    "ENGINEERING_METHOD_REGISTRATIONS",
    "ENGINEERING_METHOD_REGISTRY",
    "EXECUTABLE_METHODS_ENABLED",
    "EngineCompatibility",
    "EngineeringQuantity",
    "FINGERPRINT_SCHEMA",
    "FlowReferenceBasis",
    "FOUNDATION_VERSION",
    "GENERAL_CALCULATION_ENGINE",
    "GENERAL_CALCULATION_TYPE_PREFIX",
    "GENERAL_CALCULATORS_VERSION",
    "GENERAL_METHOD_IDS",
    "GENERAL_METHOD_REGISTRATIONS",
    "GENERAL_METHOD_REGISTRY",
    "GENERAL_METHOD_VERSION",
    "GeneralCalculationDomainError",
    "GeneralCalculationError",
    "GeneralCalculationInputError",
    "FindingCategory",
    "FindingSeverity",
    "FormulaMetadata",
    "IncompatibleUnitError",
    "InputNormalizationMode",
    "InputOrigin",
    "InputPresence",
    "InputValueType",
    "InvalidMethodLookupError",
    "InvalidMethodRegistrationError",
    "InvalidValidationContractError",
    "IterationControlError",
    "IterationController",
    "IterationLimitExceededError",
    "IterationLimits",
    "IterationOutcome",
    "IterationStateError",
    "IterationTerminationReason",
    "MAX_ENGINE_ITERATIONS",
    "MAX_REGISTERED_METHODS",
    "MAX_SAFETY_TRIGGERS",
    "MethodCalculationTypeError",
    "MethodEngineCompatibilityError",
    "MethodExecutionContext",
    "MethodExecutionNotAllowedError",
    "MethodExecutionOutcome",
    "MethodImplementation",
    "MethodInputSpecification",
    "MethodLifecycleStatus",
    "MethodOptionSpecification",
    "MethodOptionValueType",
    "MethodRegistration",
    "MethodRegistryError",
    "MethodReviewRecord",
    "MethodReviewType",
    "MethodSafetyExtension",
    "MethodSpecificNormalizer",
    "MissingCalculationInput",
    "NonFiniteIterationError",
    "NumericApplicabilityRange",
    "LoopVoltageBudgetResult",
    "LEVEL_CALCULATION_ENGINE",
    "LEVEL_CALCULATION_TYPE_PREFIX",
    "LEVEL_CALCULATORS_VERSION",
    "LEVEL_METHOD_IDS",
    "LEVEL_METHOD_REGISTRATIONS",
    "LEVEL_METHOD_REGISTRY",
    "LEVEL_METHOD_VERSION",
    "LevelCalculationDomainError",
    "LevelCalculationError",
    "LevelCalculationInputError",
    "LevelRangeResult",
    "LevelTransmitterRangeResult",
    "PACKAGE_NAME",
    "PHASE_NUMBER",
    "PhysicalDimension",
    "PresentationRoundingError",
    "PresentationRoundingMode",
    "PressureBasisError",
    "PressureLevelRangeResult",
    "PressureLimitScreenResult",
    "PipeFlowResult",
    "QuantityKind",
    "ReferenceConditionError",
    "ReferenceConditions",
    "ReferenceType",
    "ReferencedVolumetricFlow",
    "SAFETY_EVALUATION_FAILED_FINDING_ID",
    "SAFETY_EVALUATION_FAILED_VERIFICATION_ID",
    "SafetyEvaluationContext",
    "SafetyEvaluationError",
    "SafetyEvaluator",
    "SafetyReport",
    "SafetyRequirement",
    "SafetyTrigger",
    "TraceStepKind",
    "TraceStepStatus",
    "TransmitterRangeResult",
    "TankVolumeResult",
    "TrustedExecutionEvidence",
    "UnitConversionError",
    "UnitDefinition",
    "UnitRegistry",
    "UnitRegistryError",
    "UnitSystemError",
    "UnknownQuantityKindError",
    "UnknownUnitError",
    "UnknownMethodError",
    "UnknownMethodVersionError",
    "VerificationRequirement",
    "actual_volume_from_mass_flow",
    "assess_dp_transmitter_range",
    "build_attempt_fingerprint_payload",
    "build_fingerprint_payload",
    "canonical_fingerprint_bytes",
    "combine_independent_standard_uncertainties",
    "convert_pressure",
    "convert_pressure_basis",
    "convert_referenced_gas_volume",
    "convert_referenced_volumetric_flow",
    "current_from_linear_fraction",
    "current_from_square_root_flow_fraction",
    "dc_loop_voltage_budget",
    "density_from_specific_gravity",
    "dynamic_viscosity_from_kinematic",
    "dry_leg_dp_range",
    "fingerprint_payload",
    "flow_fraction_from_square_root_signal",
    "format_quantity_value",
    "hydrostatic_pressure",
    "horizontal_cylindrical_tank_volume",
    "interface_dp_range",
    "kinematic_viscosity_from_dynamic",
    "linear_fraction_from_current",
    "liquid_column_pressure",
    "liquid_head_from_pressure",
    "mass_flow_from_actual_volume",
    "pipe_area_velocity_reynolds",
    "open_vessel_dp_range",
    "presentation_value",
    "pressure_head",
    "propagate_independent_uncertainty",
    "round_decimal_places",
    "round_significant_figures",
    "remote_seal_dp_range",
    "screen_level_transmitter_range",
    "screen_pressure_limits",
    "specific_gravity_from_density",
    "square_root_flow_fraction_from_current",
    "square_root_signal_fraction_from_flow",
    "transmitter_linear_fraction",
    "transmitter_value_from_fraction",
    "vertical_cylindrical_tank_volume",
    "wet_leg_dp_range",
]
