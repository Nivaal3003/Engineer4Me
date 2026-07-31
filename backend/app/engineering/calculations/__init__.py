"""Engineer4Me Phase 7 engineering-calculation foundation.

Steps 90 through 92 provide immutable shared calculation contracts, the
deterministic unit subsystem, versioned method metadata, an exact allow-listed
registry, fail-closed validation and safety boundaries, bounded iteration, and
deterministic result fingerprinting.

No production calculation implementation is registered at this foundation
step. Uploaded, extracted, or AI-generated formula text is inert and cannot be
resolved as code. A future executable method must be directly implemented,
exactly registered, versioned, independently reviewed, and reference-tested.

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


PHASE_NUMBER = 7
PACKAGE_NAME = "engineering_calculations"
FOUNDATION_VERSION = "0.4.0"
EXECUTABLE_METHODS_ENABLED = False


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
    "EXECUTABLE_METHODS_ENABLED",
    "EngineCompatibility",
    "EngineeringQuantity",
    "FINGERPRINT_SCHEMA",
    "FlowReferenceBasis",
    "FOUNDATION_VERSION",
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
    "PACKAGE_NAME",
    "PHASE_NUMBER",
    "PhysicalDimension",
    "PresentationRoundingError",
    "PresentationRoundingMode",
    "PressureBasisError",
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
    "build_attempt_fingerprint_payload",
    "build_fingerprint_payload",
    "canonical_fingerprint_bytes",
    "convert_pressure_basis",
    "convert_referenced_volumetric_flow",
    "fingerprint_payload",
    "format_quantity_value",
    "presentation_value",
    "round_decimal_places",
    "round_significant_figures",
]
