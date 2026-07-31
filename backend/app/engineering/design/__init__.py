"""Engineer4Me Phase 7 engineering-design package.

Step 89 establishes the import-safe package boundary. Step 96 adds the strict,
vendor-neutral level-application domain used by the reviewed assessment
wizard. Design cases, analyzer application assessment, controlled datasheets,
persistence, and export services are introduced by later reviewed Phase 7
steps.

Voice input, speech recognition, voice search, and text-to-speech are not part
of this package. Those capabilities remain scheduled for Phase 10.
"""

from __future__ import annotations

from app.engineering.design.level_application_models import ApprovalText
from app.engineering.design.level_application_models import (
    LEVEL_APPLICATION_MODEL_VERSION,
)
from app.engineering.design.level_application_models import (
    SUPPORTED_LEVEL_CALCULATION_METHOD_IDS,
)
from app.engineering.design.level_application_models import (
    SUPPORTED_LEVEL_METHOD_IDS,
)
from app.engineering.design.level_application_models import (
    LevelApplicationAssessment,
)
from app.engineering.design.level_application_models import (
    LevelApplicationRequest,
)
from app.engineering.design.level_application_models import (
    LevelConditionSeverity,
)
from app.engineering.design.level_application_models import LevelConfidenceBand
from app.engineering.design.level_application_models import (
    LevelContactPreference,
)
from app.engineering.design.level_application_models import LevelDpArrangement
from app.engineering.design.level_application_models import (
    LevelEnvironmentCondition,
)
from app.engineering.design.level_application_models import LevelIndustrySector
from app.engineering.design.level_application_models import (
    LevelInstallationContext,
)
from app.engineering.design.level_application_models import (
    LevelMaintenanceAccess,
)
from app.engineering.design.level_application_models import LevelMountingPosition
from app.engineering.design.level_application_models import (
    LevelMeasurementObjective,
)
from app.engineering.design.level_application_models import (
    LevelMeasurementRequirements,
)
from app.engineering.design.level_application_models import (
    LevelMissingInformation,
)
from app.engineering.design.level_application_models import LevelProcessContext
from app.engineering.design.level_application_models import LevelProcessPhase
from app.engineering.design.level_application_models import (
    LevelProtectionFunction,
)
from app.engineering.design.level_application_models import LevelRuleStatus
from app.engineering.design.level_application_models import LevelSafetyContext
from app.engineering.design.level_application_models import (
    LevelScenarioDisposition,
)
from app.engineering.design.level_application_models import (
    LevelScenarioRuleResult,
)
from app.engineering.design.level_application_models import LevelTechnology
from app.engineering.design.level_application_models import (
    LevelTechnologyScenario,
)
from app.engineering.design.level_application_models import LevelTriState
from app.engineering.design.level_application_models import (
    LevelVerificationPriority,
)
from app.engineering.design.level_application_models import (
    LevelVerificationStep,
)
from app.engineering.design.level_application_models import LevelVaporBehavior
from app.engineering.design.level_application_models import (
    LevelVesselConfiguration,
)
from app.engineering.design.level_application_models import LevelVesselContext
from app.engineering.design.level_application_models import LevelVesselGeometry
from app.engineering.design.level_application_models import LevelWizardFinding
from app.engineering.design.level_application_models import (
    canonical_quantity_value,
)
from app.engineering.design.level_application_wizard import (
    DEFAULT_LEVEL_APPLICATION_WIZARD,
)
from app.engineering.design.level_application_wizard import (
    LEVEL_APPLICATION_RULESET_VERSION,
)
from app.engineering.design.level_application_wizard import (
    LEVEL_APPLICATION_WIZARD_VERSION,
)
from app.engineering.design.level_application_wizard import (
    LevelApplicationWizard,
)
from app.engineering.design.level_application_wizard import (
    LevelApplicationWizardError,
)
from app.engineering.design.level_application_wizard import (
    assess_level_application,
)


PHASE_NUMBER = 7
PACKAGE_NAME = "engineering_design"
FOUNDATION_VERSION = "0.2.0"
VOICE_FUNCTIONALITY_ENABLED = False


__all__ = [
    "ApprovalText",
    "DEFAULT_LEVEL_APPLICATION_WIZARD",
    "FOUNDATION_VERSION",
    "LEVEL_APPLICATION_MODEL_VERSION",
    "LEVEL_APPLICATION_RULESET_VERSION",
    "LEVEL_APPLICATION_WIZARD_VERSION",
    "LevelApplicationAssessment",
    "LevelApplicationRequest",
    "LevelApplicationWizard",
    "LevelApplicationWizardError",
    "LevelConditionSeverity",
    "LevelConfidenceBand",
    "LevelContactPreference",
    "LevelDpArrangement",
    "LevelEnvironmentCondition",
    "LevelIndustrySector",
    "LevelInstallationContext",
    "LevelMaintenanceAccess",
    "LevelMountingPosition",
    "LevelMeasurementObjective",
    "LevelMeasurementRequirements",
    "LevelMissingInformation",
    "LevelProcessContext",
    "LevelProcessPhase",
    "LevelProtectionFunction",
    "LevelRuleStatus",
    "LevelSafetyContext",
    "LevelScenarioDisposition",
    "LevelScenarioRuleResult",
    "LevelTechnology",
    "LevelTechnologyScenario",
    "LevelTriState",
    "LevelVerificationPriority",
    "LevelVerificationStep",
    "LevelVaporBehavior",
    "LevelVesselConfiguration",
    "LevelVesselContext",
    "LevelVesselGeometry",
    "LevelWizardFinding",
    "PACKAGE_NAME",
    "PHASE_NUMBER",
    "SUPPORTED_LEVEL_CALCULATION_METHOD_IDS",
    "SUPPORTED_LEVEL_METHOD_IDS",
    "VOICE_FUNCTIONALITY_ENABLED",
    "assess_level_application",
    "canonical_quantity_value",
]
