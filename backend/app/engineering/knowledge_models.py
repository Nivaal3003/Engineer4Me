"""Core data models for the Engineer4Me Engineering Knowledge Engine.

The models in this module define the vendor-neutral structure used to store,
review, retrieve, explain, and apply engineering knowledge.

The module intentionally contains no database or external-service logic. Its
models can therefore be reused by the knowledge repository, rules engine,
safety engine, standards engine, troubleshooting engine, calculation engine,
industry intelligence engine, workflow engine, and future knowledge graph.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EngineeringDiscipline(StrEnum):
    """Engineering disciplines supported by the knowledge engine."""

    INSTRUMENTATION = "instrumentation"
    AUTOMATION_CONTROL = "automation_control"
    PROCESS = "process"
    ELECTRICAL = "electrical"
    MECHANICAL = "mechanical"
    PIPING = "piping"
    ROTATING_EQUIPMENT = "rotating_equipment"
    STATIC_EQUIPMENT = "static_equipment"
    RELIABILITY = "reliability"
    SAFETY = "safety"
    CIVIL_STRUCTURAL = "civil_structural"
    ENVIRONMENTAL = "environmental"
    INDUSTRIAL_IT = "industrial_it"
    MULTIDISCIPLINARY = "multidisciplinary"


class KnowledgeCategory(StrEnum):
    """Primary categories used to classify engineering knowledge."""

    OPERATING_PRINCIPLE = "operating_principle"
    APPLICATION = "application"
    SELECTION = "selection"
    SIZING = "sizing"
    INSTALLATION = "installation"
    CONFIGURATION = "configuration"
    CALIBRATION = "calibration"
    COMMISSIONING = "commissioning"
    OPERATION = "operation"
    INSPECTION = "inspection"
    PREVENTIVE_MAINTENANCE = "preventive_maintenance"
    PREDICTIVE_MAINTENANCE = "predictive_maintenance"
    TROUBLESHOOTING = "troubleshooting"
    FAULT_CODE = "fault_code"
    FAILURE_MODE = "failure_mode"
    ROOT_CAUSE = "root_cause"
    CORRECTIVE_ACTION = "corrective_action"
    SAFETY = "safety"
    STANDARD = "standard"
    CALCULATION = "calculation"
    VERIFICATION = "verification"
    LIFECYCLE = "lifecycle"
    OBSOLESCENCE = "obsolescence"
    REPLACEMENT = "replacement"
    LESSON_LEARNED = "lesson_learned"
    TRAINING = "training"


class KnowledgeStatus(StrEnum):
    """Lifecycle status of an engineering knowledge record."""

    DRAFT = "draft"
    TECHNICAL_REVIEW = "technical_review"
    SAFETY_REVIEW = "safety_review"
    STANDARDS_REVIEW = "standards_review"
    APPROVED = "approved"
    PUBLISHED = "published"
    SUPERSEDED = "superseded"
    ARCHIVED = "archived"


class ReviewType(StrEnum):
    """Review and approval stages for controlled engineering knowledge."""

    TECHNICAL = "technical"
    SAFETY = "safety"
    STANDARDS = "standards"
    LEGAL_COMPLIANCE = "legal_compliance"
    FINAL_APPROVAL = "final_approval"


class ReviewDecision(StrEnum):
    """Possible outcomes of an engineering knowledge review."""

    PENDING = "pending"
    APPROVED = "approved"
    APPROVED_WITH_CONDITIONS = "approved_with_conditions"
    REJECTED = "rejected"


class EvidenceType(StrEnum):
    """Types of evidence that may support engineering guidance."""

    OEM_MANUAL = "oem_manual"
    OEM_DATASHEET = "oem_datasheet"
    OEM_BULLETIN = "oem_bulletin"
    INTERNATIONAL_STANDARD = "international_standard"
    NATIONAL_STANDARD = "national_standard"
    COMPANY_STANDARD = "company_standard"
    REGULATION = "regulation"
    ENGINEERING_TEXTBOOK = "engineering_textbook"
    PEER_REVIEWED_PAPER = "peer_reviewed_paper"
    TECHNICAL_REPORT = "technical_report"
    TEST_RESULT = "test_result"
    INSPECTION_RECORD = "inspection_record"
    MAINTENANCE_RECORD = "maintenance_record"
    FIELD_CASE_STUDY = "field_case_study"
    EXPERT_REVIEW = "expert_review"
    USER_EXPERIENCE = "user_experience"
    CALCULATION = "calculation"
    DRAWING = "drawing"
    OTHER = "other"


class EvidenceStrength(StrEnum):
    """Relative strength assigned to supporting evidence."""

    VERY_LOW = "very_low"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very_high"


class StandardApplicability(StrEnum):
    """How a standard applies to the knowledge record."""

    MANDATORY = "mandatory"
    RECOMMENDED = "recommended"
    INFORMATIVE = "informative"
    SITE_SPECIFIC = "site_specific"


class SafetySeverity(StrEnum):
    """Severity assigned to a safety requirement or hazard."""

    INFORMATION = "information"
    CAUTION = "caution"
    WARNING = "warning"
    CRITICAL = "critical"


class HazardCategory(StrEnum):
    """Industrial hazard categories recognised by Engineer4Me."""

    ELECTRICAL = "electrical"
    ARC_FLASH = "arc_flash"
    PRESSURE = "pressure"
    VACUUM = "vacuum"
    TEMPERATURE = "temperature"
    CHEMICAL = "chemical"
    TOXIC_GAS = "toxic_gas"
    FLAMMABLE_MATERIAL = "flammable_material"
    EXPLOSIVE_ATMOSPHERE = "explosive_atmosphere"
    RADIATION = "radiation"
    MECHANICAL = "mechanical"
    ROTATING_EQUIPMENT = "rotating_equipment"
    STORED_ENERGY = "stored_energy"
    CONFINED_SPACE = "confined_space"
    WORKING_AT_HEIGHT = "working_at_height"
    HOT_WORK = "hot_work"
    BIOLOGICAL = "biological"
    ENVIRONMENTAL = "environmental"
    CYBERSECURITY = "cybersecurity"
    PROCESS_SAFETY = "process_safety"
    OTHER = "other"


class IsolationType(StrEnum):
    """Isolation types that may be required before engineering work."""

    ELECTRICAL = "electrical"
    PROCESS_PRESSURE = "process_pressure"
    PROCESS_FLOW = "process_flow"
    CHEMICAL = "chemical"
    PNEUMATIC = "pneumatic"
    HYDRAULIC = "hydraulic"
    MECHANICAL = "mechanical"
    THERMAL = "thermal"
    RADIATION = "radiation"
    SOFTWARE_CONTROL = "software_control"
    NETWORK = "network"
    STORED_ENERGY = "stored_energy"


class PPECategory(StrEnum):
    """Common personal protective equipment categories."""

    SAFETY_HELMET = "safety_helmet"
    SAFETY_GLASSES = "safety_glasses"
    FACE_SHIELD = "face_shield"
    HEARING_PROTECTION = "hearing_protection"
    SAFETY_FOOTWEAR = "safety_footwear"
    GENERAL_GLOVES = "general_gloves"
    CHEMICAL_GLOVES = "chemical_gloves"
    CUT_RESISTANT_GLOVES = "cut_resistant_gloves"
    ARC_RATED_CLOTHING = "arc_rated_clothing"
    FLAME_RESISTANT_CLOTHING = "flame_resistant_clothing"
    CHEMICAL_SUIT = "chemical_suit"
    RESPIRATORY_PROTECTION = "respiratory_protection"
    FALL_PROTECTION = "fall_protection"
    GAS_DETECTOR = "gas_detector"
    DOSIMETER = "dosimeter"
    OTHER = "other"


class EnvironmentCondition(StrEnum):
    """Environmental and installation conditions affecting suitability."""

    HIGH_AMBIENT_TEMPERATURE = "high_ambient_temperature"
    LOW_AMBIENT_TEMPERATURE = "low_ambient_temperature"
    TEMPERATURE_CYCLING = "temperature_cycling"
    HIGH_HUMIDITY = "high_humidity"
    CONDENSATION = "condensation"
    DUST = "dust"
    WATER_INGRESS = "water_ingress"
    WASHDOWN = "washdown"
    FLOODING = "flooding"
    CORROSIVE_ATMOSPHERE = "corrosive_atmosphere"
    MARINE_ATMOSPHERE = "marine_atmosphere"
    HIGH_VIBRATION = "high_vibration"
    SHOCK = "shock"
    HIGH_ALTITUDE = "high_altitude"
    UV_EXPOSURE = "uv_exposure"
    ELECTROMAGNETIC_INTERFERENCE = "electromagnetic_interference"
    HAZARDOUS_AREA = "hazardous_area"
    HYGIENIC_SERVICE = "hygienic_service"
    ABRASIVE_SERVICE = "abrasive_service"
    OUTDOOR_INSTALLATION = "outdoor_installation"
    SUBMERGED_SERVICE = "submerged_service"
    RADIATION_AREA = "radiation_area"


class IndustrySector(StrEnum):
    """Initial industrial sectors supported by industry intelligence."""

    MINING = "mining"
    MINERALS_PROCESSING = "minerals_processing"
    OIL_GAS = "oil_gas"
    PETROCHEMICAL = "petrochemical"
    CHEMICAL = "chemical"
    POWER_GENERATION = "power_generation"
    WATER_WASTEWATER = "water_wastewater"
    FOOD_BEVERAGE = "food_beverage"
    PHARMACEUTICAL = "pharmaceutical"
    PULP_PAPER = "pulp_paper"
    METALS_STEEL = "metals_steel"
    CEMENT = "cement"
    MANUFACTURING = "manufacturing"
    MARINE_OFFSHORE = "marine_offshore"
    RENEWABLE_ENERGY = "renewable_energy"
    BUILDING_SERVICES = "building_services"
    OTHER = "other"


class RecommendationPriority(StrEnum):
    """Priority assigned to an engineering recommendation."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"
    IMMEDIATE_SAFETY_ACTION = "immediate_safety_action"


class RelationshipType(StrEnum):
    """Relationships between engineering knowledge objects."""

    APPLIES_TO = "applies_to"
    MEASURES = "measures"
    CONTROLS = "controls"
    INSTALLED_ON = "installed_on"
    CONNECTED_TO = "connected_to"
    USES_TECHNOLOGY = "uses_technology"
    COMPLIES_WITH = "complies_with"
    SUPPORTED_BY = "supported_by"
    CAUSES = "causes"
    CONTRIBUTES_TO = "contributes_to"
    DETECTED_BY = "detected_by"
    CORRECTED_BY = "corrected_by"
    PREVENTED_BY = "prevented_by"
    VERIFIED_BY = "verified_by"
    REQUIRES = "requires"
    REPLACES = "replaces"
    COMPATIBLE_WITH = "compatible_with"
    INCOMPATIBLE_WITH = "incompatible_with"
    SIMILAR_TO = "similar_to"
    SUPERSEDES = "supersedes"
    RELATED_TO = "related_to"


class SkillLevel(StrEnum):
    """Minimum skill level needed to apply engineering guidance."""

    AWARENESS = "awareness"
    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    SPECIALIST = "specialist"
    CERTIFIED_PERSON = "certified_person"
    PROFESSIONAL_ENGINEER = "professional_engineer"


class EngineeringBaseModel(BaseModel):
    """Shared strict configuration for engineering knowledge models."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
        use_enum_values=False,
    )


class StandardReference(EngineeringBaseModel):
    """Reference to a standard, regulation, code, or company requirement."""

    organisation: str = Field(min_length=1, max_length=150)
    standard_number: str = Field(min_length=1, max_length=150)
    title: str = Field(min_length=1, max_length=500)
    edition: str | None = Field(default=None, max_length=100)
    publication_year: int | None = Field(default=None, ge=1800, le=2200)
    clause: str | None = Field(default=None, max_length=150)
    applicability: StandardApplicability = StandardApplicability.RECOMMENDED
    jurisdiction: str | None = Field(default=None, max_length=150)
    notes: str | None = Field(default=None, max_length=2000)


class EvidenceReference(EngineeringBaseModel):
    """Traceable source supporting an engineering knowledge statement."""

    evidence_id: str = Field(min_length=3, max_length=100)
    evidence_type: EvidenceType
    title: str = Field(min_length=1, max_length=500)
    publisher_or_owner: str | None = Field(default=None, max_length=200)
    document_number: str | None = Field(default=None, max_length=150)
    revision: str | None = Field(default=None, max_length=100)
    publication_date: str | None = Field(default=None, max_length=50)
    source_location: str | None = Field(
        default=None,
        max_length=1000,
        description="URL, repository reference, document path, or source identifier.",
    )
    relevant_section: str | None = Field(default=None, max_length=500)
    summary: str | None = Field(default=None, max_length=3000)
    strength: EvidenceStrength = EvidenceStrength.MODERATE
    verified: bool = False
    verified_by: str | None = Field(default=None, max_length=200)
    verified_at: datetime | None = None

    @model_validator(mode="after")
    def validate_verification_details(self) -> "EvidenceReference":
        """Require verification metadata when evidence is marked verified."""

        if self.verified and not self.verified_by:
            raise ValueError(
                "verified_by is required when evidence is marked verified."
            )

        return self


class PPERequirement(EngineeringBaseModel):
    """PPE requirement associated with an engineering activity."""

    category: PPECategory
    description: str = Field(min_length=1, max_length=500)
    mandatory: bool = True
    standard_or_rating: str | None = Field(default=None, max_length=200)
    selection_notes: str | None = Field(default=None, max_length=1000)


class IsolationRequirement(EngineeringBaseModel):
    """Energy or process isolation required before work starts."""

    isolation_type: IsolationType
    description: str = Field(min_length=1, max_length=1000)
    mandatory: bool = True
    lockout_tagout_required: bool = True
    verification_method: str = Field(min_length=1, max_length=1000)
    authorised_role: str | None = Field(default=None, max_length=200)


class HazardControl(EngineeringBaseModel):
    """Hazard, its consequence, and required risk controls."""

    hazard_id: str = Field(min_length=3, max_length=100)
    category: HazardCategory
    title: str = Field(min_length=1, max_length=250)
    description: str = Field(min_length=1, max_length=2000)
    severity: SafetySeverity
    possible_consequences: list[str] = Field(default_factory=list)
    preventive_controls: list[str] = Field(default_factory=list)
    detection_controls: list[str] = Field(default_factory=list)
    required_actions: list[str] = Field(default_factory=list)
    stop_work_condition: str | None = Field(default=None, max_length=1000)
    emergency_response: str | None = Field(default=None, max_length=2000)
    standards: list[StandardReference] = Field(default_factory=list)


class SafetyGuidance(EngineeringBaseModel):
    """Complete safety guidance attached to an engineering record."""

    safety_summary: str = Field(min_length=1, max_length=3000)
    severity: SafetySeverity = SafetySeverity.CAUTION
    hazards: list[HazardControl] = Field(default_factory=list)
    ppe_requirements: list[PPERequirement] = Field(default_factory=list)
    isolation_requirements: list[IsolationRequirement] = Field(
        default_factory=list
    )
    permit_requirements: list[str] = Field(default_factory=list)
    required_site_risk_assessment: bool = True
    requires_authorised_person: bool = False
    blocks_work_until_resolved: bool = False
    pre_work_checks: list[str] = Field(default_factory=list)
    post_work_checks: list[str] = Field(default_factory=list)
    emergency_notes: str | None = Field(default=None, max_length=3000)


class EnvironmentalConstraint(EngineeringBaseModel):
    """Environmental condition and its engineering implications."""

    condition: EnvironmentCondition
    description: str = Field(min_length=1, max_length=1000)
    minimum_value: float | None = None
    maximum_value: float | None = None
    unit: str | None = Field(default=None, max_length=50)
    engineering_impact: str = Field(min_length=1, max_length=2000)
    required_protection: list[str] = Field(default_factory=list)
    inspection_points: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_environmental_range(self) -> "EnvironmentalConstraint":
        """Reject environmental ranges where minimum exceeds maximum."""

        if (
            self.minimum_value is not None
            and self.maximum_value is not None
            and self.minimum_value > self.maximum_value
        ):
            raise ValueError(
                "minimum_value cannot be greater than maximum_value."
            )

        return self


class IndustryApplicability(EngineeringBaseModel):
    """Industry context used to narrow equipment and failure possibilities."""

    industry: IndustrySector
    sub_industry: str | None = Field(default=None, max_length=200)
    plant_type: str | None = Field(default=None, max_length=200)
    process_area: str | None = Field(default=None, max_length=200)
    unit_operation: str | None = Field(default=None, max_length=200)
    typical_process_media: list[str] = Field(default_factory=list)
    typical_equipment: list[str] = Field(default_factory=list)
    common_failure_modes: list[str] = Field(default_factory=list)
    common_environmental_conditions: list[EnvironmentCondition] = Field(
        default_factory=list
    )
    common_preventive_measures: list[str] = Field(default_factory=list)
    common_safety_risks: list[HazardCategory] = Field(default_factory=list)
    applicable_standards: list[StandardReference] = Field(default_factory=list)
    applicability_notes: str | None = Field(default=None, max_length=3000)


class EquipmentApplicability(EngineeringBaseModel):
    """Equipment scope to which a knowledge record applies."""

    taxonomy_id: str | None = Field(default=None, max_length=100)
    equipment_category: str = Field(min_length=1, max_length=200)
    equipment_type: str | None = Field(default=None, max_length=200)
    measurement_principle: str | None = Field(default=None, max_length=200)
    manufacturer: str | None = Field(default=None, max_length=200)
    model_family: str | None = Field(default=None, max_length=200)
    models: list[str] = Field(default_factory=list)
    firmware_versions: list[str] = Field(default_factory=list)
    components: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)


class RequiredTool(EngineeringBaseModel):
    """Tool or test instrument required to perform a procedure."""

    name: str = Field(min_length=1, max_length=200)
    purpose: str = Field(min_length=1, max_length=1000)
    mandatory: bool = True
    specification: str | None = Field(default=None, max_length=500)
    calibration_required: bool = False
    inspection_before_use: bool = True
    alternatives: list[str] = Field(default_factory=list)


class CompetencyRequirement(EngineeringBaseModel):
    """Competency or authorisation required to apply guidance safely."""

    discipline: EngineeringDiscipline
    competency: str = Field(min_length=1, max_length=300)
    minimum_skill_level: SkillLevel
    certification: str | None = Field(default=None, max_length=300)
    authorisation_required: bool = False
    supervision_required: bool = False
    notes: str | None = Field(default=None, max_length=1500)


class ProcedureStep(EngineeringBaseModel):
    """One controlled step in an engineering procedure."""

    step_number: int = Field(gt=0)
    title: str = Field(min_length=1, max_length=300)
    instruction: str = Field(min_length=1, max_length=4000)
    purpose: str | None = Field(default=None, max_length=1500)
    expected_result: str | None = Field(default=None, max_length=2000)
    warning: str | None = Field(default=None, max_length=2000)
    hold_point: bool = False
    approval_role: str | None = Field(default=None, max_length=200)
    evidence_to_capture: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_hold_point(self) -> "ProcedureStep":
        """Require an approval role for formal procedure hold points."""

        if self.hold_point and not self.approval_role:
            raise ValueError(
                "approval_role is required when hold_point is true."
            )

        return self


class EngineeringProcedure(EngineeringBaseModel):
    """Installation, maintenance, diagnostic, or verification procedure."""

    procedure_id: str = Field(min_length=3, max_length=100)
    title: str = Field(min_length=1, max_length=300)
    purpose: str = Field(min_length=1, max_length=2000)
    prerequisites: list[str] = Field(default_factory=list)
    required_tools: list[RequiredTool] = Field(default_factory=list)
    required_competencies: list[CompetencyRequirement] = Field(
        default_factory=list
    )
    safety: SafetyGuidance | None = None
    steps: list[ProcedureStep] = Field(min_length=1)
    acceptance_criteria: list[str] = Field(default_factory=list)
    records_to_update: list[str] = Field(default_factory=list)
    estimated_duration_minutes: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_step_numbers(self) -> "EngineeringProcedure":
        """Require unique procedure step numbers."""

        step_numbers = [step.step_number for step in self.steps]

        if len(step_numbers) != len(set(step_numbers)):
            raise ValueError("Procedure step numbers must be unique.")

        return self


class PreventiveMaintenanceTask(EngineeringBaseModel):
    """Industry-aware preventive maintenance recommendation."""

    task_id: str = Field(min_length=3, max_length=100)
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=3000)
    failure_modes_prevented: list[str] = Field(default_factory=list)
    inspection_points: list[str] = Field(default_factory=list)
    normal_interval_days: int | None = Field(default=None, gt=0)
    severe_service_interval_days: int | None = Field(default=None, gt=0)
    condition_based_trigger: str | None = Field(default=None, max_length=1500)
    required_tools: list[RequiredTool] = Field(default_factory=list)
    safety: SafetyGuidance | None = None
    completion_evidence: list[str] = Field(default_factory=list)
    escalation_conditions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_maintenance_intervals(self) -> "PreventiveMaintenanceTask":
        """Ensure severe-service maintenance is not less frequent than normal."""

        if (
            self.normal_interval_days is not None
            and self.severe_service_interval_days is not None
            and self.severe_service_interval_days > self.normal_interval_days
        ):
            raise ValueError(
                "severe_service_interval_days cannot exceed "
                "normal_interval_days."
            )

        return self


class VerificationRequirement(EngineeringBaseModel):
    """Requirement used to verify that guidance was applied successfully."""

    verification_id: str = Field(min_length=3, max_length=100)
    description: str = Field(min_length=1, max_length=2000)
    method: str = Field(min_length=1, max_length=2000)
    expected_result: str = Field(min_length=1, max_length=2000)
    acceptance_tolerance: str | None = Field(default=None, max_length=500)
    required_tool: str | None = Field(default=None, max_length=300)
    verifier_role: str | None = Field(default=None, max_length=200)
    evidence_required: list[str] = Field(default_factory=list)
    independent_verification_required: bool = False


class EngineeringFormula(EngineeringBaseModel):
    """Formula used by an engineering calculation or rule."""

    formula_id: str = Field(min_length=3, max_length=100)
    name: str = Field(min_length=1, max_length=300)
    expression: str = Field(min_length=1, max_length=1000)
    description: str = Field(min_length=1, max_length=2000)
    variables: dict[str, str] = Field(default_factory=dict)
    assumptions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    applicable_standards: list[StandardReference] = Field(default_factory=list)


class EngineeringCalculationReference(EngineeringBaseModel):
    """Reference to a controlled engineering calculation method."""

    calculation_id: str = Field(min_length=3, max_length=100)
    title: str = Field(min_length=1, max_length=300)
    purpose: str = Field(min_length=1, max_length=2000)
    formulas: list[EngineeringFormula] = Field(default_factory=list)
    required_inputs: list[str] = Field(default_factory=list)
    required_units: dict[str, str] = Field(default_factory=dict)
    validation_rules: list[str] = Field(default_factory=list)
    safety_warnings: list[str] = Field(default_factory=list)
    verification_requirements: list[VerificationRequirement] = Field(
        default_factory=list
    )


class EngineeringRecommendation(EngineeringBaseModel):
    """Explainable engineering recommendation produced from knowledge."""

    recommendation_id: str = Field(min_length=3, max_length=100)
    title: str = Field(min_length=1, max_length=300)
    recommendation: str = Field(min_length=1, max_length=4000)
    engineering_reason: str = Field(min_length=1, max_length=4000)
    priority: RecommendationPriority = RecommendationPriority.MEDIUM
    expected_benefits: list[str] = Field(default_factory=list)
    risks_if_ignored: list[str] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)
    required_actions: list[str] = Field(default_factory=list)
    verification_requirements: list[VerificationRequirement] = Field(
        default_factory=list
    )
    safety: SafetyGuidance | None = None
    confidence_score: float = Field(default=50.0, ge=0.0, le=100.0)


class KnowledgeRelationship(EngineeringBaseModel):
    """Directed relationship between two engineering knowledge objects."""

    target_knowledge_id: str = Field(min_length=3, max_length=100)
    relationship_type: RelationshipType
    description: str | None = Field(default=None, max_length=1000)
    confidence_score: float = Field(default=100.0, ge=0.0, le=100.0)
    evidence_ids: list[str] = Field(default_factory=list)


class KnowledgeReview(EngineeringBaseModel):
    """Technical, safety, standards, or final review record."""

    review_type: ReviewType
    decision: ReviewDecision = ReviewDecision.PENDING
    reviewer_name: str | None = Field(default=None, max_length=200)
    reviewer_role: str | None = Field(default=None, max_length=200)
    reviewed_at: datetime | None = None
    comments: str | None = Field(default=None, max_length=4000)
    conditions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_completed_review(self) -> "KnowledgeReview":
        """Require reviewer details for a completed review."""

        if self.decision != ReviewDecision.PENDING:
            if not self.reviewer_name:
                raise ValueError(
                    "reviewer_name is required for a completed review."
                )

            if self.reviewed_at is None:
                raise ValueError(
                    "reviewed_at is required for a completed review."
                )

        return self


class RevisionMetadata(EngineeringBaseModel):
    """Revision and ownership metadata for controlled knowledge."""

    revision: str = Field(default="1.0", min_length=1, max_length=50)
    created_by: str = Field(min_length=1, max_length=200)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_by: str | None = Field(default=None, max_length=200)
    updated_at: datetime | None = None
    change_summary: str | None = Field(default=None, max_length=2000)
    previous_revision: str | None = Field(default=None, max_length=50)
    supersedes_knowledge_id: str | None = Field(default=None, max_length=100)


class EngineeringKnowledge(EngineeringBaseModel):
    """Master engineering knowledge object used throughout Engineer4Me."""

    knowledge_id: str = Field(
        min_length=3,
        max_length=100,
        description="Permanent unique knowledge identifier.",
    )
    title: str = Field(min_length=1, max_length=300)
    subject: str = Field(min_length=1, max_length=300)
    summary: str = Field(min_length=1, max_length=3000)
    detailed_guidance: str = Field(min_length=1, max_length=20_000)

    discipline: EngineeringDiscipline
    categories: list[KnowledgeCategory] = Field(min_length=1)
    status: KnowledgeStatus = KnowledgeStatus.DRAFT

    taxonomy_ids: list[str] = Field(default_factory=list)
    semantic_tags: list[str] = Field(default_factory=list)

    equipment_applicability: list[EquipmentApplicability] = Field(
        default_factory=list
    )
    industry_applicability: list[IndustryApplicability] = Field(
        default_factory=list
    )
    environmental_constraints: list[EnvironmentalConstraint] = Field(
        default_factory=list
    )

    safety: SafetyGuidance | None = None
    standards: list[StandardReference] = Field(default_factory=list)
    evidence: list[EvidenceReference] = Field(default_factory=list)

    procedures: list[EngineeringProcedure] = Field(default_factory=list)
    preventive_maintenance_tasks: list[PreventiveMaintenanceTask] = Field(
        default_factory=list
    )
    calculations: list[EngineeringCalculationReference] = Field(
        default_factory=list
    )
    recommendations: list[EngineeringRecommendation] = Field(
        default_factory=list
    )
    verification_requirements: list[VerificationRequirement] = Field(
        default_factory=list
    )

    required_tools: list[RequiredTool] = Field(default_factory=list)
    required_competencies: list[CompetencyRequirement] = Field(
        default_factory=list
    )

    relationships: list[KnowledgeRelationship] = Field(default_factory=list)
    reviews: list[KnowledgeReview] = Field(default_factory=list)
    revision_metadata: RevisionMetadata

    confidence_score: float = Field(default=50.0, ge=0.0, le=100.0)
    confidence_explanation: str | None = Field(default=None, max_length=3000)

    limitations: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_controlled_knowledge(self) -> "EngineeringKnowledge":
        """Enforce safety, evidence, and approval requirements."""

        if len(self.categories) != len(set(self.categories)):
            raise ValueError("Knowledge categories must be unique.")

        evidence_ids = [item.evidence_id for item in self.evidence]

        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("Evidence IDs must be unique.")

        if self.status in {
            KnowledgeStatus.APPROVED,
            KnowledgeStatus.PUBLISHED,
        }:
            if not self.evidence:
                raise ValueError(
                    "Approved or published knowledge must contain evidence."
                )

            if not any(item.verified for item in self.evidence):
                raise ValueError(
                    "Approved or published knowledge must contain at least "
                    "one verified evidence source."
                )

        if self.status == KnowledgeStatus.PUBLISHED:
            required_reviews = {
                ReviewType.TECHNICAL,
                ReviewType.SAFETY,
                ReviewType.STANDARDS,
                ReviewType.FINAL_APPROVAL,
            }

            approved_reviews = {
                review.review_type
                for review in self.reviews
                if review.decision
                in {
                    ReviewDecision.APPROVED,
                    ReviewDecision.APPROVED_WITH_CONDITIONS,
                }
            }

            missing_reviews = required_reviews - approved_reviews

            if missing_reviews:
                missing_values = ", ".join(
                    sorted(review.value for review in missing_reviews)
                )
                raise ValueError(
                    "Published knowledge is missing approved reviews: "
                    f"{missing_values}."
                )

        if (
            self.safety is not None
            and self.safety.blocks_work_until_resolved
            and self.status == KnowledgeStatus.PUBLISHED
            and not self.safety.required_site_risk_assessment
        ):
            raise ValueError(
                "Published knowledge with a blocking safety condition must "
                "require a site risk assessment."
            )

        return self
