package dto

// CVSS V2.0 enums for schemas

type AccessVectorTypeV2 string

const (
	AccessVectorTypeV2Network         AccessVectorTypeV2 = "NETWORK"
	AccessVectorTypeV2AdjacentNetwork AccessVectorTypeV2 = "ADJACENT_NETWORK"
	AccessVectorTypeV2Local           AccessVectorTypeV2 = "LOCAL"
)

type AccessComplexityTypeV2 string

const (
	AccessComplexityTypeV2High   AccessComplexityTypeV2 = "HIGH"
	AccessComplexityTypeV2Medium AccessComplexityTypeV2 = "MEDIUM"
	AccessComplexityTypeV2Low    AccessComplexityTypeV2 = "LOW"
)

type AuthenticationTypeV2 string

const (
	AuthenticationTypeV2Multiple AuthenticationTypeV2 = "MULTIPLE"
	AuthenticationTypeV2Single   AuthenticationTypeV2 = "SINGLE"
	AuthenticationTypeV2None     AuthenticationTypeV2 = "NONE"
)

type CiaTypeV2 string

const (
	CiaTypeV2None     CiaTypeV2 = "NONE"
	CiaTypeV2Partial  CiaTypeV2 = "PARTIAL"
	CiaTypeV2Complete CiaTypeV2 = "COMPLETE"
)

type ExploitabilityTypeV2 string

const (
	ExploitabilityTypeV2Unproven       ExploitabilityTypeV2 = "UNPROVEN"
	ExploitabilityTypeV2ProofOfConcept ExploitabilityTypeV2 = "PROOF_OF_CONCEPT"
	ExploitabilityTypeV2Functional     ExploitabilityTypeV2 = "FUNCTIONAL"
	ExploitabilityTypeV2High           ExploitabilityTypeV2 = "HIGH"
	ExploitabilityTypeV2NotDefined     ExploitabilityTypeV2 = "NOT_DEFINED"
)

type RemediationLevelTypeV2 string

const (
	RemediationLevelTypeV2OfficialFix  RemediationLevelTypeV2 = "OFFICIAL_FIX"
	RemediationLevelTypeV2TemporaryFix RemediationLevelTypeV2 = "TEMPORARY_FIX"
	RemediationLevelTypeV2Workaround   RemediationLevelTypeV2 = "WORKAROUND"
	RemediationLevelTypeV2Unavailable  RemediationLevelTypeV2 = "UNAVAILABLE"
	RemediationLevelTypeV2NotDefined   RemediationLevelTypeV2 = "NOT_DEFINED"
)

type ReportConfidenceTypeV2 string

const (
	ReportConfidenceTypeV2Unconfirmed    ReportConfidenceTypeV2 = "UNCONFIRMED"
	ReportConfidenceTypeV2Uncorroborated ReportConfidenceTypeV2 = "UNCORROBORATED"
	ReportConfidenceTypeV2Confirmed      ReportConfidenceTypeV2 = "CONFIRMED"
	ReportConfidenceTypeV2NotDefined     ReportConfidenceTypeV2 = "NOT_DEFINED"
)

type CollateralDamagePotentialTypeV2 string

const (
	CollateralDamagePotentialTypeV2None       CollateralDamagePotentialTypeV2 = "NONE"
	CollateralDamagePotentialTypeV2Low        CollateralDamagePotentialTypeV2 = "LOW"
	CollateralDamagePotentialTypeV2LowMedium  CollateralDamagePotentialTypeV2 = "LOW_MEDIUM"
	CollateralDamagePotentialTypeV2MediumHigh CollateralDamagePotentialTypeV2 = "MEDIUM_HIGH"
	CollateralDamagePotentialTypeV2High       CollateralDamagePotentialTypeV2 = "HIGH"
	CollateralDamagePotentialTypeV2NotDefined CollateralDamagePotentialTypeV2 = "NOT_DEFINED"
)

type TargetDistributionTypeV2 string

const (
	TargetDistributionTypeV2None       TargetDistributionTypeV2 = "NONE"
	TargetDistributionTypeV2Low        TargetDistributionTypeV2 = "LOW"
	TargetDistributionTypeV2Medium     TargetDistributionTypeV2 = "MEDIUM"
	TargetDistributionTypeV2High       TargetDistributionTypeV2 = "HIGH"
	TargetDistributionTypeV2NotDefined TargetDistributionTypeV2 = "NOT_DEFINED"
)

// CVSS V3.0 and V3.1 enums from schemas

type AttackVectorType string

const (
	AttackVectorTypeNetwork         AttackVectorType = "NETWORK"
	AttackVectorTypeAdjacentNetwork AttackVectorType = "ADJACENT_NETWORK"
	AttackVectorTypeLocal           AttackVectorType = "LOCAL"
	AttackVectorTypePhysical        AttackVectorType = "PHYSICAL"
)

type ModifiedAttackVectorType string

const (
	ModifiedAttackVectorTypeNetwork         ModifiedAttackVectorType = "NETWORK"
	ModifiedAttackVectorTypeAdjacentNetwork ModifiedAttackVectorType = "ADJACENT_NETWORK"
	ModifiedAttackVectorTypeLocal           ModifiedAttackVectorType = "LOCAL"
	ModifiedAttackVectorTypePhysical        ModifiedAttackVectorType = "PHYSICAL"
	ModifiedAttackVectorTypeNotDefined      ModifiedAttackVectorType = "NOT_DEFINED"
)

type AttackComplexityType string

const (
	AttackComplexityTypeHigh AttackComplexityType = "HIGH"
	AttackComplexityTypeLow  AttackComplexityType = "LOW"
)

type ModifiedAttackComplexityType string

const (
	ModifiedAttackComplexityTypeHigh       ModifiedAttackComplexityType = "HIGH"
	ModifiedAttackComplexityTypeLow        ModifiedAttackComplexityType = "LOW"
	ModifiedAttackComplexityTypeNotDefined ModifiedAttackComplexityType = "NOT_DEFINED"
)

type PrivilegesRequiredType string

const (
	PrivilegesRequiredTypeHigh PrivilegesRequiredType = "HIGH"
	PrivilegesRequiredTypeLow  PrivilegesRequiredType = "LOW"
	PrivilegesRequiredTypeNone PrivilegesRequiredType = "NONE"
)

type ModifiedPrivilegesRequiredType string

const (
	ModifiedPrivilegesRequiredTypeHigh       ModifiedPrivilegesRequiredType = "HIGH"
	ModifiedPrivilegesRequiredTypeLow        ModifiedPrivilegesRequiredType = "LOW"
	ModifiedPrivilegesRequiredTypeNone       ModifiedPrivilegesRequiredType = "NONE"
	ModifiedPrivilegesRequiredTypeNotDefined ModifiedPrivilegesRequiredType = "NOT_DEFINED"
)

type UserInteractionType string

const (
	UserInteractionTypeNone     UserInteractionType = "NONE"
	UserInteractionTypeRequired UserInteractionType = "REQUIRED"
)

type ModifiedUserInteractionType string

const (
	ModifiedUserInteractionTypeNone       ModifiedUserInteractionType = "NONE"
	ModifiedUserInteractionTypeRequired   ModifiedUserInteractionType = "REQUIRED"
	ModifiedUserInteractionTypeNotDefined ModifiedUserInteractionType = "NOT_DEFINED"
)

type ScopeType string

const (
	ScopeTypeUnchanged ScopeType = "UNCHANGED"
	ScopeTypeChanged   ScopeType = "CHANGED"
)

type ModifiedScopeType string

const (
	ModifiedScopeTypeUnchanged  ModifiedScopeType = "UNCHANGED"
	ModifiedScopeTypeChanged    ModifiedScopeType = "CHANGED"
	ModifiedScopeTypeNotDefined ModifiedScopeType = "NOT_DEFINED"
)

type CiaType string

const (
	CiaTypeNone CiaType = "NONE"
	CiaTypeLow  CiaType = "LOW"
	CiaTypeHigh CiaType = "HIGH"
)

type ModifiedCiaType string

const (
	ModifiedCiaTypeNone       ModifiedCiaType = "NONE"
	ModifiedCiaTypeLow        ModifiedCiaType = "LOW"
	ModifiedCiaTypeHigh       ModifiedCiaType = "HIGH"
	ModifiedCiaTypeNotDefined ModifiedCiaType = "NOT_DEFINED"
)

type ExploitCodeMaturityType string

const (
	ExploitCodeMaturityTypeUnproven       ExploitCodeMaturityType = "UNPROVEN"
	ExploitCodeMaturityTypeProofOfConcept ExploitCodeMaturityType = "PROOF_OF_CONCEPT"
	ExploitCodeMaturityTypeFunctional     ExploitCodeMaturityType = "FUNCTIONAL"
	ExploitCodeMaturityTypeHigh           ExploitCodeMaturityType = "HIGH"
	ExploitCodeMaturityTypeNotDefined     ExploitCodeMaturityType = "NOT_DEFINED"
)

type RemediationLevelType string

const (
	RemediationLevelTypeOfficialFix  RemediationLevelType = "OFFICIAL_FIX"
	RemediationLevelTypeTemporaryFix RemediationLevelType = "TEMPORARY_FIX"
	RemediationLevelTypeWorkaround   RemediationLevelType = "WORKAROUND"
	RemediationLevelTypeUnavailable  RemediationLevelType = "UNAVAILABLE"
	RemediationLevelTypeNotDefined   RemediationLevelType = "NOT_DEFINED"
)

type ConfidenceType string

const (
	ConfidenceTypeUnknown    ConfidenceType = "UNKNOWN"
	ConfidenceTypeReasonable ConfidenceType = "REASONABLE"
	ConfidenceTypeConfirmed  ConfidenceType = "CONFIRMED"
	ConfidenceTypeNotDefined ConfidenceType = "NOT_DEFINED"
)

type CiaRequirementType string

const (
	CiaRequirementTypeLow        CiaRequirementType = "LOW"
	CiaRequirementTypeMedium     CiaRequirementType = "MEDIUM"
	CiaRequirementTypeHigh       CiaRequirementType = "HIGH"
	CiaRequirementTypeNotDefined CiaRequirementType = "NOT_DEFINED"
)

type SeverityType string

const (
	SeverityTypeNone     SeverityType = "NONE"
	SeverityTypeLow      SeverityType = "LOW"
	SeverityTypeMedium   SeverityType = "MEDIUM"
	SeverityTypeHigh     SeverityType = "HIGH"
	SeverityTypeCritical SeverityType = "CRITICAL"
)
