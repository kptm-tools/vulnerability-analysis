package dto

type NvdAPIResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"` // If this is greater than ResultsPerPage, we require subsequent requests
	Format          string          `json:"format"`
	Version         string          `json:"version"`
	Timestamp       string          `json:"timestamp"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	Cve CveDetail `json:"cve"`
}

type CveDetail struct {
	// Required fields
	ID               string `json:"id"`
	SourceIdentifier string `json:"sourceIdentifier"`
	Published        string `json:"published"`
	LastModified     string `json:"lastModified"`
	VulnStatus       string `json:"vulnStatus"`

	// Optional Fields
	EvaluatorComment      *string `json:"evaluatorComment,omitempty"`
	EvaluatorImpact       *string `json:"evaluatorImpact,omitempty"`
	EvaluatorSolution     *string `json:"evaluatorSolution,omitempty"`
	CisaExploitAdd        *string `json:"cisaExploitAdd,omitempty"`
	CisaActionDue         *string `json:"cisaActionDue,omitempty"`
	CisaRequiredAction    *string `json:"cisaRequiredAction,omitempty"`
	CisaVulnerabilityName *string `json:"cisaVulnerabilityName,omitempty"`

	CveTags        []CveTag        `json:"cveTags,omitempty"`
	Descriptions   []Description   `json:"descriptions"` // Required
	Metrics        *Metrics        `json:"metrics,omitempty"`
	Weaknesses     []Weakness      `json:"weaknesses,omitempty"`
	Configurations []Configuration `json:"configurations,omitempty"`
	References     []Reference     `json:"references"` // Required
	VendorComments []VendorComment `json:"vendorComments,omitempty"`
}

type CveTag struct {
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

type Metrics struct {
	CvssMetricV2  []CvssMetricV2  `json:"cvssMetricV2,omitempty"`
	CvssMetricV30 []CvssMetricV30 `json:"cvssMetricV30,omitempty"`
	CvssMetricV31 []CvssMetricV31 `json:"cvssMetricV31,omitempty"`
}

type CvssMetricV2 struct {
	Source              string     `json:"source"`
	Type                string     `json:"type"`
	CvssData            CvssDataV2 `json:"cvssData"`
	BaseSeverity        string     `json:"baseSeverity"`
	ExploitabilityScore float64    `json:"exploitabilityScore"`
	ImpactScore         float64    `json:"impactScore"`

	AcInsufInfo             *bool `json:"acInsufInfo,omitempty"`
	ObtainAllPrivilege      *bool `json:"obtainAllPrivilege,omitempty"`
	ObtainUserPrivilege     *bool `json:"obtainUserPrivilege,omitempty"`
	ObtainOtherPrivilege    *bool `json:"obtainOtherPrivilege,omitempty"`
	UserInteractionRequired *bool `json:"userInteractionRequired,omitempty"`
}

type CvssDataV2 struct {
	Version               string                 `json:"version"`
	VectorString          string                 `json:"vectorString"`
	AccessVector          AccessVectorTypeV2     `json:"accessVector"`
	AccessComplexity      AccessComplexityTypeV2 `json:"accessComplexity"`
	Authentication        AuthenticationTypeV2   `json:"authentication"`
	ConfidentialityImpact CiaTypeV2              `json:"confidentialityImpact"`
	IntegrityImpact       CiaTypeV2              `json:"integrityImpact"`
	AvailabilityImpact    CiaTypeV2              `json:"availabilityImpact"`
	BaseScore             float64                `json:"baseScore"`

	// Temporal Metrics (Optional)
	Exploitability   *ExploitabilityTypeV2   `json:"exploitability,omitempty"`
	RemediationLevel *RemediationLevelTypeV2 `json:"remediationLevel,omitempty"`
	ReportConfidence *ReportConfidenceTypeV2 `json:"reportConfidence,omitempty"`
	TemporalScore    *float64                `json:"temporalScore,omitempty"`

	// Environmental Metrics (Optional)
	CollateralDamagePotential  *CollateralDamagePotentialTypeV2 `json:"collateralDamagePotential,omitempty"`
	TargetDistribution         *TargetDistributionTypeV2        `json:"targetDistribution,omitempty"`
	ConfidentialityRequirement *CiaRequirementType              `json:"confidentialityRequirement,omitempty"` // Reusing CiaRequirementType from v3.x
	IntegrityRequirement       *CiaRequirementType              `json:"integrityRequirement,omitempty"`       // Reusing CiaRequirementType from v3.x
	AvailabilityRequirement    *CiaRequirementType              `json:"availabilityRequirement,omitempty"`    // Reusing CiaRequirementType from v3.x
	EnvironmentalScore         *float64                         `json:"environmentalScore,omitempty"`
}

type CvssMetricV30 struct {
	Source              string      `json:"source"`
	Type                string      `json:"type"`
	CvssData            CvssDataV30 `json:"cvssData"`
	ExploitabilityScore float64     `json:"exploitabilityScore"`
	ImpactScore         float64     `json:"impactScore"`
}
type CvssDataV30 struct {
	Version                       string                          `json:"version"`
	VectorString                  string                          `json:"vectorString"`
	AttackVector                  AttackVectorType                `json:"attackVector"`
	AttackComplexity              AttackComplexityType            `json:"attackComplexity"`
	PrivilegesRequired            PrivilegesRequiredType          `json:"privilegesRequired"`
	UserInteraction               UserInteractionType             `json:"userInteraction"`
	Scope                         ScopeType                       `json:"scope"`
	ConfidentialityImpact         CiaType                         `json:"confidentialityImpact"`
	IntegrityImpact               CiaType                         `json:"integrityImpact"`
	AvailabilityImpact            CiaType                         `json:"availabilityImpact"`
	BaseScore                     float64                         `json:"baseScore"`
	BaseSeverity                  SeverityType                    `json:"baseSeverity"`
	ExploitCodeMaturity           *ExploitCodeMaturityType        `json:"exploitCodeMaturity,omitempty"`
	RemediationLevel              *RemediationLevelType           `json:"remediationLevel,omitempty"`
	ReportConfidence              *ConfidenceType                 `json:"reportConfidence,omitempty"`
	TemporalScore                 *float64                        `json:"temporalScore,omitempty"`
	TemporalSeverity              *SeverityType                   `json:"temporalSeverity,omitempty"`
	ConfidentialityRequirement    *CiaRequirementType             `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement          *CiaRequirementType             `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement       *CiaRequirementType             `json:"availabilityRequirement,omitempty"`
	ModifiedAttackVector          *ModifiedAttackVectorType       `json:"modifiedAttackVector,omitempty"`
	ModifiedAttackComplexity      *ModifiedAttackComplexityType   `json:"modifiedAttackComplexity,omitempty"`
	ModifiedPrivilegesRequired    *ModifiedPrivilegesRequiredType `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedUserInteraction       *ModifiedUserInteractionType    `json:"modifiedUserInteraction,omitempty"`
	ModifiedScope                 *ModifiedScopeType              `json:"modifiedScope,omitempty"`
	ModifiedConfidentialityImpact *ModifiedCiaType                `json:"modifiedConfidentialityImpact,omitempty"`
	ModifiedIntegrityImpact       *ModifiedCiaType                `json:"modifiedIntegrityImpact,omitempty"`
	ModifiedAvailabilityImpact    *ModifiedCiaType                `json:"modifiedAvailabilityImpact,omitempty"`
	EnvironmentalScore            *float64                        `json:"environmentalScore,omitempty"`
	EnvironmentalSeverity         *SeverityType                   `json:"environmentalSeverity,omitempty"`
}

type CvssMetricV31 struct {
	Source              string      `json:"source"`
	Type                string      `json:"type"`
	CvssData            CvssDataV31 `json:"cvssData"`
	ExploitabilityScore float64     `json:"exploitabilityScore"`
	ImpactScore         float64     `json:"impactScore"`
	SeveritySource      *string     `json:"severitySource,omitempty"` // Optional in practice
}

type CvssDataV31 struct {
	Version                       string                          `json:"version"`
	VectorString                  string                          `json:"vectorString"`
	AttackVector                  AttackVectorType                `json:"attackVector"`
	AttackComplexity              AttackComplexityType            `json:"attackComplexity"`
	PrivilegesRequired            PrivilegesRequiredType          `json:"privilegesRequired"`
	UserInteraction               UserInteractionType             `json:"userInteraction"`
	Scope                         ScopeType                       `json:"scope"`
	ConfidentialityImpact         CiaType                         `json:"confidentialityImpact"`
	IntegrityImpact               CiaType                         `json:"integrityImpact"`
	AvailabilityImpact            CiaType                         `json:"availabilityImpact"`
	BaseScore                     float64                         `json:"baseScore"`
	BaseSeverity                  SeverityType                    `json:"baseSeverity"`
	ExploitCodeMaturity           *ExploitCodeMaturityType        `json:"exploitCodeMaturity,omitempty"`
	RemediationLevel              *RemediationLevelType           `json:"remediationLevel,omitempty"`
	ReportConfidence              *ConfidenceType                 `json:"reportConfidence,omitempty"`
	TemporalScore                 *float64                        `json:"temporalScore,omitempty"`
	TemporalSeverity              *SeverityType                   `json:"temporalSeverity,omitempty"`
	ConfidentialityRequirement    *CiaRequirementType             `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement          *CiaRequirementType             `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement       *CiaRequirementType             `json:"availabilityRequirement,omitempty"`
	ModifiedAttackVector          *ModifiedAttackVectorType       `json:"modifiedAttackVector,omitempty"`
	ModifiedAttackComplexity      *ModifiedAttackComplexityType   `json:"modifiedAttackComplexity,omitempty"`
	ModifiedPrivilegesRequired    *ModifiedPrivilegesRequiredType `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedUserInteraction       *ModifiedUserInteractionType    `json:"modifiedUserInteraction,omitempty"`
	ModifiedScope                 *ModifiedScopeType              `json:"modifiedScope,omitempty"`
	ModifiedConfidentialityImpact *ModifiedCiaType                `json:"modifiedConfidentialityImpact,omitempty"`
	ModifiedIntegrityImpact       *ModifiedCiaType                `json:"modifiedIntegrityImpact,omitempty"`
	ModifiedAvailabilityImpact    *ModifiedCiaType                `json:"modifiedAvailabilityImpact,omitempty"`
	EnvironmentalScore            *float64                        `json:"environmentalScore,omitempty"`
	EnvironmentalSeverity         *SeverityType                   `json:"environmentalSeverity,omitempty"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Weakness struct {
	Source      string        `json:"source"`
	Type        string        `json:"type"`
	Description []Description `json:"description"`
}

type Configuration struct {
	Nodes []Node `json:"nodes"`
}

type Node struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CpeMatch []CpeMatch `json:"cpeMatch"`
}

type CpeMatch struct {
	Vulnerable            bool    `json:"vulnerable"`
	Criteria              string  `json:"criteria"`
	MatchCriteriaID       string  `json:"matchCriteriaId"`
	VersionStartExcluding *string `json:"versionStartExcluding,omitempty"`
	VersionStartIncluding *string `json:"versionStartIncluding,omitempty"`
	VersionEndExcluding   *string `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   *string `json:"versionEndIncluding,omitempty"`
}

type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags,omitempty"` // Not in docs example, but might exist
}

type VendorComment struct {
	Organization string `json:"organization"`
	Comment      string `json:"comment"`
	LastModified string `json:"lastModified"`
}
