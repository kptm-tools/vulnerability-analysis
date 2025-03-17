package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/vulnerability-analysis/pkg/dto"
)

var baseNvdAPIURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

var ErrInvalidCPE = errors.New("invalid CPE name")

// Custom error types for NVD Api interactions
var (
	ErrNVDServiceUnavailable = errors.New("NVD API service unavailable (503)")
	ErrNVDAPIStatus          = errors.New("NVD API status error")
	ErrNVDDecode             = errors.New("failed to decode NVD API response")
)

func createNVDHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
	}
}

const (
	maxRetries        = 3
	initialRetryDelay = 5 * time.Second
)

func fetchNvdDataByCPE(cpe string, baseNvdAPIURL string) (*dto.NvdAPIResponse, error) {
	// Use custom http client with a timeout
	client := createNVDHTTPClient()

	// Build URL
	query := url.Values{}
	query.Set("cpeName", cpe)
	apiURL := baseNvdAPIURL + "?" + query.Encode()

	var nvdResponse *dto.NvdAPIResponse
	var err error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		nvdResponse, err = attemptFetch(client, apiURL)

		// Success case
		if err == nil {
			return nvdResponse, nil
		}

		// Non-retriable error
		if !shouldRetry(err) {
			return nil, fmt.Errorf("non-retriable error for CPE %s: %w", cpe, err)
		}

		retryDelay := calculateRetryDelay(attempt)
		slog.Warn("NVD API request failed, retrying",
			slog.Int("attempt", attempt),
			slog.Duration("delay", retryDelay),
			slog.String("cpe", cpe))
		time.Sleep(retryDelay)
	}

	slog.Error("NVD API request failed after max retries",
		slog.Int("max_retries", maxRetries),
		slog.String("cpe", cpe),
		slog.Any("error", err))

	return nil, fmt.Errorf("failed NVD API request after %d retries: %w", maxRetries, err)
}

func attemptFetch(client *http.Client, apiURL string) (*dto.NvdAPIResponse, error) {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create NVD API request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed NVD API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, ErrNVDServiceUnavailable
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d %s", ErrNVDAPIStatus, resp.StatusCode, resp.Status)
	}

	var nvdResponse dto.NvdAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResponse); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNVDDecode, err)
	}

	return &nvdResponse, nil
}

func shouldRetry(err error) bool {
	return errors.Is(err, ErrNVDServiceUnavailable)
}

func calculateRetryDelay(attempt int) time.Duration {
	// Exponential backoff with jitter
	delay := initialRetryDelay * time.Duration(1<<uint(attempt))
	jitter := time.Duration(int64(float64(delay) * 0.2)) // +/- 20% jitter
	delay += jitter

	if delay > 15*time.Second {
		delay = 15 * time.Second
	}
	return delay
}

func isValidCPE(cpe string) error {
	parts := strings.Split(cpe, ":")

	if len(parts) != 13 {
		return fmt.Errorf("%w: must have 13 colon-separated parts, got %d", ErrInvalidCPE, len(parts))
	}

	if parts[0] != "cpe" {
		return fmt.Errorf("%w: must start with 'cpe', got '%s'", ErrInvalidCPE, parts[0])
	}

	if parts[1] != "2.3" {
		return fmt.Errorf("%w: must have '2.3' as the second part (CPE Version), got '%s'", ErrInvalidCPE, parts[1])
	}

	componentsToCheck := []struct {
		index int
		name  string
	}{
		{index: 2, name: "part"},
		{index: 3, name: "vendor"},
		{index: 4, name: "product"},
		{index: 5, name: "version"},
	}

	for _, comp := range componentsToCheck {
		if parts[comp.index] == "*" {
			return fmt.Errorf("%w: %s component must not be '*'", ErrInvalidCPE, parts[comp.index])
		}
	}

	return nil
}

// standardizeCPE transforms an incomplete CPE from nmap output into a incomplete
// CPE v2.3 format to be consumed by the NVD API
func standardizeCPE(cpe string) (string, error) {
	if !strings.HasPrefix(cpe, "cpe:/") {
		return "", fmt.Errorf("CPE does not start with 'cpe:/': %s", cpe)
	}

	cpeWithoutPrefix := strings.TrimPrefix(cpe, "cpe:/")
	parts := strings.Split(cpeWithoutPrefix, ":")

	if len(parts) < 4 { // We need part, vendor, product and version as minimum
		return "", fmt.Errorf("CPE is too short, needs at least part, vendor, product and version: %s", cpe)
	}

	// Remove leading slash from 'part' component if present
	parts[0] = strings.TrimPrefix(parts[0], "/")

	// Pad with "*" to reach 11 components after "cpe" and "2.3"
	paddingNeeded := 11 - len(parts)
	if paddingNeeded > 0 {
		for i := 0; i < paddingNeeded; i++ {
			parts = append(parts, "*")
		}
	} else if paddingNeeded < 0 {
		parts = parts[:11]
	}

	standardizedCPE := "cpe:2.3:" + strings.Join(parts, ":")
	return standardizedCPE, nil
}

func enrichVulnerabilityWithNvdData(vuln *tools.Vulnerability, nvdVuln dto.Vulnerability) error {
	if vuln == nil {
		return fmt.Errorf("expected a non-nil vulnerability")
	}

	vuln.ID = nvdVuln.Cve.ID
	vuln.Type = nvdVuln.Cve.SourceIdentifier // This may be the incorrect field...

	// Descriptions - first english description
	vuln.Description = getEnglishDescription(nvdVuln.Cve.Descriptions)

	// References
	vuln.References = getReferences(nvdVuln.Cve.References)

	// Metrics - Prioritize CVSS v3.1, then v3.0, then v2
	baseCVSSScore, baseSeverity, impactScore, access, complexity, privilegesRequired, integrityImpact, availabilityImpact, exploitability := extractMetrics(nvdVuln.Cve.Metrics)

	vuln.BaseCVSSScore = baseCVSSScore
	vuln.BaseSeverity = baseSeverity
	vuln.ImpactScore = impactScore

	vuln.Access = access
	vuln.Complexity = complexity
	vuln.PrivilegesRequired = privilegesRequired
	vuln.IntegrityImpact = integrityImpact
	vuln.AvailabilityImpact = availabilityImpact
	vuln.Exploit = exploitability

	// Published and Updated Dates
	publishedTime, err := parseNvdDateTime(nvdVuln.Cve.Published)
	if err != nil {
		return fmt.Errorf("failed to parse publishedTime: %w", err)
	}
	vuln.Published = publishedTime

	updatedTime, err := parseNvdDateTime(nvdVuln.Cve.LastModified)
	if err != nil {
		return fmt.Errorf("failed to parse updatedTime: %w", err)
	}
	vuln.LastUpdated = updatedTime

	// Likelihood - Derive from CVSS Complexity and Access Vector
	vuln.Likelihood = calculateLikelihoodSimple(*vuln)

	// Risk Score
	vuln.RiskScore = enums.CalculateRiskScore(vuln.Likelihood, vuln.IntegrityImpact, vuln.AvailabilityImpact)

	// Vendor comments
	vuln.VendorComments = parseVendorComments(nvdVuln.Cve.VendorComments)

	return nil
}

func extractMetrics(metrics *dto.Metrics) (
	baseCVSSScore float64,
	baseSeverity enums.SeverityType,
	impactScore float64,
	access enums.AccessType,
	complexity enums.ComplexityType,
	privilegesRequired enums.PrivilegesRequiredType,
	integrityImpact enums.ImpactType,
	availabilityImpact enums.ImpactType,
	exploitability tools.Exploit,
) {
	baseCVSSScore = 0.0
	impactScore = 0.0
	baseSeverity = enums.SeverityTypeUnknown
	access = enums.AccessTypeUnknown
	complexity = enums.ComplexityTypeUnknown
	privilegesRequired = enums.PrivilegesRequiredUnknown
	integrityImpact = enums.ImpactTypeUnknown
	availabilityImpact = enums.ImpactTypeUnknown
	exploitability = tools.Exploit{
		Score:          0.0,
		Exploitability: enums.ExploitabilityTypeUnknown,
	} // Initialize exploit struct

	if metrics == nil {
		return
	}

	if len(metrics.CvssMetricV31) > 0 {
		cvssDataV31 := metrics.CvssMetricV31[0].CvssData

		baseCVSSScore = cvssDataV31.BaseScore
		impactScore = metrics.CvssMetricV31[0].ImpactScore
		baseSeverity = mapSeverityType(cvssDataV31.BaseSeverity)

		access = mapAccessTypeV31AndV30(cvssDataV31.AttackVector)
		complexity = mapComplexityTypeV31AndV30(cvssDataV31.AttackComplexity)
		privilegesRequired = mapPrivilegesRequiredTypeV31AndV30(cvssDataV31.PrivilegesRequired)
		integrityImpact = mapImpactTypeV31AndV30(cvssDataV31.IntegrityImpact)
		availabilityImpact = mapImpactTypeV31AndV30(cvssDataV31.AvailabilityImpact)

		// Exploitability
		exploitability = tools.Exploit{
			Score:          metrics.CvssMetricV31[0].ExploitabilityScore,
			Exploitability: mapExploitabilityV31AndV30(cvssDataV31.ExploitCodeMaturity),
		}

	} else if len(metrics.CvssMetricV30) > 0 {
		cvssDataV30 := metrics.CvssMetricV30[0].CvssData

		baseCVSSScore = cvssDataV30.BaseScore
		impactScore = metrics.CvssMetricV30[0].ImpactScore
		baseSeverity = mapSeverityType(cvssDataV30.BaseSeverity)

		access = mapAccessTypeV31AndV30(cvssDataV30.AttackVector)
		complexity = mapComplexityTypeV31AndV30(cvssDataV30.AttackComplexity)
		privilegesRequired = mapPrivilegesRequiredTypeV31AndV30(cvssDataV30.PrivilegesRequired)
		integrityImpact = mapImpactTypeV31AndV30(cvssDataV30.IntegrityImpact)
		availabilityImpact = mapImpactTypeV31AndV30(cvssDataV30.AvailabilityImpact)

		// Exploitability
		exploitability = tools.Exploit{
			Score:          metrics.CvssMetricV30[0].ExploitabilityScore,
			Exploitability: mapExploitabilityV31AndV30(cvssDataV30.ExploitCodeMaturity),
		}

	} else if len(metrics.CvssMetricV2) > 0 {
		cvssDataV2 := metrics.CvssMetricV2[0].CvssData

		baseCVSSScore = cvssDataV2.BaseScore
		impactScore = metrics.CvssMetricV2[0].ImpactScore
		baseSeverity = tools.MapCVSS(baseCVSSScore)

		access = mapAccessTypeV2(cvssDataV2.AccessVector)
		complexity = mapComplexityTypeV2(cvssDataV2.AccessComplexity)
		integrityImpact = mapImpactTypeV2(cvssDataV2.IntegrityImpact)
		availabilityImpact = mapImpactTypeV2(cvssDataV2.AvailabilityImpact)

		// Exploitability
		exploitability = tools.Exploit{
			Score:          metrics.CvssMetricV2[0].ExploitabilityScore,
			Exploitability: mapExploitabilityV2(cvssDataV2.Exploitability),
		}
	}

	return
}

func getEnglishDescription(descriptions []dto.Description) string {
	for _, desc := range descriptions {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	return ""
}

func getReferences(vulnReferences []dto.Reference) []string {
	var refs []string
	for _, ref := range vulnReferences {
		refs = append(refs, ref.URL)
	}
	return refs
}

func parseNvdDateTime(dateStr string) (time.Time, error) {
	customLayout := "2006-01-02T15:04:05.000"

	parsedTime, err := time.Parse(customLayout, dateStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse date using custom layout: %w", err)
	}
	return parsedTime, nil
}

func parseNvdVendorCommentDateTime(dateStr string) (time.Time, error) {
	customLayout := "2006-01-02T15:04:05"

	parsedTime, err := time.Parse(customLayout, dateStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse date using custom layout: %w", err)
	}
	return parsedTime, nil
}

// Mapping functions to convert NVD API strings to common enums ---

func mapAccessTypeV31AndV30(attackVector dto.AttackVectorType) enums.AccessType {
	switch attackVector {
	case dto.AttackVectorTypeNetwork:
		return enums.AccessTypeNetwork
	case dto.AttackVectorTypeAdjacentNetwork:
		return enums.AccessTypeAdjacentNetwork
	case dto.AttackVectorTypeLocal:
		return enums.AccessTypeLocal
	case dto.AttackVectorTypePhysical:
		return enums.AccesTypePhysical
	default:
		return enums.AccessTypeUnknown
	}
}

func mapAccessTypeV2(accessVector dto.AccessVectorTypeV2) enums.AccessType {
	switch accessVector {
	case dto.AccessVectorTypeV2Network:
		return enums.AccessTypeNetwork
	case dto.AccessVectorTypeV2AdjacentNetwork:
		return enums.AccessTypeAdjacentNetwork
	case dto.AccessVectorTypeV2Local:
		return enums.AccessTypeLocal
	default:
		return enums.AccessTypeUnknown
	}
}

func mapComplexityTypeV31AndV30(complexity dto.AttackComplexityType) enums.ComplexityType {
	switch complexity {
	case dto.AttackComplexityTypeLow:
		return enums.ComplexityTypeLow
	case dto.AttackComplexityTypeHigh:
		return enums.ComplexityTypeHigh
	default:
		return enums.ComplexityTypeUnknown
	}
}

func mapComplexityTypeV2(complexity dto.AccessComplexityTypeV2) enums.ComplexityType {
	switch complexity {
	case dto.AccessComplexityTypeV2High:
		return enums.ComplexityTypeHigh
	case dto.AccessComplexityTypeV2Medium:
		return enums.ComplexityTypeMedium
	case dto.AccessComplexityTypeV2Low:
		return enums.ComplexityTypeLow
	default:
		return enums.ComplexityTypeUnknown
	}
}

func mapPrivilegesRequiredTypeV31AndV30(privReq dto.PrivilegesRequiredType) enums.PrivilegesRequiredType {
	switch privReq {
	case dto.PrivilegesRequiredTypeHigh:
		return enums.PrivilegesRequiredHigh
	case dto.PrivilegesRequiredTypeLow:
		return enums.PrivilegesRequiredLow
	case dto.PrivilegesRequiredTypeNone:
		return enums.PrivilegesRequiredNone
	default:
		return enums.PrivilegesRequiredUnknown
	}
}

func mapImpactTypeV31AndV30(cia dto.CiaType) enums.ImpactType {
	switch cia {
	case dto.CiaTypeHigh:
		return enums.ImpactTypeHigh
	case dto.CiaTypeLow:
		return enums.ImpactTypeLow
	case dto.CiaTypeNone:
		return enums.ImpactTypeNone
	default:
		return enums.ImpactTypeUnknown
	}
}

func mapImpactTypeV2(cia dto.CiaTypeV2) enums.ImpactType {
	switch cia {
	case dto.CiaTypeV2Complete:
		return enums.ImpactTypeHigh
	case dto.CiaTypeV2Partial:
		return enums.ImpactTypeLow
	case dto.CiaTypeV2None:
		return enums.ImpactTypeNone
	default:
		return enums.ImpactTypeUnknown
	}
}

func mapSeverityType(severity dto.SeverityType) enums.SeverityType {
	switch severity {
	case dto.SeverityTypeCritical:
		return enums.SeverityTypeCritical
	case dto.SeverityTypeHigh:
		return enums.SeverityTypeHigh
	case dto.SeverityTypeMedium:
		return enums.SeverityTypeMedium
	case dto.SeverityTypeLow:
		return enums.SeverityTypeLow
	case dto.SeverityTypeNone:
		return enums.SeverityTypeNone
	default:
		return enums.SeverityTypeUnknown
	}
}

func mapExploitabilityV31AndV30(exploitability *dto.ExploitCodeMaturityType) enums.ExploitabilityType {
	if exploitability == nil {
		return enums.ExploitabilityTypeUnknown
	}

	switch *exploitability {
	case dto.ExploitCodeMaturityTypeHigh:
		return enums.ExploitabilityTypeHigh
	case dto.ExploitCodeMaturityTypeFunctional:
		return enums.ExploitabilityTypeFunctional
	case dto.ExploitCodeMaturityTypeProofOfConcept:
		return enums.ExploitabilityTypeProofOfConcept
	case dto.ExploitCodeMaturityTypeUnproven:
		return enums.ExploitabilityTypeUnproven
	case dto.ExploitCodeMaturityTypeNotDefined:
		return enums.ExploitabilityTypeUndefined
	default:
		return enums.ExploitabilityTypeUnknown
	}
}

func mapExploitabilityV2(exploitability *dto.ExploitabilityTypeV2) enums.ExploitabilityType {
	if exploitability == nil {
		return enums.ExploitabilityTypeUnknown
	}
	switch *exploitability {
	case dto.ExploitabilityTypeV2Unproven:
		return enums.ExploitabilityTypeUnproven
	case dto.ExploitabilityTypeV2ProofOfConcept:
		return enums.ExploitabilityTypeProofOfConcept
	case dto.ExploitabilityTypeV2Functional:
		return enums.ExploitabilityTypeFunctional
	case dto.ExploitabilityTypeV2High:
		return enums.ExploitabilityTypeHigh
	case dto.ExploitabilityTypeV2NotDefined:
		return enums.ExploitabilityTypeUndefined
	default:
		return enums.ExploitabilityTypeUnknown
	}
}

func calculateLikelihoodSimple(vuln tools.Vulnerability) enums.LikelyhoodType {
	switch vuln.Access {
	case enums.AccessTypeNetwork:
		if vuln.Complexity == enums.ComplexityTypeLow {
			return enums.LikelyhoodTypeVeryHigh
		} else {
			return enums.LikelyhoodTypeHigh
		}
	case enums.AccessTypeAdjacentNetwork:
		return enums.LikelyhoodTypeMedium
	case enums.AccessTypeUnknown:
		return enums.LikelyhoodTypeUnknown
	default:
		return enums.LikelyhoodTypeLow
	}
}

func parseVendorComments(nvdComments []dto.VendorComment) []tools.VendorComment {
	resultComments := make([]tools.VendorComment, 0, len(nvdComments))

	for _, comment := range nvdComments {
		var resultComment tools.VendorComment
		resultComment.Organization = comment.Organization
		resultComment.Comment = comment.Comment
		lastModifiedTime, err := parseNvdVendorCommentDateTime(comment.LastModified)
		if err != nil {
			slog.Warn("Failed to parse LastModified field for vendor comment, skipping...",
				slog.String("organization", comment.Organization),
				slog.String("comment", comment.Comment))
			continue
		}

		resultComment.LastModified = lastModifiedTime
		resultComments = append(resultComments, resultComment)
	}
	return resultComments
}
