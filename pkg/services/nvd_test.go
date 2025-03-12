package services

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/vulnerability-analysis/pkg/dto"
	"github.com/stretchr/testify/assert"
)

func Test_isValidCPE(t *testing.T) {
	testCases := []struct {
		name     string
		inputCPE string
		wantErr  bool
	}{
		{
			name:     "Valid CPE",
			inputCPE: "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
			wantErr:  false,
		},
		{
			name:     "Invalid CPE length",
			inputCPE: "cpe:2.3:*:microsoft:windows_10:1607:*:*:*:*:*:*:*:*:*:*:*",
			wantErr:  true,
		},
		{
			name:     "Invalid CPE part",
			inputCPE: "cpe:2.3:*:microsoft:windows_10:1607:*:*:*:*:*:*:*",
			wantErr:  true,
		},
		{
			name:     "Invalid CPE version",
			inputCPE: "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
			wantErr:  true,
		},
		{
			name:     "Short CPE",
			inputCPE: "cpe:2.3:o:microsoft:windows_10:*:*:*:*",
			wantErr:  true,
		},
		{
			name:     "Wrong Prefix CPE",
			inputCPE: "cp:2.3:o:microsoft:windows_10:*:*:*:*",
			wantErr:  true,
		},
		{
			name:     "Wrong Version CPE",
			inputCPE: "cpe:2.4:o:microsoft:windows_10:*:*:*:*",
			wantErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := isValidCPE(tc.inputCPE)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_fetchNvdDataByCPE_SuccessWithResults(t *testing.T) {
	// 1. Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Assert request parameters (CPE in query)
		encodedCPE := url.QueryEscape("cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*")
		if !strings.Contains(r.URL.RawQuery, "cpeName="+encodedCPE) {
			t.Errorf("Expected CPE query parameter in request URL %s, got %v", encodedCPE, r.URL.RawQuery)
		}
		// Load successful API response from testdata file
		content, err := os.ReadFile("testdata/nvd_api_success.json")
		if err != nil {
			t.Fatalf("Failed to read test data file: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(content)
	}))
	defer server.Close()

	// 2. Modifyt base API URL for testing
	baseNvdAPIURL = server.URL // Set to mock server URL

	// 3. Call fetchNvdDataByCPE with a valid CPE
	cpe := "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"
	response, err := fetchNvdDataByCPE(cpe, baseNvdAPIURL)
	// 4. Assertions
	assert.NoError(t, err, "Expected no error for successful request")
	assert.NotNil(t, response, "Expected non-nil NvdAPIResponse")
	assert.Greater(t, response.TotalResults, 0, "Expected TotalResults > 0")
}

func Test_fetchNvdDataByCPE_ServiceUnavailableMaxRetriesFail(t *testing.T) {
	invalidCPE := "cpe:2.4:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"
	retryCount := 0 // Counter to track mock server responses

	// 1. Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Assert request parameters (CPE in query)
		encodedCPE := url.QueryEscape(invalidCPE)
		if !strings.Contains(r.URL.RawQuery, "cpeName="+encodedCPE) {
			t.Errorf("Expected CPE query parameter in request URL %s, got %v", encodedCPE, r.URL.RawQuery)
		}

		if retryCount < maxRetries+1 {

			content, err := os.ReadFile("testdata/nvd_service_unavailable.html")
			if err != nil {
				t.Fatalf("Failed to read test data file: %v", err)
			}

			w.WriteHeader(http.StatusServiceUnavailable)
			w.Header().Set("Content-Type", "text/html")
			w.Write(content)
			retryCount++
			return
		}

		// After retries, simulate another 503 error response
		content, err := os.ReadFile("testdata/nvd_service_unavailable.html")
		if err != nil {
			t.Fatalf("Failed to read test data file: %v", err)
		}

		w.WriteHeader(http.StatusServiceUnavailable)
		w.Header().Set("Content-Type", "text/html")
		w.Write(content)
	}))
	defer server.Close()

	// 2. Modify base API URL for testing
	baseNvdAPIURL = server.URL

	// 3. Call fetchNvdDataByCPE with an invalid CPE
	resp, err := fetchNvdDataByCPE(invalidCPE, baseNvdAPIURL)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNVDServiceUnavailable, "Expected ErrNVDServiceUnavailable")
	assert.Nil(t, resp)

	assert.Equal(t, maxRetries+1, retryCount, "Expected function to attempt max retries")
}

func Test_fetchNvdDataByCPE_ServiceUnavailableMaxRetriesSuccess(t *testing.T) {
	cpe := "cpe:2.4:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"
	retryCount := 0 // Counter to track mock server responses

	// 1. Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Assert request parameters (CPE in query)
		encodedCPE := url.QueryEscape(cpe)
		if !strings.Contains(r.URL.RawQuery, "cpeName="+encodedCPE) {
			t.Errorf("Expected CPE query parameter in request URL %s, got %v", encodedCPE, r.URL.RawQuery)
		}

		if retryCount < maxRetries {

			content, err := os.ReadFile("testdata/nvd_service_unavailable.html")
			if err != nil {
				t.Fatalf("Failed to read test data file: %v", err)
			}

			w.WriteHeader(http.StatusServiceUnavailable)
			w.Header().Set("Content-Type", "text/html")
			w.Write(content)
			retryCount++
			return
		}

		// After retries, simulate successful response
		content, err := os.ReadFile("testdata/nvd_api_success.json")
		if err != nil {
			t.Fatalf("Failed to read test data file: %v", err)
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(content)
	}))
	defer server.Close()

	// 2. Modify base API URL for testing
	baseNvdAPIURL = server.URL

	// 3. Call fetchNvdDataByCPE with an invalid CPE
	resp, err := fetchNvdDataByCPE(cpe, baseNvdAPIURL)
	assert.NoError(t, err, "Expected no error for successful request")
	assert.NotNil(t, resp, "Expected non-nil NvdAPIResponse")
	assert.Greater(t, resp.TotalResults, 0, "Expected TotalResults > 0")

	assert.Equal(t, maxRetries, retryCount, "Expected function to attempt max retries")
}

func Test_standardizeCPE(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		cpe     string
		want    string
		wantErr bool
	}{
		{
			name:    "Pure-FTPd",
			cpe:     "cpe:/a:pureftpd:pure-ftpd",
			want:    "",
			wantErr: true,
		},

		{
			name:    "OpenSSH with version",
			cpe:     "cpe:/a:openbsd:openssh:8.0",
			want:    "cpe:2.3:a:openbsd:openssh:8.0:*:*:*:*:*:*:*",
			wantErr: false,
		},
		{
			name:    "Exim with version",
			cpe:     "cpe:/a:exim:exim:4.98",
			want:    "cpe:2.3:a:exim:exim:4.98:*:*:*:*:*:*:*",
			wantErr: false,
		},
		{
			name:    "ISC BIND with version",
			cpe:     "cpe:/a:isc:bind:9.11.36",
			want:    "cpe:2.3:a:isc:bind:9.11.36:*:*:*:*:*:*:*",
			wantErr: false,
		},
		{
			name:    "Red Hat EL 8 (OS)",
			cpe:     "cpe:/o:redhat:enterprise_linux:8",
			want:    "cpe:2.3:o:redhat:enterprise_linux:8:*:*:*:*:*:*:*",
			wantErr: false,
		},
		{
			name:    "Dovecot (no version)",
			cpe:     "cpe:/a:dovecot:dovecot",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Incomplete NVD format",
			cpe:     "cpe:/o:microsoft:windows_10:1607",
			want:    "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
			wantErr: false,
		},
		{
			name:    "Invalid prefix",
			cpe:     "invalid-cpe:/a:test:test",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Too short CPE",
			cpe:     "cpe:/a:test",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Empty string",
			cpe:     "",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := standardizeCPE(tt.cpe)
			if tt.wantErr {
				assert.Error(t, gotErr)
			} else {
				assert.NoError(t, gotErr)
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_calculateLikelihoodSimple(t *testing.T) {
	testCases := []struct {
		name      string
		vulnInput tools.Vulnerability
		expected  enums.LikelyhoodType
	}{
		{
			name: "Network Access, Low Complexity",
			vulnInput: tools.Vulnerability{
				Access:     enums.AccessTypeNetwork,
				Complexity: enums.ComplexityTypeLow,
			},
			expected: enums.LikelyhoodTypeVeryHigh,
		},
		{
			name: "Network Access, High Complexity",
			vulnInput: tools.Vulnerability{
				Access:     enums.AccessTypeNetwork,
				Complexity: enums.ComplexityTypeHigh,
			},
			expected: enums.LikelyhoodTypeHigh,
		},
		{
			name: "Adjacent Network Access",
			vulnInput: tools.Vulnerability{
				Access: enums.AccessTypeAdjacentNetwork,
			},
			expected: enums.LikelyhoodTypeMedium,
		},
		{
			name: "Local Access",
			vulnInput: tools.Vulnerability{
				Access: enums.AccessTypeLocal,
			},
			expected: enums.LikelyhoodTypeLow,
		},
		{
			name: "Unknown AccessType",
			vulnInput: tools.Vulnerability{
				Access: enums.AccessTypeUnknown,
			},
			expected: enums.LikelyhoodTypeUnknown,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := calculateLikelihoodSimple(tc.vulnInput)

			assert.Equal(t, tc.expected, got)
		})
	}
}

func Test_EnrichVulnerabilityWithNvdData(t *testing.T) {
	testCases := []struct {
		name         string
		nvdVulnInput dto.Vulnerability                                     // Mocked dto.Vulnerability input
		wantErr      bool                                                  // Expect an error?
		assertFunc   func(t *testing.T, enrichedVuln *tools.Vulnerability) // Custom assertion function
	}{
		{
			name:         "Enrich with CVSS v3.1 Data",
			nvdVulnInput: createMockNvdVulnerabilityWithV31(), // Helper to create mock data
			wantErr:      false,
			assertFunc: func(t *testing.T, enrichedVuln *tools.Vulnerability) {
				if enrichedVuln.BaseCVSSScore != 7.5 { // Example assertion based on mock data
					t.Errorf("Expected BaseCVSSScore to be 7.5, got %f", enrichedVuln.BaseCVSSScore)
				}
				if enrichedVuln.Access != enums.AccessTypeNetwork {
					t.Errorf("Expected AccessTypeNetwork, got %v", enrichedVuln.Access)
				}
				if enrichedVuln.Complexity != enums.ComplexityTypeLow {
					t.Errorf("Expected ComplexityTypeLow, got %v", enrichedVuln.Complexity)
				}
				if enrichedVuln.PrivilegesRequired != enums.PrivilegesRequiredNone {
					t.Errorf("Expected PrivilegesTypeNone, got %v", enrichedVuln.PrivilegesRequired)
				}
				if enrichedVuln.IntegrityImpact != enums.ImpactTypeHigh {
					t.Errorf("Expected ImpactTypeHigh, got %v", enrichedVuln.IntegrityImpact)
				}
				if enrichedVuln.AvailabilityImpact != enums.ImpactTypeNone {
					t.Errorf("Expected ImpactTypeNone, got %v", enrichedVuln.AvailabilityImpact)
				}
				if enrichedVuln.Exploit.Exploitability != enums.ExploitabilityTypeFunctional {
					t.Errorf("Expected ExploitMaturityTypeFunctional, got %v", enrichedVuln.Exploit.Exploitability)
				}
				if enrichedVuln.BaseSeverity != enums.SeverityTypeHigh {
					t.Errorf("Expected BaseSeverity High, got %v", enrichedVuln.BaseSeverity)
				}
			},
		},
		{
			name:         "Enrich with CVSS v3.0 Data (no v3.1)",
			nvdVulnInput: createMockNvdVulnerabilityWithV30Only(), // Helper for v3.0 data
			wantErr:      false,
			assertFunc: func(t *testing.T, enrichedVuln *tools.Vulnerability) {
				if enrichedVuln.BaseCVSSScore != 6.8 {
					t.Errorf("Expected BaseCVSSScore to be 6.8, got %f", enrichedVuln.BaseCVSSScore)
				}
				if enrichedVuln.Access != enums.AccessTypeNetwork {
					t.Errorf("Expected AccessTypeNetwork, got %v", enrichedVuln.Access)
				}
				if enrichedVuln.Complexity != enums.ComplexityTypeLow {
					t.Errorf("Expected ComplexityTypeLow, got %v", enrichedVuln.Complexity)
				}
				if enrichedVuln.PrivilegesRequired != enums.PrivilegesRequiredNone {
					t.Errorf("Expected PrivilegesTypeNone, got %v", enrichedVuln.PrivilegesRequired)
				}
				if enrichedVuln.IntegrityImpact != enums.ImpactTypeLow {
					t.Errorf("Expected ImpactTypeLow, got %v", enrichedVuln.IntegrityImpact)
				}
				if enrichedVuln.AvailabilityImpact != enums.ImpactTypeLow {
					t.Errorf("Expected ImpactTypeLow, got %v", enrichedVuln.AvailabilityImpact)
				}
				if enrichedVuln.BaseSeverity != enums.SeverityTypeMedium {
					t.Errorf("Expected BaseSeverity Medium, got %v", enrichedVuln.BaseSeverity)
				}
			},
		},
		{
			name:         "Enrich with CVSS v2 Data (no v3.x)",
			nvdVulnInput: createMockNvdVulnerabilityWithV2Only(), // Helper for v2 data
			wantErr:      false,
			assertFunc: func(t *testing.T, enrichedVuln *tools.Vulnerability) {
				if enrichedVuln.BaseCVSSScore != 5.0 {
					t.Errorf("Expected BaseCVSSScore to be 5.0, got %f", enrichedVuln.BaseCVSSScore)
				}
				if enrichedVuln.Access != enums.AccessTypeNetwork {
					t.Errorf("Expected AccessTypeNetwork, got %v", enrichedVuln.Access)
				}
				if enrichedVuln.Complexity != enums.ComplexityTypeLow {
					t.Errorf("Expected ComplexityTypeLow, got %v", enrichedVuln.Complexity)
				}
				if enrichedVuln.IntegrityImpact != enums.ImpactTypeNone {
					t.Errorf("Expected ImpactTypeNone, got %v", enrichedVuln.IntegrityImpact)
				}
				if enrichedVuln.AvailabilityImpact != enums.ImpactTypeNone {
					t.Errorf("Expected ImpactTypeNone, got %v", enrichedVuln.AvailabilityImpact)
				}
				if enrichedVuln.BaseSeverity != enums.SeverityTypeMedium {
					t.Errorf("Expected BaseSeverity Medium, got %v", enrichedVuln.BaseSeverity)
				}
			},
		},
		{
			name:         "Handle Missing Metrics",
			nvdVulnInput: createMockNvdVulnerabilityNoMetrics(), // Helper for no metrics
			wantErr:      false,
			assertFunc: func(t *testing.T, enrichedVuln *tools.Vulnerability) {
				if enrichedVuln.BaseCVSSScore != 0.0 {
					t.Errorf("Expected BaseCVSSScore to be 0.0 when metrics are missing, got %f", enrichedVuln.BaseCVSSScore)
				}
				if enrichedVuln.BaseSeverity != enums.SeverityTypeUnknown {
					t.Errorf("Expected BaseSeverity to be Unknown when metrics are missing, got %v", enrichedVuln.BaseSeverity)
				}
				if enrichedVuln.Access != enums.AccessTypeUnknown {
					t.Errorf("Expected Access to be Unknown when metrics are missing, got %v", enrichedVuln.Access)
				}
				if enrichedVuln.Complexity != enums.ComplexityTypeUnknown {
					t.Errorf("Expected Complexity to be Unknown when metrics are missing, got %v", enrichedVuln.Complexity)
				}
				if enrichedVuln.IntegrityImpact != enums.ImpactTypeUnknown {
					t.Errorf("Expected IntegrityImpact to be Unknown when metrics are missing, got %v", enrichedVuln.IntegrityImpact)
				}
				if enrichedVuln.AvailabilityImpact != enums.ImpactTypeUnknown {
					t.Errorf("Expected AvailabilityImpact to be Unknown when metrics are missing, got %v", enrichedVuln.AvailabilityImpact)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vuln := &tools.Vulnerability{} // Create a new vuln for each test
			err := enrichVulnerabilityWithNvdData(vuln, tc.nvdVulnInput)

			if tc.wantErr {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				// You might want to assert the specific error type if you have defined custom errors
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				if tc.assertFunc != nil {
					tc.assertFunc(t, vuln) // Call assertion function
				}
			}
		})
	}
}

// --- Helper functions to create mock dto.Vulnerability data ---

func createMockNvdVulnerabilityWithV31() dto.Vulnerability {
	maturityFunctional := dto.ExploitCodeMaturityTypeFunctional

	return dto.Vulnerability{
		Cve: dto.CveDetail{
			ID:               "CVE-TEST-V31",
			SourceIdentifier: "TestSource",
			Descriptions: []dto.Description{
				{Lang: "en", Value: "Test Description v3.1"},
			},
			References: []dto.Reference{
				{URL: "http://example.com/ref1"},
			},
			Metrics: &dto.Metrics{
				CvssMetricV31: []dto.CvssMetricV31{
					{
						CvssData: dto.CvssDataV31{
							BaseScore:             7.5,
							BaseSeverity:          "HIGH",
							AttackVector:          "NETWORK",
							AttackComplexity:      "LOW",
							PrivilegesRequired:    "NONE",
							UserInteraction:       "NONE",
							Scope:                 "UNCHANGED",
							ConfidentialityImpact: "HIGH",
							IntegrityImpact:       "HIGH",
							AvailabilityImpact:    "NONE",
							VectorString:          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
							Version:               "3.1",
							ExploitCodeMaturity:   &maturityFunctional, // Example Exploitability
						},
						ExploitabilityScore: 3.9,
						ImpactScore:         5.9,
						// ... other fields if needed for tests ...
					},
				},
			},
			Published:    "2024-11-21T02:09:48.080",
			LastModified: "2024-11-21T02:09:48.080",
		},
	}
}

func createMockNvdVulnerabilityWithV30Only() dto.Vulnerability {
	return dto.Vulnerability{
		Cve: dto.CveDetail{
			ID:               "CVE-TEST-V30",
			SourceIdentifier: "TestSource",
			Descriptions: []dto.Description{
				{Lang: "en", Value: "Test Description v3.0 Only"},
			},
			References: []dto.Reference{
				{URL: "http://example.com/ref-v30"},
			},
			Metrics: &dto.Metrics{
				CvssMetricV30: []dto.CvssMetricV30{
					{
						CvssData: dto.CvssDataV30{
							Version:               "3.0",
							VectorString:          "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
							AttackVector:          "NETWORK",
							AttackComplexity:      "LOW",
							PrivilegesRequired:    "NONE",
							UserInteraction:       "REQUIRED",
							Scope:                 "UNCHANGED",
							ConfidentialityImpact: "LOW",
							IntegrityImpact:       "LOW",
							AvailabilityImpact:    "LOW",
							BaseScore:             6.8,
							BaseSeverity:          "MEDIUM",
						},
						ExploitabilityScore: 2.8,
						ImpactScore:         3.9,
					},
				},
			},
			Published:    "2024-11-21T02:09:48.080",
			LastModified: "2024-11-21T02:09:48.080",
		},
	}
}

func createMockNvdVulnerabilityWithV2Only() dto.Vulnerability {
	return dto.Vulnerability{
		Cve: dto.CveDetail{
			ID:               "CVE-TEST-V2",
			SourceIdentifier: "TestSource",
			Descriptions: []dto.Description{
				{Lang: "en", Value: "Test Description v2 Only"},
			},
			References: []dto.Reference{
				{URL: "http://example.com/ref-v2"},
			},
			Metrics: &dto.Metrics{
				CvssMetricV2: []dto.CvssMetricV2{
					{
						CvssData: dto.CvssDataV2{
							Version:               "2.0",
							VectorString:          "(AV:N/AC:L/Au:N/C:P/I:N/A:N)",
							AccessVector:          "NETWORK",
							AccessComplexity:      "LOW",
							Authentication:        "NONE",
							ConfidentialityImpact: "PARTIAL",
							IntegrityImpact:       "NONE",
							AvailabilityImpact:    "NONE",
							BaseScore:             5.0,
						},
						ExploitabilityScore: 10.0,
						ImpactScore:         2.9,
						BaseSeverity:        "MEDIUM",
					},
				},
			},
			Published:    "2024-11-21T02:09:48.080",
			LastModified: "2024-11-21T02:09:48.080",
		},
	}
}

func createMockNvdVulnerabilityNoMetrics() dto.Vulnerability {
	return dto.Vulnerability{
		Cve: dto.CveDetail{
			ID:               "CVE-TEST-NO-METRICS",
			SourceIdentifier: "TestSource",
			Descriptions: []dto.Description{
				{Lang: "en", Value: "Test Description No Metrics"},
			},
			References: []dto.Reference{
				{URL: "http://example.com/ref-no-metrics"},
			},
			Metrics:      nil, // Metrics are nil/missing
			Published:    "2024-11-21T02:09:48.080",
			LastModified: "2024-11-21T02:09:48.080",
		},
	}
}

func Test_parseVendorComments(t *testing.T) {
	date1Str := "2008-12-18T00:00:00"
	date1, err := parseNvdVendorCommentDateTime(date1Str)
	if err != nil {
		t.Fatalf("Failed to parse NVD test date time %s: %+v", date1Str, err)
	}

	testsCases := []struct {
		name string
		// Named input parameters for target function.
		nvdComments []dto.VendorComment
		want        []tools.VendorComment
	}{
		{
			name: "Valid nvd vendor comments",
			nvdComments: []dto.VendorComment{
				{
					Organization: "Red Hat",
					Comment:      "Not vulnerable. This issue did not affect the versions of the util-linux packages (providing /bin/login), as shipped with Red Hat Enterprise Linux 2.1, 3, 4 or 5.",
					LastModified: date1Str,
				},
				{
					Organization: "Blue Hat",
					Comment:      "Not vulnerable. This issue did not affect the versions of the util-linux packages (providing /bin/login), as shipped with Red Hat Enterprise Linux 2.1, 3, 4 or 5.",
					LastModified: date1Str,
				},
			},
			want: []tools.VendorComment{
				{
					Organization: "Red Hat",
					Comment:      "Not vulnerable. This issue did not affect the versions of the util-linux packages (providing /bin/login), as shipped with Red Hat Enterprise Linux 2.1, 3, 4 or 5.",
					LastModified: date1,
				},
				{
					Organization: "Blue Hat",
					Comment:      "Not vulnerable. This issue did not affect the versions of the util-linux packages (providing /bin/login), as shipped with Red Hat Enterprise Linux 2.1, 3, 4 or 5.",
					LastModified: date1,
				},
			},
		},
		{
			name: "Valid and invalid nvd vendor comments",
			nvdComments: []dto.VendorComment{
				{
					Organization: "Red Hat",
					Comment:      "Not vulnerable. This issue did not affect the versions of the util-linux packages (providing /bin/login), as shipped with Red Hat Enterprise Linux 2.1, 3, 4 or 5.",
					LastModified: date1Str,
				},
				{
					Organization: "Blue Hat",
					Comment:      "Not vulnerable. This issue did not affect the versions of the util-linux packages (providing /bin/login), as shipped with Red Hat Enterprise Linux 2.1, 3, 4 or 5.",
					LastModified: "2nd of May 2022 at 15:30:45",
				},
			},
			want: []tools.VendorComment{
				{
					Organization: "Red Hat",
					Comment:      "Not vulnerable. This issue did not affect the versions of the util-linux packages (providing /bin/login), as shipped with Red Hat Enterprise Linux 2.1, 3, 4 or 5.",
					LastModified: date1,
				},
			},
		},
		{
			name:        "Empty vendor comments",
			nvdComments: []dto.VendorComment{},
			want:        []tools.VendorComment{},
		},
	}
	for _, tc := range testsCases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseVendorComments(tc.nvdComments)

			assert.Equal(t, len(tc.want), len(got))
			for i, wantComment := range tc.want {
				assert.Equal(t, wantComment.Organization, got[i].Organization)
				assert.Equal(t, wantComment.Comment, got[i].Comment)
				assert.Equal(t, wantComment.LastModified, got[i].LastModified)
			}
		})
	}
}
