package services

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/Ullaakut/nmap/v2"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/vulnerability-analysis/pkg/interfaces"
)

type NmapService struct{}

var _ interfaces.INmapService = (*NmapService)(nil)

func NewNmapService() *NmapService {
	return &NmapService{}
}

func (s *NmapService) RunScan(ctx context.Context, target string) (tools.ToolResult, error) {
	slog.Info("Starting Nmap scan...", slog.String("target", target))

	// Combine timeout and cancellation contexts
	ctxWithTimeout, cancel := context.WithTimeout(
		ctx,
		calculateTimeout([]string{target}),
	)
	defer cancel()

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(target),
		nmap.WithMostCommonPorts(100),
		nmap.WithServiceInfo(),
		nmap.WithSkipHostDiscovery(),
		nmap.WithOSDetection(),
		nmap.WithOSScanGuess(),
		nmap.WithContext(ctxWithTimeout),
	)
	if err != nil {
		return s.errorResult(
				err,
				fmt.Sprintf("Failed to create Nmap scanner: %s", err.Error())),
			fmt.Errorf("failed to create nmap scanner: %w", err)
	}

	res, warnings, err := scanner.Run()
	if err := handleScanErrors(ctxWithTimeout, err, warnings, 1); err != nil {
		return s.errorResult(
				err,
				fmt.Sprintf("scan error: %s", err.Error())),
			fmt.Errorf("scan error: %w", err)
	}

	slog.Info("Nmap scan completed, moving on to vulnerability detection:",
		slog.Int("hosts_up", len(res.Hosts)),
		slog.Any("time_elapsed", res.Stats.Finished.Elapsed))

	return s.procesScanResults(res, target), nil
}

func (s *NmapService) procesScanResults(res *nmap.Run, target string) tools.ToolResult {
	if len(res.Hosts) == 0 {
		return s.errorResult(fmt.Errorf("no hosts found in scan results"), "No hosts found")
	}

	host := res.Hosts[0]

	if len(host.Ports) == 0 || len(host.Addresses) == 0 {
		slog.Warn("No ports or addresses found", slog.Any("host", host))
		return s.errorResult(
			fmt.Errorf("no ports or addresses found for host %s", target),
			"No ports or addresses found")
	}

	if !s.matchHostToTarget(host, target) {
		slog.Warn("Unmatched host in scan results", slog.Any("host", host))
		return s.errorResult(
			fmt.Errorf("unmatched host in scan results"),
			"Unmatched host")
	}

	nmapResult := createNmapResult(host)
	slog.Debug("Nmap scan for host completed", slog.Any("nmap_result", nmapResult))

	return tools.ToolResult{
		Tool:      enums.ToolNmap,
		Result:    nmapResult,
		Timestamp: time.Now().UTC(),
	}
}

// getMostLikelyOS checks for most likely OS considering TCP matches
func getMostLikelyOS(host nmap.Host) tools.OSData {
	if len(host.OS.Matches) == 0 {
		return tools.OSData{}
	}

	var mostLikelyOS tools.OSData
	maxAccuracy := 0
	fingerprint := ""

	if len(host.OS.Fingerprints) > 0 {
		fingerprint = host.OS.Fingerprints[0].Fingerprint
	}

	for _, match := range host.OS.Matches {
		if match.Accuracy <= maxAccuracy {
			continue
		}

		if len(match.Classes) == 0 {
			slog.Debug("OS Match found without Classes",
				slog.String("os_name", match.Name))
			continue
		}
		class := match.Classes[0]

		// Populate OSData with available class information, CPE might be empty
		currentOSData := tools.OSData{
			Name:        match.Name,
			Accuracy:    match.Accuracy,
			Family:      class.Family,
			Type:        class.Type,
			FingerPrint: fingerprint,
			CPE:         "", // Initialize CPE as empty string, will be populated if available
		}

		if len(class.CPEs) > 0 {
			standardizedCPE, err := standardizeCPE(string(class.CPEs[0]))
			if err != nil {
				slog.Error("Failed to standardize OS CPE, skipping to next match",
					slog.String("cpe", string(class.CPEs[0])),
					slog.Any("error", err))
				continue
			}
			if err := isValidCPE(standardizedCPE); err != nil {
				slog.Error("OS CPE is invalid, skipping to next match",
					slog.String("cpe", standardizedCPE),
					slog.Any("error", err))
				continue
			}
			currentOSData.CPE = standardizedCPE
		} else { // Skip if no CPEs in class
			slog.Debug("OS Class found without CPEs", slog.String("os_name", match.Name))
			continue
		}

		// Found a more accurate match with classes and CPEs, populate OSData
		mostLikelyOS = currentOSData
		maxAccuracy = match.Accuracy
	}

	return mostLikelyOS
}

func parseHostName(host nmap.Host) string {
	// If host type is IP, we won't get a Hostname
	var hostName string

	if len(host.Hostnames) > 0 {
		hostName = host.Hostnames[0].Name
	}

	return hostName
}

func parseHostAddress(host nmap.Host) string {
	var hostAddress string

	if len(host.Addresses) > 0 {
		hostAddress = host.Addresses[0].Addr
	}

	return hostAddress
}

// handleScanErrors logs warnings and processes potential scan errors.
func handleScanErrors(ctx context.Context, err error, warnings []string, targetCount int) error {
	if warnings != nil {
		slog.Default().Warn("Nmap raised warnings:", slog.Any("nmap_warnings", warnings))
	}
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("scan timeout after %d seconds", 240*targetCount)
		}
		return fmt.Errorf("scan error: %w", err)
	}
	return nil
}

// calculateTimeout calculates the scan timeout based on the number of targets.
func calculateTimeout(targets []string) time.Duration {
	timePerTarget := 240
	timeout := timePerTarget * len(targets)
	return time.Duration(timeout) * time.Second
}

// createNmapResult builds the NmapResult for a given host.
func createNmapResult(host nmap.Host) *tools.NmapResult {
	osData := getMostLikelyOS(host)
	osVulns := processNVDDataForOS(osData)
	osData.Vulnerabilities = append(osData.Vulnerabilities, osVulns...)

	return &tools.NmapResult{
		HostName:     parseHostName(host),
		HostAddress:  parseHostAddress(host),
		MostLikelyOS: osData,
		ScannedPorts: processPorts(host.Ports),
	}
}

// processPorts extracts port information from the scan result and uses CPEs to query NVD API.
func processPorts(ports []nmap.Port) []tools.PortData {
	portDataSlice := make([]tools.PortData, 0, len(ports))
	rateLimiter := time.Tick(7 * time.Second)

	for _, port := range ports {
		var validCPE string
		for _, cpe := range port.Service.CPEs {
			standardizedCPE, err := standardizeCPE(string(cpe))
			if err != nil {
				slog.Warn("Could not standardize CPE, skipping to next CPE",
					slog.Int("port_id", int(port.ID)),
					slog.String("service_name", port.Service.Name),
					slog.String("cpe", string(cpe)),
					slog.Any("error", err))
				continue
			}
			// Validate CPE before assigning it
			if err := isValidCPE(standardizedCPE); err != nil {
				slog.Debug("Parsed invalid CPE, skipping to next CPE",
					slog.Int("port_id", int(port.ID)),
					slog.String("service_name", port.Service.Name),
					slog.String("cpe", string(cpe)),
					slog.String("standardized_cpe", string(standardizedCPE)),
					slog.Any("error", err))
				continue
			}
			validCPE = standardizedCPE
			break // Exit after the first valid CPE
		}

		p := tools.PortData{
			ID:       port.ID,
			Protocol: port.Protocol,
			Service: tools.Service{
				Name:       port.Service.Name,
				Version:    port.Service.Version,
				Confidence: port.Service.Confidence,
				CPE:        validCPE,
			},
			Product: port.Service.Product,
			State:   port.State.State,
		}

		<-rateLimiter // Wait for rate limiter to allow the next request
		vulns := processNVDDataForPort(port, validCPE)
		p.Vulnerabilities = vulns

		portDataSlice = append(portDataSlice, p)
	}

	return portDataSlice
}

func processNVDDataForPort(port nmap.Port, validCPE string) []tools.Vulnerability {
	if validCPE == "" {
		return []tools.Vulnerability{}
	}

	nvdData, err := fetchNvdDataByCPE(validCPE, baseNvdAPIURL)
	if err != nil {
		slog.Warn("Failed to fetch data by CPE, returning empty Vulnerabilities",
			slog.String("service_name", port.Service.Name),
			slog.Int("port_id", int(port.ID)),
			slog.String("valid_cpe", validCPE),
			slog.Any("error", err),
		)
		return []tools.Vulnerability{}
	}
	slog.Info("Found vulnerabilities for Service from NVD",
		slog.Int("n_vulners", len(nvdData.Vulnerabilities)),
		slog.String("service_name", port.Service.Name),
		slog.Int("port_id", int(port.ID)),
		slog.String("valid_cpe", validCPE),
		slog.Any("error", err),
	)

	vulns := make([]tools.Vulnerability, 0, len(nvdData.Vulnerabilities))
	for _, nvdVuln := range nvdData.Vulnerabilities {
		var vuln tools.Vulnerability

		if err := enrichVulnerabilityWithNvdData(&vuln, nvdVuln); err != nil {
			slog.Error("Failed to enrich vulnerability with nvd data, skipping to next vulnerability",
				slog.String("host_name", port.Service.Hostname),
				slog.Int("port_id", int(port.ID)),
				slog.String("valid_cpe", validCPE),
				slog.Any("error", err))
			continue
		}
		vulns = append(vulns, vuln)
	}
	return vulns
}

func processNVDDataForOS(os tools.OSData) []tools.Vulnerability {
	if os.CPE == "" {
		slog.Debug("OSData has empty CPE, returning empty Vulnerabilities")
		return []tools.Vulnerability{}
	}

	nvdData, err := fetchNvdDataByCPE(os.CPE, baseNvdAPIURL)
	if err != nil {
		slog.Warn("Failed to fetch data by CPE, returning empty Vulnerabilities",
			slog.String("os_name", os.Name),
			slog.String("os_family", os.Family),
			slog.String("cpe", os.CPE),
			slog.Any("error", err),
		)
		return []tools.Vulnerability{}
	}
	slog.Info("Found vulnerabilities for OS from NVD",
		slog.Int("n_vulners", len(nvdData.Vulnerabilities)))

	vulns := make([]tools.Vulnerability, 0, len(nvdData.Vulnerabilities))
	for _, nvdVuln := range nvdData.Vulnerabilities {
		var vuln tools.Vulnerability

		if err := enrichVulnerabilityWithNvdData(&vuln, nvdVuln); err != nil {
			slog.Error("Failed to enrich OS vulnerability with nvd data, skipping to next vulnerability",
				slog.String("os_name", os.Name),
				slog.String("os_family", os.Family),
				slog.String("cpe", os.CPE),
				slog.Any("error", err),
			)
			continue
		}
		vulns = append(vulns, vuln)
	}
	return vulns
}

func (s *NmapService) matchHostToTarget(host nmap.Host, target string) bool {
	// Check addresses (IPv4, IPv6)
	for _, address := range host.Addresses {
		ip := net.ParseIP(address.Addr)
		if ip != nil {
			if ip.String() == target {
				return true
			}
		}
	}

	// Check hostnames (Domains) if no match was found with address
	for _, hostname := range host.Hostnames {
		if hostname.Name == target {
			return true
		}
	}

	return false
}

// errorResult is a helper function to create an error ToolResult.
func (s *NmapService) errorResult(err error, message string) tools.ToolResult {
	slog.Error(message, slog.Any("error", err))
	return tools.ToolResult{
		Tool:   enums.ToolNmap,
		Result: &tools.NmapResult{},
		Err: &tools.ToolError{
			Code:    enums.ToolError,
			Message: message,
		},
		Timestamp: time.Now().UTC(),
	}
}
