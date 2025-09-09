package surveyor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// DiffError represents errors in the differential scanner
var (
	ErrNoPreviousScan = fmt.Errorf("no previous scan results found")
	ErrInvalidScanID  = fmt.Errorf("invalid scan ID provided")
)

// DiffScanner handles differential scanning functionality
type DiffScanner struct {
	config        *Config
	logger        *zap.Logger
	scanHistory   map[string]*ScanHistoryEntry
	historyFile   string
	maxHistoryAge time.Duration
}

// ScanHistoryEntry represents an entry in the scan history
type ScanHistoryEntry struct {
	ScanID    string       `json:"scan_id"`
	Timestamp time.Time    `json:"timestamp"`
	Targets   []string     `json:"targets"`
	Results   []*ScanResult `json:"results"`
}

// ScanDiffResult represents the difference between two scan results
type ScanDiffResult struct {
	PreviousScanID string    `json:"previous_scan_id"`
	CurrentScanID  string    `json:"current_scan_id"`
	PreviousTime   time.Time `json:"previous_time"`
	CurrentTime    time.Time `json:"current_time"`
	
	// New hosts found in current scan but not in previous
	NewHosts []string `json:"new_hosts"`
	
	// Hosts missing in current scan that were in previous
	MissingHosts []string `json:"missing_hosts"`
	
	// Per-host changes
	HostChanges map[string]*HostDiff `json:"host_changes"`
	
	// Summary stats
	Summary DiffSummary `json:"summary"`
}

// HostDiff represents changes in a single host between scans
type HostDiff struct {
	Host           string   `json:"host"`
	OSChanged      bool     `json:"os_changed,omitempty"`
	PreviousOS     string   `json:"previous_os,omitempty"`
	CurrentOS      string   `json:"current_os,omitempty"`
	NewTCPPorts    []int    `json:"new_tcp_ports,omitempty"`
	ClosedTCPPorts []int    `json:"closed_tcp_ports,omitempty"`
	NewUDPPorts    []int    `json:"new_udp_ports,omitempty"`
	ClosedUDPPorts []int    `json:"closed_udp_ports,omitempty"`
	NewServices    []string `json:"new_services,omitempty"`
	RemovedServices []string `json:"removed_services,omitempty"`
	NewVulns       []string `json:"new_vulnerabilities,omitempty"`
	ResolvedVulns  []string `json:"resolved_vulnerabilities,omitempty"`
}

// DiffSummary provides summary statistics for a scan diff
type DiffSummary struct {
	TotalHostsChanged     int `json:"total_hosts_changed"`
	TotalNewHosts         int `json:"total_new_hosts"`
	TotalMissingHosts     int `json:"total_missing_hosts"`
	TotalNewTCPPorts      int `json:"total_new_tcp_ports"`
	TotalClosedTCPPorts   int `json:"total_closed_tcp_ports"`
	TotalNewUDPPorts      int `json:"total_new_udp_ports"`
	TotalClosedUDPPorts   int `json:"total_closed_udp_ports"`
	TotalNewServices      int `json:"total_new_services"`
	TotalRemovedServices  int `json:"total_removed_services"`
	TotalNewVulns         int `json:"total_new_vulnerabilities"`
	TotalResolvedVulns    int `json:"total_resolved_vulnerabilities"`
	RiskScore             int `json:"risk_score"`
}

// NewDiffScanner creates a new differential scanner
func NewDiffScanner(config *Config, logger *zap.Logger) (*DiffScanner, error) {
	// Ensure history directory exists
	historyDir := filepath.Join(config.ReportDir, "history")
	if err := os.MkdirAll(historyDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create history directory: %w", err)
	}
	
	historyFile := filepath.Join(historyDir, "scan_history.json")
	
	// Create scanner
	scanner := &DiffScanner{
		config:        config,
		logger:        logger.With(zap.String("component", "diff_scanner")),
		scanHistory:   make(map[string]*ScanHistoryEntry),
		historyFile:   historyFile,
		maxHistoryAge: time.Duration(30*24) * time.Hour, // 30 days by default
	}
	
	// Load history if available
	if err := scanner.loadHistory(); err != nil {
		scanner.logger.Warn("Failed to load scan history", zap.Error(err))
		// Continue without history - will create new one
	}
	
	return scanner, nil
}

// loadHistory loads scan history from the history file
func (d *DiffScanner) loadHistory() error {
	if _, err := os.Stat(d.historyFile); os.IsNotExist(err) {
		// History file doesn't exist yet, not an error
		return nil
	}
	
	data, err := os.ReadFile(d.historyFile)
	if err != nil {
		return fmt.Errorf("failed to read history file: %w", err)
	}
	
	var history []ScanHistoryEntry
	if err := json.Unmarshal(data, &history); err != nil {
		return fmt.Errorf("failed to parse history data: %w", err)
	}
	
	// Load into map and clean up old entries
	now := time.Now()
	for _, entry := range history {
		// Skip entries older than max age
		if now.Sub(entry.Timestamp) > d.maxHistoryAge {
			continue
		}
		d.scanHistory[entry.ScanID] = &entry
	}
	
	d.logger.Info("Loaded scan history", 
		zap.Int("entry_count", len(d.scanHistory)),
		zap.String("history_file", d.historyFile),
	)
	
	return nil
}

// saveHistory persists scan history to the history file
func (d *DiffScanner) saveHistory() error {
	// Convert map to slice for serialization
	var history []ScanHistoryEntry
	for _, entry := range d.scanHistory {
		history = append(history, *entry)
	}
	
	// Sort by timestamp descending (newest first)
	sort.Slice(history, func(i, j int) bool {
		return history[i].Timestamp.After(history[j].Timestamp)
	})
	
	// Marshal to JSON
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal history: %w", err)
	}
	
	// Write to file
	if err := os.WriteFile(d.historyFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write history file: %w", err)
	}
	
	d.logger.Debug("Saved scan history", 
		zap.Int("entry_count", len(history)),
		zap.String("history_file", d.historyFile),
	)
	
	return nil
}

// SaveScanResults saves the current scan results to history
func (d *DiffScanner) SaveScanResults(scanID string, targets []string, results []*ScanResult) error {
	d.logger.Info("Saving scan results to history", 
		zap.String("scan_id", scanID),
		zap.Strings("targets", targets),
		zap.Int("result_count", len(results)),
	)
	
	// Create a new history entry
	entry := &ScanHistoryEntry{
		ScanID:    scanID,
		Timestamp: time.Now(),
		Targets:   targets,
		Results:   results,
	}
	
	// Add to history
	d.scanHistory[scanID] = entry
	
	// Save to disk
	if err := d.saveHistory(); err != nil {
		d.logger.Error("Failed to save scan history", zap.Error(err))
		return err
	}
	
	return nil
}

// GetLastScanID returns the scan ID of the most recent scan
func (d *DiffScanner) GetLastScanID() (string, error) {
	var lastScanID string
	var lastTime time.Time
	
	if len(d.scanHistory) == 0 {
		return "", ErrNoPreviousScan
	}
	
	// Find most recent scan
	for id, entry := range d.scanHistory {
		if lastScanID == "" || entry.Timestamp.After(lastTime) {
			lastScanID = id
			lastTime = entry.Timestamp
		}
	}
	
	return lastScanID, nil
}

// GetScanHistory returns all scan history entries
func (d *DiffScanner) GetScanHistory() ([]*ScanHistoryEntry, error) {
	history := make([]*ScanHistoryEntry, 0, len(d.scanHistory))
	
	for _, entry := range d.scanHistory {
		history = append(history, entry)
	}
	
	// Sort by timestamp descending (newest first)
	sort.Slice(history, func(i, j int) bool {
		return history[i].Timestamp.After(history[j].Timestamp)
	})
	
	return history, nil
}

// DiffWithPrevious compares current scan results with the previous scan
func (d *DiffScanner) DiffWithPrevious(currentID string, currentResults []*ScanResult) (*ScanDiffResult, error) {
	// Get the most recent scan before the current one
	var previousID string
	var previousTime time.Time
	var previousResults []*ScanResult
	
	// Ensure current scan exists
	currentEntry, exists := d.scanHistory[currentID]
	if !exists {
		return nil, fmt.Errorf("%w: %s", ErrInvalidScanID, currentID)
	}
	
	// Find previous scan
	for id, entry := range d.scanHistory {
		if id == currentID {
			continue // Skip current scan
		}
		
		// Check if this is a newer previous scan
		if (previousID == "" || entry.Timestamp.After(previousTime)) && entry.Timestamp.Before(currentEntry.Timestamp) {
			previousID = id
			previousTime = entry.Timestamp
			previousResults = entry.Results
		}
	}
	
	if previousID == "" {
		return nil, ErrNoPreviousScan
	}
	
	// Create diff result
	diff := &ScanDiffResult{
		PreviousScanID: previousID,
		CurrentScanID:  currentID,
		PreviousTime:   previousTime,
		CurrentTime:    currentEntry.Timestamp,
		HostChanges:    make(map[string]*HostDiff),
	}
	
	// Create maps for easy lookups
	previousHosts := make(map[string]*ScanResult)
	currentHosts := make(map[string]*ScanResult)
	
	for _, result := range previousResults {
		previousHosts[result.Host] = result
	}
	
	for _, result := range currentResults {
		currentHosts[result.Host] = result
	}
	
	// Find new and missing hosts
	for host := range currentHosts {
		if _, exists := previousHosts[host]; !exists {
			diff.NewHosts = append(diff.NewHosts, host)
		}
	}
	
	for host := range previousHosts {
		if _, exists := currentHosts[host]; !exists {
			diff.MissingHosts = append(diff.MissingHosts, host)
		}
	}
	
	// Find changes in hosts present in both scans
	for host, currentResult := range currentHosts {
		previousResult, exists := previousHosts[host]
		if !exists {
			continue // New host, already counted
		}
		
		hostDiff := d.compareHostResults(previousResult, currentResult)
		if hostDiff != nil {
			diff.HostChanges[host] = hostDiff
			
			// Update summary stats
			diff.Summary.TotalHostsChanged++
			diff.Summary.TotalNewTCPPorts += len(hostDiff.NewTCPPorts)
			diff.Summary.TotalClosedTCPPorts += len(hostDiff.ClosedTCPPorts)
			diff.Summary.TotalNewUDPPorts += len(hostDiff.NewUDPPorts)
			diff.Summary.TotalClosedUDPPorts += len(hostDiff.ClosedUDPPorts)
			diff.Summary.TotalNewServices += len(hostDiff.NewServices)
			diff.Summary.TotalRemovedServices += len(hostDiff.RemovedServices)
			diff.Summary.TotalNewVulns += len(hostDiff.NewVulns)
			diff.Summary.TotalResolvedVulns += len(hostDiff.ResolvedVulns)
		}
	}
	
	// Update total summary stats
	diff.Summary.TotalNewHosts = len(diff.NewHosts)
	diff.Summary.TotalMissingHosts = len(diff.MissingHosts)
	
	// Calculate risk score (1-100)
	diff.Summary.RiskScore = calculateRiskScore(diff)
	
	d.logger.Info("Scan diff completed",
		zap.String("current_scan", currentID),
		zap.String("previous_scan", previousID),
		zap.Int("hosts_changed", diff.Summary.TotalHostsChanged),
		zap.Int("new_hosts", diff.Summary.TotalNewHosts),
		zap.Int("missing_hosts", diff.Summary.TotalMissingHosts),
		zap.Int("risk_score", diff.Summary.RiskScore),
	)
	
	return diff, nil
}

// DiffWithSpecific compares current scan results with a specific previous scan by ID
func (d *DiffScanner) DiffWithSpecific(currentID, previousID string) (*ScanDiffResult, error) {
	// Ensure both scans exist
	currentEntry, currentExists := d.scanHistory[currentID]
	if !currentExists {
		return nil, fmt.Errorf("%w: %s", ErrInvalidScanID, currentID)
	}
	
	previousEntry, previousExists := d.scanHistory[previousID]
	if !previousExists {
		return nil, fmt.Errorf("%w: %s", ErrInvalidScanID, previousID)
	}
	
	return d.createDiff(previousEntry, currentEntry)
}

// createDiff creates a diff between two scan entries
func (d *DiffScanner) createDiff(previous, current *ScanHistoryEntry) (*ScanDiffResult, error) {
	// Create diff result
	diff := &ScanDiffResult{
		PreviousScanID: previous.ScanID,
		CurrentScanID:  current.ScanID,
		PreviousTime:   previous.Timestamp,
		CurrentTime:    current.Timestamp,
		HostChanges:    make(map[string]*HostDiff),
	}
	
	// Create maps for easy lookups
	previousHosts := make(map[string]*ScanResult)
	currentHosts := make(map[string]*ScanResult)
	
	for _, result := range previous.Results {
		previousHosts[result.Host] = result
	}
	
	for _, result := range current.Results {
		currentHosts[result.Host] = result
	}
	
	// Find new and missing hosts
	for host := range currentHosts {
		if _, exists := previousHosts[host]; !exists {
			diff.NewHosts = append(diff.NewHosts, host)
		}
	}
	
	for host := range previousHosts {
		if _, exists := currentHosts[host]; !exists {
			diff.MissingHosts = append(diff.MissingHosts, host)
		}
	}
	
	// Find changes in hosts present in both scans
	for host, currentResult := range currentHosts {
		previousResult, exists := previousHosts[host]
		if !exists {
			continue // New host, already counted
		}
		
		hostDiff := d.compareHostResults(previousResult, currentResult)
		if hostDiff != nil {
			diff.HostChanges[host] = hostDiff
			
			// Update summary stats
			diff.Summary.TotalHostsChanged++
			diff.Summary.TotalNewTCPPorts += len(hostDiff.NewTCPPorts)
			diff.Summary.TotalClosedTCPPorts += len(hostDiff.ClosedTCPPorts)
			diff.Summary.TotalNewUDPPorts += len(hostDiff.NewUDPPorts)
			diff.Summary.TotalClosedUDPPorts += len(hostDiff.ClosedUDPPorts)
			diff.Summary.TotalNewServices += len(hostDiff.NewServices)
			diff.Summary.TotalRemovedServices += len(hostDiff.RemovedServices)
			diff.Summary.TotalNewVulns += len(hostDiff.NewVulns)
			diff.Summary.TotalResolvedVulns += len(hostDiff.ResolvedVulns)
		}
	}
	
	// Update total summary stats
	diff.Summary.TotalNewHosts = len(diff.NewHosts)
	diff.Summary.TotalMissingHosts = len(diff.MissingHosts)
	
	// Calculate risk score (1-100)
	diff.Summary.RiskScore = calculateRiskScore(diff)
	
	return diff, nil
}

// compareHostResults compares two scan results for the same host and returns the differences
func (d *DiffScanner) compareHostResults(previous, current *ScanResult) *HostDiff {
	// Initialize host diff
	hostDiff := &HostDiff{
		Host: current.Host,
	}
	
	// Check if there are any differences
	hasChanges := false
	
	// Compare OS
	if previous.OS != current.OS && previous.OS != "" && current.OS != "" {
		hostDiff.OSChanged = true
		hostDiff.PreviousOS = previous.OS
		hostDiff.CurrentOS = current.OS
		hasChanges = true
	}
	
	// Compare TCP ports
	previousTCPPorts := make(map[int]bool)
	currentTCPPorts := make(map[int]bool)
	
	for _, port := range previous.OpenPorts {
		previousTCPPorts[port] = true
	}
	
	for _, port := range current.OpenPorts {
		currentTCPPorts[port] = true
		
		// Check if this is a new port
		if !previousTCPPorts[port] {
			hostDiff.NewTCPPorts = append(hostDiff.NewTCPPorts, port)
			hasChanges = true
		}
	}
	
	// Find closed ports
	for port := range previousTCPPorts {
		if !currentTCPPorts[port] {
			hostDiff.ClosedTCPPorts = append(hostDiff.ClosedTCPPorts, port)
			hasChanges = true
		}
	}
	
	// Compare UDP ports
	previousUDPPorts := make(map[int]bool)
	currentUDPPorts := make(map[int]bool)
	
	for _, port := range previous.OpenUDPPorts {
		previousUDPPorts[port] = true
	}
	
	for _, port := range current.OpenUDPPorts {
		currentUDPPorts[port] = true
		
		// Check if this is a new port
		if !previousUDPPorts[port] {
			hostDiff.NewUDPPorts = append(hostDiff.NewUDPPorts, port)
			hasChanges = true
		}
	}
	
	// Find closed UDP ports
	for port := range previousUDPPorts {
		if !currentUDPPorts[port] {
			hostDiff.ClosedUDPPorts = append(hostDiff.ClosedUDPPorts, port)
			hasChanges = true
		}
	}
	
	// Compare services
	previousServices := make(map[string]bool)
	currentServices := make(map[string]bool)
	
	for port, service := range previous.Services {
		serviceKey := fmt.Sprintf("%d:%s", port, service)
		previousServices[serviceKey] = true
	}
	
	for port, service := range current.Services {
		serviceKey := fmt.Sprintf("%d:%s", port, service)
		currentServices[serviceKey] = true
		
		// Check if this is a new service
		if !previousServices[serviceKey] {
			hostDiff.NewServices = append(hostDiff.NewServices, serviceKey)
			hasChanges = true
		}
	}
	
	// Find removed services
	for serviceKey := range previousServices {
		if !currentServices[serviceKey] {
			hostDiff.RemovedServices = append(hostDiff.RemovedServices, serviceKey)
			hasChanges = true
		}
	}
	
	// Compare vulnerabilities
	previousVulns := make(map[string]bool)
	currentVulns := make(map[string]bool)
	
	for _, vuln := range previous.Vulnerabilities {
		previousVulns[vuln] = true
	}
	
	for _, vuln := range current.Vulnerabilities {
		currentVulns[vuln] = true
		
		// Check if this is a new vulnerability
		if !previousVulns[vuln] {
			hostDiff.NewVulns = append(hostDiff.NewVulns, vuln)
			hasChanges = true
		}
	}
	
	// Find resolved vulnerabilities
	for vuln := range previousVulns {
		if !currentVulns[vuln] {
			hostDiff.ResolvedVulns = append(hostDiff.ResolvedVulns, vuln)
			hasChanges = true
		}
	}
	
	// Sort slices for consistent output
	sort.Ints(hostDiff.NewTCPPorts)
	sort.Ints(hostDiff.ClosedTCPPorts)
	sort.Ints(hostDiff.NewUDPPorts)
	sort.Ints(hostDiff.ClosedUDPPorts)
	sort.Strings(hostDiff.NewServices)
	sort.Strings(hostDiff.RemovedServices)
	sort.Strings(hostDiff.NewVulns)
	sort.Strings(hostDiff.ResolvedVulns)
	
	if !hasChanges {
		return nil // No differences found
	}
	
	return hostDiff
}

// WriteDiffReport writes a differential scan report to a file
func (d *DiffScanner) WriteDiffReport(diff *ScanDiffResult, format, filePath string) error {
	if diff == nil {
		return fmt.Errorf("no differential scan result provided")
	}
	
	switch strings.ToLower(format) {
	case "json":
		// Marshal to JSON
		data, err := json.MarshalIndent(diff, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		
		// Write to file
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			return fmt.Errorf("failed to write JSON file: %w", err)
		}
		
	case "csv":
		// Open file for writing
		file, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("failed to create CSV file: %w", err)
		}
		defer file.Close()
		
		// Write header
		header := "Host,Change Type,Previous Value,Current Value\n"
		if _, err := file.WriteString(header); err != nil {
			return fmt.Errorf("failed to write CSV header: %w", err)
		}
		
		// Write new hosts
		for _, host := range diff.NewHosts {
			line := fmt.Sprintf("%s,New Host,N/A,Added\n", host)
			if _, err := file.WriteString(line); err != nil {
				return fmt.Errorf("failed to write CSV line: %w", err)
			}
		}
		
		// Write missing hosts
		for _, host := range diff.MissingHosts {
			line := fmt.Sprintf("%s,Missing Host,Present,Removed\n", host)
			if _, err := file.WriteString(line); err != nil {
				return fmt.Errorf("failed to write CSV line: %w", err)
			}
		}
		
		// Write host changes
		for host, hostDiff := range diff.HostChanges {
			// OS change
			if hostDiff.OSChanged {
				line := fmt.Sprintf("%s,OS Change,%s,%s\n", host, hostDiff.PreviousOS, hostDiff.CurrentOS)
				if _, err := file.WriteString(line); err != nil {
					return fmt.Errorf("failed to write CSV line: %w", err)
				}
			}
			
			// New TCP ports
			for _, port := range hostDiff.NewTCPPorts {
				line := fmt.Sprintf("%s,New TCP Port,Closed,%d\n", host, port)
				if _, err := file.WriteString(line); err != nil {
					return fmt.Errorf("failed to write CSV line: %w", err)
				}
			}
			
			// Closed TCP ports
			for _, port := range hostDiff.ClosedTCPPorts {
				line := fmt.Sprintf("%s,Closed TCP Port,%d,Closed\n", host, port)
				if _, err := file.WriteString(line); err != nil {
					return fmt.Errorf("failed to write CSV line: %w", err)
				}
			}
			
			// New UDP ports
			for _, port := range hostDiff.NewUDPPorts {
				line := fmt.Sprintf("%s,New UDP Port,Closed,%d\n", host, port)
				if _, err := file.WriteString(line); err != nil {
					return fmt.Errorf("failed to write CSV line: %w", err)
				}
			}
			
			// Closed UDP ports
			for _, port := range hostDiff.ClosedUDPPorts {
				line := fmt.Sprintf("%s,Closed UDP Port,%d,Closed\n", host, port)
				if _, err := file.WriteString(line); err != nil {
					return fmt.Errorf("failed to write CSV line: %w", err)
				}
			}
			
			// New services
			for _, service := range hostDiff.NewServices {
				line := fmt.Sprintf("%s,New Service,None,%s\n", host, service)
				if _, err := file.WriteString(line); err != nil {
					return fmt.Errorf("failed to write CSV line: %w", err)
				}
			}
			
			// Removed services
			for _, service := range hostDiff.RemovedServices {
				line := fmt.Sprintf("%s,Removed Service,%s,None\n", host, service)
				if _, err := file.WriteString(line); err != nil {
					return fmt.Errorf("failed to write CSV line: %w", err)
				}
			}
			
			// New vulnerabilities
			for _, vuln := range hostDiff.NewVulns {
				line := fmt.Sprintf("%s,New Vulnerability,None,%s\n", host, vuln)
				if _, err := file.WriteString(line); err != nil {
					return fmt.Errorf("failed to write CSV line: %w", err)
				}
			}
			
			// Resolved vulnerabilities
			for _, vuln := range hostDiff.ResolvedVulns {
				line := fmt.Sprintf("%s,Resolved Vulnerability,%s,None\n", host, vuln)
				if _, err := file.WriteString(line); err != nil {
					return fmt.Errorf("failed to write CSV line: %w", err)
				}
			}
		}
		
		// Write summary
		summarySection := "\nSummary\n"
		if _, err := file.WriteString(summarySection); err != nil {
			return fmt.Errorf("failed to write CSV summary: %w", err)
		}
		
		summaryItems := []struct {
			Label string
			Value int
		}{
			{"Total Hosts Changed", diff.Summary.TotalHostsChanged},
			{"New Hosts", diff.Summary.TotalNewHosts},
			{"Missing Hosts", diff.Summary.TotalMissingHosts},
			{"New TCP Ports", diff.Summary.TotalNewTCPPorts},
			{"Closed TCP Ports", diff.Summary.TotalClosedTCPPorts},
			{"New UDP Ports", diff.Summary.TotalNewUDPPorts},
			{"Closed UDP Ports", diff.Summary.TotalClosedUDPPorts},
			{"New Services", diff.Summary.TotalNewServices},
			{"Removed Services", diff.Summary.TotalRemovedServices},
			{"New Vulnerabilities", diff.Summary.TotalNewVulns},
			{"Resolved Vulnerabilities", diff.Summary.TotalResolvedVulns},
			{"Risk Score (1-100)", diff.Summary.RiskScore},
		}
		
		for _, item := range summaryItems {
			line := fmt.Sprintf("%s,%d\n", item.Label, item.Value)
			if _, err := file.WriteString(line); err != nil {
				return fmt.Errorf("failed to write CSV summary line: %w", err)
			}
		}
		
	default:
		return fmt.Errorf("unsupported diff report format: %s", format)
	}
	
	d.logger.Info("Differential report written", 
		zap.String("format", format),
		zap.String("file", filePath),
	)
	
	return nil
}

// PrintDiffSummary prints a summary of differences to the console
func (d *DiffScanner) PrintDiffSummary(diff *ScanDiffResult) {
	if diff == nil {
		fmt.Println("No differential scan result available")
		return
	}
	
	fmt.Println("\n===================================")
	fmt.Println("    Network Scan Diff Summary")
	fmt.Println("===================================")
	
	fmt.Printf("\nPrevious Scan: %s (%s)\n", diff.PreviousScanID, diff.PreviousTime.Format(time.RFC3339))
	fmt.Printf("Current Scan:  %s (%s)\n", diff.CurrentScanID, diff.CurrentTime.Format(time.RFC3339))
	
	fmt.Printf("\nSummary:\n")
	fmt.Printf("- Hosts with changes: %d\n", diff.Summary.TotalHostsChanged)
	fmt.Printf("- New hosts: %d\n", diff.Summary.TotalNewHosts)
	fmt.Printf("- Missing hosts: %d\n", diff.Summary.TotalMissingHosts)
	fmt.Printf("- New TCP ports: %d\n", diff.Summary.TotalNewTCPPorts)
	fmt.Printf("- Closed TCP ports: %d\n", diff.Summary.TotalClosedTCPPorts)
	fmt.Printf("- New UDP ports: %d\n", diff.Summary.TotalNewUDPPorts)
	fmt.Printf("- Closed UDP ports: %d\n", diff.Summary.TotalClosedUDPPorts)
	fmt.Printf("- New services: %d\n", diff.Summary.TotalNewServices)
	fmt.Printf("- Removed services: %d\n", diff.Summary.TotalRemovedServices)
	fmt.Printf("- New vulnerabilities: %d\n", diff.Summary.TotalNewVulns)
	fmt.Printf("- Resolved vulnerabilities: %d\n", diff.Summary.TotalResolvedVulns)
	fmt.Printf("- Risk Score (1-100): %d\n", diff.Summary.RiskScore)
	
	// Print new hosts
	if len(diff.NewHosts) > 0 {
		fmt.Println("\nNew Hosts:")
		for _, host := range diff.NewHosts {
			fmt.Printf("  - %s\n", host)
		}
	}
	
	// Print missing hosts
	if len(diff.MissingHosts) > 0 {
		fmt.Println("\nMissing Hosts:")
		for _, host := range diff.MissingHosts {
			fmt.Printf("  - %s\n", host)
		}
	}
	
	// Print key changes (limit to most significant for brevity)
	if len(diff.HostChanges) > 0 {
		fmt.Println("\nKey Changes:")
		
		// Sort hosts by "importance" of changes (vulnerability changes first, then service changes, etc.)
		var hostsByImportance []string
		for host, hostDiff := range diff.HostChanges {
			if len(hostDiff.NewVulns) > 0 || len(hostDiff.ResolvedVulns) > 0 {
				hostsByImportance = append(hostsByImportance, host)
			}
		}
		
		// Add hosts with service changes
		for host, hostDiff := range diff.HostChanges {
			if len(hostDiff.NewServices) > 0 || len(hostDiff.RemovedServices) > 0 {
				// Check if already added
				found := false
				for _, h := range hostsByImportance {
					if h == host {
						found = true
						break
					}
				}
				if !found {
					hostsByImportance = append(hostsByImportance, host)
				}
			}
		}
		
		// Add remaining hosts with changes
		for host := range diff.HostChanges {
			// Check if already added
			found := false
			for _, h := range hostsByImportance {
				if h == host {
					found = true
					break
				}
			}
			if !found {
				hostsByImportance = append(hostsByImportance, host)
			}
		}
		
		// Sort alphabetically
		sort.Strings(hostsByImportance)
		
		// Display changes by host
		for _, host := range hostsByImportance {
			hostDiff := diff.HostChanges[host]
			fmt.Printf("  %s:\n", host)
			
			if hostDiff.OSChanged {
				fmt.Printf("    - OS Changed: %s → %s\n", hostDiff.PreviousOS, hostDiff.CurrentOS)
			}
			
			if len(hostDiff.NewTCPPorts) > 0 {
				fmt.Printf("    - New TCP Ports: %v\n", hostDiff.NewTCPPorts)
			}
			
			if len(hostDiff.ClosedTCPPorts) > 0 {
				fmt.Printf("    - Closed TCP Ports: %v\n", hostDiff.ClosedTCPPorts)
			}
			
			if len(hostDiff.NewUDPPorts) > 0 {
				fmt.Printf("    - New UDP Ports: %v\n", hostDiff.NewUDPPorts)
			}
			
			if len(hostDiff.ClosedUDPPorts) > 0 {
				fmt.Printf("    - Closed UDP Ports: %v\n", hostDiff.ClosedUDPPorts)
			}
			
			if len(hostDiff.NewServices) > 0 {
				fmt.Printf("    - New Services: %v\n", hostDiff.NewServices)
			}
			
			if len(hostDiff.RemovedServices) > 0 {
				fmt.Printf("    - Removed Services: %v\n", hostDiff.RemovedServices)
			}
			
			if len(hostDiff.NewVulns) > 0 {
				fmt.Printf("    - New Vulnerabilities: %v\n", hostDiff.NewVulns)
			}
			
			if len(hostDiff.ResolvedVulns) > 0 {
				fmt.Printf("    - Resolved Vulnerabilities: %v\n", hostDiff.ResolvedVulns)
			}
		}
	}
	
	fmt.Println("\n===================================")
}

// calculateRiskScore calculates a risk score based on the scan differences
// Higher scores indicate greater risk
func calculateRiskScore(diff *ScanDiffResult) int {
	score := 0
	
	// Base score based on new vulnerabilities (highest weight)
	if diff.Summary.TotalNewVulns > 0 {
		score += 40 // Start with a high base if there are new vulnerabilities
		
		// Add more points based on number of vulnerabilities
		score += min(30, diff.Summary.TotalNewVulns*5) // Add 5 per vuln up to 30 more points
	}
	
	// New hosts score (moderate weight)
	if diff.Summary.TotalNewHosts > 0 {
		score += 5
		score += min(20, diff.Summary.TotalNewHosts*2) // Add 2 per host up to 20 more points
	}
	
	// Missing hosts score (low weight) - could be security issue if host disappeared unexpectedly
	if diff.Summary.TotalMissingHosts > 0 {
		score += min(10, diff.Summary.TotalMissingHosts) // Add 1 per missing host up to 10 points
	}
	
	// New ports and services score (moderate weight)
	if diff.Summary.TotalNewTCPPorts > 0 || diff.Summary.TotalNewUDPPorts > 0 {
		score += 5
		score += min(20, (diff.Summary.TotalNewTCPPorts + diff.Summary.TotalNewUDPPorts)) // Add 1 per new port up to 20 points
	}
	
	// New services score (moderate weight)
	if diff.Summary.TotalNewServices > 0 {
		score += min(15, diff.Summary.TotalNewServices*3) // Add 3 per new service up to 15 points
	}
	
	// Reduce score for resolved vulnerabilities (good thing)
	if diff.Summary.TotalResolvedVulns > 0 {
		score -= min(25, diff.Summary.TotalResolvedVulns*5) // Subtract 5 per resolved vuln up to 25 points
	}
	
	// Ensure score is in 1-100 range
	score = max(1, min(100, score))
	
	return score
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the larger of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}