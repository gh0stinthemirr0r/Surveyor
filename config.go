package surveyor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config errors
var (
	ErrInvalidPortRange     = errors.New("invalid port range")
	ErrInvalidScanTimeout   = errors.New("invalid scan timeout")
	ErrInvalidConcurrency   = errors.New("invalid concurrency value")
	ErrInvalidPacketSetting = errors.New("invalid packet setting")
	ErrInvalidPath          = errors.New("invalid path")
	ErrMissingCredentials   = errors.New("missing credentials for authentication")
)

// Config represents the configuration for the Surveyor application
type Config struct {
	// Network scanning configuration
	TargetHosts       []string `json:"target_hosts"`
	PortRangeStart    int      `json:"port_range_start"`
	PortRangeEnd      int      `json:"port_range_end"`
	ScanUDP           bool     `json:"scan_udp"`
	UDPPortRangeStart int      `json:"udp_port_range_start"`
	UDPPortRangeEnd   int      `json:"udp_port_range_end"`
	ScanTimeout       int      `json:"scan_timeout_seconds"`
	ConcurrentScans   int      `json:"concurrent_scans"`
	ExcludedPorts     []int    `json:"excluded_ports"`
	EnableCaching     bool     `json:"enable_caching"`
	CacheTTL          int      `json:"cache_ttl_minutes"`
	IPv6Support       bool     `json:"ipv6_support"`
	ScanNonResponsive bool     `json:"scan_non_responsive"`

	// Logging configuration
	LogDir   string `json:"log_dir"`
	LogLevel string `json:"log_level"`

	// Report configuration
	ReportDir     string   `json:"report_dir"`
	ReportFormats []string `json:"report_formats"`
	TemplateDir   string   `json:"template_dir"`
	ConsoleReport bool     `json:"console_report"`

	// Metrics configuration
	MetricsEnabled  bool   `json:"metrics_enabled"`
	MetricsPort     string `json:"metrics_port"`
	MetricsTLS      bool   `json:"metrics_tls"`
	MetricsHostname string `json:"metrics_hostname"`
	MetricsAuth     bool   `json:"metrics_auth"`
	MetricsUsername string `json:"metrics_username"`
	MetricsPassword string `json:"metrics_password"`

	// OS Detection configuration
	EnableOSDetection  bool   `json:"enable_os_detection"`
	UseNmap            bool   `json:"use_nmap"`
	NmapPath           string `json:"nmap_path"`
	ServiceDetection   bool   `json:"service_detection"`
	ServiceProbes      bool   `json:"service_probes"`
	ProbeTimeout       int    `json:"probe_timeout_seconds"`
	DeepInspection     bool   `json:"deep_inspection"`
	VulnerabilityCheck bool   `json:"vulnerability_check"`

	// Traffic Generation configuration
	TrafficEnabled     bool `json:"traffic_enabled"`
	PacketsPerHost     int  `json:"packets_per_host"`
	PacketDelayMillis  int  `json:"packet_delay_millis"`
	ConcurrentTraffic  int  `json:"concurrent_traffic"`
	CollectLatencyData bool `json:"collect_latency_data"`

	// Route analysis configuration
	TraceRoute        bool `json:"trace_route"`
	MaxTTL            int  `json:"max_ttl"`

	// Vulnerability scanning configuration
	VulnDBPath            string   `json:"vuln_db_path"`
	VulnDBUpdateFrequency string   `json:"vuln_db_update_frequency"`
	VulnDBSources         []string `json:"vuln_db_sources"`
	CVSSMinScore          float64  `json:"cvss_min_score"`
	ExcludeVulnTypes      []string `json:"exclude_vuln_types"`
	IncludeVulnTypes      []string `json:"include_vuln_types"`
	ExploitAware          bool     `json:"exploit_aware"`
	ExploitDBPath         string   `json:"exploit_db_path"`
	MaxCVEAge             int      `json:"max_cve_age_days"`
	CVESeverityFilter     string   `json:"cve_severity_filter"`
}

// LoadConfig loads configuration from a JSON file
func LoadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults for empty paths
	if config.LogDir == "" {
		config.LogDir = "ghostshell/logging"
	}
	if config.ReportDir == "" {
		config.ReportDir = "ghostshell/reporting"
	}
	if config.TemplateDir == "" {
		config.TemplateDir = "templates"
	}
	if config.NmapPath == "" {
		config.NmapPath = "nmap" // Just use the name to find in PATH
	}

	return &config, nil
}

// SaveConfig saves the current configuration to a file
func (c *Config) SaveConfig(configPath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		PortRangeStart:    1,
		PortRangeEnd:      1024,
		ScanUDP:           false,
		UDPPortRangeStart: 1,
		UDPPortRangeEnd:   1024,
		ScanTimeout:       5,
		ConcurrentScans:   10,
		ExcludedPorts:     []int{},
		EnableCaching:     true,
		CacheTTL:          60,
		IPv6Support:       false,
		ScanNonResponsive: false,

		LogDir:   "ghostshell/logging",
		LogLevel: "info",

		ReportDir:     "ghostshell/reporting",
		ReportFormats: []string{"csv", "pdf", "json"},
		TemplateDir:   "templates",
		ConsoleReport: true,

		MetricsEnabled:  true,
		MetricsPort:     "8080",
		MetricsTLS:      false,
		MetricsHostname: "localhost",
		MetricsAuth:     false,

		EnableOSDetection:  true,
		UseNmap:            true,
		NmapPath:           "nmap",
		ServiceDetection:   true,
		ServiceProbes:      true,
		ProbeTimeout:       5,
		DeepInspection:     false,
		VulnerabilityCheck: false,

		TrafficEnabled:     true,
		PacketsPerHost:     10,
		PacketDelayMillis:  50,
		ConcurrentTraffic:  3,
		CollectLatencyData: true,
		TraceRoute:        false,
		MaxTTL:            30,

		// Default vulnerability scanning configuration
		VulnDBPath:            "data/vulnerabilities",
		VulnDBUpdateFrequency: "daily",
		VulnDBSources:         []string{"local", "nvd"},
		CVSSMinScore:          0.0,
		ExcludeVulnTypes:      []string{},
		IncludeVulnTypes:      []string{},
		ExploitAware:          true,
		ExploitDBPath:         "data/exploitdb",
		MaxCVEAge:             0,
		CVESeverityFilter:     "",
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// TCP Port range validation
	if c.PortRangeStart < 1 || c.PortRangeEnd > 65535 || c.PortRangeStart > c.PortRangeEnd {
		return fmt.Errorf("%w: TCP %d-%d", ErrInvalidPortRange, c.PortRangeStart, c.PortRangeEnd)
	}

	// UDP Port range validation if UDP scanning is enabled
	if c.ScanUDP {
		if c.UDPPortRangeStart < 1 || c.UDPPortRangeEnd > 65535 || c.UDPPortRangeStart > c.UDPPortRangeEnd {
			return fmt.Errorf("%w: UDP %d-%d", ErrInvalidPortRange, c.UDPPortRangeStart, c.UDPPortRangeEnd)
		}
	}

	// Timeout validation
	if c.ScanTimeout < 1 {
		return fmt.Errorf("%w: %d", ErrInvalidScanTimeout, c.ScanTimeout)
	}

	// Concurrency validation
	if c.ConcurrentScans < 1 {
		return fmt.Errorf("%w: concurrent scans %d", ErrInvalidConcurrency, c.ConcurrentScans)
	}
	if c.ConcurrentTraffic < 1 {
		return fmt.Errorf("%w: concurrent traffic %d", ErrInvalidConcurrency, c.ConcurrentTraffic)
	}

	// Traffic generation validation
	if c.TrafficEnabled {
		if c.PacketsPerHost < 1 {
			return fmt.Errorf("%w: packets per host %d", ErrInvalidPacketSetting, c.PacketsPerHost)
		}
		if c.PacketDelayMillis < 0 {
			return fmt.Errorf("%w: packet delay %d", ErrInvalidPacketSetting, c.PacketDelayMillis)
		}
	}

	// Directory validation
	if c.LogDir == "" || c.ReportDir == "" {
		return fmt.Errorf("%w: directory paths cannot be empty", ErrInvalidPath)
	}

	// Log level validation
	logLevel := strings.ToLower(c.LogLevel)
	if logLevel != "debug" && logLevel != "info" && logLevel != "warn" && logLevel != "error" {
		c.LogLevel = "info" // Default to info if invalid
	}

	// Metrics authentication validation
	if c.MetricsAuth && (c.MetricsUsername == "" || c.MetricsPassword == "") {
		return fmt.Errorf("%w: both username and password required when auth enabled", ErrMissingCredentials)
	}

	// Report format validation
	validFormats := map[string]bool{
		"csv":  true,
		"pdf":  true,
		"json": true,
		"xml":  true,
		"html": true,
	}
	for i, format := range c.ReportFormats {
		format = strings.ToLower(format)
		if !validFormats[format] {
			// Remove invalid format
			c.ReportFormats = append(c.ReportFormats[:i], c.ReportFormats[i+1:]...)
		}
	}
	if len(c.ReportFormats) == 0 {
		c.ReportFormats = []string{"csv"} // Default to CSV if no valid formats
	}

	return nil
}