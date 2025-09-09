package surveyor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/semaphore"
	"go.uber.org/zap"
)

// ScanResult represents the result of a network scan
type ScanResult struct {
	Host             string
	OpenPorts        []int
	OpenUDPPorts     []int
	OS               string
	Hostname         string
	Services         map[int]string  // Maps port to service name
	Vulnerabilities  []string        // List of vulnerability identifiers
	TTL              int             // Time to live value from ping
	MAC              string          // MAC address if available
	AdditionalInfo   map[string]string
	Error            error
}

// Scanner handles network scanning operations
type Scanner struct {
	config         *Config
	logger         *zap.Logger
	dnsCache       *DNSCache
	resultCache    *ScanResultCache
	fingerprints   map[string]string // Maps TCP/UDP fingerprints to service names
	vulnDatabase   map[string][]string // Maps service identifier to known vulnerabilities
	scanStartTime  time.Time
	scanSemaphore  *semaphore.Weighted
}

// NewScanner creates a new Scanner instance
func NewScanner(config *Config, logger *zap.Logger) *Scanner {
	// Initialize caches if enabled
	var dnsCache *DNSCache
	var resultCache *ScanResultCache
	if config.EnableCaching {
		dnsCache = NewDNSCache(time.Duration(config.CacheTTL) * time.Minute)
		resultCache = NewScanResultCache(time.Duration(config.CacheTTL) * time.Minute)
	}

	return &Scanner{
		config:        config,
		logger:        logger.With(zap.String("component", "scanner")),
		dnsCache:      dnsCache,
		resultCache:   resultCache,
		fingerprints:  loadServiceFingerprints(),
		vulnDatabase:  loadVulnerabilityDatabase(),
		scanStartTime: time.Now(),
		scanSemaphore: semaphore.NewWeighted(int64(config.ConcurrentScans)),
	}
}

// loadServiceFingerprints loads service fingerprints for identification
// In a real implementation, this would read from a database or file
func loadServiceFingerprints() map[string]string {
	// Sample data, in a real application this would be comprehensive
	return map[string]string{
		"SSH-2.0":            "ssh",
		"HTTP/1.1":           "http",
		"220 (vsFTPd":        "ftp",
		"* OK IMAP4":         "imap",
		"220 SMTP":           "smtp",
		"MongoDB Server":     "mongodb",
		"5432 PostgreSQL":    "postgresql",
		"3306 MySQL":         "mysql",
		"1521 Oracle":        "oracle",
		"1433 Microsoft SQL": "mssql",
		"6379 Redis":         "redis",
		"5672 RabbitMQ":      "rabbitmq",
		"9200 Elasticsearch": "elasticsearch",
	}
}

// loadVulnerabilityDatabase loads known vulnerabilities for services
// In a real implementation, this would load from NVD or another database
func loadVulnerabilityDatabase() map[string][]string {
	// Sample data, in a real app this would connect to CVE databases
	return map[string][]string{
		"ssh:OpenSSH_7.4":    {"CVE-2018-15473", "CVE-2017-15906"},
		"http:Apache/2.4.29": {"CVE-2020-11984", "CVE-2019-0211"},
		"http:nginx/1.14.0":  {"CVE-2019-9511", "CVE-2018-16845"},
		"ftp:vsftpd_2.3.4":   {"CVE-2011-2523"},
		"smtp:Exim_4.9":      {"CVE-2019-15846", "CVE-2019-16928"},
		"mysql:5.7":          {"CVE-2020-2922", "CVE-2020-2812"},
	}
}

// ScanHost performs a comprehensive scan of a single host
func (s *Scanner) ScanHost(ctx context.Context, host string) (*ScanResult, error) {
	// Try to get from cache first if caching is enabled
	if s.config.EnableCaching && s.resultCache != nil {
		if cachedResult := s.resultCache.Get(host); cachedResult != nil {
			s.logger.Debug("Using cached scan result", zap.String("host", host))
			return cachedResult, nil
		}
	}

	result := &ScanResult{
		Host:            host,
		Services:        make(map[int]string),
		AdditionalInfo:  make(map[string]string),
	}

	// Resolve hostname if it's not an IP
	if !IsValidIP(host) {
		ip, err := s.resolveHostname(host)
		if err != nil {
			return result, fmt.Errorf("failed to resolve host: %w", err)
		}
		result.Host = ip
		result.Hostname = host
	} else {
		// Try reverse DNS lookup
		hostname, err := s.reverseLookup(host)
		if err == nil && hostname != "" {
			result.Hostname = hostname
		}
	}

	// Scan TCP ports
	openPorts, err := s.scanTCPPorts(ctx, result.Host)
	if err != nil {
		s.logger.Warn("TCP port scan had errors", zap.String("host", result.Host), zap.Error(err))
	}
	result.OpenPorts = openPorts

	// Scan UDP ports if enabled
	if s.config.ScanUDP {
		openUDPPorts, err := s.scanUDPPorts(ctx, result.Host)
		if err != nil {
			s.logger.Warn("UDP port scan had errors", zap.String("host", result.Host), zap.Error(err))
		}
		result.OpenUDPPorts = openUDPPorts
	}

	// Detect OS if enabled
	if s.config.EnableOSDetection {
		os, err := s.detectOS(ctx, result.Host)
		if err != nil {
			s.logger.Warn("OS detection failed", zap.Error(err))
		} else {
			result.OS = os
		}
	}

	// Service detection if enabled and there are open ports
	if s.config.ServiceDetection && len(result.OpenPorts) > 0 {
		s.detectServices(ctx, result)
	}

	// Vulnerability checks if enabled
	if s.config.VulnerabilityCheck && len(result.Services) > 0 {
		s.checkVulnerabilities(result)
	}

	// Store in cache if caching is enabled
	if s.config.EnableCaching && s.resultCache != nil {
		s.resultCache.Set(host, result)
	}

	return result, nil
}

// resolveHostname resolves a hostname to an IP address, using cache if enabled
func (s *Scanner) resolveHostname(hostname string) (string, error) {
	// Check cache first if enabled
	if s.config.EnableCaching && s.dnsCache != nil {
		if ip := s.dnsCache.Get(hostname); ip != "" {
			return ip, nil
		}
	}

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", err
	}

	// Handle IPv6 support
	for _, ip := range ips {
		ipStr := ip.String()
		// Return first IPv4 address by default
		if ip.To4() != nil {
			if s.config.EnableCaching && s.dnsCache != nil {
				s.dnsCache.Set(hostname, ipStr)
			}
			return ipStr, nil
		}
		
		// If no IPv4 found and IPv6 is supported, return first IPv6
		if s.config.IPv6Support && ip.To4() == nil {
			if s.config.EnableCaching && s.dnsCache != nil {
				s.dnsCache.Set(hostname, ipStr)
			}
			return ipStr, nil
		}
	}

	return "", fmt.Errorf("no suitable IP addresses found for %s", hostname)
}

// reverseLookup performs reverse DNS lookup, using cache if enabled
func (s *Scanner) reverseLookup(ip string) (string, error) {
	// Check cache first if enabled
	if s.config.EnableCaching && s.dnsCache != nil {
		if hostname := s.dnsCache.Get("r:" + ip); hostname != "" {
			return hostname, nil
		}
	}

	names, err := net.LookupAddr(ip)
	if err != nil {
		return "", err
	}

	if len(names) == 0 {
		return "", nil
	}

	// Remove trailing dot from hostname
	hostname := strings.TrimSuffix(names[0], ".")
	
	// Store in cache if enabled
	if s.config.EnableCaching && s.dnsCache != nil {
		s.dnsCache.Set("r:"+ip, hostname)
	}
	
	return hostname, nil
}

// scanTCPPorts scans a range of TCP ports on a host
func (s *Scanner) scanTCPPorts(ctx context.Context, host string) ([]int, error) {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	errors := make(chan error, s.config.ConcurrentScans)

	// Get all ports in the range minus excluded ports
	portRange := getPortsToScan(s.config.PortRangeStart, s.config.PortRangeEnd, s.config.ExcludedPorts)
	
	// Create a buffered channel for port scanning workers
	portChan := make(chan int, len(portRange))

	// Start workers
	for i := 0; i < s.config.ConcurrentScans; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				// Acquire semaphore
				if err := s.scanSemaphore.Acquire(ctx, 1); err != nil {
					errors <- fmt.Errorf("failed to acquire semaphore: %w", err)
					continue
				}
				
				select {
				case <-ctx.Done():
					s.scanSemaphore.Release(1)
					return
				default:
					address := fmt.Sprintf("%s:%d", host, port)
					
					// Set a specific timeout for the dial
					dialer := net.Dialer{
						Timeout: time.Duration(s.config.ScanTimeout) * time.Second,
					}
					
					conn, err := dialer.DialContext(ctx, "tcp", address)
					if err == nil {
						mu.Lock()
						openPorts = append(openPorts, port)
						mu.Unlock()
						conn.Close()
					}
					
					s.scanSemaphore.Release(1)
				}
			}
		}()
	}

	// Send ports to workers
	go func() {
		for _, port := range portRange {
			select {
			case <-ctx.Done():
				close(portChan)
				return
			case portChan <- port:
				// Port sent to worker
			}
		}
		close(portChan)
	}()

	wg.Wait()
	close(errors)

	// Sort open ports for consistent results
	sort.Ints(openPorts)

	// Collect any errors
	var errorsList []string
	for err := range errors {
		errorsList = append(errorsList, err.Error())
	}

	if len(errorsList) > 0 {
		return openPorts, fmt.Errorf("scan errors: %s", strings.Join(errorsList, "; "))
	}

	return openPorts, nil
}

// scanUDPPorts scans a range of UDP ports on a host
func (s *Scanner) scanUDPPorts(ctx context.Context, host string) ([]int, error) {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	errors := make(chan error, s.config.ConcurrentScans)

	// Get all ports in the range minus excluded ports
	portRange := getPortsToScan(s.config.UDPPortRangeStart, s.config.UDPPortRangeEnd, s.config.ExcludedPorts)
	
	// Create a buffered channel for port scanning workers
	portChan := make(chan int, len(portRange))

	// Start workers
	for i := 0; i < s.config.ConcurrentScans; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				// Acquire semaphore
				if err := s.scanSemaphore.Acquire(ctx, 1); err != nil {
					errors <- fmt.Errorf("failed to acquire semaphore: %w", err)
					continue
				}
				
				select {
				case <-ctx.Done():
					s.scanSemaphore.Release(1)
					return
				default:
					address := fmt.Sprintf("%s:%d", host, port)
					
					// UDP scanning requires sending packets and waiting for a response or ICMP unreachable
					// This is a simplified implementation, a real scanner would be more sophisticated
					conn, err := net.DialTimeout("udp", address, time.Duration(s.config.ScanTimeout)*time.Second)
					if err == nil {
						// Send a probe packet
						_, err = conn.Write([]byte("SURVEYOR_PROBE"))
						if err == nil {
							// Set a read deadline
							conn.SetReadDeadline(time.Now().Add(time.Duration(s.config.ScanTimeout) * time.Second))
							
							// Try to read response
							buffer := make([]byte, 1024)
							_, err := conn.Read(buffer)
							
							// If we get any response or specific errors, port might be open
							if err == nil || !strings.Contains(err.Error(), "refused") {
								mu.Lock()
								openPorts = append(openPorts, port)
								mu.Unlock()
							}
						}
						conn.Close()
					}
					
					s.scanSemaphore.Release(1)
				}
			}
		}()
	}

	// Send ports to workers
	go func() {
		for _, port := range portRange {
			select {
			case <-ctx.Done():
				close(portChan)
				return
			case portChan <- port:
				// Port sent to worker
			}
		}
		close(portChan)
	}()

	wg.Wait()
	close(errors)

	// Sort open ports for consistent results
	sort.Ints(openPorts)

	// Collect any errors
	var errorsList []string
	for err := range errors {
		errorsList = append(errorsList, err.Error())
	}

	if len(errorsList) > 0 {
		return openPorts, fmt.Errorf("UDP scan errors: %s", strings.Join(errorsList, "; "))
	}

	return openPorts, nil
}

// getPortsToScan returns a slice of ports to scan, excluding specified ports
func getPortsToScan(start, end int, excluded []int) []int {
	excludedMap := make(map[int]bool)
	for _, port := range excluded {
		excludedMap[port] = true
	}

	var ports []int
	for port := start; port <= end; port++ {
		if !excludedMap[port] {
			ports = append(ports, port)
		}
	}
	return ports
}

// detectOS attempts to identify the operating system of a host
func (s *Scanner) detectOS(ctx context.Context, host string) (string, error) {
	if !s.config.UseNmap {
		// Fallback to TTL-based OS detection if nmap not available
		return s.detectOSByTTL(ctx, host)
	}

	// Use nmap for OS detection - SECURITY NOTE: this must sanitize the host input
	if !IsValidIP(host) && !IsValidHostname(host) {
		return "Unknown", fmt.Errorf("invalid host format for OS detection: %s", host)
	}

	// Build a safe nmap command with proper escaping
	args := []string{"-O", "--osscan-limit", "-T4", "--max-retries", "1", "--host-timeout", "30s"}
	
	// Add the target as the last argument after all flags
	args = append(args, host)
	
	cmd := exec.CommandContext(ctx, s.config.NmapPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "Unknown", fmt.Errorf("nmap error: %w", err)
	}

	outputStr := string(output)
	
	// Extract OS information from nmap output
	osInfo := "Unknown"
	osPattern := regexp.MustCompile(`(?i)OS(?:\s+details|:):\s+(.+)`)
	matches := osPattern.FindStringSubmatch(outputStr)
	if len(matches) > 1 {
		osInfo = strings.TrimSpace(matches[1])
	} else {
		// Try an alternative pattern for OS detection
		altPattern := regexp.MustCompile(`(?i)Running(?::|.+?):\s+(.+)`)
		matches = altPattern.FindStringSubmatch(outputStr)
		if len(matches) > 1 {
			osInfo = strings.TrimSpace(matches[1])
		}
	}

	return osInfo, nil
}

// detectOSByTTL performs OS detection based on TTL values from ping
func (s *Scanner) detectOSByTTL(ctx context.Context, host string) (string, error) {
	// Check if ping is available and permitted
	pingArgs := []string{"-c", "1", "-W", "2"}
	
	// Add target as last argument
	pingArgs = append(pingArgs, host)
	
	cmd := exec.CommandContext(ctx, "ping", pingArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "Unknown", err
	}

	// Extract TTL from ping output
	ttlPattern := regexp.MustCompile(`ttl=(\d+)`)
	matches := ttlPattern.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		return "Unknown", fmt.Errorf("could not extract TTL")
	}

	ttl, err := strconv.Atoi(matches[1])
	if err != nil {
		return "Unknown", err
	}

	// Rough OS detection based on TTL (not 100% accurate)
	switch {
	case ttl <= 64:
		return "Linux/Unix", nil
	case ttl <= 128:
		return "Windows", nil
	case ttl <= 255:
		return "Cisco/Network", nil
	default:
		return "Unknown", nil
	}
}

// detectServices attempts to identify services running on open ports
func (s *Scanner) detectServices(ctx context.Context, result *ScanResult) {
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Process TCP ports
	for _, port := range result.OpenPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			
			// Skip if context is cancelled
			select {
			case <-ctx.Done():
				return
			default:
				// Continue execution
			}
			
			// Try common protocol-specific probes first
			service := s.probeService(ctx, result.Host, p)
			
			if service != "" {
				mu.Lock()
				result.Services[p] = service
				mu.Unlock()
			}
		}(port)
	}

	// Also process UDP ports if any
	for _, port := range result.OpenUDPPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			
			// Skip if context is cancelled
			select {
			case <-ctx.Done():
				return
			default:
				// Continue execution
			}
			
			// Probe UDP service
			service := s.probeUDPService(ctx, result.Host, p)
			
			if service != "" {
				mu.Lock()
				result.Services[p] = service + " (UDP)"
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
}

// probeService attempts to identify a service on a TCP port
func (s *Scanner) probeService(ctx context.Context, host string, port int) string {
	// Set a context with timeout for the connection
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(s.config.ScanTimeout)*time.Second)
	defer cancel()
	
	// Standard connection first
	address := fmt.Sprintf("%s:%d", host, port)
	dialer := net.Dialer{Timeout: time.Duration(s.config.ScanTimeout) * time.Second}
	conn, err := dialer.DialContext(timeoutCtx, "tcp", address)
	if err != nil {
		return ""
	}
	defer conn.Close()
	
	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(time.Duration(s.config.ScanTimeout) * time.Second))
	
	// Try to read banner
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	
	// Handle common protocols based on port number
	service := s.identifyServiceByPort(port)
	
	// Try to refine with banner grabbing if we received data
	if err == nil {
		bannerStr := string(buffer)
		for fingerprint, svcName := range s.fingerprints {
			if strings.Contains(bannerStr, fingerprint) {
				service = svcName
				break
			}
		}
		
		// For HTTP/HTTPS services, try to detect server type
		if service == "http" || service == "https" {
			// Try an HTTP request
			if httpServer := s.probeHTTP(ctx, host, port, service == "https"); httpServer != "" {
				service = httpServer
			}
		}
		
		// For SSH, try to extract version
		if service == "ssh" && strings.Contains(bannerStr, "SSH") {
			sshVersion := "ssh"
			versionPattern := regexp.MustCompile(`SSH-2.0-([^\r\n]+)`)
			matches := versionPattern.FindStringSubmatch(bannerStr)
			if len(matches) > 1 {
				sshVersion = "ssh:" + matches[1]
			}
			service = sshVersion
		}
	}
	
	return service
}

// probeUDPService attempts to identify a service on a UDP port
func (s *Scanner) probeUDPService(ctx context.Context, host string, port int) string {
	// Simplified UDP service detection - would be more sophisticated in a real scanner
	service := s.identifyServiceByPort(port)
	
	// Try to send UDP probes for common services
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("udp", address, time.Duration(s.config.ScanTimeout)*time.Second)
	if err != nil {
		return service
	}
	defer conn.Close()
	
	// Send a protocol-specific probe based on the port
	probe := []byte{0}
	switch port {
	case 53:
		// DNS probe
		probe = []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1}
		service = "dns"
	case 161:
		// SNMP probe
		probe = []byte{48, 26, 2, 1, 0, 4, 6, 112, 117, 98, 108, 105, 99, 161, 13, 2, 1, 1, 2, 1, 0, 2, 1, 0, 48, 2, 5, 0}
		service = "snmp"
	case 123:
		// NTP probe
		probe = []byte{227, 0, 0, 0, 0, 0, 0, 0, 0}
		service = "ntp"
	}
	
	_, err = conn.Write(probe)
	if err != nil {
		return service
	}
	
	// Try to read response
	conn.SetReadDeadline(time.Now().Add(time.Duration(s.config.ScanTimeout) * time.Second))
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	if err != nil {
		return service
	}
	
	// Further refine based on response
	// This would be more sophisticated in a real service detection system
	
	return service
}

// probeHTTP attempts to identify a web server type
func (s *Scanner) probeHTTP(ctx context.Context, host string, port int, isHTTPS bool) string {
	// Set up HTTP(S) client with timeout
	client := &http.Client{
		Timeout: time.Duration(s.config.ScanTimeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skip certificate verification for scanning
			},
		},
	}
	
	// Construct URL
	protocol := "http"
	if isHTTPS {
		protocol = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", protocol, host, port)
	
	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ""
	}
	
	// Add user agent to avoid blocking
	req.Header.Set("User-Agent", "Mozilla/5.0 Surveyor/1.0")
	
	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return protocol
	}
	defer resp.Body.Close()
	
	// Check server header
	server := resp.Header.Get("Server")
	if server != "" {
		return fmt.Sprintf("%s:%s", protocol, server)
	}
	
	return protocol
}

// identifyServiceByPort makes an educated guess about a service based on port number
func (s *Scanner) identifyServiceByPort(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25, 587, 465:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 119:
		return "nntp"
	case 123:
		return "ntp"
	case 143:
		return "imap"
	case 161:
		return "snmp"
	case 443:
		return "https"
	case 445:
		return "smb"
	case 514:
		return "syslog"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 8080, 8443:
		return "http-alt"
	case 9200, 9300:
		return "elasticsearch"
	case 27017, 27018, 27019:
		return "mongodb"
	default:
		return ""
	}
}

// checkVulnerabilities checks for known vulnerabilities in detected services
func (s *Scanner) checkVulnerabilities(result *ScanResult) {
	// Skip if no services were detected
	if len(result.Services) == 0 {
		return
	}
	
	// Check each service against vulnerability database
	for _, serviceInfo := range result.Services {
		if vulns, exists := s.vulnDatabase[serviceInfo]; exists {
			result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
		}
	}
}

// testSSHConnection attempts to connect to an SSH server to gather version info
func (s *Scanner) testSSHConnection(host string, port int) (string, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	config := &ssh.ClientConfig{
		User: "surveyor",
		Auth: []ssh.AuthMethod{
			ssh.Password("invalid_password"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(s.config.ScanTimeout) * time.Second,
	}
	
	// We expect this to fail, but we want to grab the banner info
	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		// Check if the error contains version information
		if strings.Contains(err.Error(), "ssh:") {
			versionInfo := err.Error()
			// Extract just the version part
			versionPattern := regexp.MustCompile(`remote: (.+)`)
			matches := versionPattern.FindStringSubmatch(versionInfo)
			if len(matches) > 1 {
				return "ssh:" + matches[1], nil
			}
			return "ssh", nil
		}
		return "", err
	}
	// If we somehow succeed (with invalid credentials), close the connection
	client.Close()
	return "ssh", nil
}

// ScanNetwork scans multiple hosts concurrently
func (s *Scanner) ScanNetwork(ctx context.Context, hosts []string) ([]*ScanResult, error) {
	// Record start time for performance measurement
	s.scanStartTime = time.Now()
	
	var results []*ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	errors := make(chan error, len(hosts))

	// Create a buffered channel for host scanning workers
	hostChan := make(chan string, len(hosts))

	// Log scan start
	s.logger.Info("Starting network scan",
		zap.Int("hosts", len(hosts)),
		zap.Int("concurrency", s.config.ConcurrentScans),
		zap.Strings("target_hosts", hosts),
	)

	// Create a context with a timeout if using our own timeouts
	timeoutCtx := ctx
	if s.config.ScanTimeout > 0 {
		var cancel context.CancelFunc
		timeoutCtx, cancel = context.WithTimeout(ctx, time.Duration(s.config.ScanTimeout*len(hosts))*time.Second)
		defer cancel()
	}

	// Start workers
	for i := 0; i < s.config.ConcurrentScans; i++ {
		wg.Add(1)
		go func(workerId int) {
			defer wg.Done()
			
			s.logger.Debug("Scanner worker started", zap.Int("worker_id", workerId))
			
			for host := range hostChan {
				// Check if the context has been canceled
				select {
				case <-timeoutCtx.Done():
					errors <- fmt.Errorf("scan timeout or cancellation for host %s: %v", host, timeoutCtx.Err())
					continue
				default:
					// Continue with the scan
				}

				s.logger.Debug("Scanning host", zap.String("host", host), zap.Int("worker", workerId))
				result, err := s.ScanHost(timeoutCtx, host)
				
				if err != nil {
					errors <- fmt.Errorf("failed to scan host %s: %w", host, err)
					// Still add the partial result
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
				} else {
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
					
					s.logger.Debug("Host scan completed",
						zap.String("host", host),
						zap.Int("open_tcp_ports", len(result.OpenPorts)),
						zap.Int("open_udp_ports", len(result.OpenUDPPorts)),
						zap.String("os", result.OS),
					)
				}
			}
		}(i)
	}

	// Send hosts to workers
	for _, host := range hosts {
		select {
		case <-timeoutCtx.Done():
			close(hostChan)
			s.logger.Warn("Scan operation timeout or cancelled", zap.Error(timeoutCtx.Err()))
			return results, fmt.Errorf("scan operation canceled or timed out: %v", timeoutCtx.Err())
		case hostChan <- host:
			// Host sent to worker
		}
	}
	close(hostChan)

	// Wait for all workers to finish
	wg.Wait()
	close(errors)

	// Collect any errors
	var errorsList []string
	for err := range errors {
		errorsList = append(errorsList, err.Error())
	}

	// Record scan duration
	scanDuration := time.Since(s.scanStartTime)
	
	s.logger.Info("Network scan completed",
		zap.Duration("duration", scanDuration),
		zap.Int("hosts_scanned", len(results)),
		zap.Int("errors", len(errorsList)),
	)

	if len(errorsList) > 0 {
		return results, fmt.Errorf("scan errors occurred: %s", strings.Join(errorsList, "; "))
	}

	return results, nil
}

// DNSCache provides a simple time-based cache for DNS lookups
type DNSCache struct {
	cache      map[string]dnsCacheEntry
	mu         sync.RWMutex
	defaultTTL time.Duration
}

type dnsCacheEntry struct {
	value     string
	expiresAt time.Time
}

// NewDNSCache creates a new DNS cache with the specified TTL
func NewDNSCache(ttl time.Duration) *DNSCache {
	return &DNSCache{
		cache:      make(map[string]dnsCacheEntry),
		defaultTTL: ttl,
	}
}

// Get retrieves a value from the cache
func (c *DNSCache) Get(key string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	entry, exists := c.cache[key]
	if !exists {
		return ""
	}
	
	// Check if the entry has expired
	if time.Now().After(entry.expiresAt) {
		// Expired entry
		go c.removeExpired(key)
		return ""
	}
	
	return entry.value
}

// Set adds a value to the cache
func (c *DNSCache) Set(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.cache[key] = dnsCacheEntry{
		value:     value,
		expiresAt: time.Now().Add(c.defaultTTL),
	}
}

// removeExpired removes an expired entry from the cache
func (c *DNSCache) removeExpired(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	entry, exists := c.cache[key]
	if exists && time.Now().After(entry.expiresAt) {
		delete(c.cache, key)
	}
}

// Cleanup removes all expired entries from the cache
func (c *DNSCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	now := time.Now()
	for key, entry := range c.cache {
		if now.After(entry.expiresAt) {
			delete(c.cache, key)
		}
	}
}

// ScanResultCache provides a simple time-based cache for scan results
type ScanResultCache struct {
	cache      map[string]scanResultCacheEntry
	mu         sync.RWMutex
	defaultTTL time.Duration
}

type scanResultCacheEntry struct {
	result    *ScanResult
	expiresAt time.Time
}

// NewScanResultCache creates a new scan result cache with the specified TTL
func NewScanResultCache(ttl time.Duration) *ScanResultCache {
	cache := &ScanResultCache{
		cache:      make(map[string]scanResultCacheEntry),
		defaultTTL: ttl,
	}
	
	// Start a cleanup goroutine
	go func() {
		ticker := time.NewTicker(ttl / 2)
		defer ticker.Stop()
		
		for range ticker.C {
			cache.Cleanup()
		}
	}()
	
	return cache
}

// Get retrieves a result from the cache
func (c *ScanResultCache) Get(key string) *ScanResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	entry, exists := c.cache[key]
	if !exists {
		return nil
	}
	
	// Check if the entry has expired
	if time.Now().After(entry.expiresAt) {
		// Expired entry
		go c.removeExpired(key)
		return nil
	}
	
	return entry.result
}

// Set adds a result to the cache
func (c *ScanResultCache) Set(key string, result *ScanResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.cache[key] = scanResultCacheEntry{
		result:    result,
		expiresAt: time.Now().Add(c.defaultTTL),
	}
}

// removeExpired removes an expired entry from the cache
func (c *ScanResultCache) removeExpired(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	entry, exists := c.cache[key]
	if exists && time.Now().After(entry.expiresAt) {
		delete(c.cache, key)
	}
}

// Cleanup removes all expired entries from the cache
func (c *ScanResultCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	now := time.Now()
	for key, entry := range c.cache {
		if now.After(entry.expiresAt) {
			delete(c.cache, key)
		}
	}
}