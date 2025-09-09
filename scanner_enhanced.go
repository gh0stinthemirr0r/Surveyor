package surveyor

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"
)

// EnhancedPortScanner provides improved port scanning with better concurrency
type EnhancedPortScanner struct {
	config       *Config
	logger       *zap.Logger
	cache        *CachingService
	scanSemaphore *semaphore.Weighted
	stats        *ScanStats
	hostWaitGroup sync.WaitGroup
	portWaitGroup sync.WaitGroup
	scannerID    string
}

// ScanStats tracks various statistics about the scanning process
type ScanStats struct {
	PortsScanned     int64
	OpenPortsFound   int64
	ScanDuration     time.Duration
	PortsPerSecond   float64
	HostsScanned     int64
	ActiveWorkers    int64
	ErrorCount       int64
	CacheHits        int64
	mu               sync.RWMutex
}

// NewEnhancedPortScanner creates a new instance of EnhancedPortScanner
func NewEnhancedPortScanner(config *Config, logger *zap.Logger, cache *CachingService) *EnhancedPortScanner {
	return &EnhancedPortScanner{
		config:       config,
		logger:       logger.With(zap.String("component", "enhanced_scanner")),
		cache:        cache,
		scanSemaphore: semaphore.NewWeighted(int64(config.ConcurrentScans)),
		stats:        &ScanStats{},
		scannerID:    GenerateRandomID(8),
	}
}

// ScanHost performs an enhanced scan of a single host
func (s *EnhancedPortScanner) ScanHost(ctx context.Context, host string) (*ScanResult, error) {
	// Check cache first
	if s.cache != nil {
		if cachedResult := s.cache.GetScanResult(host); cachedResult != nil {
			s.logger.Debug("Using cached scan result", zap.String("host", host))
			s.stats.mu.Lock()
			s.stats.CacheHits++
			s.stats.mu.Unlock()
			return cachedResult, nil
		}
	}

	// Increase counter for hosts scanned
	s.stats.mu.Lock()
	s.stats.HostsScanned++
	s.stats.mu.Unlock()

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

	// Create port work pool
	tcpPorts := getPortsToScan(s.config.PortRangeStart, s.config.PortRangeEnd, s.config.ExcludedPorts)
	
	// Use appropriate worker pool size based on port count
	workerCount := s.config.ConcurrentScans
	if len(tcpPorts) < workerCount {
		workerCount = len(tcpPorts)
	}
	if workerCount < 1 {
		workerCount = 1
	}

	// Create work channels
	portChan := make(chan int, len(tcpPorts))
	resultChan := make(chan int, len(tcpPorts))
	errorChan := make(chan error, workerCount)

	// Start TCP port scanning workers
	var openPorts []int
	var mutex sync.Mutex

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Launch port scanning workers
	for i := 0; i < workerCount; i++ {
		go func(workerId int) {
			// Increase active worker count
			s.stats.mu.Lock()
			s.stats.ActiveWorkers++
			s.stats.mu.Unlock()
			
			defer func() {
				// Decrease active worker count
				s.stats.mu.Lock()
				s.stats.ActiveWorkers--
				s.stats.mu.Unlock()
			}()

			for port := range portChan {
				select {
				case <-ctx.Done():
					return
				default:
					if err := s.scanSemaphore.Acquire(ctx, 1); err != nil {
						errorChan <- fmt.Errorf("failed to acquire semaphore: %w", err)
						continue
					}

					isOpen, err := s.isPortOpen(ctx, result.Host, port)
					
					// Track total ports scanned
					s.stats.mu.Lock()
					s.stats.PortsScanned++
					s.stats.mu.Unlock()

					if err != nil {
						errorChan <- fmt.Errorf("failed to scan port %d: %w", port, err)
					} else if isOpen {
						mutex.Lock()
						openPorts = append(openPorts, port)
						mutex.Unlock()
						resultChan <- port
						
						// Track open ports found
						s.stats.mu.Lock()
						s.stats.OpenPortsFound++
						s.stats.mu.Unlock()
					}

					s.scanSemaphore.Release(1)
				}
			}
		}(i)
	}

	// Feed ports to workers
	go func() {
		for _, port := range tcpPorts {
			select {
			case <-ctx.Done():
				close(portChan)
				return
			case portChan <- port:
				// Port sent successfully
			}
		}
		close(portChan)
	}()

	// Collect results until all ports have been processed
	portsDone := 0
	expectedPorts := len(tcpPorts)
	errors := make([]error, 0)

	for {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case err := <-errorChan:
			errors = append(errors, err)
			s.stats.mu.Lock()
			s.stats.ErrorCount++
			s.stats.mu.Unlock()
			portsDone++
		case <-resultChan:
			portsDone++
		default:
			if portsDone >= expectedPorts {
				goto LoopEnd
			}
			// Sleep briefly to avoid CPU spinning
			time.Sleep(5 * time.Millisecond)
		}
	}

LoopEnd:
	// Sort open ports and assign to result
	result.OpenPorts = sortInts(openPorts)

	// Scan UDP ports if enabled
	if s.config.ScanUDP {
		udpPorts, err := s.scanUDPPorts(ctx, result.Host)
		if err != nil {
			s.logger.Warn("UDP port scan had errors", zap.String("host", result.Host), zap.Error(err))
		}
		result.OpenUDPPorts = udpPorts
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
	if s.cache != nil {
		s.cache.SetScanResult(host, result)
	}

	return result, nil
}

// ScanPortRange scans a range of ports on a host using adaptive techniques
func (s *EnhancedPortScanner) ScanPortRange(ctx context.Context, host string, startPort, endPort int) ([]int, error) {
	// Validate port range
	if startPort < 1 || endPort > 65535 || startPort > endPort {
		return nil, fmt.Errorf("invalid port range: %d-%d", startPort, endPort)
	}

	// Generate port list
	ports := make([]int, 0, endPort-startPort+1)
	for port := startPort; port <= endPort; port++ {
		ports = append(ports, port)
	}

	// Reorder ports to prioritize common ones
	ports = s.prioritizePorts(ports)

	// Track scan timing
	startTime := time.Now()
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	errorChan := make(chan error, s.config.ConcurrentScans)

	// Create a worker pool
	concurrency := s.config.ConcurrentScans
	if len(ports) < concurrency {
		concurrency = len(ports)
	}

	// Split ports into chunks
	portChunks := s.splitPortsIntoChunks(ports, concurrency)

	// Start workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		chunk := portChunks[i]

		go func(workerID int, ports []int) {
			defer wg.Done()

			for _, port := range ports {
				select {
				case <-ctx.Done():
					return
				default:
					if err := s.scanSemaphore.Acquire(ctx, 1); err != nil {
						errorChan <- err
						continue
					}

					isOpen, err := s.isPortOpen(ctx, host, port)
					s.scanSemaphore.Release(1)

					if err != nil {
						errorChan <- err
					} else if isOpen {
						mu.Lock()
						openPorts = append(openPorts, port)
						mu.Unlock()
					}

					// Update scan stats
					s.stats.mu.Lock()
					s.stats.PortsScanned++
					if isOpen {
						s.stats.OpenPortsFound++
					}
					s.stats.mu.Unlock()
				}
			}
		}(i, chunk)
	}

	// Start a goroutine to collect errors
	errors := make([]error, 0)
	errDone := make(chan struct{})

	go func() {
		for err := range errorChan {
			errors = append(errors, err)
			s.stats.mu.Lock()
			s.stats.ErrorCount++
			s.stats.mu.Unlock()
		}
		close(errDone)
	}()

	// Wait for all workers to finish
	wg.Wait()
	close(errorChan)
	<-errDone

	// Update scan stats
	scanDuration := time.Since(startTime)
	portsPerSecond := float64(endPort-startPort+1) / scanDuration.Seconds()

	s.stats.mu.Lock()
	s.stats.ScanDuration = scanDuration
	s.stats.PortsPerSecond = portsPerSecond
	s.stats.mu.Unlock()

	s.logger.Debug("Port scan completed",
		zap.String("host", host),
		zap.Int("ports_scanned", endPort-startPort+1),
		zap.Int("open_ports", len(openPorts)),
		zap.Float64("ports_per_second", portsPerSecond),
		zap.Duration("duration", scanDuration),
	)

	// Return sorted list of open ports
	return sortInts(openPorts), nil
}

// isPortOpen checks if a specific port is open on a host
func (s *EnhancedPortScanner) isPortOpen(ctx context.Context, host string, port int) (bool, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	
	// Create a dialer with timeout
	var d net.Dialer
	d.Timeout = time.Duration(s.config.ScanTimeout) * time.Second
	
	// Connect to the target
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return false, nil
	}
	
	// Close the connection
	defer conn.Close()
	return true, nil
}

// prioritizePorts reorders ports to check common ones first
func (s *EnhancedPortScanner) prioritizePorts(ports []int) []int {
	// Common service ports to prioritize
	commonPorts := map[int]bool{
		22: true, 80: true, 443: true, 3389: true, 21: true,
		25: true, 110: true, 143: true, 445: true, 8080: true,
		8443: true, 3306: true, 5432: true, 1433: true, 27017: true,
		6379: true, 5672: true, 9200: true, 2375: true, 2376: true,
	}
	
	// Sort ports: common ones first, then others
	prioritized := make([]int, 0, len(ports))
	other := make([]int, 0, len(ports))
	
	for _, port := range ports {
		if commonPorts[port] {
			prioritized = append(prioritized, port)
		} else {
			other = append(other, port)
		}
	}
	
	// Combine prioritized and other ports
	return append(prioritized, other...)
}

// splitPortsIntoChunks divides ports into roughly equal chunks for workers
func (s *EnhancedPortScanner) splitPortsIntoChunks(ports []int, numChunks int) [][]int {
	// Make sure we have at least one chunk
	if numChunks < 1 {
		numChunks = 1
	}
	
	// Make sure we don't have more chunks than ports
	if numChunks > len(ports) {
		numChunks = len(ports)
	}
	
	// Calculate chunk size and create chunks
	chunkSize := (len(ports) + numChunks - 1) / numChunks
	chunks := make([][]int, numChunks)
	
	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		
		if end > len(ports) {
			end = len(ports)
		}
		
		chunks[i] = ports[start:end]
	}
	
	return chunks
}

// detectOS attempts to determine the operating system of a host
func (s *EnhancedPortScanner) detectOS(ctx context.Context, host string) (string, error) {
	// Try to use existing detectOS implementation if available
	if detectOS, ok := interface{}(s).(interface{ detectOS(ctx context.Context, host string) (string, error) }); ok {
		return detectOS.detectOS(ctx, host)
	}

	// Fallback to basic OS detection
	return s.basicOSDetection(host)
}

// basicOSDetection performs basic OS detection using TTL values
func (s *EnhancedPortScanner) basicOSDetection(host string) (string, error) {
	// Use echo port (7) for detection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:7", host), time.Duration(s.config.ScanTimeout)*time.Second)
	if err != nil {
		// Try HTTP port (80) instead
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:80", host), time.Duration(s.config.ScanTimeout)*time.Second)
		if err != nil {
			// Try HTTPS port (443) as last resort
			conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:443", host), time.Duration(s.config.ScanTimeout)*time.Second)
			if err != nil {
				return "Unknown", fmt.Errorf("failed to connect for OS detection: %w", err)
			}
		}
	}
	defer conn.Close()

	// Extract TTL from connection (this is a simplified approach)
	// In a real implementation, you would analyze TCP/IP packet headers
	// This simplified version returns a placeholder
	return "OS detection disabled", nil
}

// scanUDPPorts scans for open UDP ports
func (s *EnhancedPortScanner) scanUDPPorts(ctx context.Context, host string) ([]int, error) {
	if !s.config.ScanUDP {
		return nil, nil
	}

	// UDP common ports to check
	udpPorts := []int{
		53,    // DNS
		67,    // DHCP
		68,    // DHCP
		69,    // TFTP
		123,   // NTP
		137,   // NetBIOS
		138,   // NetBIOS
		161,   // SNMP
		162,   // SNMP
		500,   // IKE
		514,   // Syslog
		520,   // RIP
		1434,  // MS-SQL
		1900,  // UPNP
		5353,  // mDNS
	}

	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Create a context with timeout
	scanCtx, cancel := context.WithTimeout(ctx, time.Duration(s.config.ScanTimeout)*time.Second)
	defer cancel()

	// Scan each port
	for _, port := range udpPorts {
		wg.Add(1)

		go func(port int) {
			defer wg.Done()

			// Create UDP address
			address := fmt.Sprintf("%s:%d", host, port)
			addr, err := net.ResolveUDPAddr("udp", address)
			if err != nil {
				s.logger.Debug("Failed to resolve UDP address", 
					zap.String("address", address),
					zap.Error(err))
				return
			}

			// Create UDP connection
			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				s.logger.Debug("Failed to create UDP connection", 
					zap.String("address", address),
					zap.Error(err))
				return
			}
			defer conn.Close()

			// Set deadlines
			conn.SetDeadline(time.Now().Add(time.Duration(s.config.ScanTimeout) * time.Second))

			// Send a probe packet
			_, err = conn.Write([]byte("Surveyor UDP probe"))
			if err != nil {
				s.logger.Debug("Failed to send UDP probe", 
					zap.String("address", address),
					zap.Error(err))
				return
			}

			// Try to read response
			buf := make([]byte, 1024)
			_, _, err = conn.ReadFromUDP(buf)
			
			// If we get any response or a timeout error (which is expected),
			// the port might be open
			if err == nil {
				// Definite response
				mu.Lock()
				openPorts = append(openPorts, port)
				mu.Unlock()
				s.logger.Debug("UDP port open (response received)", zap.Int("port", port))
			} else if err, ok := err.(net.Error); ok && err.Timeout() {
				// For UDP, a timeout could mean the port is open but no response was sent
				// This is a false positive, but we include it for thoroughness
				mu.Lock()
				openPorts = append(openPorts, port)
				mu.Unlock()
				s.logger.Debug("UDP port possibly open (timeout)", zap.Int("port", port))
			}
		}(port)
	}

	// Wait for all UDP scans to complete
	wg.Wait()

	// Sort the open ports
	sort.Ints(openPorts)
	
	return openPorts, nil
}

// detectServices identifies services running on open ports
func (s *EnhancedPortScanner) detectServices(ctx context.Context, result *ScanResult) {
	if len(result.OpenPorts) == 0 {
		return
	}

	// Use a wait group to track goroutines
	var wg sync.WaitGroup
	var mutex sync.Mutex

	// Create a map of well-known services
	wellKnownServices := getWellKnownServices()

	// Check each open port
	for _, port := range result.OpenPorts {
		wg.Add(1)

		go func(port int) {
			defer wg.Done()

			// First, check if it's a well-known service
			if serviceName, found := wellKnownServices[port]; found {
				mutex.Lock()
				result.Services[port] = serviceName
				mutex.Unlock()
				return
			}

			// Try to connect and get banner
			address := fmt.Sprintf("%s:%d", result.Host, port)
			
			// Create context with timeout
			connCtx, cancel := context.WithTimeout(ctx, time.Duration(s.config.ScanTimeout)*time.Second)
			defer cancel()

			var d net.Dialer
			conn, err := d.DialContext(connCtx, "tcp", address)
			if err != nil {
				// Can't connect to get banner
				return
			}
			defer conn.Close()

			// Set read deadline
			conn.SetReadDeadline(time.Now().Add(time.Duration(s.config.ScanTimeout) * time.Second))

			// Try to read banner
			buffer := make([]byte, 1024)
			n, err := conn.Read(buffer)
			
			serviceName := "unknown"
			if err == nil && n > 0 {
				// Got a banner, try to identify service
				banner := string(buffer[:n])
				serviceName = identifyServiceFromBanner(banner, port)
			} else {
				// No banner, try to identify by sending probes
				serviceName = identifyServiceWithProbes(conn, port)
			}

			// Store the service information
			mutex.Lock()
			result.Services[port] = serviceName
			mutex.Unlock()
		}(port)
	}

	// Wait for all service detection to complete
	wg.Wait()
}

// identifyServiceFromBanner attempts to identify a service from its banner
func identifyServiceFromBanner(banner string, port int) string {
	// Check for common banner patterns
	// These are simplified examples; a real implementation would have more patterns
	if containsAny(banner, []string{"SSH", "OpenSSH"}) {
		return "ssh"
	} else if containsAny(banner, []string{"HTTP", "Server:", "Apache", "nginx", "IIS"}) {
		return "http"
	} else if containsAny(banner, []string{"FTP", "FileZilla", "vsftpd"}) {
		return "ftp"
	} else if containsAny(banner, []string{"SMTP", "Postfix", "Sendmail", "Exchange"}) {
		return "smtp"
	} else if containsAny(banner, []string{"POP3", "Dovecot", "Courier"}) {
		return "pop3"
	} else if containsAny(banner, []string{"IMAP"}) {
		return "imap"
	} else if containsAny(banner, []string{"MySQL", "MariaDB"}) {
		return "mysql"
	} else if containsAny(banner, []string{"Postgres", "PostgreSQL"}) {
		return "postgresql"
	} else if containsAny(banner, []string{"Microsoft SQL Server"}) {
		return "mssql"
	} else if containsAny(banner, []string{"MongoDB"}) {
		return "mongodb"
	} else if containsAny(banner, []string{"Redis"}) {
		return "redis"
	}

	// Default to unknown
	return fmt.Sprintf("unknown:%d", port)
}

// identifyServiceWithProbes tries to identify a service by sending specific probes
func identifyServiceWithProbes(conn net.Conn, port int) string {
	// This is a simplified implementation
	// A real version would send different protocol-specific probes
	
	// Most common port mappings
	switch port {
	case 22:
		return "ssh"
	case 80, 8080, 8000:
		return "http"
	case 443, 8443:
		return "https"
	case 21:
		return "ftp"
	case 25, 587:
		return "smtp"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 1433:
		return "mssql"
	case 27017:
		return "mongodb"
	case 6379:
		return "redis"
	case 5672, 5671:
		return "amqp"
	case 9200, 9300:
		return "elasticsearch"
	case 53:
		return "dns"
	case 161:
		return "snmp"
	case 389:
		return "ldap"
	case 636:
		return "ldaps"
	case 3389:
		return "rdp"
	case 5900:
		return "vnc"
	}
	
	// Default to unknown with port
	return fmt.Sprintf("unknown:%d", port)
}

// containsAny checks if a string contains any of the substrings in the list
func containsAny(s string, substrings []string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// checkVulnerabilities checks for known vulnerabilities in detected services
// This is a placeholder - in a real implementation, it would query a vulnerability database
func (s *EnhancedPortScanner) checkVulnerabilities(result *ScanResult) {
	// This is a placeholder implementation
	// A real implementation would check a vulnerability database
	
	// For now, we'll add a dummy vulnerability for demonstration purposes
	if _, found := result.Services[22]; found {
		result.Vulnerabilities = append(result.Vulnerabilities, "CVE-2018-15473")
	}
	
	if _, found := result.Services[80]; found {
		result.Vulnerabilities = append(result.Vulnerabilities, "CVE-2021-44228")
	}
}

// resolveHostname resolves a hostname to an IP address
func (s *EnhancedPortScanner) resolveHostname(hostname string) (string, error) {
	// Check cache first
	if s.cache != nil {
		if ip := s.cache.GetDNS(hostname); ip != "" {
			return ip, nil
		}
	}

	// Perform DNS lookup
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", fmt.Errorf("failed to resolve hostname %s: %w", hostname, err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for %s", hostname)
	}

	// Prefer IPv4 addresses
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			// Cache the result if caching is enabled
			if s.cache != nil {
				s.cache.SetDNS(hostname, ipv4.String())
			}
			return ipv4.String(), nil
		}
	}

	// Fall back to first IPv6 address
	ipString := ips[0].String()
	
	// Cache the result if caching is enabled
	if s.cache != nil {
		s.cache.SetDNS(hostname, ipString)
	}
	
	return ipString, nil
}

// reverseLookup performs a reverse DNS lookup on an IP
func (s *EnhancedPortScanner) reverseLookup(ip string) (string, error) {
	// Check cache first
	if s.cache != nil {
		if hostname := s.cache.GetDNS("rev:" + ip); hostname != "" {
			return hostname, nil
		}
	}

	// Perform reverse lookup
	names, err := net.LookupAddr(ip)
	if err != nil {
		return "", fmt.Errorf("reverse lookup failed for %s: %w", ip, err)
	}

	if len(names) == 0 {
		return "", fmt.Errorf("no hostnames found for %s", ip)
	}

	// Cache the result if caching is enabled
	if s.cache != nil {
		s.cache.SetDNS("rev:"+ip, names[0])
	}

	return names[0], nil
}

// GetScanStats returns current scanning statistics
func (s *EnhancedPortScanner) GetScanStats() ScanStats {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()
	
	return *s.stats
}

// ScanNetwork performs a scan of a network range
func (s *EnhancedPortScanner) ScanNetwork(ctx context.Context, targets []string) ([]*ScanResult, error) {
	// Start timing the scan
	startTime := time.Now()
	
	// Track scan targets
	var results []*ScanResult
	var resultsMutex sync.Mutex
	
	// Create a wait group to track concurrent host scans
	var wg sync.WaitGroup
	
	// Create a semaphore to limit concurrent host scans
	hostSemaphore := semaphore.NewWeighted(int64(s.config.ConcurrentHosts))
	
	// Expand CIDR ranges if present
	expandedTargets, err := expandTargets(targets)
	if err != nil {
		return nil, fmt.Errorf("failed to expand targets: %w", err)
	}
	
	// Scan each target
	for _, target := range expandedTargets {
		// Acquire semaphore to limit concurrency
		if err := hostSemaphore.Acquire(ctx, 1); err != nil {
			s.logger.Warn("Failed to acquire semaphore, context cancelled", zap.Error(err))
			break
		}
		
		wg.Add(1)
		
		go func(host string) {
			defer wg.Done()
			defer hostSemaphore.Release(1)
			
			// Scan the host
			result, err := s.ScanHost(ctx, host)
			if err != nil {
				s.logger.Warn("Failed to scan host", 
					zap.String("host", host),
					zap.Error(err))
				return
			}
			
			// Add to results
			resultsMutex.Lock()
			results = append(results, result)
			resultsMutex.Unlock()
		}(target)
	}
	
	// Wait for all scans to complete
	wg.Wait()
	
	// Update scan stats
	scanDuration := time.Since(startTime)
	s.stats.mu.Lock()
	s.stats.ScanDuration = scanDuration
	s.stats.mu.Unlock()
	
	s.logger.Info("Network scan completed",
		zap.Int("targets", len(expandedTargets)),
		zap.Int("results", len(results)),
		zap.Duration("duration", scanDuration),
		zap.Float64("hosts_per_second", float64(len(expandedTargets))/scanDuration.Seconds()),
	)
	
	return results, nil
}

// GenerateRandomID generates a random ID string of the given length
func GenerateRandomID(length int) string {
	// This is a simplified implementation
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

// getWellKnownServices returns a map of well-known port numbers to service names
func getWellKnownServices() map[int]string {
	return map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		115:   "sftp",
		119:   "nntp",
		123:   "ntp",
		143:   "imap",
		161:   "snmp",
		194:   "irc",
		443:   "https",
		445:   "smb",
		465:   "smtps",
		587:   "submission",
		993:   "imaps",
		995:   "pop3s",
		1080:  "socks",
		1194:  "openvpn",
		1433:  "mssql",
		1521:  "oracle",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http-proxy",
		8443:  "https-alt",
		27017: "mongodb",
	}
}

// expandTargets expands CIDR ranges and resolves hostnames in the target list
func expandTargets(targets []string) ([]string, error) {
	var expanded []string
	
	for _, target := range targets {
		// Check if it's a CIDR range
		if strings.Contains(target, "/") {
			hosts, err := expandCIDR(target)
			if err != nil {
				return nil, fmt.Errorf("failed to expand CIDR %s: %w", target, err)
			}
			expanded = append(expanded, hosts...)
		} else {
			// Single host
			expanded = append(expanded, target)
		}
	}
	
	return expanded, nil
}

// expandCIDR expands a CIDR range into individual IP addresses
func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	
	var ips []string
	
	// Count of IPs in the range
	count := int(math.Pow(2, float64(32-countBits(ipnet.Mask))))
	if count > 1000 {
		// Limit large scans to avoid memory issues
		return nil, fmt.Errorf("CIDR range %s contains too many IPs (%d)", cidr, count)
	}
	
	// Iterate through IPs in the range
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	
	// Remove network and broadcast addresses for IPv4 if range is large enough
	if len(ips) > 2 && ip.To4() != nil {
		return ips[1 : len(ips)-1], nil
	}
	
	return ips, nil
}

// countBits counts the number of set bits in a network mask
func countBits(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// sortInts sorts an integer slice
func sortInts(ints []int) []int {
	// Copy to avoid modifying the original slice
	result := make([]int, len(ints))
	copy(result, ints)
	
	// Simple insertion sort for small slices
	for i := 1; i < len(result); i++ {
		key := result[i]
		j := i - 1
		for j >= 0 && result[j] > key {
			result[j+1] = result[j]
			j--
		}
		result[j+1] = key
	}
	
	return result
}