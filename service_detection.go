package surveyor

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
)

// ServiceDetector provides enhanced service detection capabilities
type ServiceDetector struct {
	config *Config
	logger *zap.Logger
	// Map of probes by port
	probesByPort map[int][]ServiceProbe
	// Map of probes by service name
	probesByService map[string][]ServiceProbe
}

// ServiceProbe represents a probe used to identify a service
type ServiceProbe struct {
	Name        string            // Name of the service
	Payload     []byte            // Data to send
	Pattern     *regexp.Regexp    // Pattern to match in the response
	Protocol    string            // TCP or UDP
	Ports       []int             // Common ports for this service
	Headers     map[string]string // HTTP headers to send (for HTTP probes)
	SSL         bool              // Whether to use SSL/TLS
	MinVersion  string            // Minimum version to detect (semver format)
	Timeout     time.Duration     // Timeout for this probe
}

// ServiceInfo contains information about a detected service
type ServiceInfo struct {
	Name         string            // Service name (e.g., "http", "ssh")
	Version      string            // Version if detected
	Product      string            // Product name if detected
	Banner       string            // Raw banner data
	ResponseTime time.Duration     // Response time
	Protocol     string            // TCP or UDP
	TLS          bool              // Whether service uses TLS
	TLSInfo      *TLSInfo          // TLS information if available
	Headers      map[string]string // HTTP headers if applicable
	Metadata     map[string]string // Additional metadata about the service
}

// TLSInfo contains information about TLS configuration
type TLSInfo struct {
	Version           string
	Cipher            string
	CertSubject       string
	CertIssuer        string
	CertExpiry        time.Time
	CertSelfSigned    bool
	SupportedVersions []string
	SupportedCiphers  []string
}

// NewServiceDetector creates a new service detector
func NewServiceDetector(config *Config, logger *zap.Logger) *ServiceDetector {
	sd := &ServiceDetector{
		config:         config,
		logger:         logger.With(zap.String("component", "service_detector")),
		probesByPort:   make(map[int][]ServiceProbe),
		probesByService: make(map[string][]ServiceProbe),
	}
	
	// Initialize with default probes
	sd.initializeProbes()
	
	return sd
}

// initializeProbes sets up the default service probes
func (sd *ServiceDetector) initializeProbes() {
	// HTTP probe
	httpProbe := ServiceProbe{
		Name:     "http",
		Payload:  []byte("GET / HTTP/1.1\r\nHost: host\r\nUser-Agent: Surveyor/2.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"),
		Pattern:  regexp.MustCompile(`(?i)^HTTP\/\d\.\d`),
		Protocol: "tcp",
		Ports:    []int{80, 8080, 8000, 8008, 8081, 8082, 8800},
		Timeout:  time.Second * 5,
	}
	
	// HTTPS probe
	httpsProbe := ServiceProbe{
		Name:     "https",
		Protocol: "tcp",
		SSL:      true,
		Ports:    []int{443, 8443, 4443, 8843},
		Timeout:  time.Second * 5,
	}
	
	// SSH probe
	sshProbe := ServiceProbe{
		Name:     "ssh",
		Payload:  []byte(""), // SSH servers send banner first
		Pattern:  regexp.MustCompile(`^SSH-\d\.\d`),
		Protocol: "tcp",
		Ports:    []int{22, 2222},
		Timeout:  time.Second * 5,
	}
	
	// FTP probe
	ftpProbe := ServiceProbe{
		Name:     "ftp",
		Payload:  []byte(""), // FTP servers send banner first
		Pattern:  regexp.MustCompile(`^220.*FTP`),
		Protocol: "tcp",
		Ports:    []int{21},
		Timeout:  time.Second * 5,
	}
	
	// SMTP probe
	smtpProbe := ServiceProbe{
		Name:     "smtp",
		Payload:  []byte(""), // SMTP servers send banner first
		Pattern:  regexp.MustCompile(`^220.*SMTP`),
		Protocol: "tcp",
		Ports:    []int{25, 587, 465},
		Timeout:  time.Second * 5,
	}
	
	// MySQL probe
	mysqlProbe := ServiceProbe{
		Name:     "mysql",
		Payload:  []byte{}, // MySQL servers send a greeting packet
		Pattern:  regexp.MustCompile(`^.\x00\x00\x00\x0a(.|[\r\n])*mysql`),
		Protocol: "tcp",
		Ports:    []int{3306},
		Timeout:  time.Second * 5,
	}
	
	// PostgreSQL probe
	postgresProbe := ServiceProbe{
		Name:     "postgresql",
		Payload:  []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}, // Startup message
		Pattern:  regexp.MustCompile(`^.`),
		Protocol: "tcp",
		Ports:    []int{5432},
		Timeout:  time.Second * 5,
	}
	
	// IMAP probe
	imapProbe := ServiceProbe{
		Name:     "imap",
		Payload:  []byte(""), // IMAP servers send banner first
		Pattern:  regexp.MustCompile(`^\* OK.*IMAP`),
		Protocol: "tcp",
		Ports:    []int{143, 993},
		Timeout:  time.Second * 5,
	}
	
	// DNS probe (TCP)
	dnsProbe := ServiceProbe{
		Name:     "dns",
		Payload:  []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1},
		Pattern:  regexp.MustCompile(`^.`),
		Protocol: "tcp",
		Ports:    []int{53},
		Timeout:  time.Second * 5,
	}
	
	// Add probes to maps
	probes := []ServiceProbe{httpProbe, httpsProbe, sshProbe, ftpProbe, smtpProbe, mysqlProbe, postgresProbe, imapProbe, dnsProbe}
	
	for _, probe := range probes {
		// Add to service map
		sd.probesByService[probe.Name] = append(sd.probesByService[probe.Name], probe)
		
		// Add to port map
		for _, port := range probe.Ports {
			sd.probesByPort[port] = append(sd.probesByPort[port], probe)
		}
	}
	
	sd.logger.Info("Service detector initialized", 
		zap.Int("probe_count", len(probes)),
		zap.Int("service_count", len(sd.probesByService)),
	)
}

// DetectService attempts to identify a service on the given host and port
func (sd *ServiceDetector) DetectService(ctx context.Context, host string, port int) (*ServiceInfo, error) {
	sd.logger.Debug("Detecting service", zap.String("host", host), zap.Int("port", port))
	
	// Create a context with timeout
	timeoutDuration := time.Duration(sd.config.ProbeTimeout) * time.Second
	if timeoutDuration == 0 {
		timeoutDuration = 5 * time.Second
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()
	
	// Check if we have specific probes for this port
	var probesToTry []ServiceProbe
	if probes, exists := sd.probesByPort[port]; exists {
		probesToTry = append(probesToTry, probes...)
	}
	
	// If port-specific probes don't exist or fail, try generic probes
	if len(probesToTry) == 0 {
		// Try common service probes based on port ranges
		switch {
		case port == 80 || port == 443 || (port >= 8000 && port <= 8999):
			// Web ports
			if probes, exists := sd.probesByService["http"]; exists {
				probesToTry = append(probesToTry, probes...)
			}
			if probes, exists := sd.probesByService["https"]; exists {
				probesToTry = append(probesToTry, probes...)
			}
		case port == 22:
			// SSH port
			if probes, exists := sd.probesByService["ssh"]; exists {
				probesToTry = append(probesToTry, probes...)
			}
		case port == 25 || port == 587 || port == 465:
			// Mail ports
			if probes, exists := sd.probesByService["smtp"]; exists {
				probesToTry = append(probesToTry, probes...)
			}
		default:
			// Try all probes as a fallback
			for _, probes := range sd.probesByService {
				probesToTry = append(probesToTry, probes...)
			}
		}
	}
	
	// Try each probe
	for _, probe := range probesToTry {
		service, err := sd.runProbe(timeoutCtx, host, port, probe)
		if err != nil {
			sd.logger.Debug("Probe failed", 
				zap.String("host", host), 
				zap.Int("port", port),
				zap.String("probe", probe.Name),
				zap.Error(err),
			)
			continue
		}
		
		if service != nil {
			sd.logger.Debug("Service detected",
				zap.String("host", host),
				zap.Int("port", port),
				zap.String("service", service.Name),
				zap.String("version", service.Version),
			)
			return service, nil
		}
	}
	
	// If we get here, try generic banner grabbing as a last resort
	service, err := sd.genericBannerGrab(timeoutCtx, host, port)
	if err != nil {
		sd.logger.Debug("Generic banner grab failed", 
			zap.String("host", host), 
			zap.Int("port", port),
			zap.Error(err),
		)
		// Return unknown service instead of error
		return &ServiceInfo{
			Name:     "unknown",
			Protocol: "tcp",
			Metadata: map[string]string{
				"detection_method": "port_only",
				"confidence":       "low",
			},
		}, nil
	}
	
	return service, nil
}

// runProbe executes a service probe against a host:port
func (sd *ServiceDetector) runProbe(ctx context.Context, host string, port int, probe ServiceProbe) (*ServiceInfo, error) {
	// Different handling based on protocol
	switch probe.Protocol {
	case "tcp":
		return sd.runTCPProbe(ctx, host, port, probe)
	case "udp":
		return sd.runUDPProbe(ctx, host, port, probe)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", probe.Protocol)
	}
}

// runTCPProbe performs a TCP-based service probe
func (sd *ServiceDetector) runTCPProbe(ctx context.Context, host string, port int, probe ServiceProbe) (*ServiceInfo, error) {
	// Setup dialer with timeout
	dialer := &net.Dialer{
		Timeout: probe.Timeout,
	}
	
	// Record start time for response timing
	startTime := time.Now()
	
	address := fmt.Sprintf("%s:%d", host, port)
	
	// Handle HTTPS and other SSL/TLS protocols
	if probe.SSL {
		// Try TLS connection
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // Skip certificate verification for scanning
			MinVersion:         tls.VersionTLS10,
		}
		
		conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		
		// Get TLS connection state
		tlsState := conn.ConnectionState()
		
		// Create service info
		serviceInfo := &ServiceInfo{
			Name:         probe.Name,
			ResponseTime: time.Since(startTime),
			Protocol:     "tcp",
			TLS:          true,
			TLSInfo: &TLSInfo{
				Version:        getTLSVersionString(tlsState.Version),
				Cipher:         tls.CipherSuiteName(tlsState.CipherSuite),
				SelfSigned:     isSelfSigned(tlsState),
			},
			Metadata: map[string]string{
				"detection_method": "tls_probe",
				"confidence":       "high",
			},
		}
		
		// For HTTPS, try to get HTTP server info
		if probe.Name == "https" {
			// Add certificate info
			if len(tlsState.PeerCertificates) > 0 {
				cert := tlsState.PeerCertificates[0]
				serviceInfo.TLSInfo.CertSubject = cert.Subject.String()
				serviceInfo.TLSInfo.CertIssuer = cert.Issuer.String()
				serviceInfo.TLSInfo.CertExpiry = cert.NotAfter
				
				// Extract server name from certificate
				if len(cert.DNSNames) > 0 {
					if serviceInfo.Product == "" {
						serviceInfo.Product = "Web Server"
					}
					serviceInfo.Metadata["server_name"] = cert.DNSNames[0]
				}
				
				// Check if self-signed
				serviceInfo.TLSInfo.CertSelfSigned = (cert.Issuer.String() == cert.Subject.String())
			}
			
			// Try an HTTP request to get server info
			httpInfo, err := sd.probeHTTPS(ctx, host, port)
			if err == nil && httpInfo != nil {
				// Merge information
				serviceInfo.Name = "https"
				serviceInfo.Version = httpInfo.Version
				serviceInfo.Product = httpInfo.Product
				serviceInfo.Headers = httpInfo.Headers
				
				// Add server info to metadata
				if server, exists := httpInfo.Headers["Server"]; exists {
					serviceInfo.Metadata["http_server"] = server
				}
			}
		}
		
		return serviceInfo, nil
	}
	
	// Regular TCP connection
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	
	// Set timeouts
	conn.SetReadDeadline(time.Now().Add(probe.Timeout))
	conn.SetWriteDeadline(time.Now().Add(probe.Timeout))
	
	// Some servers send banner first, try to read before sending payload
	preBuffer := make([]byte, 1024)
	preReadLen, preReadErr := conn.Read(preBuffer)
	
	var initialBanner string
	if preReadErr == nil && preReadLen > 0 {
		initialBanner = string(preBuffer[:preReadLen])
		
		// Check if initial banner matches pattern
		if probe.Pattern != nil && probe.Pattern.MatchString(initialBanner) {
			// Create service info from banner
			serviceInfo := createServiceFromBanner(probe.Name, initialBanner, time.Since(startTime))
			return serviceInfo, nil
		}
	}
	
	// Send probe payload if provided
	if len(probe.Payload) > 0 {
		_, err = conn.Write(probe.Payload)
		if err != nil {
			return nil, err
		}
	}
	
	// Read response
	buffer := make([]byte, 1024)
	readLen, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		return nil, err
	}
	
	responseTime := time.Since(startTime)
	
	// Handle case where we got data
	if readLen > 0 {
		response := string(buffer[:readLen])
		
		// Combine with initial banner if any
		if initialBanner != "" {
			response = initialBanner + response
		}
		
		// Check if response matches pattern
		if probe.Pattern != nil && probe.Pattern.MatchString(response) {
			// Create service info from response
			serviceInfo := createServiceFromBanner(probe.Name, response, responseTime)
			
			// Special handling for HTTP
			if probe.Name == "http" && strings.HasPrefix(response, "HTTP/") {
				httpInfo := parseHTTPResponse(response)
				serviceInfo.Headers = httpInfo.Headers
				serviceInfo.Version = httpInfo.Version
				serviceInfo.Product = httpInfo.Product
				
				// Add additional metadata
				if server, exists := httpInfo.Headers["Server"]; exists {
					serviceInfo.Metadata["http_server"] = server
				}
			}
			
			return serviceInfo, nil
		}
	}
	
	// No match
	return nil, fmt.Errorf("no service match found")
}

// runUDPProbe performs a UDP-based service probe
func (sd *ServiceDetector) runUDPProbe(ctx context.Context, host string, port int, probe ServiceProbe) (*ServiceInfo, error) {
	// Not fully implemented yet - would be similar to TCP but using UDP
	return nil, fmt.Errorf("UDP probe not implemented")
}

// probeHTTPS performs an HTTPS request to gather server information
func (sd *ServiceDetector) probeHTTPS(ctx context.Context, host string, port int) (*ServiceInfo, error) {
	url := fmt.Sprintf("https://%s:%d/", host, port)
	
	// Setup HTTP client with TLS config
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects
			return http.ErrUseLastResponse
		},
	}
	
	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	// Add headers to help with service detection
	req.Header.Set("User-Agent", "Surveyor/2.0")
	
	// Send request
	startTime := time.Now()
	resp, err := client.Do(req)
	responseTime := time.Since(startTime)
	
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	// Create service info
	serviceInfo := &ServiceInfo{
		Name:         "https",
		Protocol:     "tcp",
		ResponseTime: responseTime,
		TLS:          true,
		Headers:      make(map[string]string),
		Metadata:     make(map[string]string),
	}
	
	// Extract HTTP headers
	for name, values := range resp.Header {
		if len(values) > 0 {
			serviceInfo.Headers[name] = values[0]
		}
	}
	
	// Try to determine web server type and version
	if server, exists := serviceInfo.Headers["Server"]; exists {
		serviceInfo.Product = extractProductName(server)
		serviceInfo.Version = extractVersion(server)
		serviceInfo.Metadata["server_header"] = server
	} else {
		// No Server header, try other detection methods
		serviceInfo.Product = "Web Server"
		
		// Check for common headers that might indicate server type
		if _, exists := serviceInfo.Headers["X-Powered-By"]; exists {
			serviceInfo.Metadata["powered_by"] = serviceInfo.Headers["X-Powered-By"]
		}
	}
	
	return serviceInfo, nil
}

// genericBannerGrab attempts to grab a banner without a specific probe
func (sd *ServiceDetector) genericBannerGrab(ctx context.Context, host string, port int) (*ServiceInfo, error) {
	// Set up dialer with timeout
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}
	
	// Record start time
	startTime := time.Now()
	
	// Try standard TCP connection
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	
	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	
	// Try to read banner
	buffer := make([]byte, 1024)
	readLen, err := conn.Read(buffer)
	
	responseTime := time.Since(startTime)
	
	// If we got data, try to identify the service
	if err == nil && readLen > 0 {
		banner := string(buffer[:readLen])
		return createServiceFromBanner("unknown", banner, responseTime), nil
	}
	
	// If no initial banner, send a generic probe (HTTP GET) and see if we get a response
	_, err = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	if err != nil {
		return nil, err
	}
	
	// Read response
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	readLen, err = conn.Read(buffer)
	
	if err == nil && readLen > 0 {
		response := string(buffer[:readLen])
		
		// Check if it looks like HTTP
		if strings.HasPrefix(response, "HTTP/") {
			httpInfo := parseHTTPResponse(response)
			return &ServiceInfo{
				Name:         "http",
				Version:      httpInfo.Version,
				Product:      httpInfo.Product,
				Banner:       response,
				ResponseTime: responseTime,
				Protocol:     "tcp",
				Headers:      httpInfo.Headers,
				Metadata: map[string]string{
					"detection_method": "generic_probe",
					"confidence":       "medium",
				},
			}, nil
		}
		
		// Try to identify based on banner
		return createServiceFromBanner("unknown", response, responseTime), nil
	}
	
	// If still no response, create an unknown service
	return &ServiceInfo{
		Name:         "unknown",
		ResponseTime: responseTime,
		Protocol:     "tcp",
		Metadata: map[string]string{
			"detection_method": "connection_only",
			"confidence":       "low",
		},
	}, nil
}

// createServiceFromBanner creates a ServiceInfo from a banner
func createServiceFromBanner(probeName string, banner string, responseTime time.Duration) *ServiceInfo {
	service := &ServiceInfo{
		Name:         probeName,
		Banner:       banner,
		ResponseTime: responseTime,
		Protocol:     "tcp",
		Metadata:     make(map[string]string),
	}
	
	// Set detection method in metadata
	service.Metadata["detection_method"] = "banner"
	service.Metadata["confidence"] = "medium"
	
	// Try to identify service name if not provided
	if probeName == "unknown" {
		service.Name = guessServiceFromBanner(banner)
	}
	
	// Try to extract version information
	if strings.Contains(banner, "SSH-") {
		// SSH banner
		service.Name = "ssh"
		sshVersionPattern := regexp.MustCompile(`SSH-\d\.\d-([^\s\r\n]+)`)
		if matches := sshVersionPattern.FindStringSubmatch(banner); len(matches) > 1 {
			service.Product = "SSH"
			service.Version = matches[1]
			service.Metadata["confidence"] = "high"
		}
	} else if strings.Contains(banner, "220") && strings.Contains(banner, "FTP") {
		// FTP banner
		service.Name = "ftp"
		ftpVersionPattern := regexp.MustCompile(`220[^\(]*\(([^\)]+)\)`)
		if matches := ftpVersionPattern.FindStringSubmatch(banner); len(matches) > 1 {
			service.Product = "FTP"
			service.Version = matches[1]
			service.Metadata["confidence"] = "high"
		}
	} else if strings.Contains(banner, "SMTP") {
		// SMTP banner
		service.Name = "smtp"
		smtpVersionPattern := regexp.MustCompile(`([^\s]+) ESMTP ([^\s\r\n]+)`)
		if matches := smtpVersionPattern.FindStringSubmatch(banner); len(matches) > 2 {
			service.Product = matches[1]
			service.Version = matches[2]
			service.Metadata["confidence"] = "high"
		}
	} else if strings.Contains(banner, "POP3") {
		// POP3 banner
		service.Name = "pop3"
		service.Product = "POP3"
		popVersionPattern := regexp.MustCompile(`([^\s]+) POP3 ([^\s\r\n]+)`)
		if matches := popVersionPattern.FindStringSubmatch(banner); len(matches) > 2 {
			service.Product = matches[1]
			service.Version = matches[2]
		}
	} else if strings.Contains(banner, "IMAP") {
		// IMAP banner
		service.Name = "imap"
		service.Product = "IMAP"
		imapVersionPattern := regexp.MustCompile(`([^\s]+) IMAP4rev1 ([^\s\r\n]+)`)
		if matches := imapVersionPattern.FindStringSubmatch(banner); len(matches) > 2 {
			service.Product = matches[1]
			service.Version = matches[2]
		}
	} else if strings.HasPrefix(banner, "HTTP/") {
		// HTTP response
		service.Name = "http"
		httpInfo := parseHTTPResponse(banner)
		service.Headers = httpInfo.Headers
		service.Version = httpInfo.Version
		service.Product = httpInfo.Product
	}
	
	return service
}

// parseHTTPResponse parses an HTTP response for service information
func parseHTTPResponse(response string) *ServiceInfo {
	service := &ServiceInfo{
		Name:     "http",
		Headers:  make(map[string]string),
		Metadata: make(map[string]string),
	}
	
	// Extract HTTP version
	versionPattern := regexp.MustCompile(`HTTP/(\d\.\d)`)
	if matches := versionPattern.FindStringSubmatch(response); len(matches) > 1 {
		service.Version = "HTTP/" + matches[1]
	}
	
	// Extract headers
	headerPattern := regexp.MustCompile(`(?m)^([^:\r\n]+):\s*([^\r\n]*)`)
	headerMatches := headerPattern.FindAllStringSubmatch(response, -1)
	
	for _, match := range headerMatches {
		if len(match) > 2 {
			headerName := match[1]
			headerValue := match[2]
			service.Headers[headerName] = headerValue
			
			// Look for server information in the Server header
			if strings.EqualFold(headerName, "Server") {
				service.Product = extractProductName(headerValue)
				if service.Version == "" || service.Version == "HTTP/1.1" {
					service.Version = extractVersion(headerValue)
				}
			} else if strings.EqualFold(headerName, "X-Powered-By") {
				// X-Powered-By can provide additional information
				service.Metadata["powered_by"] = headerValue
			}
		}
	}
	
	// If no product was found but we have a Server header
	if service.Product == "" && service.Headers["Server"] != "" {
		service.Product = service.Headers["Server"]
	}
	
	return service
}

// guessServiceFromBanner attempts to identify the service from a banner
func guessServiceFromBanner(banner string) string {
	lowerBanner := strings.ToLower(banner)
	
	// Check for common service signatures
	if strings.Contains(lowerBanner, "ssh") {
		return "ssh"
	} else if strings.Contains(lowerBanner, "ftp") {
		return "ftp"
	} else if strings.Contains(lowerBanner, "smtp") {
		return "smtp"
	} else if strings.Contains(lowerBanner, "pop3") {
		return "pop3"
	} else if strings.Contains(lowerBanner, "imap") {
		return "imap"
	} else if strings.Contains(lowerBanner, "http") {
		return "http"
	} else if strings.Contains(lowerBanner, "mysql") {
		return "mysql"
	} else if strings.Contains(lowerBanner, "postgresql") {
		return "postgresql"
	} else if strings.Contains(lowerBanner, "mongodb") {
		return "mongodb"
	} else if strings.Contains(lowerBanner, "redis") {
		return "redis"
	} else if strings.Contains(lowerBanner, "vnc") {
		return "vnc"
	} else if strings.Contains(lowerBanner, "rtsp") {
		return "rtsp"
	}
	
	return "unknown"
}

// extractProductName extracts a product name from a server string
func extractProductName(server string) string {
	// Split by spaces and get first part
	parts := strings.Split(server, " ")
	if len(parts) > 0 {
		// Split by / to separate product from version
		productParts := strings.Split(parts[0], "/")
		if len(productParts) > 0 {
			return productParts[0]
		}
	}
	return server
}

// extractVersion extracts a version number from a string
func extractVersion(s string) string {
	// Look for patterns like product/1.2.3 or version 1.2.3
	versionPattern := regexp.MustCompile(`[\/\s](\d+\.\d+(?:\.\d+)?)`)
	if matches := versionPattern.FindStringSubmatch(s); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// getTLSVersionString converts a TLS version constant to a string
func getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// isSelfSigned checks if a TLS certificate is self-signed
func isSelfSigned(state tls.ConnectionState) bool {
	if len(state.PeerCertificates) == 0 {
		return false
	}
	
	cert := state.PeerCertificates[0]
	return cert.Issuer.String() == cert.Subject.String()
}

// Additional helper functions for service detection

// IsServiceVulnerable checks if a service is likely vulnerable based on version
func IsServiceVulnerable(serviceInfo *ServiceInfo) bool {
	// This would implement simple version-based vulnerability checks
	// For example, checking for known vulnerable versions
	
	// Example: Apache 2.4.49 was vulnerable to path traversal (CVE-2021-41773)
	if serviceInfo.Name == "http" && 
	   serviceInfo.Product == "Apache" && 
	   strings.HasPrefix(serviceInfo.Version, "2.4.49") {
		return true
	}
	
	// Example: OpenSSH < 7.7 vulnerable to user enumeration (CVE-2018-15473)
	if serviceInfo.Name == "ssh" && 
	   strings.Contains(serviceInfo.Product, "OpenSSH") {
		version := parseVersionNumber(serviceInfo.Version)
		if version < 7.7 {
			return true
		}
	}
	
	return false
}

// parseVersionNumber parses a version string to a float
func parseVersionNumber(version string) float64 {
	// Extract digits from version string
	versionPattern := regexp.MustCompile(`(\d+\.\d+)`)
	if matches := versionPattern.FindStringSubmatch(version); len(matches) > 1 {
		v, err := strconv.ParseFloat(matches[1], 64)
		if err == nil {
			return v
		}
	}
	return 0.0
}

// CompareTLSQuality assesses the quality of a TLS configuration
func CompareTLSQuality(tlsInfo *TLSInfo) string {
	if tlsInfo == nil {
		return "No TLS information available"
	}
	
	// Check for modern TLS version
	var versionScore int
	switch tlsInfo.Version {
	case "TLS 1.3":
		versionScore = 3 // Excellent
	case "TLS 1.2":
		versionScore = 2 // Good
	case "TLS 1.1":
		versionScore = 1 // Poor
	case "TLS 1.0", "SSLv3":
		versionScore = 0 // Bad
	default:
		versionScore = -1 // Unknown
	}
	
	// Check for certificate issues
	certIssues := []string{}
	if tlsInfo.CertSelfSigned {
		certIssues = append(certIssues, "self-signed certificate")
	}
	if !tlsInfo.CertExpiry.IsZero() && time.Now().After(tlsInfo.CertExpiry) {
		certIssues = append(certIssues, "expired certificate")
	}
	
	// Generate assessment
	var assessment string
	switch versionScore {
	case 3:
		assessment = "Excellent - Using TLS 1.3"
	case 2:
		assessment = "Good - Using TLS 1.2"
	case 1:
		assessment = "Poor - Using TLS 1.1 (deprecated)"
	case 0:
		assessment = "Bad - Using outdated TLS/SSL version"
	default:
		assessment = "Unknown TLS version"
	}
	
	if len(certIssues) > 0 {
		assessment += ", but has " + strings.Join(certIssues, " and ")
	}
	
	return assessment
}