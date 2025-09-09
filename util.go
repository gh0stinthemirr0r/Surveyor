package surveyor

import (
\t"crypto/sha256"
\t"encoding/base64"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
\t"io"
\t"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
\t"strconv"
	"runtime"
\t"sync"
	"strings"
	"time"
)

// Error definitions
var (
	ErrInvalidHostFormat = errors.New("invalid host format")
	ErrLookupFailed      = errors.New("DNS lookup failed")
	ErrScanFailed        = errors.New("port scan failed")
	ErrOSDetectFailed    = errors.New("OS detection failed")
	ErrNotImplemented    = errors.New("functionality not implemented")
)

// IsValidIP validates if a given string is a valid IP address.
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsValidIPv4 validates if a given string is a valid IPv4 address.
func IsValidIPv4(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() != nil
}

// IsValidIPv6 validates if a given string is a valid IPv6 address.
func IsValidIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() == nil
}

// IsValidCIDR validates if a given string is a valid CIDR notation.
func IsValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// IsValidHostname validates if a given string is a valid hostname.
func IsValidHostname(hostname string) bool {
	// Simple hostname validation
	// RFC 1123 compliant hostname check (simplified)
	hostnameRegex := regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
	return hostnameRegex.MatchString(hostname)
}

// ResolveHost attempts to resolve a hostname to an IP address.
func ResolveHost(hostname string) (string, error) {
	if IsValidIP(hostname) {
		return hostname, nil
	}

	if !IsValidHostname(hostname) {
		return "", fmt.Errorf("%w: %s", ErrInvalidHostFormat, hostname)
	}

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrLookupFailed, err.Error())
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("%w: no IP addresses found for %s", ErrLookupFailed, hostname)
	}

	// Return first IPv4 address by default
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}

	// If no IPv4 found, return first IPv6
	return ips[0].String(), nil
}

// ScanPorts scans a given host for open ports within the specified range.
func ScanPorts(host string, startPort, endPort int, timeout time.Duration) ([]int, error) {
	if !IsValidIP(host) && !IsValidHostname(host) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidHostFormat, host)
	}

	var openPorts []int

	if startPort < 1 || endPort > 65535 || startPort > endPort {
		return nil, errors.New("invalid port range")
	}

	for port := startPort; port <= endPort; port++ {
		address := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}

	return openPorts, nil
}

// DetectOS identifies the operating system of the destination host.
// This is a safer implementation that validates the host and uses a controlled
// execution environment for nmap.
func DetectOS(host string, timeout time.Duration) (string, error) {
	if !IsValidIP(host) && !IsValidHostname(host) {
		return "", fmt.Errorf("%w: %s", ErrInvalidHostFormat, host)
	}

	// First try with TTL method which is safer
	if os, err := DetectOSByTTL(host); err == nil {
		return os, nil
	}

	// Safe execution of nmap
	args := []string{"-O", "--osscan-limit", "-T4", "--max-retries", "1", "--host-timeout", "30s", host}
	cmd := exec.Command("nmap", args...)
	
	// Set timeout for the command
	timer := time.AfterFunc(timeout, func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	})
	defer timer.Stop()
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "Unknown", fmt.Errorf("%w: %s", ErrOSDetectFailed, err.Error())
	}

	outputStr := string(output)
	if strings.Contains(outputStr, "Windows") {
		return "Windows", nil
	} else if strings.Contains(outputStr, "Linux") {
		return "Linux", nil
	} else if strings.Contains(outputStr, "Mac OS") {
		return "Mac OS", nil
	}
	
	return "Unknown", nil
}

// DetectOSByTTL attempts to identify OS based on TTL values from ping
func DetectOSByTTL(host string) (string, error) {
	if !IsValidIP(host) && !IsValidHostname(host) {
		return "", fmt.Errorf("%w: %s", ErrInvalidHostFormat, host)
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "2000", host)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "2", host)
	}
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	// Extract TTL from ping output
	ttlPattern := regexp.MustCompile(`(?i)ttl=(\d+)`)
	matches := ttlPattern.FindStringSubmatch(string(output))
	if len(matches) < 2 {
		return "", errors.New("could not extract TTL")
	}

	ttlStr := matches[1]
	
	// Identify OS based on TTL
	switch {
	case ttlStr == "64", ttlStr == "63":
		return "Linux/Unix", nil
	case ttlStr == "128", ttlStr == "127":
		return "Windows", nil
	case ttlStr == "254", ttlStr == "255":
		return "Cisco/Network", nil
	default:
		return "Unknown", nil
	}
}

// SanitizeInput removes potentially harmful characters from user input.
func SanitizeInput(input string) string {
	// Remove shell special characters
	unsafe := []string{"|", "&", ";", "`", "$", "\\", "!", ">", "<", "*", "?", "(", ")", "[", "]", "{", "}", "'", "\"", "\n", "\r"}
	clean := input

	for _, char := range unsafe {
		clean = strings.ReplaceAll(clean, char, "")
	}

	// Limit length
	if len(clean) > 1000 {
		clean = clean[:1000]
	}
	
	return clean
}

// ValidatePort checks if a port number is valid.
func ValidatePort(port int) bool {
	return port > 0 && port < 65536
}

// GetLocalIP retrieves the local machine's IP address.
func GetLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String(), nil
			}
		}
	}
	
	return "", errors.New("no valid IP address found")
}

// GetPreferredOutboundIP gets the preferred outbound IP of this machine
func GetPreferredOutboundIP() (string, error) {
	// This doesn't actually make a connection, just creates a UDP socket
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// GetSystemInfo retrieves system information of the local machine.
func GetSystemInfo() map[string]string {
	info := make(map[string]string)
	info["os"] = runtime.GOOS
	info["arch"] = runtime.GOARCH
	info["cpus"] = fmt.Sprintf("%d", runtime.NumCPU())
	
	hostname, err := os.Hostname()
	if err == nil {
		info["hostname"] = hostname
	}
	
	ip, err := GetLocalIP()
	if err == nil {
		info["ip"] = ip
	}
	
	return info
}

// WriteToFile writes data to a file with proper permissions.
func WriteToFile(filePath, content string) error {
	// Create directory if it doesn't exist
	dir := strings.TrimSuffix(filePath, strings.TrimPrefix(filePath, strings.TrimSuffix(filePath, "/")))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Create/open the file with proper permissions
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Write content
	if _, err := file.WriteString(content); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	
	return nil
}

// IsPortOpen checks if a specific port is open on a host
func IsPortOpen(host string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// CheckConnectivity tests if the internet is accessible
func CheckConnectivity() bool {
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	_, err := client.Get("https://www.google.com")
	return err == nil
}

// GenerateRandomID generates a random identifier for tracking operations
func GenerateRandomID(length int) string {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp if crypto rand fails
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// ExtractPortsFromString extracts port numbers from a string
// Example: "80,443,8080" => []int{80, 443, 8080}
func ExtractPortsFromString(portsStr string) ([]int, error) {
	var ports []int
	
	// Handle empty string
	if portsStr == "" {
		return ports, nil
	}
	
	// Split by comma
	portStrings := strings.Split(portsStr, ",")
	
	for _, portStr := range portStrings {
		// Remove whitespace
		portStr = strings.TrimSpace(portStr)
		
		// Parse port number
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port number: %s", portStr)
		}
		
		// Validate port range
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port out of range (1-65535): %d", port)
		}
		
		ports = append(ports, port)
	}
	
	return ports, nil
}

// ExtractPortRangeFromString extracts a port range from a string
// Example: "80-100" => (80, 100)
func ExtractPortRangeFromString(rangeStr string) (int, int, error) {
	// Split by hyphen
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid port range format: %s", rangeStr)
	}
	
	// Parse start port
	startPort, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port: %s", parts[0])
	}
	
	// Parse end port
	endPort, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port: %s", parts[1])
	}
	
	// Validate port range
	if startPort < 1 || startPort > 65535 {
		return 0, 0, fmt.Errorf("start port out of range (1-65535): %d", startPort)
	}
	if endPort < 1 || endPort > 65535 {
		return 0, 0, fmt.Errorf("end port out of range (1-65535): %d", endPort)
	}
	if startPort > endPort {
		return 0, 0, fmt.Errorf("start port cannot be greater than end port: %d > %d", startPort, endPort)
	}
	
	return startPort, endPort, nil
}
// HashString creates a SHA-256 hash of a string
func HashString(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// EncodeBase64 encodes a string to base64
func EncodeBase64(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

// DecodeBase64 decodes a base64 string
func DecodeBase64(encodedData string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedData)
	if err \!= nil {
		return "", err
	}
	return string(decodedBytes), nil
}

// IsPrivateIP checks if an IP address is in a private range
func IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	
	// Check for private IPv4 addresses
	if ipv4 := parsedIP.To4(); ipv4 \!= nil {
		// Private IPv4 ranges:
		// 10.0.0.0/8
		// 172.16.0.0/12
		// 192.168.0.0/16
		return ipv4[0] == 10 ||
			(ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31) ||
			(ipv4[0] == 192 && ipv4[1] == 168)
	}
	
	// Check for private IPv6 addresses
	// fd00::/8 is the private IPv6 range
	return len(parsedIP) == net.IPv6len && parsedIP[0] == 0xfd
}

// SplitCIDR breaks a CIDR into a list of IP addresses
func SplitCIDR(cidr string) ([]string, error) {
	if \!IsValidCIDR(cidr) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidHostFormat, cidr)
	}
	
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err \!= nil {
		return nil, err
	}
	
	var ips []string
	
	// Convert IP to 4-byte representation
	ipv4 := ip.To4()
	if ipv4 == nil {
		// IPv6 addresses - just return the network address for now
		// Full IPv6 enumeration could generate too many addresses
		return []string{ip.String()}, nil
	}
	
	// Get the mask size for IPv4
	ones, bits := ipNet.Mask.Size()
	if ones == bits {
		// Single IP address CIDR (like 192.168.1.1/32)
		return []string{ip.String()}, nil
	}
	
	// Calculate number of hosts in this CIDR
	// 2^(32-ones) - 2 for IPv4 (excluding network and broadcast addresses)
	hostCount := int(math.Pow(2, float64(bits-ones))) - 2
	
	// Limit to a reasonable number to prevent generating too many IPs
	maxHosts := 1024  // Adjust this number based on your requirements
	if hostCount > maxHosts {
		return nil, fmt.Errorf("CIDR contains too many hosts (%d)", hostCount)
	}
	
	// Convert IP to uint32 for easy increment
	ipInt := uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
	
	// Get the start and end IPs
	mask := uint32(0xffffffff) << uint(bits-ones)
	start := ipInt & mask
	end := start | ^mask
	
	// Skip network and broadcast addresses
	for i := start + 1; i < end; i++ {
		// Convert uint32 back to IP address
		nextIP := net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
		ips = append(ips, nextIP.String())
	}
	
	return ips, nil
}

// RunConcurrent runs a function concurrently with a specified number of workers
func RunConcurrent[T any, R any](items []T, workerCount int, workFn func(T) (R, error)) ([]R, error) {
	if workerCount < 1 {
		workerCount = 1
	}
	
	// Adjust worker count if there are fewer items than workers
	if len(items) < workerCount {
		workerCount = len(items)
	}
	
	// Channel for input items
	jobs := make(chan T, len(items))
	
	// Channel for results
	results := make(chan R, len(items))
	
	// Channel for errors
	errs := make(chan error, len(items))
	
	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				result, err := workFn(item)
				if err \!= nil {
					errs <- err
					continue
				}
				results <- result
			}
		}()
	}
	
	// Send jobs to workers
	for _, item := range items {
		jobs <- item
	}
	close(jobs)
	
	// Wait for all workers to finish
	wg.Wait()
	close(results)
	close(errs)
	
	// Collect results and errors
	var resultList []R
	for result := range results {
		resultList = append(resultList, result)
	}
	
	// Check for errors
	var errList []error
	for err := range errs {
		errList = append(errList, err)
	}
	
	// If there were errors, return a combined error
	if len(errList) > 0 {
		// Build error message
		var errMsg strings.Builder
		errMsg.WriteString(fmt.Sprintf("%d errors occurred: ", len(errList)))
		for i, err := range errList {
			if i > 0 {
				errMsg.WriteString("; ")
			}
			errMsg.WriteString(err.Error())
			
			// Limit error message length
			if i >= 2 && len(errList) > 3 {
				errMsg.WriteString(fmt.Sprintf("; and %d more errors", len(errList)-i-1))
				break
			}
		}
		return resultList, errors.New(errMsg.String())
	}
	
	return resultList, nil
}

// CalculateSubnetMask calculates the subnet mask from CIDR notation
func CalculateSubnetMask(cidr string) (string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err \!= nil {
		return "", err
	}
	
	mask := network.Mask
	if len(mask) == 4 {
		// IPv4 mask
		return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]), nil
	} else if len(mask) == 16 {
		// IPv6 mask - convert to hex notation
		return mask.String(), nil
	}
	
	return "", errors.New("unknown mask format")
}

// CheckIfPortsAreCommon analyzes a slice of ports to see if they match common port patterns
func CheckIfPortsAreCommon(ports []int) map[string][]int {
	// Map of common port categories
	commonPorts := map[string]map[int]string{
		"web": {
			80:    "HTTP",
			443:   "HTTPS",
			8080:  "HTTP-Alt",
			8443:  "HTTPS-Alt",
			8000:  "HTTP-Alt",
			8008:  "HTTP-Alt",
			3000:  "Development",
			4000:  "Development",
			5000:  "Development",
			8888:  "Development",
		},
		"database": {
			3306:  "MySQL",
			5432:  "PostgreSQL",
			1521:  "Oracle",
			1433:  "MSSQL",
			6379:  "Redis",
			27017: "MongoDB",
			9200:  "Elasticsearch",
			5601:  "Kibana",
			5984:  "CouchDB",
		},
		"mail": {
			25:   "SMTP",
			587:  "SMTP Submission",
			465:  "SMTPS",
			110:  "POP3",
			995:  "POP3S",
			143:  "IMAP",
			993:  "IMAPS",
		},
		"file_sharing": {
			21:   "FTP",
			22:   "SSH/SFTP",
			139:  "NetBIOS",
			445:  "SMB",
			2049: "NFS",
		},
		"remote_access": {
			22:    "SSH",
			23:    "Telnet",
			3389:  "RDP",
			5900:  "VNC",
			5901:  "VNC-1",
			5902:  "VNC-2",
		},
		"monitoring": {
			161:   "SNMP",
			162:   "SNMP-Trap",
			9090:  "Prometheus",
			9100:  "Node Exporter",
			9104:  "MySQL Exporter",
		},
		"other": {
			53:    "DNS",
			67:    "DHCP",
			68:    "DHCP",
			123:   "NTP",
			179:   "BGP",
			389:   "LDAP",
			636:   "LDAPS",
			1080:  "SOCKS",
			1194:  "OpenVPN",
			5353:  "mDNS",
			6660:  "IRC",
			8883:  "MQTT",
		},
	}
	
	// Result map
	result := make(map[string][]int)
	
	// Check each port against categories
	for _, port := range ports {
		categorized := false
		
		for category, portMap := range commonPorts {
			if _, exists := portMap[port]; exists {
				result[category] = append(result[category], port)
				categorized = true
				break
			}
		}
		
		if \!categorized {
			result["unknown"] = append(result["unknown"], port)
		}
	}
	
	return result
}

// ParseIPRange parses a string representation of an IP range (e.g., "192.168.1.1-192.168.1.10")
func ParseIPRange(ipRange string) ([]string, error) {
	// Split the range
	rangeParts := strings.Split(ipRange, "-")
	if len(rangeParts) \!= 2 {
		return nil, fmt.Errorf("invalid IP range format: %s", ipRange)
	}
	
	startIP := strings.TrimSpace(rangeParts[0])
	endIP := strings.TrimSpace(rangeParts[1])
	
	// Validate IPs
	startIPParsed := net.ParseIP(startIP)
	endIPParsed := net.ParseIP(endIP)
	
	if startIPParsed == nil || endIPParsed == nil {
		return nil, fmt.Errorf("invalid IP address in range: %s", ipRange)
	}
	
	// Only support IPv4 ranges for now
	startIPv4 := startIPParsed.To4()
	endIPv4 := endIPParsed.To4()
	
	if startIPv4 == nil || endIPv4 == nil {
		return nil, fmt.Errorf("only IPv4 ranges are supported: %s", ipRange)
	}
	
	// Convert IPs to uint32
	startInt := uint32(startIPv4[0])<<24 | uint32(startIPv4[1])<<16 | uint32(startIPv4[2])<<8 | uint32(startIPv4[3])
	endInt := uint32(endIPv4[0])<<24 | uint32(endIPv4[1])<<16 | uint32(endIPv4[2])<<8 | uint32(endIPv4[3])
	
	// Make sure end is greater than start
	if endInt < startInt {
		return nil, fmt.Errorf("end IP must be greater than start IP: %s", ipRange)
	}
	
	// Check if range is reasonable
	if endInt-startInt > 1024 {
		return nil, fmt.Errorf("IP range too large (>1024 addresses): %s", ipRange)
	}
	
	// Generate IP list
	var ips []string
	for i := startInt; i <= endInt; i++ {
		ip := net.IPv4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
		ips = append(ips, ip.String())
	}
	
	return ips, nil
}

// GetRandomString generates a random string of specified length
func GetRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err \!= nil {
		// Fallback to time-based string if crypto/rand fails
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	
	for i, b := range randomBytes {
		randomBytes[i] = charset[b%byte(len(charset))]
	}
	
	return string(randomBytes)
}

// DownloadFile downloads a file from a URL to a local path
func DownloadFile(url, filepath string) error {
	// Create the file
	out, err := os.Create(filepath)
	if err \!= nil {
		return err
	}
	defer out.Close()
	
	// Get the data
	resp, err := http.Get(url)
	if err \!= nil {
		return err
	}
	defer resp.Body.Close()
	
	// Check server response
	if resp.StatusCode \!= http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}
	
	// Writer the body to file
	_, err = io.Copy(out, resp.Body)
	if err \!= nil {
		return err
	}
	
	return nil
}

// FormatDuration formats a duration in a human-readable way
func FormatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%d µs", d.Microseconds())
	} else if d < time.Second {
		return fmt.Sprintf("%d ms", d.Milliseconds())
	} else if d < time.Minute {
		return fmt.Sprintf("%.2f sec", float64(d)/float64(time.Second))
	} else if d < time.Hour {
		return fmt.Sprintf("%.2f min", float64(d)/float64(time.Minute))
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%.2f hours", float64(d)/float64(time.Hour))
	}
	return fmt.Sprintf("%.2f days", float64(d)/float64(24*time.Hour))
}
