package surveyor

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"
)

// NetworkDiscovery handles enhanced network discovery operations
type NetworkDiscovery struct {
	config       *Config
	logger       *zap.Logger
	dnsCache     *DNSCache
	discoveryMu  sync.Mutex
	discoveryMap map[string]*DiscoveryResult
	sem          *semaphore.Weighted
}

// DiscoveryResult contains information about discovered network hosts
type DiscoveryResult struct {
	IP              string
	Hostname        string
	MAC             string
	ResponseTime    time.Duration
	FirstDiscovered time.Time
	LastSeen        time.Time
	DeviceType      string
	Manufacturer    string
	IsRouter        bool
	TTL             int
	IsCacheable     bool
}

// NewNetworkDiscovery creates a new NetworkDiscovery
func NewNetworkDiscovery(config *Config, logger *zap.Logger, dnsCache *DNSCache) *NetworkDiscovery {
	return &NetworkDiscovery{
		config:       config,
		logger:       logger.With(zap.String("component", "discovery")),
		dnsCache:     dnsCache,
		discoveryMap: make(map[string]*DiscoveryResult),
		sem:          semaphore.NewWeighted(int64(config.ConcurrentScans)),
	}
}

// DiscoverNetwork performs network discovery on a CIDR range
func (d *NetworkDiscovery) DiscoverNetwork(ctx context.Context, cidr string) ([]*DiscoveryResult, error) {
	d.logger.Info("Starting network discovery", zap.String("cidr", cidr))
	
	// Parse CIDR
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR format: %w", err)
	}
	
	var results []*DiscoveryResult
	var resultsMu sync.Mutex
	var wg sync.WaitGroup
	
	// Create a worker pool for scanning
	// Channel for IP addresses to scan
	ipChan := make(chan string, 100)
	
	// Start worker goroutines
	for i := 0; i < d.config.ConcurrentScans; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ipStr := range ipChan {
				select {
				case <-ctx.Done():
					return
				default:
					// Acquire semaphore
					if err := d.sem.Acquire(ctx, 1); err != nil {
						d.logger.Error("Failed to acquire semaphore", zap.Error(err))
						continue
					}
					
					// Perform discovery
					result, err := d.discoverHost(ctx, ipStr)
					d.sem.Release(1)
					
					if err != nil {
						d.logger.Debug("Host discovery error", 
							zap.String("ip", ipStr),
							zap.Error(err),
						)
						continue
					}
					
					if result != nil {
						resultsMu.Lock()
						results = append(results, result)
						resultsMu.Unlock()
						
						// Update discovery map
						d.discoveryMu.Lock()
						d.discoveryMap[ipStr] = result
						d.discoveryMu.Unlock()
					}
				}
			}
		}()
	}
	
	// Increment IP addresses in CIDR
	// Start from IP address after network address
	for ip := incrementIP(ip); ipNet.Contains(ip); ip = incrementIP(ip) {
		select {
		case <-ctx.Done():
			close(ipChan)
			return results, ctx.Err()
		case ipChan <- ip.String():
			// IP sent to worker
		}
	}
	
	close(ipChan)
	wg.Wait()
	
	d.logger.Info("Network discovery completed", 
		zap.String("cidr", cidr),
		zap.Int("hosts_discovered", len(results)),
	)
	
	return results, nil
}

// discoverHost performs discovery on a single host
func (d *NetworkDiscovery) discoverHost(ctx context.Context, ip string) (*DiscoveryResult, error) {
	// Check if we have a cached result first
	d.discoveryMu.Lock()
	cachedResult, exists := d.discoveryMap[ip]
	d.discoveryMu.Unlock()
	
	if exists && cachedResult.IsCacheable && time.Since(cachedResult.LastSeen) < time.Duration(d.config.CacheTTL)*time.Minute {
		// Update last seen time for cached result
		cachedResult.LastSeen = time.Now()
		return cachedResult, nil
	}
	
	// Create result with current timestamp
	result := &DiscoveryResult{
		IP:              ip,
		FirstDiscovered: time.Now(),
		LastSeen:        time.Now(),
		IsCacheable:     true,
	}
	
	// Perform ICMP echo (ping)
	pingResult, pingTime, ttl, err := pingHost(ctx, ip, d.config.ScanTimeout)
	if err != nil {
		return nil, fmt.Errorf("ping failed: %w", err)
	}
	
	result.ResponseTime = pingTime
	result.TTL = ttl
	
	// Only proceed if ping was successful
	if !pingResult {
		// Host is not responding to ping, but we might want to scan anyway if stealth scan is enabled
		if !d.config.ScanNonResponsive {
			return nil, nil
		}
	}
	
	// Try to determine if it's a router
	isRouter, err := isRouter(ctx, ip)
	if err == nil {
		result.IsRouter = isRouter
	}
	
	// Try reverse DNS lookup
	if d.dnsCache != nil {
		hostname := d.dnsCache.Get("r:" + ip)
		if hostname != "" {
			result.Hostname = hostname
		} else {
			// Try to lookup
			hostnames, err := net.LookupAddr(ip)
			if err == nil && len(hostnames) > 0 {
				result.Hostname = hostnames[0]
				// Cache the result
				d.dnsCache.Set("r:"+ip, result.Hostname)
			}
		}
	}
	
	// Try to determine device type based on TTL and other heuristics
	result.DeviceType = determineDeviceType(ttl, result.IsRouter)
	
	// Try to get MAC address and manufacturer for local network
	mac, manufacturer, err := getMACAndManufacturer(ctx, ip)
	if err == nil && mac != "" {
		result.MAC = mac
		result.Manufacturer = manufacturer
	}
	
	return result, nil
}

// incrementIP returns the next IP address
func incrementIP(ip net.IP) net.IP {
	nextIP := make(net.IP, len(ip))
	copy(nextIP, ip)
	
	for i := len(nextIP) - 1; i >= 0; i-- {
		nextIP[i]++
		if nextIP[i] > 0 {
			break
		}
	}
	
	return nextIP
}

// pingHost sends an ICMP echo request to a host
func pingHost(ctx context.Context, ip string, timeout int) (bool, time.Duration, int, error) {
	// In a real implementation, this would use a proper ICMP library
	// For now, we'll just use the system ping command
	
	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	
	// Record start time
	start := time.Now()
	
	// Simulate ping with a connection attempt
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), time.Duration(timeout)*time.Second)
	if err != nil {
		// Try another common port
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:443", ip), time.Duration(timeout)*time.Second)
		if err != nil {
			return false, 0, 0, err
		}
	}
	
	// Close connection if successful
	if conn != nil {
		conn.Close()
	}
	
	// Calculate response time
	responseTime := time.Since(start)
	
	// Simulate TTL (would be extracted from real ICMP response)
	// Using a fixed value for now
	ttl := 64
	
	return true, responseTime, ttl, nil
}

// isRouter attempts to determine if an IP is a router/gateway
func isRouter(ctx context.Context, ip string) (bool, error) {
	// In a real implementation, this would use techniques like:
	// 1. Check if it's the default gateway
	// 2. Check if it responds to router discovery protocols
	// 3. Check for open ports common to routers (80, 443, 8080 for web management)
	
	// Simplified implementation - just check for common router management ports
	commonPorts := []int{80, 443, 8080, 8443}
	
	for _, port := range commonPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return true, nil
		}
	}
	
	return false, nil
}

// determineDeviceType guesses the device type based on TTL and other information
func determineDeviceType(ttl int, isRouter bool) string {
	if isRouter {
		return "Router/Gateway"
	}
	
	// Rough estimation based on TTL values
	switch {
	case ttl <= 64:
		return "Linux/Unix/IoT"
	case ttl <= 128:
		return "Windows"
	case ttl <= 255:
		return "Network Device"
	default:
		return "Unknown"
	}
}

// getMACAndManufacturer tries to get the MAC address and manufacturer
func getMACAndManufacturer(ctx context.Context, ip string) (string, string, error) {
	// This is a simplified implementation
	// In a real implementation, this would use ARP, check the ARP table, 
	// and lookup the OUI database for manufacturer
	
	// For now, just return placeholder values for demonstration
	return "", "", fmt.Errorf("MAC address lookup not implemented")
}

// GetLocalNetworks returns a list of local network CIDRs
func GetLocalNetworks() ([]string, error) {
	var networks []string
	
	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	
	// Look for local networks on each interface
	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				// Skip loopback addresses
				if v.IP.IsLoopback() {
					continue
				}
				
				// Only include IPv4 for now
				if v.IP.To4() != nil {
					networks = append(networks, v.String())
				}
			}
		}
	}
	
	return networks, nil
}