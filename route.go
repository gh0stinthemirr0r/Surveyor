package surveyor

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// RouteAnalyzer is responsible for tracing routes and analyzing network topology
type RouteAnalyzer struct {
	config *Config
	logger *zap.Logger
}

// HopInfo represents information about a network hop
type HopInfo struct {
	HopNumber    int
	IPAddress    string
	Hostname     string
	RTT          []time.Duration // Round trip time for multiple attempts
	AvgRTT       time.Duration   // Average round trip time
	PacketLoss   float64         // Percentage of packet loss
	ASN          string          // Autonomous System Number
	Organization string          // Organization that owns this IP
	IsRouter     bool            // Whether this appears to be a router
}

// RouteInfo contains the complete trace route information
type RouteInfo struct {
	Destination      string
	StartTime        time.Time
	EndTime          time.Time
	Hops             []*HopInfo
	TotalHops        int
	DestinationReached bool
	FailedHops       int
	AvgResponseTime  time.Duration
}

// NewRouteAnalyzer creates a new RouteAnalyzer
func NewRouteAnalyzer(config *Config, logger *zap.Logger) *RouteAnalyzer {
	return &RouteAnalyzer{
		config: config,
		logger: logger.With(zap.String("component", "route_analyzer")),
	}
}

// TraceRoute performs a traceroute to the destination
func (r *RouteAnalyzer) TraceRoute(ctx context.Context, destination string) (*RouteInfo, error) {
	r.logger.Info("Starting traceroute analysis", zap.String("destination", destination))
	
	// Create result
	route := &RouteInfo{
		Destination: destination,
		StartTime:   time.Now(),
		Hops:        []*HopInfo{},
	}
	
	// Determine the max TTL value for traceroute
	maxTTL := 30
	if r.config.MaxTTL > 0 {
		maxTTL = r.config.MaxTTL
	}
	
	// Build traceroute command
	// Security note: Ensure destination is properly validated to prevent command injection
	if !IsValidIP(destination) && !IsValidHostname(destination) {
		return nil, fmt.Errorf("invalid destination format: %s", destination)
	}
	
	// Prepare traceroute arguments
	args := []string{"-n", "-m", strconv.Itoa(maxTTL), "-q", "3", destination}
	
	// Run traceroute command with context for timeout
	cmd := exec.CommandContext(ctx, "traceroute", args...)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		r.logger.Warn("Traceroute command failed", 
			zap.String("destination", destination),
			zap.Error(err),
			zap.ByteString("output", output),
		)
		// Continue processing output as we might have partial results
	}
	
	// Parse traceroute output
	hops, err := r.parseTracerouteOutput(string(output))
	if err != nil {
		return nil, fmt.Errorf("failed to parse traceroute output: %w", err)
	}
	
	route.Hops = hops
	route.EndTime = time.Now()
	route.TotalHops = len(hops)
	
	// Calculate additional statistics
	var totalResponseTime time.Duration
	failedHops := 0
	
	for _, hop := range hops {
		totalResponseTime += hop.AvgRTT
		if hop.IPAddress == "" {
			failedHops++
		}
	}
	
	// Check if destination was reached
	if len(hops) > 0 && hops[len(hops)-1].IPAddress != "" {
		route.DestinationReached = true
		// Calculate average response time across all hops
		if len(hops) > 0 {
			route.AvgResponseTime = totalResponseTime / time.Duration(len(hops))
		}
	}
	
	route.FailedHops = failedHops
	
	// Enrich hop information if possible (AS lookup, etc.)
	r.enrichRouteInfo(route)
	
	r.logger.Info("Traceroute analysis completed",
		zap.String("destination", destination),
		zap.Int("total_hops", route.TotalHops),
		zap.Bool("destination_reached", route.DestinationReached),
		zap.Duration("total_time", route.EndTime.Sub(route.StartTime)),
	)
	
	return route, nil
}

// parseTracerouteOutput parses the output of the traceroute command
func (r *RouteAnalyzer) parseTracerouteOutput(output string) ([]*HopInfo, error) {
	var hops []*HopInfo
	
	// Split output into lines
	lines := strings.Split(output, "\n")
	
	// Skip the first line as it's usually a header
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		
		hop, err := r.parseHopLine(line)
		if err != nil {
			r.logger.Debug("Error parsing hop line", 
				zap.String("line", line),
				zap.Error(err),
			)
			continue
		}
		
		if hop != nil {
			hops = append(hops, hop)
		}
	}
	
	return hops, nil
}

// parseHopLine parses a single line from traceroute output
func (r *RouteAnalyzer) parseHopLine(line string) (*HopInfo, error) {
	// Regular expressions to extract data from traceroute output
	hopNumberRegex := regexp.MustCompile(`^(\d+)`)
	ipRegex := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
	rttRegex := regexp.MustCompile(`(\d+\.\d+)\s*ms`)
	
	hopMatches := hopNumberRegex.FindStringSubmatch(line)
	if len(hopMatches) < 2 {
		return nil, fmt.Errorf("could not parse hop number from line: %s", line)
	}
	
	hopNumber, err := strconv.Atoi(hopMatches[1])
	if err != nil {
		return nil, fmt.Errorf("invalid hop number: %w", err)
	}
	
	hop := &HopInfo{
		HopNumber: hopNumber,
	}
	
	// Extract IP address
	ipMatches := ipRegex.FindStringSubmatch(line)
	if len(ipMatches) >= 2 {
		hop.IPAddress = ipMatches[1]
	}
	
	// Extract RTT values
	rttMatches := rttRegex.FindAllStringSubmatch(line, -1)
	for _, match := range rttMatches {
		if len(match) >= 2 {
			rttValue, err := strconv.ParseFloat(match[1], 64)
			if err != nil {
				continue
			}
			
			hop.RTT = append(hop.RTT, time.Duration(rttValue*float64(time.Millisecond)))
		}
	}
	
	// Calculate average RTT
	if len(hop.RTT) > 0 {
		var totalRTT time.Duration
		for _, rtt := range hop.RTT {
			totalRTT += rtt
		}
		hop.AvgRTT = totalRTT / time.Duration(len(hop.RTT))
		
		// Calculate packet loss
		expectedResponses := 3 // traceroute typically sends 3 packets per hop
		hop.PacketLoss = (1.0 - float64(len(hop.RTT))/float64(expectedResponses)) * 100.0
	}
	
	return hop, nil
}

// enrichRouteInfo adds additional information to route hops
func (r *RouteAnalyzer) enrichRouteInfo(route *RouteInfo) {
	for _, hop := range route.Hops {
		if hop.IPAddress == "" {
			continue
		}
		
		// Attempt reverse DNS lookup if hostname is missing
		if hop.Hostname == "" {
			hostname, err := net.LookupAddr(hop.IPAddress)
			if err == nil && len(hostname) > 0 {
				hop.Hostname = strings.TrimSuffix(hostname[0], ".")
			}
		}
		
		// Determine if hop is likely a router (simplified approach)
		hop.IsRouter = true // assume all hops in traceroute are routers except the last one
		
		// Additional enrichment could be done here:
		// - Looking up ASN/Organization using IP-to-ASN databases
		// - Fingerprinting router types
		// - Geolocation information
	}
	
	// Mark the last hop as not a router if it's the destination
	if len(route.Hops) > 0 && route.DestinationReached {
		route.Hops[len(route.Hops)-1].IsRouter = false
	}
}

// AnalyzeNetworkPath performs a full analysis of the network path to a destination
func (r *RouteAnalyzer) AnalyzeNetworkPath(ctx context.Context, destination string) (*RouteInfo, error) {
	// First perform a basic traceroute
	routeInfo, err := r.TraceRoute(ctx, destination)
	if err != nil {
		return nil, err
	}
	
	// Additional analysis could be added here:
	// - MTU discovery
	// - Bandwidth estimation
	// - Path stability analysis
	// - Latency variance analysis
	// - Geographic path visualization
	// - Autonomous System path mapping
	
	return routeInfo, nil
}

// PrintRouteSummary prints a summary of the route to the console
func PrintRouteSummary(route *RouteInfo) {
	fmt.Printf("Traceroute to %s\n", route.Destination)
	fmt.Printf("Start time: %s\n", route.StartTime.Format(time.RFC3339))
	fmt.Printf("End time: %s\n", route.EndTime.Format(time.RFC3339))
	fmt.Printf("Total hops: %d\n", route.TotalHops)
	fmt.Printf("Destination reached: %t\n", route.DestinationReached)
	fmt.Printf("Failed hops: %d\n", route.FailedHops)
	fmt.Printf("Average response time: %s\n", route.AvgResponseTime)
	fmt.Println("\nHop details:")
	
	fmt.Printf("%-4s %-15s %-30s %-15s %-10s %-10s\n", 
		"Hop", "IP Address", "Hostname", "Avg RTT", "Loss %", "Router")
	
	fmt.Println(strings.Repeat("-", 85))
	
	for _, hop := range route.Hops {
		hostname := hop.Hostname
		if hostname == "" {
			hostname = "*"
		}
		
		ipAddress := hop.IPAddress
		if ipAddress == "" {
			ipAddress = "*"
		}
		
		fmt.Printf("%-4d %-15s %-30s %-15s %-10.1f %-10t\n",
			hop.HopNumber,
			ipAddress,
			hostname,
			hop.AvgRTT,
			hop.PacketLoss,
			hop.IsRouter,
		)
	}
}