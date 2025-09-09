package surveyor

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/time/rate"
)

// AppVersion represents the application version
const (
	AppVersion = "2.0.0"
)

// Application errors
var (
	ErrInvalidConfig = errors.New("invalid configuration")
	ErrScanFailed    = errors.New("scan operation failed")
	ErrReportFailed  = errors.New("report generation failed")
)

// -------------- Prometheus Metrics --------------

// Metrics holds all Prometheus metrics used by the application
type Metrics struct {
	// Traffic metrics
	TrafficGenerated *prometheus.CounterVec
	PacketLatency    *prometheus.HistogramVec
	RequestErrors    *prometheus.CounterVec

	// Host discovery metrics
	EnumeratedHosts    *prometheus.GaugeVec
	PortsDiscovered    *prometheus.CounterVec
	ScanDuration       *prometheus.HistogramVec
	OperationStatus    *prometheus.CounterVec
	MemoryUsage        *prometheus.GaugeVec
	ThreadUtilization  *prometheus.GaugeVec
}

// NewMetrics initializes and returns a new Metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		TrafficGenerated: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "surveyor_traffic_generated_total",
				Help: "Total number of traffic packets generated.",
			},
			[]string{"destination", "protocol"},
		),
		EnumeratedHosts: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "surveyor_enumerated_hosts",
				Help: "Number of hosts enumerated in a CIDR or single IP domain.",
			},
			[]string{"destination", "scan_id"},
		),
		PacketLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "surveyor_packet_latency_ms",
				Help:    "Latency of generated packets in milliseconds.",
				Buckets: prometheus.ExponentialBuckets(1, 2, 10), // Better bucket distribution
			},
			[]string{"destination", "protocol"},
		),
		RequestErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "surveyor_request_errors_total",
				Help: "Total number of failed requests by error type.",
			},
			[]string{"error_type", "destination"},
		),
		PortsDiscovered: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "surveyor_ports_discovered_total",
				Help: "Total number of open ports discovered.",
			},
			[]string{"destination", "port_type"},
		),
		ScanDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "surveyor_scan_duration_seconds",
				Help:    "Duration of scanning operations in seconds.",
				Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
			},
			[]string{"operation_type", "scan_id"},
		),
		OperationStatus: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "surveyor_operation_status",
				Help: "Status of operations (success=1, failure=0).",
			},
			[]string{"operation", "status"},
		),
		MemoryUsage: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "surveyor_memory_usage_bytes",
				Help: "Current memory usage of the application.",
			},
			[]string{"type"},
		),
		ThreadUtilization: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "surveyor_thread_utilization",
				Help: "Number of active goroutines.",
			},
			[]string{"operation"},
		),
	}
}

// Register registers all metrics with Prometheus
func (m *Metrics) Register() {
	prometheus.MustRegister(
		m.TrafficGenerated,
		m.EnumeratedHosts,
		m.PacketLatency,
		m.RequestErrors,
		m.PortsDiscovered,
		m.ScanDuration,
		m.OperationStatus,
		m.MemoryUsage,
		m.ThreadUtilization,
	)
}

// -------------- Application --------------

// App represents the main application with its dependencies
type App struct {
	Config      *Config
	Logger      *zap.Logger
	Metrics     *Metrics
	Scanner     *Scanner
	Input       *InputHandler
	MetricsSrv  *http.Server
	RateLimiter *rate.Limiter
	scanID      string
}

// NewApp creates a new application instance
func NewApp(config *Config, logger *zap.Logger) *App {
	metrics := NewMetrics()
	scanner := NewScanner(config, logger)
	input := NewInputHandler(logger)

	// Create a rate limiter for network operations
	// Allow burst of config.ConcurrentScans*2 with rate of operations per second
	limiter := rate.NewLimiter(rate.Limit(config.ConcurrentScans*2), config.ConcurrentScans*4)

	return &App{
		Config:      config,
		Logger:      logger,
		Metrics:     metrics,
		Scanner:     scanner,
		Input:       input,
		RateLimiter: limiter,
		scanID:      uuid.New().String(),
	}
}

// -------------- Logging Initialization --------------

// SetupLogger configures and initializes the logger
func SetupLogger(config *Config) (*zap.Logger, error) {
	if err := os.MkdirAll(config.LogDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}
	timestamp := time.Now().Format("20060102_150405")
	logFile := filepath.Join(config.LogDir, fmt.Sprintf("surveyor_log_%s.log", timestamp))

	// Create custom encoder config
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig = encoderConfig
	cfg.OutputPaths = []string{logFile, "stdout"}
	cfg.Level = zap.NewAtomicLevelAt(parseLogLevel(config.LogLevel))
	cfg.Development = config.LogLevel == "debug"
	
	// Add sampling to reduce log volume in production while preserving important events
	if config.LogLevel != "debug" {
		cfg.Sampling = &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		}
	}

	logger, err := cfg.Build(zap.AddStacktrace(zapcore.ErrorLevel))
	if err != nil {
		return nil, fmt.Errorf("failed to init logger: %w", err)
	}
	
	// Add version to global logger context
	logger = logger.With(
		zap.String("version", AppVersion),
		zap.String("pid", strconv.Itoa(os.Getpid())),
	)
	
	return logger, nil
}

// parseLogLevel converts a string log level to zapcore.Level
func parseLogLevel(level string) zapcore.Level {
	switch strings.ToLower(level) {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

// -------------- Main --------------

// Run is the entry point for the application
func Run(ctx context.Context) error {
	// Create context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Parse command line flags
	configPath := flag.String("config", "", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	disableCache := flag.Bool("no-cache", false, "Disable DNS and result caching")
	outputFormat := flag.String("output", "", "Override output format (csv,pdf,json,xml,html)")
	flag.Parse()

	// Show version and exit if requested
	if *showVersion {
		fmt.Printf("Surveyor version %s\n", AppVersion)
		return nil
	}

	// Load configuration
	var config *Config
	if *configPath != "" {
		var err error
		config, err = LoadConfig(*configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
	} else {
		config = DefaultConfig()
	}

	// Apply command line overrides
	if *disableCache {
		config.EnableCaching = false
	}
	
	// Override output format if specified
	if *outputFormat != "" {
		formats := strings.Split(*outputFormat, ",")
		var validFormats []string
		for _, format := range formats {
			format = strings.TrimSpace(strings.ToLower(format))
			if format == "csv" || format == "pdf" || format == "json" || format == "xml" || format == "html" {
				validFormats = append(validFormats, format)
			}
		}
		if len(validFormats) > 0 {
			config.ReportFormats = validFormats
		}
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}

	// Setup logger
	logger, err := SetupLogger(config)
	if err != nil {
		return fmt.Errorf("failed to setup logger: %w", err)
	}
	defer logger.Sync()

	// Initialize application
	app := NewApp(config, logger)

	logger.Info("Surveyor starting...",
		zap.String("version", AppVersion),
		zap.String("scan_id", app.scanID),
		zap.Any("config", config),
	)

	// Register Prometheus metrics if enabled
	if config.MetricsEnabled {
		app.Metrics.Register()
		srv := app.startMetricsServer(config.MetricsPort, config.MetricsTLS)
		app.MetricsSrv = srv
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Warn("Prometheus server shutdown error", zap.Error(err))
			}
		}()
	}

	// Start operation timing
	opStart := time.Now()
	defer func() {
		if config.MetricsEnabled {
			app.Metrics.ScanDuration.WithLabelValues("complete_operation", app.scanID).Observe(time.Since(opStart).Seconds())
		}
	}()

	// Create required directories
	if err := os.MkdirAll(config.ReportDir, 0755); err != nil {
		app.Logger.Error("Failed to create report directory", zap.Error(err))
		return fmt.Errorf("failed to create report directory: %w", err)
	}

	// Get target hosts if not specified in config
	if len(config.TargetHosts) == 0 {
		hosts, err := app.Input.GetDestination()
		if err != nil {
			app.Logger.Error("Failed to get target hosts", zap.Error(err))
			if config.MetricsEnabled {
				app.Metrics.OperationStatus.WithLabelValues("input", "failure").Inc()
			}
			return fmt.Errorf("failed to get target hosts: %w", err)
		}
		config.TargetHosts = hosts
		if config.MetricsEnabled {
			app.Metrics.OperationStatus.WithLabelValues("input", "success").Inc()
		}
	}

	// Start scanning
	scanStart := time.Now()
	results, err := app.Scanner.ScanNetwork(ctx, config.TargetHosts)
	if err != nil {
		app.Logger.Error("Scanning failed", zap.Error(err))
		if config.MetricsEnabled {
			app.Metrics.OperationStatus.WithLabelValues("scan", "failure").Inc()
			app.Metrics.RequestErrors.WithLabelValues("scan_error", strings.Join(config.TargetHosts, ",")).Inc()
		}
		return fmt.Errorf("%w: %v", ErrScanFailed, err)
	}
	
	scanDuration := time.Since(scanStart)
	app.Logger.Info("Scanning completed", 
		zap.Duration("duration", scanDuration),
		zap.Int("host_count", len(results)),
	)
	
	if config.MetricsEnabled {
		app.Metrics.OperationStatus.WithLabelValues("scan", "success").Inc()
		app.Metrics.ScanDuration.WithLabelValues("network_scan", app.scanID).Observe(scanDuration.Seconds())
		
		// Update enumerated hosts metrics
		for _, dest := range config.TargetHosts {
			app.Metrics.EnumeratedHosts.WithLabelValues(dest, app.scanID).Set(float64(len(results)))
		}
		
		// Count discovered ports by type
		tcpPorts := 0
		udpPorts := 0
		for _, result := range results {
			tcpPorts += len(result.OpenPorts)
			udpPorts += len(result.OpenUDPPorts)
		}
		
		app.Metrics.PortsDiscovered.WithLabelValues(strings.Join(config.TargetHosts, ","), "tcp").Add(float64(tcpPorts))
		app.Metrics.PortsDiscovered.WithLabelValues(strings.Join(config.TargetHosts, ","), "udp").Add(float64(udpPorts))
	}

	// Perform traffic generation if enabled
	if config.TrafficEnabled {
		app.generateTraffic(ctx, config.TargetHosts, results)
	}

	// Generate reports
	if err := app.generateReports(results); err != nil {
		app.Logger.Error("Report generation failed", zap.Error(err))
		if config.MetricsEnabled {
			app.Metrics.OperationStatus.WithLabelValues("report", "failure").Inc()
		}
		return fmt.Errorf("%w: %v", ErrReportFailed, err)
	}
	
	if config.MetricsEnabled {
		app.Metrics.OperationStatus.WithLabelValues("report", "success").Inc()
	}

	app.Logger.Info("Surveying completed. Awaiting shutdown signal...")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case s := <-sigChan:
		app.Logger.Info("Received shutdown signal", zap.String("signal", s.String()))
	case <-ctx.Done():
		app.Logger.Info("Context cancelled")
	}

	app.Logger.Info("Surveyor exited cleanly")
	return nil
}

// -------------- Start the Prometheus server --------------

// startMetricsServer initializes and starts the metrics HTTP server
func (a *App) startMetricsServer(port string, useTLS bool) *http.Server {
	// Create a more secure mux with additional middleware
	mux := http.NewServeMux()
	
	// Basic authentication middleware if configured
	var handler http.Handler = promhttp.Handler()
	if a.Config.MetricsAuth {
		handler = basicAuthMiddleware(handler, a.Config.MetricsUsername, a.Config.MetricsPassword)
	}
	
	// Add rate limiting to prevent DoS
	handler = rateLimitMiddleware(handler, rate.NewLimiter(5, 10))
	
	// Add request logging
	handler = loggerMiddleware(handler, a.Logger)
	
	mux.Handle("/metrics", handler)
	mux.HandleFunc("/health", healthCheckHandler)
	
	// Add version endpoint
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Surveyor version %s\n", AppVersion)
	})

	var srv *http.Server
	
	if useTLS {
		// Configure TLS using autocert for automatic certificate management
		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache("certs"),
			HostPolicy: autocert.HostWhitelist(a.Config.MetricsHostname),
		}
		
		srv = &http.Server{
			Addr:      ":" + port,
			Handler:   mux,
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
				MinVersion:     tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
			},
		}
		
		go func() {
			a.Logger.Info("Starting TLS metrics server", zap.String("port", port))
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				a.Logger.Error("Metrics server listen failed", zap.Error(err))
			}
		}()
	} else {
		srv = &http.Server{
			Addr:    ":" + port,
			Handler: mux,
		}
		
		go func() {
			a.Logger.Info("Starting metrics server", zap.String("port", port))
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				a.Logger.Error("Metrics server listen failed", zap.Error(err))
			}
		}()
	}
	
	return srv
}

// -------------- HTTP Middleware --------------

// basicAuthMiddleware adds basic authentication to an HTTP handler
func basicAuthMiddleware(next http.Handler, username, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware adds rate limiting to an HTTP handler
func rateLimitMiddleware(next http.Handler, limiter *rate.Limiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loggerMiddleware adds request logging to an HTTP handler
func loggerMiddleware(next http.Handler, logger *zap.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a custom response writer to capture status code
		rw := &responseWriter{w, http.StatusOK}
		
		next.ServeHTTP(rw, r)
		
		logger.Debug("HTTP request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
			zap.Int("status", rw.statusCode),
			zap.Duration("duration", time.Since(start)),
		)
	})
}

// responseWriter is a custom response writer that captures the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// healthCheckHandler responds to health check requests
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// -------------- Traffic Generation --------------

// generateTraffic generates network traffic to the target hosts
func (a *App) generateTraffic(ctx context.Context, targetHosts []string, results []*ScanResult) {
	a.Logger.Info("Starting traffic generation", 
		zap.Int("host_count", len(results)),
		zap.Int("packets_per_host", a.Config.PacketsPerHost),
	)
	
	if a.Config.MetricsEnabled {
		a.Metrics.ThreadUtilization.WithLabelValues("traffic_generation").Set(float64(a.Config.ConcurrentTraffic))
	}

	// Create a pool of workers to generate traffic
	jobChan := make(chan *ScanResult, len(results))
	var wg sync.WaitGroup
	wg.Add(a.Config.ConcurrentTraffic)

	// Start the worker pool
	for i := 0; i < a.Config.ConcurrentTraffic; i++ {
		go func(workerId int) {
			defer wg.Done()
			for result := range jobChan {
				select {
				case <-ctx.Done():
					return
				default:
					// Wait for rate limiter to allow the request
					if err := a.RateLimiter.Wait(ctx); err != nil {
						a.Logger.Warn("Rate limiter interrupted", zap.Error(err))
						continue
					}
					a.generateTrafficForHost(ctx, result)
				}
			}
		}(i)
	}

	// Send jobs to workers
	for _, result := range results {
		select {
		case <-ctx.Done():
			close(jobChan)
			a.Logger.Info("Traffic generation cancelled")
			return
		case jobChan <- result:
			// Job sent successfully
		}
	}
	
	close(jobChan)
	wg.Wait()
	
	if a.Config.MetricsEnabled {
		a.Metrics.ThreadUtilization.WithLabelValues("traffic_generation").Set(0)
	}
	
	a.Logger.Info("Traffic generation completed")
}

// generateTrafficForHost generates traffic for a single host
func (a *App) generateTrafficForHost(ctx context.Context, result *ScanResult) {
	a.Logger.Debug("Generating traffic", 
		zap.String("host", result.Host),
		zap.Int("packets", a.Config.PacketsPerHost),
	)
	
	// Generate TCP traffic to open ports
	for _, port := range result.OpenPorts {
		for i := 0; i < a.Config.PacketsPerHost; i++ {
			select {
			case <-ctx.Done():
				return
			default:
				start := time.Now()
				
				// TCP connection attempt - in a production app, this would use real traffic
				dialer := net.Dialer{Timeout: time.Duration(a.Config.ScanTimeout) * time.Second}
				conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", result.Host, port))
				
				latency := time.Since(start).Milliseconds()
				
				if err != nil {
					a.Logger.Debug("TCP connection failed", 
						zap.String("host", result.Host),
						zap.Int("port", port),
						zap.Error(err),
					)
					if a.Config.MetricsEnabled {
						a.Metrics.RequestErrors.WithLabelValues("connection_error", result.Host).Inc()
					}
					continue
				}
				
				// Successfully connected
				if a.Config.MetricsEnabled {
					a.Metrics.TrafficGenerated.WithLabelValues(result.Host, "tcp").Inc()
					a.Metrics.PacketLatency.WithLabelValues(result.Host, "tcp").Observe(float64(latency))
				}
				
				conn.Close()
				
				// Respect packet delay setting
				if a.Config.PacketDelayMillis > 0 {
					time.Sleep(time.Duration(a.Config.PacketDelayMillis) * time.Millisecond)
				}
			}
		}
	}
}

// -------------- Report Generation --------------

// generateReports generates all configured report formats
func (a *App) generateReports(results []*ScanResult) error {
	timestamp := time.Now().Format("20060102_150405")
	reportData := make([]ReportData, len(results))
	
	// Get local hostname for report
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	
	// Convert scan results to report data
	for i, result := range results {
		metrics := map[string]string{
			"hostname": result.Hostname,
			"scan_id":  a.scanID,
			"scan_timestamp": timestamp,
		}
		
		// Add service information if available
		if len(result.Services) > 0 {
			var serviceList []string
			for port, service := range result.Services {
				serviceList = append(serviceList, fmt.Sprintf("%d:%s", port, service))
			}
			metrics["services"] = strings.Join(serviceList, ", ")
		}
		
		// Add vulnerability information if available
		if len(result.Vulnerabilities) > 0 {
			metrics["vulnerabilities"] = strings.Join(result.Vulnerabilities, ", ")
		}
		
		// Add MAC address if available
		if result.MAC != "" {
			metrics["mac_address"] = result.MAC
		}
		
		// Add TTL if available
		if result.TTL > 0 {
			metrics["ttl"] = strconv.Itoa(result.TTL)
		}
		
		// Add additional info
		for k, v := range result.AdditionalInfo {
			metrics[k] = v
		}
		
		reportData[i] = ReportData{
			Source:           hostname,
			Destination:      result.Host,
			OS:               result.OS,
			OpenPorts:        result.OpenPorts,
			OpenUDPPorts:     result.OpenUDPPorts,
			Services:         result.Services,
			Vulnerabilities:  result.Vulnerabilities,
			GeneratedTraffic: a.Config.PacketsPerHost * len(result.OpenPorts),
			ScanTime:         time.Now(),
			Metrics:          metrics,
		}
	}

	// Ensure report directory exists
	if err := os.MkdirAll(a.Config.ReportDir, 0755); err != nil {
		return fmt.Errorf("failed to create report directory: %w", err)
	}

	// Generate each requested report format
	for _, format := range a.Config.ReportFormats {
		var reportFilePath string
		var err error
		
		format = strings.ToLower(format)
		switch format {
		case "csv":
			reportFilePath = filepath.Join(a.Config.ReportDir, fmt.Sprintf("surveyor_report_%s.csv", timestamp))
			err = WriteCSVReport(reportData, reportFilePath)
			
		case "pdf":
			reportFilePath = filepath.Join(a.Config.ReportDir, fmt.Sprintf("surveyor_report_%s.pdf", timestamp))
			err = WritePDFReport(reportData, reportFilePath)
			
		case "json":
			reportFilePath = filepath.Join(a.Config.ReportDir, fmt.Sprintf("surveyor_report_%s.json", timestamp))
			err = WriteJSONReport(reportData, reportFilePath)
			
		case "xml":
			reportFilePath = filepath.Join(a.Config.ReportDir, fmt.Sprintf("surveyor_report_%s.xml", timestamp))
			err = WriteXMLReport(reportData, reportFilePath)
			
		case "html":
			reportFilePath = filepath.Join(a.Config.ReportDir, fmt.Sprintf("surveyor_report_%s.html", timestamp))
			err = WriteHTMLReport(reportData, reportFilePath, a.Config.TemplateDir)
			
		default:
			a.Logger.Warn("Unsupported report format", zap.String("format", format))
			continue
		}
		
		if err != nil {
			a.Logger.Error("Failed to write report",
				zap.String("format", format),
				zap.String("file", reportFilePath),
				zap.Error(err),
			)
		} else {
			a.Logger.Info("Report generated successfully",
				zap.String("format", format),
				zap.String("file", reportFilePath),
			)
		}
	}
	
	// Also print a console summary if requested
	if a.Config.ConsoleReport {
		PrintConsoleReport(reportData)
	}

	return nil
}

// ReportMemoryUsage reports memory usage to Prometheus metrics
func (a *App) ReportMemoryUsage() {
	if !a.Config.MetricsEnabled {
		return
	}
	
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	
	a.Metrics.MemoryUsage.WithLabelValues("alloc").Set(float64(mem.Alloc))
	a.Metrics.MemoryUsage.WithLabelValues("total_alloc").Set(float64(mem.TotalAlloc))
	a.Metrics.MemoryUsage.WithLabelValues("sys").Set(float64(mem.Sys))
	a.Metrics.MemoryUsage.WithLabelValues("heap_alloc").Set(float64(mem.HeapAlloc))
	a.Metrics.MemoryUsage.WithLabelValues("heap_sys").Set(float64(mem.HeapSys))
	
	a.Metrics.ThreadUtilization.WithLabelValues("goroutines").Set(float64(runtime.NumGoroutine()))
}