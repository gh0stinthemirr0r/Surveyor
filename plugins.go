package surveyor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"plugin"
	"reflect"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Plugin errors
var (
	ErrPluginLoad          = errors.New("failed to load plugin")
	ErrPluginSymbol        = errors.New("failed to lookup plugin symbol")
	ErrInvalidPluginType   = errors.New("invalid plugin type")
	ErrPluginInit          = errors.New("failed to initialize plugin")
	ErrPluginDirNotFound   = errors.New("plugin directory not found")
	ErrPluginAlreadyLoaded = errors.New("plugin already loaded")
)

// PluginType defines the type of plugin
type PluginType string

const (
	// Scanner plugins enhance scanning capabilities
	ScannerPlugin PluginType = "scanner"
	// Reporter plugins add new report types
	ReporterPlugin PluginType = "reporter"
	// Detector plugins provide specialized detection capabilities
	DetectorPlugin PluginType = "detector"
	// Analyzer plugins analyze scan results
	AnalyzerPlugin PluginType = "analyzer"
	// Integration plugins connect with external systems
	IntegrationPlugin PluginType = "integration"
)

// PluginInfo contains metadata about a plugin
type PluginInfo struct {
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Description string     `json:"description"`
	Author      string     `json:"author"`
	Type        PluginType `json:"type"`
	Enabled     bool       `json:"enabled"`
}

// Plugin is the interface that all plugins must implement
type Plugin interface {
	// Info returns plugin metadata
	Info() PluginInfo
	// Init initializes the plugin with configuration
	Init(config map[string]interface{}, logger *zap.Logger) error
	// Shutdown is called when the plugin is being unloaded
	Shutdown() error
}

// ScannerPluginInterface extends the Scanner capabilities
type ScannerPluginInterface interface {
	Plugin
	// EnhanceScanResult enhances scan results with additional information
	EnhanceScanResult(result *ScanResult) error
	// GetSupportedOptions returns options this scanner plugin accepts
	GetSupportedOptions() []string
}

// ReporterPluginInterface adds new report formats
type ReporterPluginInterface interface {
	Plugin
	// GenerateReport creates a report from scan results
	GenerateReport(results []*ScanResult, outputPath string) error
	// GetReportFormat returns the format provided by this plugin
	GetReportFormat() string
}

// DetectorPluginInterface provides specialized detection capabilities
type DetectorPluginInterface interface {
	Plugin
	// Detect attempts to identify specific characteristics
	Detect(host string, port int) (map[string]string, error)
	// GetDetectionType returns what this plugin detects
	GetDetectionType() string
}

// AnalyzerPluginInterface analyzes scan results
type AnalyzerPluginInterface interface {
	Plugin
	// Analyze performs analysis on scan results
	Analyze(results []*ScanResult) (map[string]interface{}, error)
	// GetAnalysisType returns the type of analysis performed
	GetAnalysisType() string
}

// IntegrationPluginInterface connects with external systems
type IntegrationPluginInterface interface {
	Plugin
	// Export exports data to external system
	Export(results []*ScanResult) error
	// GetIntegrationType returns the type of external system
	GetIntegrationType() string
}

// PluginManager manages loading and accessing plugins
type PluginManager struct {
	pluginDir      string
	loadedPlugins  map[string]Plugin
	scannerPlugins map[string]ScannerPluginInterface
	reportPlugins  map[string]ReporterPluginInterface
	detectorPlugins map[string]DetectorPluginInterface
	analyzerPlugins map[string]AnalyzerPluginInterface
	integrationPlugins map[string]IntegrationPluginInterface
	logger         *zap.Logger
	mu             sync.RWMutex
}

// NewPluginManager creates a new plugin manager
func NewPluginManager(pluginDir string, logger *zap.Logger) *PluginManager {
	return &PluginManager{
		pluginDir:      pluginDir,
		loadedPlugins:  make(map[string]Plugin),
		scannerPlugins: make(map[string]ScannerPluginInterface),
		reportPlugins:  make(map[string]ReporterPluginInterface),
		detectorPlugins: make(map[string]DetectorPluginInterface),
		analyzerPlugins: make(map[string]AnalyzerPluginInterface),
		integrationPlugins: make(map[string]IntegrationPluginInterface),
		logger:         logger.With(zap.String("component", "plugin_manager")),
	}
}

// LoadPlugin loads a single plugin by path
func (pm *PluginManager) LoadPlugin(pluginPath string, config map[string]interface{}) (Plugin, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if plugin is already loaded
	if _, exists := pm.loadedPlugins[pluginPath]; exists {
		return nil, fmt.Errorf("%w: %s", ErrPluginAlreadyLoaded, pluginPath)
	}

	// Load the plugin
	plug, err := plugin.Open(pluginPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s - %v", ErrPluginLoad, pluginPath, err)
	}

	// Look up the "New" symbol (plugin constructor)
	newSym, err := plug.Lookup("New")
	if err != nil {
		return nil, fmt.Errorf("%w: 'New' not found in %s - %v", ErrPluginSymbol, pluginPath, err)
	}

	// Assert that the symbol is a constructor function
	constructor, ok := newSym.(func() Plugin)
	if !ok {
		return nil, fmt.Errorf("%w: 'New' has wrong type in %s", ErrInvalidPluginType, pluginPath)
	}

	// Create an instance of the plugin
	instance := constructor()
	if instance == nil {
		return nil, fmt.Errorf("%w: plugin constructor returned nil in %s", ErrPluginInit, pluginPath)
	}

	// Initialize the plugin
	err = instance.Init(config, pm.logger)
	if err != nil {
		return nil, fmt.Errorf("%w: %s - %v", ErrPluginInit, pluginPath, err)
	}

	// Register the plugin by type
	info := instance.Info()
	pluginName := info.Name
	pm.loadedPlugins[pluginName] = instance

	// Register in type-specific maps
	switch info.Type {
	case ScannerPlugin:
		if scannerPlugin, ok := instance.(ScannerPluginInterface); ok {
			pm.scannerPlugins[pluginName] = scannerPlugin
			pm.logger.Info("Loaded scanner plugin", zap.String("name", pluginName))
		} else {
			return nil, fmt.Errorf("%w: plugin claims to be scanner plugin but does not implement interface", ErrInvalidPluginType)
		}
	case ReporterPlugin:
		if reporterPlugin, ok := instance.(ReporterPluginInterface); ok {
			pm.reportPlugins[pluginName] = reporterPlugin
			pm.logger.Info("Loaded reporter plugin", zap.String("name", pluginName))
		} else {
			return nil, fmt.Errorf("%w: plugin claims to be reporter plugin but does not implement interface", ErrInvalidPluginType)
		}
	case DetectorPlugin:
		if detectorPlugin, ok := instance.(DetectorPluginInterface); ok {
			pm.detectorPlugins[pluginName] = detectorPlugin
			pm.logger.Info("Loaded detector plugin", zap.String("name", pluginName))
		} else {
			return nil, fmt.Errorf("%w: plugin claims to be detector plugin but does not implement interface", ErrInvalidPluginType)
		}
	case AnalyzerPlugin:
		if analyzerPlugin, ok := instance.(AnalyzerPluginInterface); ok {
			pm.analyzerPlugins[pluginName] = analyzerPlugin
			pm.logger.Info("Loaded analyzer plugin", zap.String("name", pluginName))
		} else {
			return nil, fmt.Errorf("%w: plugin claims to be analyzer plugin but does not implement interface", ErrInvalidPluginType)
		}
	case IntegrationPlugin:
		if integrationPlugin, ok := instance.(IntegrationPluginInterface); ok {
			pm.integrationPlugins[pluginName] = integrationPlugin
			pm.logger.Info("Loaded integration plugin", zap.String("name", pluginName))
		} else {
			return nil, fmt.Errorf("%w: plugin claims to be integration plugin but does not implement interface", ErrInvalidPluginType)
		}
	default:
		pm.logger.Warn("Loaded plugin with unknown type", 
			zap.String("name", pluginName), 
			zap.String("type", string(info.Type)))
	}

	return instance, nil
}

// LoadPluginsFromDirectory loads all plugins from the configured directory
func (pm *PluginManager) LoadPluginsFromDirectory(config *Config) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if plugin directory exists
	if _, err := os.Stat(pm.pluginDir); os.IsNotExist(err) {
		if err := os.MkdirAll(pm.pluginDir, 0755); err != nil {
			return fmt.Errorf("%w: failed to create plugin directory - %v", ErrPluginDirNotFound, err)
		}
		pm.logger.Info("Created plugin directory", zap.String("dir", pm.pluginDir))
		return nil // No plugins to load yet
	}

	// Get a list of plugin files (.so files on Linux/Mac, .dll on Windows)
	var pluginExtension string
	if os.PathSeparator == '\\' { // Windows
		pluginExtension = ".dll"
	} else { // Linux/Mac
		pluginExtension = ".so"
	}

	var pluginFiles []string
	err := filepath.Walk(pm.pluginDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == pluginExtension {
			pluginFiles = append(pluginFiles, path)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking plugin directory: %v", err)
	}

	// Load each plugin
	for _, path := range pluginFiles {
		pluginName := filepath.Base(path)
		pluginConfig := make(map[string]interface{})

		// Get plugin specific config if available
		if config.PluginConfigs != nil {
			if cfg, exists := config.PluginConfigs[pluginName]; exists {
				pluginConfig = cfg
			}
		}

		_, err := pm.LoadPlugin(path, pluginConfig)
		if err != nil {
			pm.logger.Error("Failed to load plugin", 
				zap.String("path", path), 
				zap.Error(err))
			// Continue loading other plugins even if one fails
		}
	}

	pm.logger.Info("Loaded plugins", 
		zap.Int("total", len(pm.loadedPlugins)),
		zap.Int("scanners", len(pm.scannerPlugins)),
		zap.Int("reporters", len(pm.reportPlugins)),
		zap.Int("detectors", len(pm.detectorPlugins)),
		zap.Int("analyzers", len(pm.analyzerPlugins)),
		zap.Int("integrations", len(pm.integrationPlugins)))

	return nil
}

// GetLoadedPlugins returns a map of all loaded plugins
func (pm *PluginManager) GetLoadedPlugins() map[string]PluginInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	plugins := make(map[string]PluginInfo)
	for name, plugin := range pm.loadedPlugins {
		plugins[name] = plugin.Info()
	}
	return plugins
}

// GetScannerPlugins returns all loaded scanner plugins
func (pm *PluginManager) GetScannerPlugins() map[string]ScannerPluginInterface {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	// Return a copy to prevent race conditions
	result := make(map[string]ScannerPluginInterface)
	for k, v := range pm.scannerPlugins {
		result[k] = v
	}
	return result
}

// GetReporterPlugins returns all loaded reporter plugins
func (pm *PluginManager) GetReporterPlugins() map[string]ReporterPluginInterface {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	// Return a copy to prevent race conditions
	result := make(map[string]ReporterPluginInterface)
	for k, v := range pm.reportPlugins {
		result[k] = v
	}
	return result
}

// GetDetectorPlugins returns all loaded detector plugins
func (pm *PluginManager) GetDetectorPlugins() map[string]DetectorPluginInterface {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	// Return a copy to prevent race conditions
	result := make(map[string]DetectorPluginInterface)
	for k, v := range pm.detectorPlugins {
		result[k] = v
	}
	return result
}

// GetAnalyzerPlugins returns all loaded analyzer plugins
func (pm *PluginManager) GetAnalyzerPlugins() map[string]AnalyzerPluginInterface {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	// Return a copy to prevent race conditions
	result := make(map[string]AnalyzerPluginInterface)
	for k, v := range pm.analyzerPlugins {
		result[k] = v
	}
	return result
}

// GetIntegrationPlugins returns all loaded integration plugins
func (pm *PluginManager) GetIntegrationPlugins() map[string]IntegrationPluginInterface {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	// Return a copy to prevent race conditions
	result := make(map[string]IntegrationPluginInterface)
	for k, v := range pm.integrationPlugins {
		result[k] = v
	}
	return result
}

// EnhanceScanResultWithPlugins runs all scanner plugins on a scan result
func (pm *PluginManager) EnhanceScanResultWithPlugins(result *ScanResult) {
	pm.mu.RLock()
	plugins := make([]ScannerPluginInterface, 0, len(pm.scannerPlugins))
	for _, p := range pm.scannerPlugins {
		plugins = append(plugins, p)
	}
	pm.mu.RUnlock()

	for _, p := range plugins {
		info := p.Info()
		if !info.Enabled {
			continue
		}

		err := p.EnhanceScanResult(result)
		if err != nil {
			pm.logger.Warn("Plugin failed to enhance scan result",
				zap.String("plugin", info.Name),
				zap.String("host", result.Host),
				zap.Error(err))
		}
	}
}

// GeneratePluginReports generates reports using reporter plugins
func (pm *PluginManager) GeneratePluginReports(results []*ScanResult, outputDir string) []string {
	pm.mu.RLock()
	plugins := make([]ReporterPluginInterface, 0, len(pm.reportPlugins))
	for _, p := range pm.reportPlugins {
		plugins = append(plugins, p)
	}
	pm.mu.RUnlock()

	generatedReports := make([]string, 0)
	
	for _, p := range plugins {
		info := p.Info()
		if !info.Enabled {
			continue
		}

		format := p.GetReportFormat()
		outputPath := filepath.Join(outputDir, fmt.Sprintf("surveyor_report_%s.%s", time.Now().Format("20060102_150405"), format))
		
		err := p.GenerateReport(results, outputPath)
		if err != nil {
			pm.logger.Warn("Plugin failed to generate report",
				zap.String("plugin", info.Name),
				zap.String("format", format),
				zap.Error(err))
			continue
		}
		
		generatedReports = append(generatedReports, outputPath)
		pm.logger.Info("Generated plugin report",
			zap.String("plugin", info.Name),
			zap.String("format", format),
			zap.String("path", outputPath))
	}
	
	return generatedReports
}

// DetectWithPlugins runs all detector plugins on a host and port
func (pm *PluginManager) DetectWithPlugins(host string, port int) map[string]map[string]string {
	pm.mu.RLock()
	plugins := make([]DetectorPluginInterface, 0, len(pm.detectorPlugins))
	for _, p := range pm.detectorPlugins {
		plugins = append(plugins, p)
	}
	pm.mu.RUnlock()

	results := make(map[string]map[string]string)
	
	for _, p := range plugins {
		info := p.Info()
		if !info.Enabled {
			continue
		}

		detectionData, err := p.Detect(host, port)
		if err != nil {
			pm.logger.Debug("Plugin detection failed",
				zap.String("plugin", info.Name),
				zap.String("host", host),
				zap.Int("port", port),
				zap.Error(err))
			continue
		}
		
		if len(detectionData) > 0 {
			results[info.Name] = detectionData
		}
	}
	
	return results
}

// AnalyzeResultsWithPlugins runs all analyzer plugins on the scan results
func (pm *PluginManager) AnalyzeResultsWithPlugins(results []*ScanResult) map[string]map[string]interface{} {
	pm.mu.RLock()
	plugins := make([]AnalyzerPluginInterface, 0, len(pm.analyzerPlugins))
	for _, p := range pm.analyzerPlugins {
		plugins = append(plugins, p)
	}
	pm.mu.RUnlock()

	analysisResults := make(map[string]map[string]interface{})
	
	for _, p := range plugins {
		info := p.Info()
		if !info.Enabled {
			continue
		}

		analysis, err := p.Analyze(results)
		if err != nil {
			pm.logger.Warn("Plugin analysis failed",
				zap.String("plugin", info.Name),
				zap.Error(err))
			continue
		}
		
		if len(analysis) > 0 {
			analysisResults[info.Name] = analysis
		}
	}
	
	return analysisResults
}

// ExportResultsWithPlugins exports results using all integration plugins
func (pm *PluginManager) ExportResultsWithPlugins(results []*ScanResult) []string {
	pm.mu.RLock()
	plugins := make([]IntegrationPluginInterface, 0, len(pm.integrationPlugins))
	for _, p := range pm.integrationPlugins {
		plugins = append(plugins, p)
	}
	pm.mu.RUnlock()

	successful := make([]string, 0)
	
	for _, p := range plugins {
		info := p.Info()
		if !info.Enabled {
			continue
		}

		integrationType := p.GetIntegrationType()
		err := p.Export(results)
		if err != nil {
			pm.logger.Warn("Plugin export failed",
				zap.String("plugin", info.Name),
				zap.String("integration", integrationType),
				zap.Error(err))
			continue
		}
		
		successful = append(successful, info.Name)
		pm.logger.Info("Successfully exported results",
			zap.String("plugin", info.Name),
			zap.String("integration", integrationType))
	}
	
	return successful
}

// UnloadPlugin unloads a specific plugin
func (pm *PluginManager) UnloadPlugin(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	plugin, exists := pm.loadedPlugins[name]
	if !exists {
		return fmt.Errorf("plugin not found: %s", name)
	}

	// Call shutdown to allow plugin to clean up
	err := plugin.Shutdown()
	if err != nil {
		pm.logger.Warn("Plugin shutdown error", 
			zap.String("name", name), 
			zap.Error(err))
	}

	// Remove from appropriate maps
	info := plugin.Info()
	switch info.Type {
	case ScannerPlugin:
		delete(pm.scannerPlugins, name)
	case ReporterPlugin:
		delete(pm.reportPlugins, name)
	case DetectorPlugin:
		delete(pm.detectorPlugins, name)
	case AnalyzerPlugin:
		delete(pm.analyzerPlugins, name)
	case IntegrationPlugin:
		delete(pm.integrationPlugins, name)
	}

	// Remove from main plugins map
	delete(pm.loadedPlugins, name)
	
	pm.logger.Info("Unloaded plugin", zap.String("name", name))
	return nil
}

// UnloadAllPlugins unloads all plugins
func (pm *PluginManager) UnloadAllPlugins() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for name, plugin := range pm.loadedPlugins {
		err := plugin.Shutdown()
		if err != nil {
			pm.logger.Warn("Plugin shutdown error", 
				zap.String("name", name), 
				zap.Error(err))
		}
	}

	// Clear all plugin maps
	pm.loadedPlugins = make(map[string]Plugin)
	pm.scannerPlugins = make(map[string]ScannerPluginInterface)
	pm.reportPlugins = make(map[string]ReporterPluginInterface)
	pm.detectorPlugins = make(map[string]DetectorPluginInterface)
	pm.analyzerPlugins = make(map[string]AnalyzerPluginInterface)
	pm.integrationPlugins = make(map[string]IntegrationPluginInterface)

	pm.logger.Info("Unloaded all plugins")
}

// PluginTemplate provides a skeleton for implementing plugins
type PluginTemplate struct {
	info   PluginInfo
	config map[string]interface{}
	logger *zap.Logger
}

// Info returns plugin metadata
func (p *PluginTemplate) Info() PluginInfo {
	return p.info
}

// Init initializes the plugin
func (p *PluginTemplate) Init(config map[string]interface{}, logger *zap.Logger) error {
	p.config = config
	p.logger = logger.With(zap.String("plugin", p.info.Name))
	return nil
}

// Shutdown cleans up the plugin
func (p *PluginTemplate) Shutdown() error {
	return nil
}

// CreateExamplePluginStructure creates example plugin skeleton files
func CreateExamplePluginStructure(outputDir string) error {
	// Create the plugin directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %v", err)
	}

	// Create example plugin skeleton files
	scannerExample := filepath.Join(outputDir, "scanner_example.go")
	scannerCode := `package main

import (
	"go.uber.org/zap"
	"github.com/yourusername/surveyor"
)

// ExampleScannerPlugin implements a scanner plugin
type ExampleScannerPlugin struct {
	info    surveyor.PluginInfo
	config  map[string]interface{}
	logger  *zap.Logger
}

// New creates a new instance of the plugin
func New() surveyor.Plugin {
	return &ExampleScannerPlugin{
		info: surveyor.PluginInfo{
			Name:        "example_scanner",
			Version:     "1.0.0",
			Description: "Example scanner plugin",
			Author:      "Your Name",
			Type:        surveyor.ScannerPlugin,
			Enabled:     true,
		},
	}
}

// Info returns the plugin information
func (p *ExampleScannerPlugin) Info() surveyor.PluginInfo {
	return p.info
}

// Init initializes the plugin
func (p *ExampleScannerPlugin) Init(config map[string]interface{}, logger *zap.Logger) error {
	p.config = config
	p.logger = logger.With(zap.String("plugin", p.info.Name))
	return nil
}

// Shutdown is called when the plugin is being unloaded
func (p *ExampleScannerPlugin) Shutdown() error {
	return nil
}

// EnhanceScanResult adds additional information to scan results
func (p *ExampleScannerPlugin) EnhanceScanResult(result *surveyor.ScanResult) error {
	// Example enhancement: add a custom field
	if result.AdditionalInfo == nil {
		result.AdditionalInfo = make(map[string]string)
	}
	result.AdditionalInfo["example_scanner_version"] = p.info.Version
	return nil
}

// GetSupportedOptions returns options this scanner plugin accepts
func (p *ExampleScannerPlugin) GetSupportedOptions() []string {
	return []string{"example_option1", "example_option2"}
}
`

	if err := os.WriteFile(scannerExample, []byte(scannerCode), 0644); err != nil {
		return fmt.Errorf("failed to write scanner example: %v", err)
	}

	// Example for building a plugin
	buildScript := filepath.Join(outputDir, "build_plugin.sh")
	buildScriptCode := `#!/bin/bash
# Example build script for a plugin
go build -buildmode=plugin -o example_scanner.so scanner_example.go
`

	if err := os.WriteFile(buildScript, []byte(buildScriptCode), 0755); err != nil {
		return fmt.Errorf("failed to write build script: %v", err)
	}

	return nil
}