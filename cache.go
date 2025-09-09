package surveyor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto"
	"go.uber.org/zap"
)

// Cache errors
var (
	ErrCacheInitFailed = fmt.Errorf("failed to initialize cache")
	ErrCacheSetFailed  = fmt.Errorf("failed to set cache entry")
	ErrCacheGetFailed  = fmt.Errorf("failed to get cache entry")
)

// CacheType represents the type of cache
type CacheType int

const (
	// MemoryCache stores cache items in memory only
	MemoryCache CacheType = iota
	// PersistentCache stores cache items in memory and persists to disk
	PersistentCache
	// DistributedCache stores cache items in a distributed cache (e.g., Redis)
	DistributedCache
)

// dnsCacheEntry represents a DNS cache entry
type dnsCacheEntry struct {
	value     string
	expiresAt time.Time
}

// scanResultCacheEntry represents a scan result cache entry
type scanResultCacheEntry struct {
	result    *ScanResult
	expiresAt time.Time
}

// DNSCache provides a simple cache for DNS lookups
type DNSCache struct {
	cache map[string]dnsCacheEntry
	ttl   time.Duration
	mu    sync.RWMutex
}

// NewDNSCache creates a new DNS cache
func NewDNSCache(ttl time.Duration) *DNSCache {
	return &DNSCache{
		cache: make(map[string]dnsCacheEntry),
		ttl:   ttl,
	}
}

// Set adds an entry to the DNS cache
func (c *DNSCache) Set(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = dnsCacheEntry{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Get retrieves an entry from the DNS cache
func (c *DNSCache) Get(key string) string {
	c.mu.RLock()
	entry, found := c.cache[key]
	c.mu.RUnlock()

	if !found {
		return ""
	}

	// Check if the entry has expired
	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.cache, key)
		c.mu.Unlock()
		return ""
	}

	return entry.value
}

// Cleanup removes expired entries from the cache
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

// Delete removes an entry from the DNS cache
func (c *DNSCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, key)
}

// Clear removes all entries from the DNS cache
func (c *DNSCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]dnsCacheEntry)
}

// ScanResultCache provides a cache for scan results
type ScanResultCache struct {
	cache map[string]scanResultCacheEntry
	ttl   time.Duration
	mu    sync.RWMutex
}

// NewScanResultCache creates a new scan result cache
func NewScanResultCache(ttl time.Duration) *ScanResultCache {
	return &ScanResultCache{
		cache: make(map[string]scanResultCacheEntry),
		ttl:   ttl,
	}
}

// Set adds an entry to the scan result cache
func (c *ScanResultCache) Set(key string, result *ScanResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = scanResultCacheEntry{
		result:    result,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Get retrieves an entry from the scan result cache
func (c *ScanResultCache) Get(key string) *ScanResult {
	c.mu.RLock()
	entry, found := c.cache[key]
	c.mu.RUnlock()

	if !found {
		return nil
	}

	// Check if the entry has expired
	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.cache, key)
		c.mu.Unlock()
		return nil
	}

	return entry.result
}

// Cleanup removes expired entries from the cache
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

// Delete removes an entry from the scan result cache
func (c *ScanResultCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, key)
}

// Clear removes all entries from the scan result cache
func (c *ScanResultCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]scanResultCacheEntry)
}

// CachingService provides caching functionality for the application
type CachingService struct {
	memCache      *ristretto.Cache
	diskCachePath string
	dnsCache      *DNSCache
	resultCache   *ScanResultCache
	logger        *zap.Logger
	cacheType     CacheType
	ttl           time.Duration
	mu            sync.RWMutex
}

// NewCachingService creates a new caching service
func NewCachingService(config *Config, logger *zap.Logger) (*CachingService, error) {
	ttl := time.Duration(config.CacheTTL) * time.Minute
	cacheType := MemoryCache
	if config.PersistentCache {
		cacheType = PersistentCache
	}

	// Create cache directory if persistent caching is enabled
	diskCachePath := ""
	if cacheType == PersistentCache {
		diskCachePath = filepath.Join(config.DataDir, "cache")
		if err := os.MkdirAll(diskCachePath, 0755); err != nil {
			return nil, fmt.Errorf("failed to create cache directory: %w", err)
		}
	}

	// Configure ristretto cache
	cacheConfig := &ristretto.Config{
		NumCounters: 1e7,     // number of keys to track frequency of (10M)
		MaxCost:     1 << 30, // maximum cost of cache (1GB)
		BufferItems: 64,      // number of keys per Get buffer
		Metrics:     true,
	}

	cache, err := ristretto.NewCache(cacheConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCacheInitFailed, err)
	}

	// Create DNS and scan result caches
	dnsCache := NewDNSCache(ttl)
	resultCache := NewScanResultCache(ttl)

	cacheService := &CachingService{
		memCache:      cache,
		diskCachePath: diskCachePath,
		dnsCache:      dnsCache,
		resultCache:   resultCache,
		logger:        logger.With(zap.String("component", "cache")),
		cacheType:     cacheType,
		ttl:           ttl,
	}

	// Load persistent cache from disk if enabled
	if cacheType == PersistentCache {
		if err := cacheService.loadFromDisk(); err != nil {
			logger.Warn("Failed to load cache from disk", zap.Error(err))
		}
	}

	// Start a background goroutine to periodically clean up expired cache entries
	go cacheService.startCleanupWorker(ttl / 2)

	return cacheService, nil
}

// SetDNS sets a DNS entry in the cache
func (c *CachingService) SetDNS(key, value string) {
	c.dnsCache.Set(key, value)
	c.memCache.SetWithTTL(key, value, 1, c.ttl)

	// Persist to disk if enabled
	if c.cacheType == PersistentCache {
		go c.persistToDisk()
	}
}

// GetDNS gets a DNS entry from the cache
func (c *CachingService) GetDNS(key string) string {
	// First try the DNS cache
	value := c.dnsCache.Get(key)
	if value != "" {
		return value
	}

	// Then try the memory cache
	if val, found := c.memCache.Get(key); found {
		if str, ok := val.(string); ok {
			return str
		}
	}

	return ""
}

// SetScanResult sets a scan result in the cache
func (c *CachingService) SetScanResult(key string, result *ScanResult) {
	c.resultCache.Set(key, result)
	c.memCache.SetWithTTL(key, result, 1, c.ttl)

	// Persist to disk if enabled
	if c.cacheType == PersistentCache {
		go c.persistToDisk()
	}
}

// GetScanResult gets a scan result from the cache
func (c *CachingService) GetScanResult(key string) *ScanResult {
	// First try the scan result cache
	result := c.resultCache.Get(key)
	if result != nil {
		return result
	}

	// Then try the memory cache
	if val, found := c.memCache.Get(key); found {
		if result, ok := val.(*ScanResult); ok {
			return result
		}
	}

	return nil
}

// Set sets a generic entry in the cache
func (c *CachingService) Set(key string, value interface{}) {
	c.memCache.SetWithTTL(key, value, 1, c.ttl)

	// Persist to disk if enabled
	if c.cacheType == PersistentCache {
		go c.persistToDisk()
	}
}

// Get gets a generic entry from the cache
func (c *CachingService) Get(key string) (interface{}, bool) {
	return c.memCache.Get(key)
}

// Delete removes an entry from the cache
func (c *CachingService) Delete(key string) {
	c.dnsCache.Delete(key)
	c.resultCache.Delete(key)
	c.memCache.Del(key)

	// Persist to disk if enabled
	if c.cacheType == PersistentCache {
		go c.persistToDisk()
	}
}

// Clear clears the entire cache
func (c *CachingService) Clear() {
	c.dnsCache.Clear()
	c.resultCache.Clear()
	c.memCache.Clear()

	// Remove disk cache if enabled
	if c.cacheType == PersistentCache {
		go c.deleteDiskCache()
	}
}

// persistToDisk persists the cache to disk
func (c *CachingService) persistToDisk() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.diskCachePath == "" {
		return
	}

	// Create a structure to hold cache data
	type CacheData struct {
		DNS         map[string]dnsCacheEntry       `json:"dns"`
		ScanResults map[string]scanResultCacheEntry `json:"scan_results"`
		Timestamp   time.Time                      `json:"timestamp"`
	}

	// Get DNS cache data
	dnsData := make(map[string]dnsCacheEntry)
	c.dnsCache.mu.RLock()
	for k, v := range c.dnsCache.cache {
		dnsData[k] = v
	}
	c.dnsCache.mu.RUnlock()

	// Get scan result cache data
	scanData := make(map[string]scanResultCacheEntry)
	c.resultCache.mu.RLock()
	for k, v := range c.resultCache.cache {
		scanData[k] = v
	}
	c.resultCache.mu.RUnlock()

	cacheData := CacheData{
		DNS:         dnsData,
		ScanResults: scanData,
		Timestamp:   time.Now(),
	}

	// Marshal to JSON
	data, err := json.Marshal(cacheData)
	if err != nil {
		c.logger.Error("Failed to marshal cache data", zap.Error(err))
		return
	}

	// Write to disk
	cacheFile := filepath.Join(c.diskCachePath, "cache.json")
	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		c.logger.Error("Failed to write cache to disk", zap.Error(err))
	}
}

// loadFromDisk loads the cache from disk
func (c *CachingService) loadFromDisk() error {
	if c.diskCachePath == "" {
		return nil
	}

	cacheFile := filepath.Join(c.diskCachePath, "cache.json")
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return nil // No cache file exists
	}

	// Read from disk
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return fmt.Errorf("failed to read cache file: %w", err)
	}

	// Create a structure to hold cache data
	type CacheData struct {
		DNS         map[string]dnsCacheEntry       `json:"dns"`
		ScanResults map[string]scanResultCacheEntry `json:"scan_results"`
		Timestamp   time.Time                      `json:"timestamp"`
	}

	var cacheData CacheData
	if err := json.Unmarshal(data, &cacheData); err != nil {
		return fmt.Errorf("failed to unmarshal cache data: %w", err)
	}

	// Check if cache is too old
	if time.Since(cacheData.Timestamp) > c.ttl {
		c.logger.Info("Cache is too old, ignoring")
		return nil
	}

	// Load DNS cache data
	c.dnsCache.mu.Lock()
	for k, v := range cacheData.DNS {
		// Skip expired entries
		if time.Now().After(v.expiresAt) {
			continue
		}
		c.dnsCache.cache[k] = v
	}
	c.dnsCache.mu.Unlock()

	// Load scan result cache data
	c.resultCache.mu.Lock()
	for k, v := range cacheData.ScanResults {
		// Skip expired entries
		if time.Now().After(v.expiresAt) {
			continue
		}
		c.resultCache.cache[k] = v
	}
	c.resultCache.mu.Unlock()

	c.logger.Info("Cache loaded from disk", 
		zap.Int("dns_entries", len(cacheData.DNS)),
		zap.Int("scan_results", len(cacheData.ScanResults)))

	return nil
}

// deleteDiskCache deletes the cache file from disk
func (c *CachingService) deleteDiskCache() {
	if c.diskCachePath == "" {
		return
	}

	cacheFile := filepath.Join(c.diskCachePath, "cache.json")
	if err := os.Remove(cacheFile); err != nil && !os.IsNotExist(err) {
		c.logger.Error("Failed to delete cache file", zap.Error(err))
	}
}

// startCleanupWorker starts a background goroutine to periodically clean up expired cache entries
func (c *CachingService) startCleanupWorker(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		c.logger.Debug("Running cache cleanup")
		c.dnsCache.Cleanup()
		c.resultCache.Cleanup()
		
		// Persist to disk if enabled
		if c.cacheType == PersistentCache {
			c.persistToDisk()
		}
	}
}

// GetStats returns cache statistics
func (c *CachingService) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	
	metrics := c.memCache.Metrics
	stats["hit_count"] = metrics.Hits()
	stats["miss_count"] = metrics.Misses()
	stats["cost"] = metrics.Cost()
	stats["ratio"] = metrics.Ratio()

	// Count entries in specialized caches
	c.dnsCache.mu.RLock()
	stats["dns_entries"] = len(c.dnsCache.cache)
	c.dnsCache.mu.RUnlock()

	c.resultCache.mu.RLock()
	stats["scan_results"] = len(c.resultCache.cache)
	c.resultCache.mu.RUnlock()

	return stats
}