# Changelog

## Version 2.0.0 (2025-03-04)

### Major Enhancements
- **Enhanced Network Discovery**: Added detailed host discovery capabilities with improved network mapping
- **Advanced Service Detection**: Improved service fingerprinting with TLS analysis and version detection
- **Comprehensive Vulnerability Scanning**: Implemented CVE checking with severity tracking and remediation suggestions
- **Network Topology Analysis**: Added route tracing with path analysis and network mapping
- **Improved Utility Functions**: Extended helper functions for IP handling, concurrency, and data processing

### New Features
- Added service probe-based detection for accurate service identification
- Implemented TLS configuration quality assessment
- Added vulnerability management with CVE database integration
- Created route analysis with hop detection and latency measurement
- Added exploitability assessment for discovered vulnerabilities
- Improved IP range handling with CIDR and range support
- Added concurrent processing patterns for better performance
- Enhanced data encoding and security utilities

### Technical Improvements
- Restructured core components for better extensibility
- Improved error handling and logging
- Enhanced configuration options
- Added memory-efficient caching
- Optimized network operations
- Improved multithreading and resource management

### Configuration Options
- Added fine-grained control for vulnerability scanning
- Enhanced service detection configuration
- Added route analysis options
- Extended report generation capabilities
- Added performance tuning parameters

### Documentation
- Updated usage documentation with examples for new features
- Added detailed configuration reference
- Included vulnerability management guide
- Provided examples for common scanning scenarios

### Dependencies
- Updated to Go 1.21
- Added crypto libraries for enhanced security features
- Updated zap logger for improved logging capabilities

## Version 1.1.0 (Previous release)

- Initial public release of Surveyor
- Basic port scanning functionality
- Simple OS detection
- Basic service identification
- CSV and JSON reporting