package surveyor

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
)

// ReportData represents the data to be included in the reports.
type ReportData struct {
	Source           string
	Destination      string
	OS               string
	OpenPorts        []int
	OpenUDPPorts     []int
	Services         map[int]string
	Shares           []string
	Vulnerabilities  []string
	GeneratedTraffic int
	ScanTime         time.Time
	Metrics          map[string]string
}

// XMLReportData is a wrapper for XML report generation
type XMLReportData struct {
	XMLName        xml.Name        `xml:"SurveyorReport"`
	GeneratedAt    string          `xml:"generatedAt,attr"`
	Version        string          `xml:"version,attr"`
	TargetSystems  []XMLTargetData `xml:"TargetSystems>Target"`
}

// XMLTargetData represents a single target for XML reporting
type XMLTargetData struct {
	IP              string           `xml:"ip,attr"`
	Hostname        string           `xml:"hostname,attr"`
	OS              string           `xml:"os,attr"`
	TCPPorts        []XMLPortData    `xml:"TCPPorts>Port,omitempty"`
	UDPPorts        []XMLPortData    `xml:"UDPPorts>Port,omitempty"`
	Vulnerabilities []XMLVulnData    `xml:"Vulnerabilities>Vulnerability,omitempty"`
	Metrics         []XMLMetricData  `xml:"Metrics>Metric,omitempty"`
}

// XMLPortData represents port data for XML reporting
type XMLPortData struct {
	Number  int    `xml:"number,attr"`
	Service string `xml:"service,attr,omitempty"`
}

// XMLVulnData represents vulnerability data for XML reporting
type XMLVulnData struct {
	ID          string `xml:"id,attr"`
	Description string `xml:",chardata"`
}

// XMLMetricData represents metric data for XML reporting
type XMLMetricData struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

// WriteCSVReport generates a detailed CSV report.
func WriteCSVReport(data []ReportData, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"Source", "Destination", "Hostname", "OS", "TCP Ports", "UDP Ports",
		"Services", "Vulnerabilities", "Generated Traffic", "Scan Time",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write data rows
	for _, entry := range data {
		// Format ports as comma-separated list
		tcpPorts := formatPortsList(entry.OpenPorts)
		udpPorts := formatPortsList(entry.OpenUDPPorts)
		
		// Format services
		services := formatServices(entry.Services)
		
		// Format vulnerabilities
		vulns := strings.Join(entry.Vulnerabilities, ", ")
		
		// Get hostname from metrics if available
		hostname := ""
		if entry.Metrics != nil {
			if h, ok := entry.Metrics["hostname"]; ok {
				hostname = h
			}
		}
		
		// Format scan time
		scanTime := ""
		if !entry.ScanTime.IsZero() {
			scanTime = entry.ScanTime.Format(time.RFC3339)
		} else {
			scanTime = time.Now().Format(time.RFC3339)
		}
		
		row := []string{
			entry.Source,
			entry.Destination,
			hostname,
			entry.OS,
			tcpPorts,
			udpPorts,
			services,
			vulns,
			strconv.Itoa(entry.GeneratedTraffic),
			scanTime,
		}
		
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}

// WritePDFReport generates a detailed PDF report.
func WritePDFReport(data []ReportData, filePath string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetAuthor("Surveyor Tool", true)
	pdf.SetTitle("Network Scan Report", true)
	pdf.SetSubject("Security Assessment", true)
	
	// Add a custom header
	pdf.SetHeaderFunc(func() {
		pdf.SetFont("Arial", "B", 15)
		pdf.Cell(0, 10, "Surveyor Network Scan Report")
		pdf.Ln(20)
	})
	
	// Add a custom footer
	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Arial", "I", 8)
		pdf.Cell(0, 10, fmt.Sprintf("Page %d / {nb}", pdf.PageNo()))
	})
	
	pdf.AliasNbPages("{nb}")
	pdf.AddPage()

	// Report timestamp
	pdf.SetFont("Arial", "I", 10)
	currentTime := time.Now().Format("2006-01-02 15:04:05 MST")
	pdf.Cell(0, 10, fmt.Sprintf("Generated: %s", currentTime))
	pdf.Ln(15)

	// Add summary section
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 10, "Scan Summary")
	pdf.Ln(10)
	
	pdf.SetFont("Arial", "", 10)
	pdf.Cell(40, 8, fmt.Sprintf("Total Hosts Scanned: %d", len(data)))
	pdf.Ln(8)
	
	// Count open ports and vulnerabilities
	tcpPortCount := 0
	udpPortCount := 0
	vulnCount := 0
	for _, entry := range data {
		tcpPortCount += len(entry.OpenPorts)
		udpPortCount += len(entry.OpenUDPPorts)
		vulnCount += len(entry.Vulnerabilities)
	}
	
	pdf.Cell(40, 8, fmt.Sprintf("Open TCP Ports Found: %d", tcpPortCount))
	pdf.Ln(8)
	pdf.Cell(40, 8, fmt.Sprintf("Open UDP Ports Found: %d", udpPortCount))
	pdf.Ln(8)
	pdf.Cell(40, 8, fmt.Sprintf("Potential Vulnerabilities: %d", vulnCount))
	pdf.Ln(20)

	// Add detailed host information
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 10, "Host Details")
	pdf.Ln(10)

	for i, entry := range data {
		// If this isn't the first host, add a page break
		if i > 0 {
			pdf.AddPage()
		}
		
		// Host header
		pdf.SetFont("Arial", "B", 11)
		hostname := entry.Destination
		if entry.Metrics != nil && entry.Metrics["hostname"] != "" {
			hostname = fmt.Sprintf("%s (%s)", entry.Metrics["hostname"], entry.Destination)
		}
		pdf.Cell(0, 10, fmt.Sprintf("Host: %s", hostname))
		pdf.Ln(10)
		
		// Host details
		pdf.SetFont("Arial", "", 10)
		pdf.Cell(60, 8, fmt.Sprintf("Operating System: %s", entry.OS))
		pdf.Ln(8)
		
		// TCP Ports
		if len(entry.OpenPorts) > 0 {
			pdf.SetFont("Arial", "B", 10)
			pdf.Cell(60, 8, "Open TCP Ports:")
			pdf.Ln(8)
			
			pdf.SetFont("Arial", "", 10)
			pdf.SetFillColor(240, 240, 240)
			
			// Create a table for ports and services
			headers := []string{"Port", "Service"}
			widths := []float64{20, 160}
			
			// Draw table header
			for i, header := range headers {
				pdf.CellFormat(widths[i], 8, header, "1", 0, "", true, 0, "")
			}
			pdf.Ln(8)
			
			// Draw table rows
			fill := false
			for _, port := range entry.OpenPorts {
				service := ""
				if entry.Services != nil {
					if s, ok := entry.Services[port]; ok {
						service = s
					}
				}
				
				pdf.CellFormat(widths[0], 8, fmt.Sprintf("%d", port), "1", 0, "", fill, 0, "")
				pdf.CellFormat(widths[1], 8, service, "1", 0, "", fill, 0, "")
				pdf.Ln(8)
				fill = !fill
			}
			pdf.Ln(5)
		}
		
		// UDP Ports
		if len(entry.OpenUDPPorts) > 0 {
			pdf.SetFont("Arial", "B", 10)
			pdf.Cell(60, 8, "Open UDP Ports:")
			pdf.Ln(8)
			
			pdf.SetFont("Arial", "", 10)
			pdf.SetFillColor(240, 240, 240)
			
			// Create a table for ports
			headers := []string{"Port", "Service"}
			widths := []float64{20, 160}
			
			// Draw table header
			for i, header := range headers {
				pdf.CellFormat(widths[i], 8, header, "1", 0, "", true, 0, "")
			}
			pdf.Ln(8)
			
			// Draw table rows
			fill := false
			for _, port := range entry.OpenUDPPorts {
				service := ""
				if entry.Services != nil {
					if s, ok := entry.Services[port]; ok {
						service = s
					}
				}
				
				pdf.CellFormat(widths[0], 8, fmt.Sprintf("%d", port), "1", 0, "", fill, 0, "")
				pdf.CellFormat(widths[1], 8, service, "1", 0, "", fill, 0, "")
				pdf.Ln(8)
				fill = !fill
			}
			pdf.Ln(5)
		}
		
		// Vulnerabilities
		if len(entry.Vulnerabilities) > 0 {
			pdf.SetFont("Arial", "B", 10)
			pdf.Cell(60, 8, "Potential Vulnerabilities:")
			pdf.Ln(8)
			
			pdf.SetFont("Arial", "", 10)
			pdf.SetFillColor(255, 240, 240) // Light red for vulnerabilities
			
			// Create a table for vulnerabilities
			headers := []string{"ID", "Description"}
			widths := []float64{40, 140}
			
			// Draw table header
			for i, header := range headers {
				pdf.CellFormat(widths[i], 8, header, "1", 0, "", true, 0, "")
			}
			pdf.Ln(8)
			
			// Draw table rows
			fill := false
			for _, vuln := range entry.Vulnerabilities {
				// For this example, we're just printing the vulnerability ID
				// In a real report, you'd want to include more details
				pdf.CellFormat(widths[0], 8, vuln, "1", 0, "", fill, 0, "")
				pdf.CellFormat(widths[1], 8, "See CVE database for details", "1", 0, "", fill, 0, "")
				pdf.Ln(8)
				fill = !fill
			}
			pdf.Ln(5)
		}
		
		// Additional Metrics
		if entry.Metrics != nil && len(entry.Metrics) > 0 {
			pdf.SetFont("Arial", "B", 10)
			pdf.Cell(60, 8, "Additional Information:")
			pdf.Ln(8)
			
			pdf.SetFont("Arial", "", 10)
			for key, value := range entry.Metrics {
				if key != "hostname" { // Hostname already displayed in the header
					pdf.Cell(60, 8, fmt.Sprintf("%s: %s", key, value))
					pdf.Ln(8)
				}
			}
		}
	}

	return pdf.OutputFileAndClose(filePath)
}

// WriteJSONReport generates a JSON report.
func WriteJSONReport(data []ReportData, filePath string) error {
	// Create a report structure
	type Report struct {
		Generated time.Time    `json:"generated"`
		Hosts     []ReportData `json:"hosts"`
		Summary   struct {
			HostCount    int `json:"host_count"`
			TCPPortCount int `json:"tcp_port_count"`
			UDPPortCount int `json:"udp_port_count"`
			VulnCount    int `json:"vulnerability_count"`
		} `json:"summary"`
	}

	report := Report{
		Generated: time.Now(),
		Hosts:     data,
	}

	// Calculate summary statistics
	report.Summary.HostCount = len(data)
	for _, entry := range data {
		report.Summary.TCPPortCount += len(entry.OpenPorts)
		report.Summary.UDPPortCount += len(entry.OpenUDPPorts)
		report.Summary.VulnCount += len(entry.Vulnerabilities)
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}

// WriteXMLReport generates an XML report.
func WriteXMLReport(data []ReportData, filePath string) error {
	// Create the XML report structure
	report := XMLReportData{
		GeneratedAt: time.Now().Format(time.RFC3339),
		Version:     "1.0",
	}

	// Convert each host to XML format
	for _, entry := range data {
		target := XMLTargetData{
			IP:       entry.Destination,
			OS:       entry.OS,
		}

		// Add hostname if available
		if entry.Metrics != nil {
			if hostname, ok := entry.Metrics["hostname"]; ok {
				target.Hostname = hostname
			}
		}

		// Add TCP ports
		for _, port := range entry.OpenPorts {
			portData := XMLPortData{
				Number: port,
			}
			
			// Add service if known
			if entry.Services != nil {
				if service, ok := entry.Services[port]; ok {
					portData.Service = service
				}
			}
			
			target.TCPPorts = append(target.TCPPorts, portData)
		}

		// Add UDP ports
		for _, port := range entry.OpenUDPPorts {
			portData := XMLPortData{
				Number: port,
			}
			
			// Add service if known
			if entry.Services != nil {
				if service, ok := entry.Services[port]; ok {
					portData.Service = service
				}
			}
			
			target.UDPPorts = append(target.UDPPorts, portData)
		}

		// Add vulnerabilities
		for _, vuln := range entry.Vulnerabilities {
			target.Vulnerabilities = append(target.Vulnerabilities, XMLVulnData{
				ID:          vuln,
				Description: "See CVE database for details",
			})
		}

		// Add metrics
		if entry.Metrics != nil {
			for key, value := range entry.Metrics {
				if key != "hostname" { // Hostname is already a dedicated field
					target.Metrics = append(target.Metrics, XMLMetricData{
						Name:  key,
						Value: value,
					})
				}
			}
		}

		report.TargetSystems = append(report.TargetSystems, target)
	}

	// Marshal to XML
	xmlData, err := xml.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal XML: %w", err)
	}

	// Add XML header
	xmlData = append([]byte(xml.Header), xmlData...)

	// Write to file
	if err := os.WriteFile(filePath, xmlData, 0644); err != nil {
		return fmt.Errorf("failed to write XML file: %w", err)
	}

	return nil
}

// WriteHTMLReport generates an HTML report using templates.
func WriteHTMLReport(data []ReportData, filePath string, templateDir string) error {
	// Check if template directory exists and create default template if not
	if _, err := os.Stat(templateDir); os.IsNotExist(err) {
		os.MkdirAll(templateDir, 0755)
		
		// Create a default template
		defaultTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Surveyor Network Scan Report</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px; 
        }
        h1 { color: #2c3e50; }
        h2 { 
            color: #3498db; 
            border-bottom: 1px solid #eee; 
            padding-bottom: 10px; 
        }
        h3 { color: #2980b9; }
        .summary { 
            background-color: #f8f9fa; 
            padding: 15px; 
            border-radius: 5px; 
            margin-bottom: 20px; 
        }
        .host { 
            background-color: #fff; 
            border: 1px solid #ddd; 
            border-radius: 5px; 
            padding: 15px; 
            margin-bottom: 20px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-bottom: 15px; 
        }
        th, td { 
            padding: 8px; 
            text-align: left; 
            border: 1px solid #ddd; 
        }
        th { 
            background-color: #f2f2f2; 
            font-weight: bold; 
        }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .vulnerability { color: #e74c3c; }
        .footer { 
            margin-top: 40px; 
            text-align: center; 
            font-size: 0.8em; 
            color: #7f8c8d; 
        }
    </style>
</head>
<body>
    <h1>Surveyor Network Scan Report</h1>
    <p>Generated on: {{ .GeneratedTime }}</p>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <p>Total Hosts Scanned: {{ len .Hosts }}</p>
        <p>Open TCP Ports Found: {{ .TCPPortCount }}</p>
        <p>Open UDP Ports Found: {{ .UDPPortCount }}</p>
        <p>Potential Vulnerabilities: {{ .VulnCount }}</p>
    </div>

    <h2>Host Details</h2>
    
    {{ range .Hosts }}
    <div class="host">
        <h3>Host: {{ .Hostname }} ({{ .Destination }})</h3>
        <p><strong>Operating System:</strong> {{ .OS }}</p>
        
        {{ if .OpenPorts }}
        <h4>Open TCP Ports</h4>
        <table>
            <tr>
                <th>Port</th>
                <th>Service</th>
            </tr>
            {{ range .TCPPortsWithServices }}
            <tr>
                <td>{{ .Port }}</td>
                <td>{{ .Service }}</td>
            </tr>
            {{ end }}
        </table>
        {{ end }}
        
        {{ if .OpenUDPPorts }}
        <h4>Open UDP Ports</h4>
        <table>
            <tr>
                <th>Port</th>
                <th>Service</th>
            </tr>
            {{ range .UDPPortsWithServices }}
            <tr>
                <td>{{ .Port }}</td>
                <td>{{ .Service }}</td>
            </tr>
            {{ end }}
        </table>
        {{ end }}
        
        {{ if .Vulnerabilities }}
        <h4>Potential Vulnerabilities</h4>
        <table>
            <tr>
                <th>ID</th>
                <th>Description</th>
            </tr>
            {{ range .Vulnerabilities }}
            <tr class="vulnerability">
                <td>{{ . }}</td>
                <td>See CVE database for details</td>
            </tr>
            {{ end }}
        </table>
        {{ end }}
        
        {{ if .AdditionalMetrics }}
        <h4>Additional Information</h4>
        <table>
            <tr>
                <th>Key</th>
                <th>Value</th>
            </tr>
            {{ range $key, $value := .AdditionalMetrics }}
            <tr>
                <td>{{ $key }}</td>
                <td>{{ $value }}</td>
            </tr>
            {{ end }}
        </table>
        {{ end }}
    </div>
    {{ end }}
    
    <div class="footer">
        <p>Generated by Surveyor Network Scanning Tool</p>
    </div>
</body>
</html>`
		
		// Write default template
		templatePath := filepath.Join(templateDir, "report_template.html")
		err := os.WriteFile(templatePath, []byte(defaultTemplate), 0644)
		if err != nil {
			return fmt.Errorf("failed to create default template: %w", err)
		}
	}

	// Define template data structure
	type PortService struct {
		Port    int
		Service string
	}
	
	type TemplateHost struct {
		Destination       string
		Hostname          string
		OS                string
		OpenPorts         []int
		OpenUDPPorts      []int
		TCPPortsWithServices []PortService
		UDPPortsWithServices []PortService
		Vulnerabilities   []string
		AdditionalMetrics map[string]string
	}

	type TemplateData struct {
		GeneratedTime string
		Hosts         []TemplateHost
		TCPPortCount  int
		UDPPortCount  int
		VulnCount     int
	}

	// Prepare template data
	templateData := TemplateData{
		GeneratedTime: time.Now().Format("January 2, 2006 15:04:05 MST"),
	}

	for _, entry := range data {
		host := TemplateHost{
			Destination:     entry.Destination,
			OS:              entry.OS,
			OpenPorts:       entry.OpenPorts,
			OpenUDPPorts:    entry.OpenUDPPorts,
			Vulnerabilities: entry.Vulnerabilities,
			AdditionalMetrics: make(map[string]string),
		}

		// Add hostname if available
		if entry.Metrics != nil {
			if hostname, ok := entry.Metrics["hostname"]; ok {
				host.Hostname = hostname
			}
		}
		
		if host.Hostname == "" {
			host.Hostname = entry.Destination
		}

		// Map TCP ports to services
		for _, port := range entry.OpenPorts {
			service := ""
			if entry.Services != nil {
				if s, ok := entry.Services[port]; ok {
					service = s
				}
			}
			host.TCPPortsWithServices = append(host.TCPPortsWithServices, PortService{
				Port:    port,
				Service: service,
			})
		}

		// Map UDP ports to services
		for _, port := range entry.OpenUDPPorts {
			service := ""
			if entry.Services != nil {
				if s, ok := entry.Services[port]; ok {
					service = s
				}
			}
			host.UDPPortsWithServices = append(host.UDPPortsWithServices, PortService{
				Port:    port,
				Service: service,
			})
		}

		// Add additional metrics
		if entry.Metrics != nil {
			for key, value := range entry.Metrics {
				if key != "hostname" { // Hostname is already used in a dedicated field
					host.AdditionalMetrics[key] = value
				}
			}
		}

		templateData.Hosts = append(templateData.Hosts, host)
		
		// Update summary counts
		templateData.TCPPortCount += len(entry.OpenPorts)
		templateData.UDPPortCount += len(entry.OpenUDPPorts)
		templateData.VulnCount += len(entry.Vulnerabilities)
	}

	// Load template
	templatePath := filepath.Join(templateDir, "report_template.html")
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Create output file
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer file.Close()

	// Execute template
	if err := tmpl.Execute(file, templateData); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

// PrintConsoleReport outputs a summary to the console.
func PrintConsoleReport(data []ReportData) {
	fmt.Println("\n===================================")
	fmt.Println("      Network Scan Results")
	fmt.Println("===================================")
	
	// Print summary
	tcpPortCount := 0
	udpPortCount := 0
	vulnCount := 0
	for _, entry := range data {
		tcpPortCount += len(entry.OpenPorts)
		udpPortCount += len(entry.OpenUDPPorts)
		vulnCount += len(entry.Vulnerabilities)
	}
	
	fmt.Printf("\nSummary:\n")
	fmt.Printf("- Hosts scanned: %d\n", len(data))
	fmt.Printf("- TCP ports found: %d\n", tcpPortCount)
	fmt.Printf("- UDP ports found: %d\n", udpPortCount)
	fmt.Printf("- Potential vulnerabilities: %d\n", vulnCount)
	
	// Print details for each host
	for _, entry := range data {
		fmt.Println("\n-----------------------------------")
		
		// Get hostname from metrics if available
		hostname := entry.Destination
		if entry.Metrics != nil {
			if h, ok := entry.Metrics["hostname"]; ok && h != "" {
				hostname = fmt.Sprintf("%s (%s)", h, entry.Destination)
			}
		}
		
		fmt.Printf("Host: %s\n", hostname)
		fmt.Printf("OS: %s\n", entry.OS)
		
		// Print TCP ports
		if len(entry.OpenPorts) > 0 {
			fmt.Printf("Open TCP Ports: %s\n", formatPortsList(entry.OpenPorts))
			
			// Print services if available
			if entry.Services != nil {
				fmt.Println("Services:")
				for _, port := range entry.OpenPorts {
					if service, ok := entry.Services[port]; ok && service != "" {
						fmt.Printf("  %d: %s\n", port, service)
					}
				}
			}
		}
		
		// Print UDP ports
		if len(entry.OpenUDPPorts) > 0 {
			fmt.Printf("Open UDP Ports: %s\n", formatPortsList(entry.OpenUDPPorts))
		}
		
		// Print vulnerabilities if any
		if len(entry.Vulnerabilities) > 0 {
			fmt.Println("Potential vulnerabilities:")
			for _, vuln := range entry.Vulnerabilities {
				fmt.Printf("  - %s\n", vuln)
			}
		}
	}
	
	fmt.Println("\n===================================")
}

// Helper functions

// formatPortsList formats a slice of port numbers as a comma-separated string
func formatPortsList(ports []int) string {
	if len(ports) == 0 {
		return "None"
	}
	
	strPorts := make([]string, len(ports))
	for i, port := range ports {
		strPorts[i] = strconv.Itoa(port)
	}
	
	return strings.Join(strPorts, ", ")
}

// formatServices formats the services map for CSV output
func formatServices(services map[int]string) string {
	if len(services) == 0 {
		return ""
	}
	
	var serviceStrings []string
	for port, service := range services {
		serviceStrings = append(serviceStrings, fmt.Sprintf("%d:%s", port, service))
	}
	
	return strings.Join(serviceStrings, ", ")
}