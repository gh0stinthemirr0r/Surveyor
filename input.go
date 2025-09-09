// Package surveyor handles user input and validation for the application.
package surveyor

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// Input errors
var (
	ErrEmptyInput = errors.New("input cannot be empty")
	ErrInvalidInput = errors.New("invalid input format")
	ErrInvalidDestination = errors.New("invalid destination")
	ErrFileNotFound = errors.New("file not found")
)

// InputHandler manages user input and validation.
type InputHandler struct {
	logger *zap.Logger
	reader *bufio.Reader
}

// NewInputHandler creates a new instance of InputHandler.
func NewInputHandler(logger *zap.Logger) *InputHandler {
	return &InputHandler{
		logger: logger.With(zap.String("component", "input")),
		reader: bufio.NewReader(os.Stdin),
	}
}

// GetDestination prompts the user for a destination and validates the input.
func (ih *InputHandler) GetDestination() ([]string, error) {
	fmt.Println("\nEnter destination IP(s) or network(s) (comma-separated):")
	fmt.Println("  - Individual IPs: 192.168.1.1")
	fmt.Println("  - CIDR notation: 192.168.1.0/24") 
	fmt.Println("  - Multiple targets: 10.0.0.1,10.0.0.2,10.0.0.0/24")
	fmt.Print("> ")

	input, err := ih.reader.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("user terminated input: %w", err)
		}
		return nil, fmt.Errorf("failed to read input: %w", err)
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return nil, ErrEmptyInput
	}

	// Check if the input might be a file with targets
	if strings.HasPrefix(input, "@") {
		filePath := strings.TrimPrefix(input, "@")
		return ih.loadTargetsFromFile(filePath)
	}

	// Split the input into multiple destinations.
	destinations := strings.Split(input, ",")
	var validDestinations []string

	ih.logger.Debug("Processing input destinations", zap.Strings("raw_destinations", destinations))

	for _, dest := range destinations {
		dest = strings.TrimSpace(dest)
		if dest == "" {
			continue
		}

		if isValidIP(dest) || isValidCIDR(dest) || isValidHostname(dest) {
			validDestinations = append(validDestinations, dest)
		} else {
			ih.logger.Warn("Invalid destination detected", zap.String("destination", dest))
			return nil, fmt.Errorf("%w: %s", ErrInvalidDestination, dest)
		}
	}

	if len(validDestinations) == 0 {
		return nil, errors.New("no valid destinations provided")
	}

	ih.logger.Debug("Valid destinations processed", zap.Strings("valid_destinations", validDestinations))
	return validDestinations, nil
}

// loadTargetsFromFile loads targets from a file, one per line.
func (ih *InputHandler) loadTargetsFromFile(filePath string) ([]string, error) {
	// Resolve the file path
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve file path: %w", err)
	}

	// Check if the file exists
	_, err = os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrFileNotFound, filePath)
		}
		return nil, fmt.Errorf("failed to access file: %w", err)
	}

	// Open and read the file
	file, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var validDestinations []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if isValidIP(line) || isValidCIDR(line) || isValidHostname(line) {
			validDestinations = append(validDestinations, line)
		} else {
			ih.logger.Warn("Invalid destination in file", 
				zap.String("file", filePath), 
				zap.Int("line", lineNum), 
				zap.String("value", line))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if len(validDestinations) == 0 {
		return nil, errors.New("no valid destinations found in file")
	}

	ih.logger.Info("Loaded targets from file", 
		zap.String("file", filePath), 
		zap.Int("target_count", len(validDestinations)))
	return validDestinations, nil
}

// PromptUser prompts the user for input and returns their response.
func (ih *InputHandler) PromptUser(prompt string) (string, error) {
	fmt.Println(prompt)
	fmt.Print("> ")
	
	input, err := ih.reader.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			return "", fmt.Errorf("user terminated input: %w", err)
		}
		return "", fmt.Errorf("failed to read input: %w", err)
	}
	
	response := strings.TrimSpace(input)
	if response == "" {
		return "", ErrEmptyInput
	}

	return response, nil
}

// PromptYesNo prompts the user for a yes/no answer.
func (ih *InputHandler) PromptYesNo(prompt string, defaultYes bool) (bool, error) {
	var defaultOption, options string
	if defaultYes {
		defaultOption = "Y"
		options = "[Y/n]"
	} else {
		defaultOption = "N"
		options = "[y/N]"
	}

	fmt.Printf("%s %s: ", prompt, options)
	input, err := ih.reader.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			return defaultYes, nil // Use default on EOF
		}
		return false, fmt.Errorf("failed to read input: %w", err)
	}

	response := strings.TrimSpace(strings.ToLower(input))
	if response == "" {
		return defaultYes, nil
	}

	if response == "y" || response == "yes" {
		return true, nil
	} else if response == "n" || response == "no" {
		return false, nil
	} else {
		fmt.Printf("Invalid response. Using default (%s).\n", defaultOption)
		return defaultYes, nil
	}
}

// GetPortRange prompts the user for a port range.
func (ih *InputHandler) GetPortRange() (int, int, error) {
	fmt.Println("\nEnter port range (e.g., 1-1024):")
	fmt.Print("> ")

	input, err := ih.reader.ReadString('\n')
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read input: %w", err)
	}

	input = strings.TrimSpace(input)
	if input == "" {
		// Default range
		return 1, 1024, nil
	}

	// Try to parse range from input
	startPort, endPort, err := ExtractPortRangeFromString(input)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}

	return startPort, endPort, nil
}

// isValidIP is a helper function that checks if the provided input is a valid IP address.
func isValidIP(ip string) bool {
	return IsValidIP(ip)
}

// isValidCIDR is a helper function that checks if the provided input is a valid CIDR notation.
func isValidCIDR(cidr string) bool {
	return IsValidCIDR(cidr)
}

// isValidHostname is a helper function that checks if the provided input is a valid hostname.
func isValidHostname(hostname string) bool {
	return IsValidHostname(hostname)
}