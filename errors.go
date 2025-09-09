package surveyor

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
)

// ErrorCode represents specific error codes for better error handling
type ErrorCode int

const (
	// ErrCodeUnknown is used when the error doesn't fit any other category
	ErrCodeUnknown ErrorCode = iota
	// ErrCodeNetworkFailure is used for network connectivity issues
	ErrCodeNetworkFailure
	// ErrCodeTimeout is used when an operation times out
	ErrCodeTimeout
	// ErrCodeValidation is used for validation errors
	ErrCodeValidation
	// ErrCodePermission is used for permission-related errors
	ErrCodePermission
	// ErrCodeConfiguration is used for configuration-related errors
	ErrCodeConfiguration
	// ErrCodeResource is used for resource availability issues
	ErrCodeResource
	// ErrCodeSystem is used for system-level errors
	ErrCodeSystem
	// ErrCodeExternal is used for errors from external dependencies
	ErrCodeExternal
	// ErrCodeCancelled is used when an operation is cancelled
	ErrCodeCancelled
)

// AppError represents an application-specific error with context
type AppError struct {
	// Underlying error
	Err error
	// Error code for programmatic handling
	Code ErrorCode
	// Human-readable message
	Message string
	// Component where the error occurred
	Component string
	// Operation that was being performed
	Operation string
	// Source file and line number for debugging
	Source string
	// Target of the operation (e.g., hostname, IP)
	Target string
	// Additional context as key-value pairs
	Context map[string]string
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap implements the errors.Unwrap interface
func (e *AppError) Unwrap() error {
	return e.Err
}

// AddContext adds a key-value pair to the error context
func (e *AppError) AddContext(key, value string) *AppError {
	if e.Context == nil {
		e.Context = make(map[string]string)
	}
	e.Context[key] = value
	return e
}

// WithSource adds source file and line information to the error
func (e *AppError) WithSource() *AppError {
	_, file, line, ok := runtime.Caller(1)
	if ok {
		// Extract just the filename, not the full path
		parts := strings.Split(file, "/")
		if len(parts) > 0 {
			file = parts[len(parts)-1]
		}
		e.Source = fmt.Sprintf("%s:%d", file, line)
	}
	return e
}

// NewAppError creates a new application error
func NewAppError(err error, code ErrorCode, message, component, operation string) *AppError {
	return &AppError{
		Err:       err,
		Code:      code,
		Message:   message,
		Component: component,
		Operation: operation,
		Context:   make(map[string]string),
	}
}

// IsNetworkError checks if an error is a network-related error
func IsNetworkError(err error) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code == ErrCodeNetworkFailure
	}
	return false
}

// IsTimeoutError checks if an error is a timeout error
func IsTimeoutError(err error) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code == ErrCodeTimeout
	}
	return false
}

// IsValidationError checks if an error is a validation error
func IsValidationError(err error) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code == ErrCodeValidation
	}
	return false
}

// GetErrorCode extracts the error code from an error
func GetErrorCode(err error) ErrorCode {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code
	}
	return ErrCodeUnknown
}

// ErrorResponse represents an error response for API endpoints
type ErrorResponse struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Code    string      `json:"code"`
	Details interface{} `json:"details,omitempty"`
}

// NewErrorResponse creates a new error response
func NewErrorResponse(status int, code, message string, details interface{}) *ErrorResponse {
	return &ErrorResponse{
		Status:  status,
		Message: message,
		Code:    code,
		Details: details,
	}
}

// ErrorMiddleware is a generic error handler that can be used in API handlers
func ErrorMiddleware(handler func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := handler(w, r)
		if err != nil {
			handleError(w, err)
		}
	}
}

// handleError converts an error to an HTTP response
func handleError(w http.ResponseWriter, err error) {
	var appErr *AppError
	status := http.StatusInternalServerError
	code := "internal_server_error"
	message := "An unexpected error occurred"
	var details interface{}
	
	if errors.As(err, &appErr) {
		// Map error code to HTTP status
		switch appErr.Code {
		case ErrCodeValidation:
			status = http.StatusBadRequest
			code = "validation_error"
		case ErrCodePermission:
			status = http.StatusForbidden
			code = "permission_denied"
		case ErrCodeTimeout:
			status = http.StatusRequestTimeout
			code = "timeout"
		case ErrCodeResource:
			status = http.StatusConflict
			code = "resource_conflict"
		case ErrCodeCancelled:
			status = http.StatusRequestTimeout
			code = "operation_cancelled"
		}
		
		message = appErr.Message
		details = appErr.Context
	}
	
	// Create error response
	response := NewErrorResponse(status, code, message, details)
	
	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}