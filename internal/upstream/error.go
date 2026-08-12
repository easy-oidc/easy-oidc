// Truster <https://truster.dev>
// Copyright The Truster Authors
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// ErrorKind classifies a provider failure without exposing response bodies or credentials.
type ErrorKind string

const (
	ErrorUnauthorized  ErrorKind = "unauthorized"
	ErrorNoRotation    ErrorKind = "definitive_no_rotation"
	ErrorConfiguration ErrorKind = "configuration"
	ErrorTerminal      ErrorKind = "terminal"
	ErrorRateLimit     ErrorKind = "rate_limit"
	ErrorTemporary     ErrorKind = "temporary"
)

// ConnectorError is a sanitized, typed provider failure.
type ConnectorError struct {
	Kind       ErrorKind
	RetryAfter string
	Operation  string
}

// Error returns a body- and credential-free provider error.
func (e *ConnectorError) Error() string {
	return fmt.Sprintf("upstream %s failed (%s)", e.Operation, e.Kind)
}

// ClassifyHTTPStatus classifies a provider HTTP status and optional Retry-After value.
func ClassifyHTTPStatus(operation string, status int, retryAfter string) error {
	kind := ErrorTemporary
	switch status {
	case http.StatusUnauthorized:
		kind = ErrorUnauthorized
	case http.StatusTooManyRequests:
		kind = ErrorRateLimit
	}
	return &ConnectorError{Kind: kind, RetryAfter: retryAfter, Operation: operation}
}

// ClassifyError converts OAuth and transport errors into the connector contract.
func ClassifyError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var classified *ConnectorError
	if errors.As(err, &classified) {
		return classified
	}
	var retrieve *oauth2.RetrieveError
	if errors.As(err, &retrieve) {
		kind := ErrorTemporary
		status := 0
		if retrieve.Response != nil {
			status = retrieve.Response.StatusCode
		}
		if retrieve.ErrorCode == "invalid_grant" {
			kind = ErrorNoRotation
		} else if retrieve.ErrorCode == "invalid_client" {
			kind = ErrorConfiguration
		} else if retrieve.ErrorCode == "access_denied" {
			kind = ErrorTerminal
		} else if retrieve.ErrorCode == "invalid_token" || status == http.StatusUnauthorized {
			kind = ErrorUnauthorized
		} else if status == http.StatusTooManyRequests {
			kind = ErrorRateLimit
		}
		retry := ""
		if retrieve.Response != nil {
			retry = retrieve.Response.Header.Get("Retry-After")
		}
		return &ConnectorError{Kind: kind, RetryAfter: retry, Operation: operation}
	}
	return &ConnectorError{Kind: ErrorTemporary, Operation: operation}
}

// ErrorInfo returns a connector error's classification.
func ErrorInfo(err error) (ErrorKind, string) {
	var e *ConnectorError
	if errors.As(err, &e) {
		return e.Kind, e.RetryAfter
	}
	return ErrorTemporary, ""
}
