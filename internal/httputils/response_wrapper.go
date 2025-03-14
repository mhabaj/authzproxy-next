// internal/httputil/response_wrapper.go
package httputils

import (
	"bufio"
	"errors"
	"net"
	"net/http"
)

// ResponseWriter is a wrapper for http.ResponseWriter that captures the status code
type ResponseWriter struct {
	http.ResponseWriter
	StatusCode    int
	BytesWritten  int
	HeaderWritten bool
}

// NewResponseWriter creates a new response writer wrapper
func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{
		ResponseWriter: w,
		StatusCode:     http.StatusOK, // Default status code is 200 OK
	}
}

// WriteHeader captures the status code and passes it to the underlying ResponseWriter
func (rw *ResponseWriter) WriteHeader(code int) {
	if !rw.HeaderWritten {
		rw.StatusCode = code
		rw.HeaderWritten = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

// Write captures the bytes written and passes them to the underlying ResponseWriter
func (rw *ResponseWriter) Write(b []byte) (int, error) {
	if !rw.HeaderWritten {
		rw.WriteHeader(http.StatusOK)
	}
	size, err := rw.ResponseWriter.Write(b)
	rw.BytesWritten += size
	return size, err
}

// Hijack implements the http.Hijacker interface to forward calls to the underlying ResponseWriter
func (rw *ResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, errors.New("underlying ResponseWriter does not implement http.Hijacker")
}

// Flush implements the http.Flusher interface to forward calls to the underlying ResponseWriter
func (rw *ResponseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// CloseNotify implements the http.CloseNotifier interface to forward calls to the underlying ResponseWriter
// Note: http.CloseNotifier is deprecated but included for compatibility
func (rw *ResponseWriter) CloseNotify() <-chan bool {
	if closeNotifier, ok := rw.ResponseWriter.(http.CloseNotifier); ok {
		return closeNotifier.CloseNotify()
	}
	return nil
}

// Push implements the http.Pusher interface to forward calls to the underlying ResponseWriter
func (rw *ResponseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := rw.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return errors.New("underlying ResponseWriter does not implement http.Pusher")
}
