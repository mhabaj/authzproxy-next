package logging

import (
	"log/slog"
	"net/url"
	"regexp"
	"strings"
)

// RedactedURL wraps a url.URL for logging without exposing sensitive information
type RedactedURL struct {
	url *url.URL
}

// LogValue implements slog.LogValuer to avoid revealing passwords
func (u RedactedURL) LogValue() slog.Value {
	return slog.StringValue(u.url.Redacted())
}

// RedactURL returns a safely loggable URL value
func RedactURL(url *url.URL) RedactedURL {
	return RedactedURL{url: url}
}

// RedactedStringURL is a string containing a URL for safe logging
type RedactedStringURL string

// LogValue implements slog.LogValuer to avoid revealing passwords
func (s RedactedStringURL) LogValue() slog.Value {
	u, err := url.Parse(string(s))
	if err != nil {
		return slog.StringValue(string(s))
	}
	return slog.StringValue(u.Redacted())
}

// RedactStringURL returns a safely loggable URL string
func RedactStringURL(s string) slog.LogValuer {
	return RedactedStringURL(s)
}

// RedactedMysqlURL is a string containing a MySQL DSN for safe logging
type RedactedMysqlURL string

// LogValue implements slog.LogValuer to avoid revealing passwords in database URIs
func (s RedactedMysqlURL) LogValue() slog.Value {
	re := regexp.MustCompile(`(?P<User>[^:@]+):[^@]+@`)
	if re.MatchString(string(s)) {
		// Replace the password with 'xxxxx'
		redacted := re.ReplaceAllString(string(s), `${User}:xxxxx@`)
		return slog.StringValue(redacted)
	}
	return slog.StringValue(string(s))
}

// RedactMysqlURL returns a safely loggable MySQL URL
func RedactMysqlURL(s string) slog.LogValuer {
	return RedactedMysqlURL(s)
}

// RedactedStringURLList is a string containing a comma-separated list of URLs
type RedactedStringURLList string

// LogValue implements slog.LogValuer to avoid revealing passwords in a list of URLs
func (s RedactedStringURLList) LogValue() slog.Value {
	strs := strings.Split(string(s), ",")

	redacted := make([]string, len(strs))
	for i, str := range strs {
		u, err := url.Parse(strings.TrimSpace(str))
		if err != nil {
			redacted[i] = str
		} else {
			redacted[i] = u.Redacted()
		}
	}
	return slog.StringValue(strings.Join(redacted, ","))
}

// RedactStringURLList returns a safely loggable list of URLs
func RedactStringURLList(s string) RedactedStringURLList {
	return RedactedStringURLList(s)
}
