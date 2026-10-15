package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	attemptTimeout = 5 * time.Second

	baseIntervalMs = 200
	intervalFactor = 2
	maxIntervalMs  = 2000

	idempotencyKeyHeader = "Idempotency-Key"
	retryAfterHeader     = "Retry-After"

	// maxRetryAfter is the longest pause the client agrees to wait for.
	// If server asks for more in Retry-After, retries stop instead of coming back earlier.
	maxRetryAfter = 30 * time.Minute
)

type config struct {
	url            string
	method         string
	maxAttempts    int
	idempotencyKey string
}

func parseArgs(args []string) (config, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return config{}, errors.New("first arg must be resource url")
	}

	cfg := config{url: args[0]}

	fs := flag.NewFlagSet("retry", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.method, "method", http.MethodGet, "request method")
	fs.IntVar(&cfg.maxAttempts, "max-attempts", 5, "max number of attempts including the first one")
	fs.StringVar(&cfg.idempotencyKey, "idempotency-key", "", "value of Idempotency-Key header")

	if err := fs.Parse(args[1:]); err != nil {
		return config{}, err
	}

	if fs.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected arg %q", fs.Arg(0))
	}

	if cfg.maxAttempts < 1 {
		return config{}, fmt.Errorf("max-attempts must be at least 1, got %d", cfg.maxAttempts)
	}

	u, err := url.Parse(cfg.url)
	if err != nil {
		return config{}, fmt.Errorf("parse url: %w", err)
	}

	if u.Scheme != "http" || u.Host == "" {
		return config{}, fmt.Errorf("url must look like http://host:port/path, got %q", cfg.url)
	}

	return cfg, nil
}

func requestFromConfig(cfg config) (*http.Request, error) {
	req, err := http.NewRequest(cfg.method, cfg.url, nil)
	if err != nil {
		return nil, err
	}

	if cfg.idempotencyKey != "" {
		req.Header.Set(idempotencyKeyHeader, cfg.idempotencyKey)
	}

	return req, nil
}

func newClient() *http.Client {
	return &http.Client{
		Timeout:   attemptTimeout,
		Transport: &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type response struct {
	status     int
	retryAfter string
}

// sendRequest makes one attempt. Error means there is no response from server:
// connection refused, connection reset or timeout.
func sendRequest(client *http.Client, req *http.Request) (response, error) {
	resp, err := client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return response{}, err
	}

	return response{
		status:     resp.StatusCode,
		retryAfter: resp.Header.Get(retryAfterHeader),
	}, nil
}

func isIdempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPut,
		http.MethodDelete, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

func shouldRetry(req *http.Request, resp response, err error) bool {
	if !isIdempotent(req.Method) && req.Header.Get(idempotencyKeyHeader) == "" {
		return false
	}

	if err != nil {
		return true
	}

	switch resp.status {
	case 429, 500, 502, 503, 504:
		return true
	default:
		return false
	}
}

func calculateIntervalBound(n int) int {
	res := baseIntervalMs
	for range n - 1 {
		res *= intervalFactor
		if res > maxIntervalMs {
			return maxIntervalMs
		}
	}
	return res
}

// ok is false when Retry-After asks to wait longer than maxRetryAfter
func pause(nextAttempt int, retryAfter string) (time.Duration, bool) {
	sec, err := strconv.ParseInt(retryAfter, 10, 64)
	if (err != nil && !errors.Is(err, strconv.ErrRange)) || sec < 0 {
		return time.Duration(rand.Intn(calculateIntervalBound(nextAttempt)+1)) * time.Millisecond, true
	}
	if sec > int64(maxRetryAfter/time.Second) {
		return 0, false
	}
	return time.Duration(sec) * time.Second, true
}

func printResult(success bool, attempts int) {
	if success {
		fmt.Printf("result success attempts %d\n", attempts)
	} else {
		fmt.Printf("result failure attempts %d\n", attempts)
	}
}

func runRetry(client *http.Client, req *http.Request, maxAttempts int) bool {
	for attempt := 1; ; attempt++ {
		resp, err := sendRequest(client, req)
		if err != nil {
			fmt.Printf("attempt %d error %s\n", attempt, err)
		} else {
			fmt.Printf("attempt %d status %d\n", attempt, resp.status)
		}

		success := err == nil && resp.status >= 200 && resp.status <= 399
		if success || attempt == maxAttempts || !shouldRetry(req, resp, err) {
			printResult(success, attempt)
			return success
		}

		d, ok := pause(attempt+1, resp.retryAfter)
		if !ok {
			slog.Warn("server asked to wait longer than client limit, giving up",
				slog.String("retry_after", resp.retryAfter),
				slog.Duration("limit", maxRetryAfter),
			)
			printResult(false, attempt)
			return false
		}

		fmt.Printf("sleep_ms %d\n", d.Milliseconds())
		time.Sleep(d)
	}
}

func main() {
	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		slog.Error("incorrect args in command line", slog.Any("error", err))
		os.Exit(1)
	}

	req, err := requestFromConfig(cfg)
	if err != nil {
		slog.Error("failed to build request from args", slog.Any("error", err))
		os.Exit(1)
	}

	if !runRetry(newClient(), req, cfg.maxAttempts) {
		os.Exit(1)
	}
}
