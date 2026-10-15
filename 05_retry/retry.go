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

	cfg.method = strings.ToUpper(cfg.method)

	return cfg, nil
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
func sendRequest(client *http.Client, cfg config) (response, error) {
	req, err := http.NewRequest(cfg.method, cfg.url, nil)
	if err != nil {
		return response{}, err
	}

	if cfg.idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", cfg.idempotencyKey)
	}

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
		retryAfter: resp.Header.Get("Retry-After"),
	}, nil
}

func shouldRetry(cfg config, resp response, err error) bool {
	if cfg.method == http.MethodPost && cfg.idempotencyKey == "" {
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

func pauseMs(nextAttempt int, retryAfter string) int {
	retryAfterInt, err := strconv.Atoi(retryAfter)
	if err != nil || retryAfterInt < 0 {
		return rand.Intn(calculateIntervalBound(nextAttempt) + 1)
	}
	return retryAfterInt * 1000
}

func runRetry(client *http.Client, cfg config) bool {
	attempt := 1
	shouldRetryFlag := true
	success := false

	for !success && shouldRetryFlag && attempt <= cfg.maxAttempts {
		resp, err := sendRequest(client, cfg)
		if err != nil {
			fmt.Printf("attempt %d error %s\n", attempt, err)
		} else {
			fmt.Printf("attempt %d status %d\n", attempt, resp.status)
		}

		success = err == nil && resp.status >= 200 && resp.status <= 399
		shouldRetryFlag = attempt < cfg.maxAttempts && shouldRetry(cfg, resp, err)
		if shouldRetryFlag {
			attempt++
			ms := pauseMs(attempt, resp.retryAfter)
			fmt.Printf("sleep_ms %d\n", ms)
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}
	}

	if success {
		fmt.Printf("result success attempts %d\n", attempt)
	} else {
		fmt.Printf("result failure attempts %d\n", attempt)
	}

	return success
}

func main() {
	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		slog.Error("incorrect args in command line", slog.Any("error", err))
		os.Exit(1)
	}

	if !runRetry(newClient(), cfg) {
		os.Exit(1)
	}
}
