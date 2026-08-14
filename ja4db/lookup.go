package ja4db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	ja4plus "github.com/Crank-Git/ja4plus-go"
)

// defaultTimeout bounds one remote lookup. FR-lookup-10 states the value.
//
// The ja4db.com service publishes no versioned API, so a caller reads no service bound of
// its own. A request without a timeout holds the caller for as long as the server keeps the
// connection open.
const defaultTimeout = 10 * time.Second

// maxResponseBytes bounds the response body. FR-lookup-13 states the value.
//
// One record of the service holds a few hundred bytes, so a body of one megabyte covers
// every answer. A server that answers with more exhausts the memory of the caller.
const maxResponseBytes = 1 << 20

// maxRedirects bounds the redirect chain of one lookup.
//
// The client of the standard library applies this bound when it holds no redirect policy.
// This package states a policy, so it states the bound too.
const maxRedirects = 10

// libraryName names this library in the User-Agent header. FR-lookup-16 states the header.
const libraryName = "ja4plus-go"

// modulePath names the module of this library. The build information keys the version on it.
const modulePath = "github.com/Crank-Git/ja4plus-go"

// unknownVersion names the version that a build without module information reports.
//
// A test binary of this module reports `(devel)`, and a header token holds no parenthesis.
const unknownVersion = "devel"

// RemoteLookupConfig configures opt-in remote lookups against ja4db.com.
//
// A nil HTTPClient makes the lookup build a client with a 10 second timeout.
type RemoteLookupConfig struct {
	// Endpoint is the base URL of the lookup service. If empty, defaults to
	// "https://ja4db.com/api/read/" (the GET-by-fingerprint endpoint).
	Endpoint string
	// HTTPClient is the client to use. If nil, the lookup builds one with a timeout.
	// The lookup copies the supplied client, and it writes a redirect policy into the copy
	// when the caller states none.
	HTTPClient *http.Client
}

// defaultHTTPClient returns the client that a lookup uses when the caller supplies none.
//
// It sets no transport, so the transport of the standard library serves the request and it
// verifies the server certificate. FR-lookup-11 is met by that default, and this package
// weakens nothing.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       defaultTimeout,
		CheckRedirect: refuseInsecureRedirect,
	}
}

// effectiveClient returns the client that serves one lookup.
//
// It copies the client of the caller, so the lookup changes no value that the caller holds.
// It writes the redirect policy into the copy when the caller states none, because
// FR-lookup-12 binds every remote lookup. A caller that states a policy keeps it.
func effectiveClient(supplied *http.Client) *http.Client {
	if supplied == nil {
		return defaultHTTPClient()
	}

	client := *supplied
	if client.CheckRedirect == nil {
		client.CheckRedirect = refuseInsecureRedirect
	}

	return &client
}

// refuseInsecureRedirect returns an error for a redirect to a scheme other than https.
//
// The request path carries the fingerprint, so a redirect to a plain scheme discloses it to
// an observer of the network. FR-lookup-12 bars that redirect.
func refuseInsecureRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("ja4plus: remote lookup refuses a redirect to the %q scheme", req.URL.Scheme)
	}

	if len(via) >= maxRedirects {
		return fmt.Errorf("ja4plus: remote lookup stopped after %d redirects", maxRedirects)
	}

	return nil
}

// libraryVersion returns the module version of this library.
//
// A build without module information carries no version, and a build of this module itself
// reports `(devel)`. The function returns "devel" for each of those two cases.
func libraryVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return unknownVersion
	}

	if version := moduleVersion(info.Main); version != "" {
		return version
	}

	for _, dep := range info.Deps {
		if version := moduleVersion(*dep); version != "" {
			return version
		}
	}

	return unknownVersion
}

// moduleVersion returns the version of the module when that module is this library.
//
// It returns an empty string for another module, and for a version that carries no `v`
// prefix. `(devel)` is the second case.
func moduleVersion(module debug.Module) string {
	if module.Path != modulePath || !strings.HasPrefix(module.Version, "v") {
		return ""
	}

	return module.Version
}

// userAgent returns the User-Agent header of one lookup. FR-lookup-16 states the header.
//
// The operator of the service reads the header to attribute a request, so it names the
// library, the version and the repository.
func userAgent() string {
	return libraryName + "/" + libraryVersion() + " (+https://" + modulePath + ")"
}

// readBounded returns the bytes of the reader, and it returns an error beyond the bound.
//
// It reads one byte more than the bound, because that byte separates a body at the bound
// from a body beyond it. FR-lookup-14 states the error, so a bound that truncates without
// one is a defect: the caller then reads a partial document as a complete one.
func readBounded(body io.Reader) ([]byte, error) {
	read, err := io.ReadAll(io.LimitReader(body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}

	if len(read) > maxResponseBytes {
		return nil, fmt.Errorf("ja4plus: remote lookup response exceeds the %d byte bound", maxResponseBytes)
	}

	return read, nil
}

// LookupFingerprintRemote performs an opt-in HTTP lookup against ja4db.com
// (or another configured endpoint) for the given fingerprint. Callers must
// supply a context and a config; this function does NOT change the default
// behavior of ja4plus.LookupFingerprint, which remains offline-only.
//
// Returns nil and a non-nil error on transport / non-200 / decoding failures.
// Returns nil and nil when the fingerprint is not found.
func LookupFingerprintRemote(ctx context.Context, cfg *RemoteLookupConfig, fingerprint string) (*ja4plus.LookupResult, error) {
	if fingerprint == "" {
		return nil, errors.New("ja4plus: empty fingerprint")
	}
	if cfg == nil {
		cfg = &RemoteLookupConfig{}
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://ja4db.com/api/read/"
	}
	client := effectiveClient(cfg.HTTPClient)

	// A fingerprint reaches this function from a packet, so it is untrusted input. A slash in
	// it otherwise moves the request to another path of the service.
	requestURL := strings.TrimRight(endpoint, "/") + "/" + url.PathEscape(fingerprint)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ja4plus: remote lookup status %d", resp.StatusCode)
	}

	body, err := readBounded(resp.Body)
	if err != nil {
		return nil, err
	}

	// The ja4db.com API returns JSON with at least one of these fields populated.
	// Be permissive: collapse Application/Library/Device/OS into one identifier.
	var raw struct {
		Application string `json:"application"`
		Library     string `json:"library"`
		Device      string `json:"device"`
		OS          string `json:"os"`
		Notes       string `json:"notes"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("ja4plus: decode remote lookup: %w", err)
	}
	var parts []string
	for _, p := range []string{raw.Application, raw.Library, raw.Device, raw.OS} {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return nil, nil
	}
	return &ja4plus.LookupResult{
		Application: strings.Join(parts, " / "),
		Notes:       strings.TrimSpace(raw.Notes),
	}, nil
}
