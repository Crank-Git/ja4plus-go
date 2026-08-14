package ja4db

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #73 holds every guard of this file, and `docs/specs/features/09-database-lookup.md` holds
// the requirements it names. FR-lookup-8 through FR-lookup-17 govern the transport of one
// remote lookup, and no guard of this file reaches the network.

// productionSource returns the text of each production Go file of this package, keyed by the
// base name.
//
// A source guard reports a property that no request exercises. FR-lookup-8 bars one
// identifier, and a run that never takes the fallback branch proves nothing about it.
func productionSource(t *testing.T) map[string]string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}

	source := map[string]string{}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		content, readErr := os.ReadFile(filepath.Clean(name))
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}

		source[name] = string(content)
	}

	if len(source) == 0 {
		t.Fatal("the reader found no production Go file of this package, so every guard below reads nothing")
	}

	return source
}

// TestNoProductionFileOfThisPackageNamesTheSharedDefaultClient holds FR-lookup-8.
//
// `http.DefaultClient` carries no timeout, so a request through it waits without a bound.
func TestNoProductionFileOfThisPackageNamesTheSharedDefaultClient(t *testing.T) {
	for name, content := range productionSource(t) {
		if strings.Contains(content, "http.DefaultClient") {
			t.Errorf("%s names http.DefaultClient, and FR-lookup-8 bars it.\n"+
				"\tThat client carries no timeout, so a slow server holds the caller without a bound.", name)
		}
	}
}

// TestTheDefaultClientIsNotTheSharedDefaultClient holds FR-lookup-8 at the value.
//
// The guard above reads the text of this package, and this one reads the client that a
// lookup uses when the caller supplies none.
func TestTheDefaultClientIsNotTheSharedDefaultClient(t *testing.T) {
	if defaultHTTPClient() == http.DefaultClient {
		t.Error("the default client of this package is http.DefaultClient, and FR-lookup-8 bars it")
	}
}

// TestTheDefaultClientCarriesATimeout holds FR-lookup-9.
func TestTheDefaultClientCarriesATimeout(t *testing.T) {
	if defaultHTTPClient().Timeout <= 0 {
		t.Error("the default client of this package carries no timeout, and FR-lookup-9 states that it does")
	}
}

// TestTheDefaultTimeoutIsTenSeconds holds FR-lookup-10.
func TestTheDefaultTimeoutIsTenSeconds(t *testing.T) {
	if got := defaultHTTPClient().Timeout; got != 10*time.Second {
		t.Errorf("the default timeout is %v, and FR-lookup-10 states 10s", got)
	}
}

// TestTheDefaultClientWeakensNoCertificateVerification holds FR-lookup-11.
//
// The transport of the standard library verifies the server certificate, so this package
// adds no code that verifies one. The requirement is met by the absence of a weakening, and
// this guard reads that absence.
func TestTheDefaultClientWeakensNoCertificateVerification(t *testing.T) {
	transport := defaultHTTPClient().Transport
	if transport == nil {
		// A nil transport is http.DefaultTransport, which sets no TLS configuration of its own.
		return
	}

	httpTransport, ok := transport.(*http.Transport)
	if !ok {
		t.Fatalf("the default client carries a %T transport, and this guard reads no TLS configuration from it", transport)
	}

	if httpTransport.TLSClientConfig != nil {
		t.Errorf("the default client carries a TLS configuration, and FR-lookup-11 states that a lookup verifies the server certificate.\n"+
			"\tInsecureSkipVerify = %v", httpTransport.TLSClientConfig.InsecureSkipVerify)
	}
}

// TestNoProductionFileOfThisPackageDisablesCertificateVerification holds FR-lookup-11 in the
// text of this package.
//
// A later edit can add a transport that sets the field, and the value guard above then reads
// a client this edit never built.
func TestNoProductionFileOfThisPackageDisablesCertificateVerification(t *testing.T) {
	for name, content := range productionSource(t) {
		for _, barred := range []string{"InsecureSkipVerify", "TLSClientConfig", "tls.Config"} {
			if strings.Contains(content, barred) {
				t.Errorf("%s names %s, and FR-lookup-11 states that a lookup verifies the server certificate.\n"+
					"\tThe transport of the standard library verifies it already, so this package weakens nothing.",
					name, barred)
			}
		}
	}
}

// TestARemoteLookupRefusesARedirectToTheHTTPScheme holds FR-lookup-12.
//
// The lookup carries the fingerprint in the request path, so a redirect to a plain scheme
// discloses it to an observer.
func TestARemoteLookupRefusesARedirectToTheHTTPScheme(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"application":"reached the plain target"}`))
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer redirector.Close()

	cfg := &RemoteLookupConfig{Endpoint: redirector.URL + "/api/read/"}

	got, err := LookupFingerprintRemote(context.Background(), cfg, "known_fp")
	if err == nil {
		t.Fatalf("a redirect to the http scheme returned %+v and no error, and FR-lookup-12 states an error", got)
	}

	if !strings.Contains(err.Error(), "http") {
		t.Errorf("the error is %q, and it names no scheme", err)
	}
}

// TestARemoteLookupAppliesTheRedirectPolicyToTheClientOfTheCaller holds FR-lookup-12 for the
// caller that supplies a client.
//
// The requirement names every remote lookup, and a caller supplies a client for a proxy or
// for a certificate pool rather than for a redirect policy.
func TestARemoteLookupAppliesTheRedirectPolicyToTheClientOfTheCaller(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"application":"reached the plain target"}`))
	}))
	defer target.Close()

	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer redirector.Close()

	// The client of the test server trusts the certificate of that server, and it sets no
	// redirect policy of its own.
	callerClient := redirector.Client()

	cfg := &RemoteLookupConfig{Endpoint: redirector.URL + "/api/read/", HTTPClient: callerClient}

	if _, err := LookupFingerprintRemote(context.Background(), cfg, "known_fp"); err == nil {
		t.Fatal("a redirect to the http scheme returned no error, and FR-lookup-12 states an error")
	}

	// The lookup copies the client of the caller, so the value the caller holds keeps its own
	// policy.
	if callerClient.CheckRedirect != nil {
		t.Error("the lookup wrote a redirect policy into the client of the caller, and it copies that client instead")
	}
}

// TestARemoteLookupKeepsTheRedirectPolicyOfTheCaller holds the other half of the rule above.
//
// A caller that states a policy states it for a reason, and this package replaces no policy
// the caller wrote.
func TestARemoteLookupKeepsTheRedirectPolicyOfTheCaller(t *testing.T) {
	called := false

	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		called = true

		return errors.New("the policy of the caller refuses this redirect")
	}}

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid/api/read/known_fp", http.StatusFound)
	}))
	defer redirector.Close()

	cfg := &RemoteLookupConfig{Endpoint: redirector.URL + "/api/read/", HTTPClient: client}

	if _, err := LookupFingerprintRemote(context.Background(), cfg, "known_fp"); err == nil {
		t.Fatal("the policy of the caller refused the redirect, and the lookup returned no error")
	}

	if !called {
		t.Error("the lookup replaced the redirect policy of the caller, and it keeps that policy")
	}
}

// TestARemoteLookupBoundsTheResponseBodyToOneMegabyte holds FR-lookup-13 and FR-lookup-14.
//
// A server that answers with two megabytes returns an error that names the bound.
func TestARemoteLookupBoundsTheResponseBodyToOneMegabyte(t *testing.T) {
	if maxResponseBytes != 1<<20 {
		t.Errorf("the bound is %d bytes, and FR-lookup-13 states 1 MB", maxResponseBytes)
	}

	oversize := make([]byte, 2<<20)
	for i := range oversize {
		oversize[i] = 'a'
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(oversize)
	}))
	defer srv.Close()

	cfg := &RemoteLookupConfig{Endpoint: srv.URL + "/api/read/"}

	got, err := LookupFingerprintRemote(context.Background(), cfg, "known_fp")
	if err == nil {
		t.Fatalf("a two megabyte body returned %+v and no error, and FR-lookup-14 states an error", got)
	}

	if !strings.Contains(err.Error(), "1048576") {
		t.Errorf("the error is %q, and it names no bound", err)
	}
}

// countingReader delivers a long stream, and it counts the bytes it delivers.
//
// It stops at ceiling rather than running without an end. A reader without an end hangs the
// whole test binary when the bound of readBounded regresses, and a hang reports no test name.
// The ceiling stands far beyond the bound, so a bounded read never reaches it.
type countingReader struct {
	read    int
	chunk   int
	ceiling int
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.read >= c.ceiling {
		return 0, errors.New("the reader reached the ceiling of this test, so the read of the package is unbounded")
	}

	n := len(p)
	if c.chunk > 0 && n > c.chunk {
		n = c.chunk
	}

	for i := range n {
		p[i] = 'a'
	}

	c.read += n

	return n, nil
}

// TestABoundedReadStopsAtOneByteBeyondTheBound holds FR-lookup-14 at the read.
//
// A bound that truncates without an error returns a document the caller reads as complete.
// The reader stops one byte beyond the bound, because that byte is the evidence of the
// overrun.
func TestABoundedReadStopsAtOneByteBeyondTheBound(t *testing.T) {
	// The reader delivers far more than the bound, so an unbounded read takes the whole stream.
	source := &countingReader{chunk: 4096, ceiling: 8 * maxResponseBytes}

	body, err := readBounded(source)
	if err == nil {
		t.Fatalf("an endless body returned %d bytes and no error, and FR-lookup-14 states an error", len(body))
	}

	if source.read > maxResponseBytes+1 {
		t.Errorf("the read took %d bytes, and FR-lookup-14 states that it reads no more than %d",
			source.read, maxResponseBytes+1)
	}
}

// TestABoundedReadReturnsABodyAtTheBound holds the other half of FR-lookup-13.
//
// A guard that reads one byte too few rejects a document the requirement admits.
func TestABoundedReadReturnsABodyAtTheBound(t *testing.T) {
	body, err := readBounded(strings.NewReader(strings.Repeat("a", maxResponseBytes)))
	if err != nil {
		t.Fatalf("a body of exactly %d bytes returned %v, and FR-lookup-13 admits it", maxResponseBytes, err)
	}

	if len(body) != maxResponseBytes {
		t.Errorf("the read returned %d bytes, and the body holds %d", len(body), maxResponseBytes)
	}
}

// TestARemoteLookupEscapesTheFingerprintInTheRequestPath holds FR-lookup-15.
//
// A fingerprint reaches this function from a packet, so it is untrusted input. A slash in it
// otherwise moves the request to another path of the service.
func TestARemoteLookupEscapesTheFingerprintInTheRequestPath(t *testing.T) {
	var escaped string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped = r.URL.EscapedPath()

		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := &RemoteLookupConfig{Endpoint: srv.URL + "/api/read/"}

	if _, err := LookupFingerprintRemote(context.Background(), cfg, "a/../b?q=1"); err != nil {
		t.Fatalf("the lookup returned %v, and the server answered 404", err)
	}

	if want := "/api/read/a%2F..%2Fb%3Fq=1"; escaped != want {
		t.Errorf("the request path is %q, and FR-lookup-15 states %q", escaped, want)
	}
}

// TestARemoteLookupSendsAUserAgentThatNamesTheLibraryAndItsVersion holds FR-lookup-16.
func TestARemoteLookupSendsAUserAgentThatNamesTheLibraryAndItsVersion(t *testing.T) {
	var sent string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = r.Header.Get("User-Agent")

		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := &RemoteLookupConfig{Endpoint: srv.URL + "/api/read/"}

	if _, err := LookupFingerprintRemote(context.Background(), cfg, "known_fp"); err != nil {
		t.Fatalf("the lookup returned %v, and the server answered 404", err)
	}

	if !strings.HasPrefix(sent, libraryName+"/") {
		t.Errorf("the User-Agent is %q, and FR-lookup-16 states that it names %q", sent, libraryName)
	}

	version := strings.TrimPrefix(strings.Fields(sent)[0], libraryName+"/")
	if version == "" {
		t.Errorf("the User-Agent is %q, and FR-lookup-16 states that it names a version", sent)
	}

	// A version that carries a space or a parenthesis breaks the header at the reader of the
	// service. `runtime/debug` reports `(devel)` for a build of this module itself.
	if strings.ContainsAny(version, " ()") {
		t.Errorf("the version segment is %q, and a header token holds no space and no parenthesis", version)
	}
}

// TestARemoteLookupHonorsACanceledContext holds FR-lookup-17.
func TestARemoteLookupHonorsACanceledContext(t *testing.T) {
	reached := make(chan struct{}, 1)
	release := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached <- struct{}{}
		<-release
	}))

	defer func() {
		close(release)
		srv.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &RemoteLookupConfig{Endpoint: srv.URL + "/api/read/"}

	done := make(chan error, 1)

	go func() {
		_, err := LookupFingerprintRemote(ctx, cfg, "known_fp")
		done <- err
	}()

	<-reached
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("the lookup returned %v, and FR-lookup-17 states that it honors the context", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the lookup ran for 5 seconds after the cancel, and FR-lookup-17 states that it honors the context")
	}
}

// TestALookupAgainstAServerThatNeverRespondsReturnsAnErrorWithinElevenSeconds holds the
// acceptance criterion of #73 that names 11 seconds.
//
// The test takes the whole default timeout, because the criterion states a wall-clock bound.
func TestALookupAgainstAServerThatNeverRespondsReturnsAnErrorWithinElevenSeconds(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
	}))

	defer func() {
		close(release)
		srv.Close()
	}()

	cfg := &RemoteLookupConfig{Endpoint: srv.URL + "/api/read/"}

	start := time.Now()

	_, err := LookupFingerprintRemote(context.Background(), cfg, "known_fp")

	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a server that never responds returned no error, and the criterion states an error")
	}

	if elapsed > 11*time.Second {
		t.Errorf("the lookup took %v, and the criterion states 11 seconds", elapsed)
	}

	if !strings.Contains(err.Error(), "Timeout") && !strings.Contains(err.Error(), "timeout") {
		t.Errorf("the error is %q, and the criterion states that it names the timeout", err)
	}
}

// TestThePackageDocumentationStatesTheTransportRules holds the acceptance criterion of #73
// that states `go doc` for the package.
//
// **This guard reads the documentation, and it holds no behavior.** A reader who deletes a
// rule from the code and leaves the page alone passes this guard. Each guard above holds the
// behavior, and this one holds the page that states it.
func TestThePackageDocumentationStatesTheTransportRules(t *testing.T) {
	content, err := os.ReadFile(filepath.Clean("doc.go"))
	if err != nil {
		t.Fatalf("read doc.go: %v", err)
	}

	for _, stated := range []string{
		"LookupFingerprintRemote",
		"10 seconds",
		"1 MB",
		"https",
		"User-Agent",
	} {
		if !strings.Contains(string(content), stated) {
			t.Errorf("doc.go states no %q, and the reader of go doc reads the transport rules there", stated)
		}
	}
}
