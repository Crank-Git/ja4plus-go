package ja4plus

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The corpus fetch is a build gate, and no Go code reads it at run time. These tests hold
// the gate, so that a later edit cannot drop it without a failure.
//
// Every test here runs the script against a local archive. The corpus is FoxIO-licensed
// material, so no test commits a fetched file, and no test reaches the network.

// requireCorpusFetchTools skips the test when a program the script needs is absent.
func requireCorpusFetchTools(t *testing.T) {
	t.Helper()

	for _, program := range []string{"bash", "curl", "tar"} {
		if _, err := exec.LookPath(program); err != nil {
			t.Skipf("%s is absent: %v", program, err)
		}
	}
}

// newCorpusFetchRoot returns a temporary repository root that holds the script and the
// pin. The script writes the corpus below that root, so a test never touches the real
// `testdata/foxio/`.
func newCorpusFetchRoot(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	for source, target := range map[string]string{
		"scripts/fetch-corpus.sh": "scripts/fetch-corpus.sh",
		"testdata/foxio.pin":      "testdata/foxio.pin",
	} {
		content, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read %s: %v", source, err)
		}

		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(target)), 0o755); err != nil {
			t.Fatalf("create the directory for %s: %v", target, err)
		}

		if err := os.WriteFile(filepath.Join(root, target), content, 0o755); err != nil {
			t.Fatalf("write %s: %v", target, err)
		}
	}

	return root
}

// newCorpusArchive returns the path of a gzip archive that holds the three corpus
// directories. The archive has one top directory, as the FoxIO archive does.
func newCorpusArchive(t *testing.T) string {
	t.Helper()

	stage := t.TempDir()
	top := filepath.Join(stage, "ja4-fixture")
	files := map[string]string{
		"pcap/tls12.pcap":                          "capture",
		"pcap/dhcp.pcapng":                         "capture",
		"python/test/testdata/tls12.pcap.json":     "[]",
		"wireshark/test/testdata/dhcp.pcapng.json": "[]",
		"README.md":                                "the archive holds more than the corpus",
	}

	for name, content := range files {
		path := filepath.Join(top, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create the directory for %s: %v", name, err)
		}

		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	archive := filepath.Join(stage, "corpus.tar.gz")
	command := exec.Command("tar", "-czf", archive, "-C", stage, "ja4-fixture")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build the archive: %v\n%s", err, output)
	}

	return archive
}

// runFetchCorpus runs the script below the root and returns the combined output.
func runFetchCorpus(t *testing.T, root string, url string) (string, error) {
	t.Helper()

	command := exec.Command("bash", filepath.Join(root, "scripts", "fetch-corpus.sh"))
	command.Env = append(os.Environ(), "JA4PLUS_CORPUS_URL="+url)
	output, err := command.CombinedOutput()

	return string(output), err
}

// fileURL returns the `file:` URL that curl reads for a local path.
func fileURL(path string) string {
	return "file://" + path
}

func TestFoxioPinNamesOneFullCommitHash(t *testing.T) {
	content, err := os.ReadFile("testdata/foxio.pin")
	if err != nil {
		t.Fatalf("read testdata/foxio.pin: %v", err)
	}

	pin := strings.TrimSpace(string(content))
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(pin) {
		t.Errorf("testdata/foxio.pin holds %q, and FR-conformance-1 names one full commit hash", pin)
	}
}

func TestFetchCorpusWritesTheThreeCorpusDirectories(t *testing.T) {
	requireCorpusFetchTools(t)

	root := newCorpusFetchRoot(t)
	output, err := runFetchCorpus(t, root, fileURL(newCorpusArchive(t)))
	if err != nil {
		t.Fatalf("the script failed: %v\n%s", err, output)
	}

	for _, path := range []string{
		"testdata/foxio/pcap/tls12.pcap",
		"testdata/foxio/pcap/dhcp.pcapng",
		"testdata/foxio/python/tls12.pcap.json",
		"testdata/foxio/wireshark/dhcp.pcapng.json",
	} {
		if _, statErr := os.Stat(filepath.Join(root, path)); statErr != nil {
			t.Errorf("%s is absent: %v\n%s", path, statErr, output)
		}
	}
}

func TestFetchCorpusRecordsThePinnedCommitInTheFetchedFile(t *testing.T) {
	requireCorpusFetchTools(t)

	root := newCorpusFetchRoot(t)
	output, err := runFetchCorpus(t, root, fileURL(newCorpusArchive(t)))
	if err != nil {
		t.Fatalf("the script failed: %v\n%s", err, output)
	}

	pin := readTrimmedFile(t, filepath.Join(root, "testdata", "foxio.pin"))
	fetched := readTrimmedFile(t, filepath.Join(root, "testdata", "foxio", ".fetched"))
	if fetched != pin {
		t.Errorf("testdata/foxio/.fetched holds %q, and testdata/foxio.pin holds %q", fetched, pin)
	}
}

// The second run must read `.fetched` and stop. The test removes the archive first, so a
// download of any kind fails the run.
func TestFetchCorpusDownloadsNothingWhenTheFetchedCommitMatchesThePin(t *testing.T) {
	requireCorpusFetchTools(t)

	root := newCorpusFetchRoot(t)
	archive := newCorpusArchive(t)
	if output, err := runFetchCorpus(t, root, fileURL(archive)); err != nil {
		t.Fatalf("the first run failed: %v\n%s", err, output)
	}

	if err := os.Remove(archive); err != nil {
		t.Fatalf("remove the archive: %v", err)
	}

	output, err := runFetchCorpus(t, root, fileURL(archive))
	if err != nil {
		t.Fatalf("the second run failed: %v\n%s", err, output)
	}

	if !strings.Contains(output, "downloads nothing") {
		t.Errorf("the second run does not report that it downloads nothing:\n%s", output)
	}
}

// FR-conformance-9 names the network in the failure message. The host `corpus.invalid`
// never resolves, because RFC 2606 reserves the `.invalid` name. The test moves the pin
// after the first run, because a moved pin is the case that starts a second download.
func TestFetchCorpusNamesTheNetworkWhenItCannotReachTheReference(t *testing.T) {
	requireCorpusFetchTools(t)

	root := newCorpusFetchRoot(t)
	if output, err := runFetchCorpus(t, root, fileURL(newCorpusArchive(t))); err != nil {
		t.Fatalf("the first run failed: %v\n%s", err, output)
	}

	movedPin := "0123456789abcdef0123456789abcdef01234567\n"
	if err := os.WriteFile(filepath.Join(root, "testdata", "foxio.pin"), []byte(movedPin), 0o644); err != nil {
		t.Fatalf("move the pin: %v", err)
	}

	output, err := runFetchCorpus(t, root, "https://corpus.invalid/corpus.tar.gz")
	if err == nil {
		t.Fatalf("the script reported success without the reference:\n%s", output)
	}

	if !strings.Contains(output, "network") {
		t.Errorf("the failure message does not name the network:\n%s", output)
	}

	// The failed run must leave the corpus of the first run in place.
	if _, statErr := os.Stat(filepath.Join(root, "testdata", "foxio", "pcap", "tls12.pcap")); statErr != nil {
		t.Errorf("the failed run removed the corpus: %v", statErr)
	}
}

// readTrimmedFile returns the content of the file without the surrounding space.
func readTrimmedFile(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return strings.TrimSpace(string(content))
}
