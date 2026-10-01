package repocheck

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
// material, so no test commits a fetched file.
//
// One test resolves the name `corpus.invalid`. RFC 2606 reserves the `.invalid` top-level
// domain, so that name cannot exist and the lookup fails. No test reaches a real host.

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
// two pins. The script writes the corpus below that root, so a test never touches the real
// `testdata/foxio/`.
func newCorpusFetchRoot(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	for path, mode := range map[string]os.FileMode{
		"scripts/fetch-corpus.sh":    0o755,
		"testdata/foxio.pin":         0o644,
		"testdata/foxio-reading.pin": 0o644,
	} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}

		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(path)), 0o755); err != nil {
			t.Fatalf("create the directory for %s: %v", path, err)
		}

		if err := os.WriteFile(filepath.Join(root, path), content, mode); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	return root
}

// newCorpusArchive returns the path of a gzip archive that holds the corpus and the
// reference. The archive has one top directory, as the FoxIO archive does.
func newCorpusArchive(t *testing.T) string {
	t.Helper()

	return newCorpusArchiveWithout(t, "")
}

// newCorpusArchiveWithout returns the same archive without one path. It builds the case
// where FoxIO moved a file or a directory that a reading cites. A directory name omits
// every file below it, and the empty name omits nothing.
//
// The archive holds the vectors and every cited path, so one archive serves both downloads
// of a test that names no reading archive of its own.
func newCorpusArchiveWithout(t *testing.T, omitted string) string {
	t.Helper()

	files := map[string]string{
		"pcap/tls12.pcap":                          "capture",
		"pcap/dhcp.pcapng":                         "capture",
		"python/test/testdata/tls12.pcap.json":     "[]",
		"wireshark/test/testdata/dhcp.pcapng.json": "[]",
		"python/test/test_ja4_output.py":           "the per-stream harness",
		"python/ja4.py":                            "the per-stream reference",
		"wireshark/test/test_tshark_output.py":     "the per-packet harness",
		"wireshark/source/packet-ja4.c":            "the per-packet reference",
		"zeek/ja4t/main.zeek":                      "the Zeek reference",
		"rust/ja4/src/tls.rs":                      "the Rust reference",
		"technical_details/JA4.png":                "the JA4 image",
		"README.md":                                "the archive holds more than the corpus",
	}

	for name := range files {
		if omitted != "" && (name == omitted || strings.HasPrefix(name, omitted+"/")) {
			delete(files, name)
		}
	}

	return newArchiveOfFiles(t, files)
}

// newArchiveOfFiles returns the path of a gzip archive that holds the files. The archive
// has one top directory, as the FoxIO archive does.
func newArchiveOfFiles(t *testing.T, files map[string]string) string {
	t.Helper()

	stage := t.TempDir()
	top := filepath.Join(stage, "ja4-fixture")

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

// runFetchCorpus runs the script below the root and returns the combined output. The one
// archive serves the download at the vector pin and the download at the reading pin.
func runFetchCorpus(t *testing.T, root string, url string) (string, error) {
	t.Helper()

	return runFetchCorpusWithReading(t, root, url, url)
}

// runFetchCorpusWithReading runs the script with a separate archive for the reading pin.
//
// The environment of the test process can already hold `JA4PLUS_CORPUS_URL` or
// `JA4PLUS_READING_CORPUS_URL`. A C library reads the first entry that matches, so the
// function removes both entries before it appends the URLs of the test. An inherited entry
// would send the script to the network.
func runFetchCorpusWithReading(t *testing.T, root string, url string, readingURL string) (string, error) {
	t.Helper()

	environment := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "JA4PLUS_CORPUS_URL=") && !strings.HasPrefix(entry, "JA4PLUS_READING_CORPUS_URL=") {
			environment = append(environment, entry)
		}
	}

	command := exec.Command("bash", filepath.Join(root, "scripts", "fetch-corpus.sh"))
	command.Env = append(environment, "JA4PLUS_CORPUS_URL="+url, "JA4PLUS_READING_CORPUS_URL="+readingURL)
	output, err := command.CombinedOutput()

	return string(output), err
}

// fileURL returns the `file:` URL that curl reads for a local path.
func fileURL(path string) string {
	return "file://" + path
}

func TestFoxioPinNamesOneFullCommitHash(t *testing.T) {
	// The reading pin is the second pin of #797, and FR-conformance-1 binds it the same way.
	for _, path := range []string{"testdata/foxio.pin", "testdata/foxio-reading.pin"} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}

		pin := strings.TrimSpace(string(content))
		if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(pin) {
			t.Errorf("%s holds %q, and FR-conformance-1 names one full commit hash", path, pin)
		}
	}
}

// corpusCacheKeys returns every corpus cache key that the workflow names. The
// `conformance` job and the `coverage` job each restore the corpus, so the workflow names
// two keys, and a test that read the first key alone would leave the second unheld. It
// fails the test when the workflow names no such key.
func corpusCacheKeys(t *testing.T, workflow string) []string {
	t.Helper()

	matches := regexp.MustCompile(`(?m)^[ \t]*key:[ \t]*(foxio-corpus.*)$`).FindAllStringSubmatch(workflow, -1)
	if len(matches) == 0 {
		t.Fatalf(".github/workflows/ci.yml names no corpus cache key")
	}

	keys := make([]string, 0, len(matches))
	for _, match := range matches {
		keys = append(keys, strings.TrimSpace(match[1]))
	}

	return keys
}

// FR-conformance-37 — the cache key reads the hash of `scripts/fetch-corpus.sh`, because
// that script decides which directories a complete corpus holds. `actions/cache@v4` writes
// no entry when the key matches an entry that already exists, and GitHub states that the
// content of an entry never changes. #165 added `testdata/foxio/reference/` and moved no
// pin, so every run restored a corpus that the script rejects, downloaded the archive
// again, and wrote nothing back. The hash moves the key on the commit that changes the
// layout, and the key needs no version number that a reader must remember.
func TestTheCorpusCacheKeyReadsTheHashOfTheFetchScript(t *testing.T) {
	for _, key := range corpusCacheKeys(t, readRepoFile(t, ".github/workflows/ci.yml")) {
		if !strings.Contains(key, "hashFiles('scripts/fetch-corpus.sh')") {
			t.Errorf("the corpus cache key is %q, and it reads no hash of scripts/fetch-corpus.sh", key)
		}
	}
}

// FR-conformance-37 — the cache key reads the pinned commit, so a pin move misses the
// cache and the next run fetches the corpus of the new commit.
func TestTheCorpusCacheKeyReadsThePinnedCommit(t *testing.T) {
	for _, key := range corpusCacheKeys(t, readRepoFile(t, ".github/workflows/ci.yml")) {
		if !strings.Contains(key, "steps.pin.outputs.commit") {
			t.Errorf("the corpus cache key is %q, and it reads no pinned commit", key)
		}
	}
}

// #797 — the cache key reads the hash of the reading pin. The key reads the vector pin
// through `steps.pin.outputs.commit`, and a move of the reading pin alone would otherwise
// restore a reference tree of the previous commit. The script would then download the
// reading archive on every run, and the cache would write nothing back.
func TestTheCorpusCacheKeyReadsTheHashOfTheReadingPin(t *testing.T) {
	for _, key := range corpusCacheKeys(t, readRepoFile(t, ".github/workflows/ci.yml")) {
		if !strings.Contains(key, "hashFiles('testdata/foxio-reading.pin')") {
			t.Errorf("the corpus cache key is %q, and it reads no hash of testdata/foxio-reading.pin", key)
		}
	}
}

func TestFetchCorpusWritesTheCapturesAndTheVectors(t *testing.T) {
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

// FR-conformance-38 — `.claude/rules/rulings.md` requires a reading to cite a file and a
// line at the pinned commit. #165 found that no FoxIO source file reached the corpus, so
// the citation of #41 was unverifiable here. The reference tree holds the cited paths
// below `testdata/foxio/reference/`, under the names the FoxIO repository uses.
func TestFetchCorpusWritesTheReferenceTreeUnderTheFoxioPaths(t *testing.T) {
	requireCorpusFetchTools(t)

	root := newCorpusFetchRoot(t)
	output, err := runFetchCorpus(t, root, fileURL(newCorpusArchive(t)))
	if err != nil {
		t.Fatalf("the script failed: %v\n%s", err, output)
	}

	for _, path := range []string{
		"testdata/foxio/reference/technical_details/JA4.png",
		"testdata/foxio/reference/python/test/test_ja4_output.py",
		"testdata/foxio/reference/python/ja4.py",
		"testdata/foxio/reference/wireshark/test/test_tshark_output.py",
		"testdata/foxio/reference/wireshark/source/packet-ja4.c",
		"testdata/foxio/reference/zeek/ja4t/main.zeek",
		"testdata/foxio/reference/rust/ja4/src/tls.rs",
	} {
		if _, statErr := os.Stat(filepath.Join(root, path)); statErr != nil {
			t.Errorf("%s is absent: %v\n%s", path, statErr, output)
		}
	}
}

// #797 — the reference tree comes from the commit of `testdata/foxio-reading.pin`, and the
// captures and the vectors come from the commit of `testdata/foxio.pin`. The maintainer
// ruled on 2026-10-01 UTC that the vectors move and that every reading stays at its commit.
// #801 rereads each citation at the vector pin, and it removes the reading pin.
//
// The two archives hold different text at each shared path. The test therefore fails when
// the script writes a tree from the wrong archive.
func TestFetchCorpusWritesTheReferenceTreeFromTheReadingPin(t *testing.T) {
	requireCorpusFetchTools(t)

	vectors := map[string]string{
		"pcap/tls12.pcap":                          "the capture at the vector pin",
		"python/test/testdata/tls12.pcap.json":     "the vector at the vector pin",
		"wireshark/test/testdata/dhcp.pcapng.json": "[]",
		"python/ja4.py":                            "the reference at the vector pin",
	}
	reading := map[string]string{
		"pcap/tls12.pcap":                          "the capture at the reading pin",
		"python/test/testdata/tls12.pcap.json":     "the vector at the reading pin",
		"wireshark/test/testdata/dhcp.pcapng.json": "[]",
		"python/test/test_ja4_output.py":           "the per-stream harness",
		"python/ja4.py":                            "the reference at the reading pin",
		"wireshark/test/test_tshark_output.py":     "the per-packet harness",
		"wireshark/source/packet-ja4.c":            "the per-packet reference",
		"zeek/ja4t/main.zeek":                      "the Zeek scripts at the reading pin",
		"rust/ja4/src/tls.rs":                      "the Rust reference",
		"technical_details/JA4.png":                "the JA4 image",
	}

	root := newCorpusFetchRoot(t)
	output, err := runFetchCorpusWithReading(t, root, fileURL(newArchiveOfFiles(t, vectors)), fileURL(newArchiveOfFiles(t, reading)))
	if err != nil {
		t.Fatalf("the script failed: %v\n%s", err, output)
	}

	for path, want := range map[string]string{
		"testdata/foxio/reference/python/ja4.py":       reading["python/ja4.py"],
		"testdata/foxio/reference/zeek/ja4t/main.zeek": reading["zeek/ja4t/main.zeek"],
		"testdata/foxio/pcap/tls12.pcap":               vectors["pcap/tls12.pcap"],
		"testdata/foxio/python/tls12.pcap.json":        vectors["python/test/testdata/tls12.pcap.json"],
	} {
		if got := readTrimmedFile(t, filepath.Join(root, path)); got != want {
			t.Errorf("%s holds %q, and the archive of its pin holds %q\n%s", path, got, want, output)
		}
	}

	// The reference tree holds no capture of the reading archive, because the corpus holds
	// each capture once, at the vector pin.
	if _, statErr := os.Stat(filepath.Join(root, "testdata", "foxio", "reference", "pcap")); statErr == nil {
		t.Errorf("the reference tree holds pcap/, and the corpus holds the captures once\n%s", output)
	}

	pin := readTrimmedFile(t, filepath.Join(root, "testdata", "foxio-reading.pin"))
	fetched := readTrimmedFile(t, filepath.Join(root, "testdata", "foxio", ".fetched-reading"))
	if fetched != pin {
		t.Errorf("testdata/foxio/.fetched-reading holds %q, and testdata/foxio-reading.pin holds %q", fetched, pin)
	}
}

// FR-conformance-38 — the script stops when the reading archive holds no path that a
// reading cites. A reference tree that silently lost one such path would break a reading
// in `docs/specs/foxio/` and report success.
//
// Each case omits one path of the `cited` list of `scripts/fetch-corpus.sh`, so the test
// fails when a later edit drops a path from that list or narrows it. #797 once narrowed
// `zeek` to `zeek/ja4t/main.zeek`, and the readings cite every Zeek script.
func TestFetchCorpusFailsWhenACitedReferencePathIsAbsent(t *testing.T) {
	requireCorpusFetchTools(t)

	for _, omitted := range []string{
		"technical_details",
		"python/ja4.py",
		"python/test/test_ja4_output.py",
		"wireshark/source/packet-ja4.c",
		"wireshark/test/test_tshark_output.py",
		"zeek",
		"rust",
	} {
		t.Run(omitted, func(t *testing.T) {
			root := newCorpusFetchRoot(t)
			output, err := runFetchCorpusWithReading(t, root, fileURL(newCorpusArchive(t)), fileURL(newCorpusArchiveWithout(t, omitted)))
			if err == nil {
				t.Fatalf("the script reported success without %s:\n%s", omitted, output)
			}

			if !strings.Contains(output, "holds no "+omitted+". ") {
				t.Errorf("the failure message does not name %s:\n%s", omitted, output)
			}
		})
	}
}

// #797 — the vector archive supplies the captures and the vectors alone, so the script
// reads no cited path in it. A guard that read a cited path in the vector archive would
// stop a fetch at a vector pin where FoxIO moved a reference file, and no reading cites
// that commit.
func TestFetchCorpusReadsNoCitedPathInTheVectorArchive(t *testing.T) {
	requireCorpusFetchTools(t)

	vectors := map[string]string{
		"pcap/tls12.pcap":                          "capture",
		"python/test/testdata/tls12.pcap.json":     "[]",
		"wireshark/test/testdata/dhcp.pcapng.json": "[]",
	}

	root := newCorpusFetchRoot(t)
	output, err := runFetchCorpusWithReading(t, root, fileURL(newArchiveOfFiles(t, vectors)), fileURL(newCorpusArchive(t)))
	if err != nil {
		t.Fatalf("the script failed for a vector archive that holds no reference file: %v\n%s", err, output)
	}
}

// FR-conformance-39 — the corpus holds one copy of each capture and of each vector. A
// second copy below `reference/` would let a reader compare the corpus with itself.
func TestFetchCorpusWritesOneCopyOfEachCaptureAndVector(t *testing.T) {
	requireCorpusFetchTools(t)

	root := newCorpusFetchRoot(t)
	output, err := runFetchCorpus(t, root, fileURL(newCorpusArchive(t)))
	if err != nil {
		t.Fatalf("the script failed: %v\n%s", err, output)
	}

	// The absence check below passes for a corpus that holds no reference tree at all, so
	// this check states that the reference tree is present first.
	reference := filepath.Join(root, "testdata", "foxio", "reference")
	if _, statErr := os.Stat(reference); statErr != nil {
		t.Fatalf("the reference tree is absent: %v\n%s", statErr, output)
	}

	for _, path := range []string{
		"testdata/foxio/reference/pcap",
		"testdata/foxio/reference/python/test/testdata",
		"testdata/foxio/reference/wireshark/test/testdata",
	} {
		if _, statErr := os.Stat(filepath.Join(root, path)); statErr == nil {
			t.Errorf("%s is present, and the corpus holds that content once\n%s", path, output)
		}
	}
}

// FR-conformance-40 — a corpus that an earlier version of the script wrote holds the
// pinned commit and no reference tree. The script fetches again for that corpus, because
// the commit alone does not report a complete corpus.
func TestFetchCorpusFetchesAgainWhenTheReferenceTreeIsAbsent(t *testing.T) {
	requireCorpusFetchTools(t)

	root := newCorpusFetchRoot(t)
	archive := fileURL(newCorpusArchive(t))
	if output, err := runFetchCorpus(t, root, archive); err != nil {
		t.Fatalf("the first run failed: %v\n%s", err, output)
	}

	reference := filepath.Join(root, "testdata", "foxio", "reference")
	if err := os.RemoveAll(reference); err != nil {
		t.Fatalf("remove the reference tree: %v", err)
	}

	output, err := runFetchCorpus(t, root, archive)
	if err != nil {
		t.Fatalf("the second run failed: %v\n%s", err, output)
	}

	if _, statErr := os.Stat(filepath.Join(reference, "technical_details", "JA4.png")); statErr != nil {
		t.Errorf("the second run wrote no reference tree: %v\n%s", statErr, output)
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
//
// A runner that drops a name request instead of a refusal makes this test wait for the
// connect timeout of the script, which is 30 seconds. The test still reports the same
// result.
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

// A moved pin is the case that starts a second download. The fetched file must then name
// the new commit, so that a later run does not read a corpus of two commits.
func TestFetchCorpusUpdatesTheFetchedFileWhenThePinMoves(t *testing.T) {
	requireCorpusFetchTools(t)

	root := newCorpusFetchRoot(t)
	archive := fileURL(newCorpusArchive(t))
	if output, err := runFetchCorpus(t, root, archive); err != nil {
		t.Fatalf("the first run failed: %v\n%s", err, output)
	}

	movedPin := "0123456789abcdef0123456789abcdef01234567"
	pinPath := filepath.Join(root, "testdata", "foxio.pin")
	if err := os.WriteFile(pinPath, []byte(movedPin+"\n"), 0o644); err != nil {
		t.Fatalf("move the pin: %v", err)
	}

	output, err := runFetchCorpus(t, root, archive)
	if err != nil {
		t.Fatalf("the run after the moved pin failed: %v\n%s", err, output)
	}

	fetched := readTrimmedFile(t, filepath.Join(root, "testdata", "foxio", ".fetched"))
	if fetched != movedPin {
		t.Errorf("testdata/foxio/.fetched holds %q, and the moved pin holds %q", fetched, movedPin)
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
