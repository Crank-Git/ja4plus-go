package ja4plus

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Issue #148 closes a gap that a later change opens. The package held one list of the
// fingerprinter set for each reader, and derived none of them from another. A new
// fingerprinter therefore reached the processor and left every count at its old value.
//
// The list that Processor.fingerprinters returns is the source of truth of the set. Every
// other list in the package derives from the two functions below, so a new fingerprinter
// moves each of them together.

// fingerprinterInterface is the reflected Fingerprinter interface.
// A field of Processor whose type implements it holds one fingerprinter.
var fingerprinterInterface = reflect.TypeOf((*Fingerprinter)(nil)).Elem()

// fingerprinterTypeName returns the type name of the fingerprinter, such as
// `JA4Fingerprinter`. Every list of the set names a fingerprinter this way.
func fingerprinterTypeName(fingerprinter Fingerprinter) string {
	typ := reflect.TypeOf(fingerprinter)
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	return typ.Name()
}

// processorFingerprinters returns each fingerprinter the processor runs, by type name.
// A test that reads a fingerprinter value calls this function, because the map covers the
// set that ProcessPacket runs.
func processorFingerprinters(proc *Processor) map[string]Fingerprinter {
	set := map[string]Fingerprinter{}
	for _, fingerprinter := range proc.fingerprinters() {
		set[fingerprinterTypeName(fingerprinter)] = fingerprinter
	}

	return set
}

// processorFingerprinterNames returns the type name of every fingerprinter the processor
// runs, sorted.
func processorFingerprinterNames() []string {
	var names []string
	for name := range processorFingerprinters(NewProcessor()) {
		names = append(names, name)
	}
	slices.Sort(names)

	return names
}

// processorFieldNames returns the type name of every fingerprinter field of Processor,
// sorted. A field the run list omits reads no packet, so the two lists must agree.
func processorFieldNames() []string {
	typ := reflect.TypeOf(Processor{})

	var names []string
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if !field.Type.Implements(fingerprinterInterface) {
			continue
		}

		fieldType := field.Type
		for fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}

		names = append(names, fieldType.Name())
	}
	slices.Sort(names)

	return names
}

// fingerprinterShortName returns the lower-case name of the fingerprinter, such as `ja4h`.
// A benchmark case and a `FingerprintResult.Type` value read this form.
func fingerprinterShortName(typeName string) string {
	return strings.ToLower(strings.TrimSuffix(typeName, "Fingerprinter"))
}

// assertCoversEveryFingerprinterShortName fails when the lower-case names are not exactly
// the set the processor runs.
func assertCoversEveryFingerprinterShortName(t *testing.T, source string, names []string) {
	t.Helper()

	var want []string
	for _, name := range processorFingerprinterNames() {
		want = append(want, fingerprinterShortName(name))
	}
	slices.Sort(want)

	got := slices.Clone(names)
	slices.Sort(got)

	if !slices.Equal(got, want) {
		t.Errorf("%s names %v, and the processor runs %v", source, got, want)
	}
}

// assertCoversEveryFingerprinter fails when the names are not exactly the set the
// processor runs. The source names the list under test, so a failure message points at
// the list that a new fingerprinter left behind.
func assertCoversEveryFingerprinter(t *testing.T, source string, names []string) {
	t.Helper()

	got := slices.Clone(names)
	slices.Sort(got)

	if want := processorFingerprinterNames(); !slices.Equal(got, want) {
		t.Errorf("%s names %v, and the processor runs %v", source, got, want)
	}
}

// The run list is the source of truth of the set, so a field outside it reads no packet.
// Issue #148 states the gap: a new field that reaches no list fails no test.
func TestProcessorRunsEveryFingerprinterFieldItHolds(t *testing.T) {
	assertCoversEveryFingerprinter(t, "the Processor fields", processorFieldNames())
}

// A nil fingerprinter in the run list panics on the first packet.
func TestNewProcessorFillsEveryFingerprinterField(t *testing.T) {
	for name, fingerprinter := range processorFingerprinters(NewProcessor()) {
		if reflect.ValueOf(fingerprinter).IsNil() {
			t.Errorf("NewProcessor leaves the %s field nil", name)
		}
	}
}

// A caller who writes `var p Processor` reaches ensure, and a field that ensure omits
// panics on the first packet.
func TestEnsureFillsEveryFingerprinterFieldOfAZeroValueProcessor(t *testing.T) {
	var proc Processor
	proc.ensure()

	for name, fingerprinter := range processorFingerprinters(&proc) {
		if reflect.ValueOf(fingerprinter).IsNil() {
			t.Errorf("ensure leaves the %s field nil", name)
		}
	}
}
