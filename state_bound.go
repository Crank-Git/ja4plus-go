package ja4plus

import (
	"container/list"
	"time"
)

// boundedKeys holds the recency order of one state table, and it names the key that the entry
// bound and the age bound remove.
//
// A fingerprinter of this package keys two or three maps with one key. This type holds the
// order and the last packet time of that key once.
// A fingerprinter that stored the time in its own entry would need a wrapper struct for a map
// whose value is a slice. `quic_tunnel_cleanup_test.go` writes such a value directly.
//
// One boundedKeys serves one fingerprinter, and one fingerprinter serves one goroutine. No
// lock guards it, and `.claude/rules/concurrency.md` states that contract.
//
// The zero value is usable, and `ensure` fills the two maps and the order list.
// Every fingerprinter of this package reads its first packet from a zero value without a
// panic.
type boundedKeys struct {
	// order names every key, least recent first. The entry bound removes the front.
	order *list.List
	// elements reaches the order entry of one key, so that a touch and a removal cost no scan.
	elements map[string]*list.Element
	// lastSeen holds the capture timestamp of the last packet of one key.
	lastSeen map[string]time.Time
	// packets counts the packets this table admitted. The age pass runs on the interval.
	packets int
}

// ensure fills the two maps and the order list.
// A write to a nil map panics, and a method of a nil list panics.
func (b *boundedKeys) ensure() {
	if b.order == nil {
		b.order = list.New()
	}

	if b.elements == nil {
		b.elements = make(map[string]*list.Element)
	}

	if b.lastSeen == nil {
		b.lastSeen = make(map[string]time.Time)
	}
}

// count returns the number of keys the table holds.
func (b *boundedKeys) count() int {
	return len(b.elements)
}

// touch records one packet of the key, and it moves the key to the most recent position.
func (b *boundedKeys) touch(key string, now time.Time) {
	b.ensure()

	if element, held := b.elements[key]; held {
		b.order.MoveToBack(element)
	} else {
		b.elements[key] = b.order.PushBack(key)
	}

	b.lastSeen[key] = now
}

// remove drops one key from the recency order.
// The caller removes the map entries of that key, because this type holds no map of its own.
func (b *boundedKeys) remove(key string) {
	b.ensure()

	if element, held := b.elements[key]; held {
		b.order.Remove(element)
		delete(b.elements, key)
	}

	delete(b.lastSeen, key)
}

// reset drops every key.
func (b *boundedKeys) reset() {
	b.order = list.New()
	b.elements = make(map[string]*list.Element)
	b.lastSeen = make(map[string]time.Time)
	b.packets = 0
}

// admit records one packet of the key, and it holds the entry bound and the age bound.
//
// It calls drop for each key that a bound removes. The fingerprinter passes its own removal
// path, so one call reaches every map that the key names. A bound that removed one map and
// left its partner would move the leak rather than close it, and issue #565 names that trap.
//
// The clock reads the capture timestamp, and never the wall clock. A capture replays faster
// than the wall clock, so a wall clock removes state that the capture still needs.
//
// The age pass reads every key, so it runs on the interval the caller names. The pass precedes
// the key of this packet, so it can remove the connection that this packet continues. The
// packet then opens that connection again.
func (b *boundedKeys) admit(
	key string, now time.Time, entries int, age time.Duration, interval int, drop func(string),
) {
	b.ensure()

	b.packets++
	if interval > 0 && b.packets%interval == 0 {
		for _, aged := range b.agedKeys(now, age) {
			drop(aged)
			b.remove(aged)
		}
	}

	if _, held := b.elements[key]; !held {
		b.evictToTheEntryBound(entries, drop)
	}

	b.touch(key, now)
}

// agedKeys returns each key whose last packet is older than the maximum age.
//
// The pass reads every key. A capture states a timestamp of its own, so two packets can arrive
// out of order. The recency order then does not follow the age.
//
// The packet carries that timestamp, so a crafted capture controls it, and one timestamp
// decides the age of every key. A packet dated far in the future ages the whole table at once,
// and this pass then removes every entry. `ja4ssh.go` and `ja4ts.go` hold the same rule, and
// the port holds it at `ja4plus/utils/state_table.py` of tag `v1.1.0`. **Issue #577 carries
// that question**, and this file repeats the established rule rather than inventing one.
//
// The entry bound holds the memory whatever the timestamp states, because it reads the recency
// order and no timestamp. So the loss is the tracked state, and never the memory.
func (b *boundedKeys) agedKeys(now time.Time, age time.Duration) []string {
	var aged []string

	for key, seen := range b.lastSeen {
		if now.Sub(seen) > age {
			aged = append(aged, key)
		}
	}

	return aged
}

// evictToTheEntryBound removes the least recent key until the table holds space for one more.
// The caller runs it before it adds a key, so the table never passes its bound.
//
// It removes the key from the recency order after the drop. A removal path that missed the
// order would otherwise leave this loop with no end.
func (b *boundedKeys) evictToTheEntryBound(entries int, drop func(string)) {
	for len(b.elements) >= entries {
		front := b.order.Front()
		if front == nil {
			return
		}

		oldest, held := front.Value.(string)
		if !held {
			b.order.Remove(front)

			continue
		}

		drop(oldest)
		b.remove(oldest)
	}
}
