//go:build !linux && !darwin

package capture

import (
	"errors"
	"runtime"
)

func routeTable() ([]routeEntry, error) {
	return nil, errors.New("capture: the scan reads no routing table on " + runtime.GOOS)
}

func neighborTable() ([]neighborEntry, error) {
	return nil, errors.New("capture: the scan reads no neighbor table on " + runtime.GOOS)
}
