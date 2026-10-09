//go:build !windows

package app

import "errors"

func protect([]byte) ([]byte, error) {
	return nil, errors.New("server list encryption requires Windows")
}
func unprotect([]byte) ([]byte, error) {
	return nil, errors.New("server list encryption requires Windows")
}
