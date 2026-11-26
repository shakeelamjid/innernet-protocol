//go:build windows

package main

import "errors"

func execSelf(string, []string, []string) error { return errors.New("not used on Windows") }
