//go:build windows

package main

// Windows: no standard-library way to read free disk or memory; setup asks instead.
func freeDiskGiB(string) int { return 0 }
func totalMemoryMiB() int    { return 0 }
