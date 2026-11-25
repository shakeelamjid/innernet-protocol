package main

import (
	"crypto/sha256"
	"encoding/binary"
)

// STO-1 proof of storage, byte-for-byte the same as innernet2/irm_storage.py.
const stoBlock = 1024

var stoTag = []byte("STO-1")

func stoLeaf(b []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(stoTag)
	h.Write(b)
	return h.Sum(nil)
}

func stoNode(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(stoTag)
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

func stoCommit(mth []byte, n int) []byte {
	h := sha256.New()
	h.Write([]byte{2})
	h.Write(stoTag)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], uint32(n))
	h.Write(c[:])
	h.Write(mth)
	return h.Sum(nil)
}

func stoBlocks(chunk []byte) [][]byte {
	var out [][]byte
	for i := 0; i < len(chunk); i += stoBlock {
		out = append(out, chunk[i:min(i+stoBlock, len(chunk))])
	}
	return out
}

func stoSplit(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func stoMTH(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := stoSplit(len(leaves))
	return stoNode(stoMTH(leaves[:k]), stoMTH(leaves[k:]))
}

func stoPath(leaves [][]byte, i int) [][]byte {
	if len(leaves) == 1 {
		return nil
	}
	k := stoSplit(len(leaves))
	if i < k {
		return append(stoPath(leaves[:k], i), stoMTH(leaves[k:]))
	}
	return append(stoPath(leaves[k:], i-k), stoMTH(leaves[:k]))
}

func stoLeaves(chunk []byte) [][]byte {
	blocks := stoBlocks(chunk)
	leaves := make([][]byte, len(blocks))
	for i, b := range blocks {
		leaves[i] = stoLeaf(b)
	}
	return leaves
}

// stoRoot returns the committed root and block count of a chunk.
func stoRoot(chunk []byte) ([]byte, int) {
	leaves := stoLeaves(chunk)
	return stoCommit(stoMTH(leaves), len(leaves)), len(leaves)
}

// stoProve returns block i and its audit path.
func stoProve(chunk []byte, i int) ([]byte, [][]byte, bool) {
	blocks := stoBlocks(chunk)
	if i < 0 || i >= len(blocks) {
		return nil, nil, false
	}
	return blocks[i], stoPath(stoLeaves(chunk), i), true
}
