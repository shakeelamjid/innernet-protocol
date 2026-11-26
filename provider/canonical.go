package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
)

// canonicalJSON reproduces Python json.dumps(sort_keys=True, separators=(",",":"),
// ensure_ascii=True). This is what every INNERNET signature covers.
func canonicalJSON(v any) ([]byte, error) {
	// Round-trip through encoding/json with UseNumber so Go structs and maps
	// both end up as the same generic tree.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(tree, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(v any, buf *bytes.Buffer) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		if _, err := strconv.ParseInt(string(x), 10, 64); err != nil {
			return errors.New("non-integer number in signed payload")
		}
		buf.WriteString(string(x))
	case string:
		writeJSONString(x, buf)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(e, buf); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJSONString(k, buf)
			buf.WriteByte(':')
			if err := writeCanonical(x[k], buf); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON type %T", v)
	}
	return nil
}

func writeJSONString(s string, buf *bytes.Buffer) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			if r < 0x20 || r > 0x7e {
				if r > 0xffff {
					a, b := utf16.EncodeRune(r)
					fmt.Fprintf(buf, `\u%04x\u%04x`, a, b)
				} else {
					fmt.Fprintf(buf, `\u%04x`, r)
				}
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
