// Cross-check of RFC 8785 canonicalization: reads raw JSON texts, writes the canonical form and the
// base64url SHA-256 that Go's encoding/json/jsontext (Value.Canonicalize) produces.
// Run: GOEXPERIMENT=jsonv2 go run . ../../tests/vectors/jcs_inputs.json > ../../tests/vectors/jcs_go_golden.json
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"os"
)

type out struct {
	Input     string `json:"input"`
	Canonical string `json:"canonical"`
	SHA256    string `json:"sha256"`
}

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var inputs []string
	if err := json.Unmarshal(raw, &inputs); err != nil {
		panic(err)
	}
	var res []out
	for _, in := range inputs {
		v := jsontext.Value(in)
		if err := v.Canonicalize(); err != nil {
			fmt.Fprintf(os.Stderr, "cannot canonicalize %q: %v\n", in, err)
			os.Exit(1)
		}
		h := sha256.Sum256(v)
		res = append(res, out{in, string(v), base64.RawURLEncoding.EncodeToString(h[:])})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(res); err != nil {
		panic(err)
	}
}
