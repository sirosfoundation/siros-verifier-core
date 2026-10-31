// Interop harness: cross-checks siros_verifier_core against go-jose (ECDH-ES JWE) and
// SUNET/vc's sdjwtvc package (SD-JWT VC).
//
//	go run . gen            write ../../tests/vectors/*.json (Go -> Rust)
//	go run . verify         verify ../../target/interop/*.json (Rust -> Go)
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/SUNET/vc/pkg/sdjwtvc"
	jose "github.com/go-jose/go-jose/v4"
)

const vectors = "../../tests/vectors/"
const rustOut = "../../target/interop/"

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	must(err)
	must(os.WriteFile(path, append(b, '\n'), 0o644))
}

func readJSON(path string, v any) {
	b, err := os.ReadFile(path)
	must(err)
	must(json.Unmarshal(b, v))
}

func jwkOf(key any) map[string]any {
	b, err := (&jose.JSONWebKey{Key: key}).MarshalJSON()
	must(err)
	var m map[string]any
	must(json.Unmarshal(b, &m))
	return m
}

// ---- ES256 signer for vc ----

type signer struct{ key *ecdsa.PrivateKey }

func (s signer) Sign(_ context.Context, data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	r, sg, err := ecdsa.Sign(rand.Reader, s.key, h[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	sg.FillBytes(out[32:])
	return out, nil
}
func (signer) Algorithm() string { return "ES256" }
func (signer) KeyID() string     { return "go-issuer-1" }
func (s signer) PublicKey() any  { return &s.key.PublicKey }

// ---- Go -> Rust ----

type jweVector struct {
	Enc       string `json:"enc"`
	WithParty bool   `json:"with_party_info"`
	JWE       string `json:"jwe"`
}

func genJWE() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	plaintext := `{"vp_token":{"pid":["x"]},"state":"s-from-go"}`
	var vs []jweVector
	// No apu/apv here on purpose: go-jose v4.1.4's *encrypter* writes apu/apv given via
	// WithHeader into the header but does not feed them into the KDF, so it cannot decrypt
	// its own output. Party info is covered by the RFC 7518 Appendix C vector and by the
	// Rust -> Go direction (go-jose's decrypter does honour apu/apv).
	for _, enc := range []jose.ContentEncryption{jose.A128GCM, jose.A256GCM} {
		e, err := jose.NewEncrypter(enc, jose.Recipient{Algorithm: jose.ECDH_ES, Key: &priv.PublicKey},
			(&jose.EncrypterOptions{}).WithHeader("kid", "go-recipient"))
		must(err)
		obj, err := e.Encrypt([]byte(plaintext))
		must(err)
		s, err := obj.CompactSerialize()
		must(err)
		vs = append(vs, jweVector{Enc: string(enc), WithParty: false, JWE: s})
	}
	jk := jwkOf(priv)
	writeJSON(vectors+"go_jwe.json", map[string]any{
		"generator": "go-jose/v4 " + "ECDH-ES",
		"private_jwk": jk, "plaintext": plaintext, "vectors": vs,
	})
	fmt.Println("wrote go_jwe.json with", len(vs), "vectors")
}

const vctm = `{"vct":"urn:vp-spike:test:1","name":"Test credential","claims":[
 {"path":["given_name"],"sd":"always"},
 {"path":["family_name"],"sd":"always"},
 {"path":["address","street"],"sd":"always"},
 {"path":["address","locality"],"sd":"allowed"}
]}`

func genSDJWT() {
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	doc := `{"given_name":"Ada","family_name":"Lovelace","address":{"street":"St James's Square 1","locality":"London"}}`
	c := sdjwtvc.New()
	sd, err := c.BuildCredentialWithSigner(context.Background(), "https://go-issuer.example", signer{issuer},
		[]byte(vctm), []byte(doc), jwkOf(&holder.PublicKey), &sdjwtvc.CredentialOptions{DecoyDigests: 3})
	must(err)
	nonce, aud := "go-nonce-123", "https://verifier.example"
	kb, err := sdjwtvc.CreateKeyBindingJWT(sd, nonce, aud, holder, "sha-256")
	must(err)
	pres := sdjwtvc.CombineWithKeyBinding(sd, kb)
	writeJSON(vectors+"vc_sdjwt.json", map[string]any{
		"generator":         "SUNET/vc pkg/sdjwtvc",
		"issuer_public_jwk": jwkOf(&issuer.PublicKey),
		"presentation":      pres,
		"nonce":             nonce, "aud": aud,
		"generated_at": time.Now().Unix(),
		"expect": map[string]any{
			"iss": "https://go-issuer.example", "vct": "urn:vp-spike:test:1",
			"given_name": "Ada", "family_name": "Lovelace", "street": "St James's Square 1", "locality": "London",
		},
	})
	fmt.Println("wrote vc_sdjwt.json")
}

// ---- Rust -> Go ----

func verifyJWE() {
	var in struct {
		PrivateJWK json.RawMessage `json:"private_jwk"`
		Plaintext  string          `json:"plaintext"`
		Vectors    []jweVector     `json:"vectors"`
	}
	readJSON(rustOut+"rust_jwe.json", &in)
	var jwk jose.JSONWebKey
	must(jwk.UnmarshalJSON(in.PrivateJWK))
	for _, v := range in.Vectors {
		obj, err := jose.ParseEncrypted(v.JWE, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A128GCM, jose.A256GCM})
		must(err)
		got, err := obj.Decrypt(jwk.Key)
		must(err)
		if string(got) != in.Plaintext {
			must(fmt.Errorf("plaintext mismatch for %s party=%v", v.Enc, v.WithParty))
		}
		fmt.Printf("go-jose decrypted Rust JWE: enc=%s party=%v ok\n", v.Enc, v.WithParty)
	}
}

func verifySDJWT() {
	var in struct {
		IssuerPublicJWK json.RawMessage `json:"issuer_public_jwk"`
		Presentation    string          `json:"presentation"`
		Nonce           string          `json:"nonce"`
		Aud             string          `json:"aud"`
	}
	readJSON(rustOut+"rust_sdjwt.json", &in)
	var jwk jose.JSONWebKey
	must(jwk.UnmarshalJSON(in.IssuerPublicJWK))
	h, err := sdjwtvc.NewSDJWTHandler(sdjwtvc.WithSDJWTStaticKey(jwk.Key), sdjwtvc.WithSDJWTRequireKeyBinding(in.Nonce, in.Aud))
	must(err)
	res, err := h.VerifyAndExtract(context.Background(), in.Presentation)
	must(err)
	claims := res.GetClaims()
	fmt.Printf("vc verified Rust SD-JWT VC: given_name=%v family_name=%v\n", claims["given_name"], claims["family_name"])
	if claims["given_name"] != "Ada" {
		must(fmt.Errorf("unexpected claims: %v", claims))
	}
	// Non-vacuity: vc must reject the same presentation under a different nonce.
	h2, err := sdjwtvc.NewSDJWTHandler(sdjwtvc.WithSDJWTStaticKey(jwk.Key), sdjwtvc.WithSDJWTRequireKeyBinding("other-nonce", in.Aud))
	must(err)
	if _, err := h2.VerifyAndExtract(context.Background(), in.Presentation); err == nil {
		must(fmt.Errorf("vc accepted a presentation with the wrong nonce"))
	}
	fmt.Println("vc rejected the same presentation under a wrong nonce")
}

func main() {
	if len(os.Args) < 2 {
		must(fmt.Errorf("usage: gen | verify"))
	}
	switch os.Args[1] {
	case "gen":
		genJWE()
		genSDJWT()
	case "verify":
		verifyJWE()
		verifySDJWT()
	default:
		must(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}
