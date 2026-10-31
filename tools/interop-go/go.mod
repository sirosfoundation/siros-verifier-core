module vpspike/interop

go 1.26.5

require (
	github.com/SUNET/vc v0.6.5
	github.com/go-jose/go-jose/v4 v4.1.4
)

require (
	github.com/PaesslerAG/gval v1.2.4 // indirect
	github.com/PaesslerAG/jsonpath v0.1.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.15 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.3 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jellydator/ttlcache/v3 v3.4.1 // indirect
	github.com/leodido/go-urn v1.5.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.6 // indirect
	github.com/lestrrat-go/jwx/v3 v3.2.0 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/sirosfoundation/go-cryptoutil v0.6.0 // indirect
	github.com/sirosfoundation/go-spocp v0.1.0 // indirect
	github.com/sirosfoundation/go-trust v0.15.1 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)

// Read-only use of the local vc checkout as the reference implementation.
replace github.com/SUNET/vc => ../../../vc
