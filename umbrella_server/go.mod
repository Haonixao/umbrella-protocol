module umbrella_server

go 1.26.0

replace github.com/anacrolix/utp => github.com/Haonixao/utp v0.0.0-20260512111648-6d2d2fc87c8c

replace github.com/apernet/hysteria/core/v2 => github.com/Haonixao/hysteria/core/v2 v2.0.0-20260806122212-1514bdd0b820

replace github.com/apernet/hysteria/extras/v2 => github.com/Haonixao/hysteria/extras/v2 v2.0.0-20260806122212-1514bdd0b820

require (
	github.com/anacrolix/utp v0.0.0-00010101000000-000000000000
	github.com/apernet/hysteria/core/v2 v2.0.0-00010101000000-000000000000
	github.com/apernet/hysteria/extras/v2 v2.0.0-00010101000000-000000000000
	github.com/apernet/quic-go v0.61.1-0.20260801011216-0ad2f221c8d7
	github.com/hashicorp/yamux v0.1.2
	github.com/xtls/reality v0.0.0-20260322125925-9234c772ba8f
	golang.org/x/net v0.56.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/anacrolix/missinggo v1.3.0 // indirect
	github.com/anacrolix/missinggo/perf v1.0.0 // indirect
	github.com/anacrolix/missinggo/v2 v2.5.1 // indirect
	github.com/anacrolix/sync v0.4.0 // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/huandu/xstrings v1.3.1 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/pires/go-proxyproto v0.11.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)
