module umbrella_server

go 1.27.0

replace github.com/anacrolix/utp => github.com/Haonixao/utp v0.0.0-20260903070339-0c968f3e07fc

replace github.com/apernet/hysteria/core/v2 => github.com/Haonixao/hysteria/core/v2 v2.0.0-20261008175724-84f293ca6140

replace github.com/apernet/hysteria/extras/v2 => github.com/Haonixao/hysteria/extras/v2 v2.0.0-20261008175724-84f293ca6140

require (
	github.com/anacrolix/utp v0.0.0-00010101000000-000000000000
	github.com/apernet/hysteria/core/v2 v2.0.0-00010101000000-000000000000
	github.com/apernet/hysteria/extras/v2 v2.0.0-00010101000000-000000000000
	github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c
	github.com/emersion/go-imap v1.2.1
	github.com/google/uuid v1.6.0
	github.com/hashicorp/yamux v0.1.2
	github.com/xtls/reality v0.0.0-20260921001439-3c98159dee38
	golang.org/x/net v0.59.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/anacrolix/missinggo v1.3.0 // indirect
	github.com/anacrolix/missinggo/perf v1.0.0 // indirect
	github.com/anacrolix/missinggo/v2 v2.5.1 // indirect
	github.com/anacrolix/sync v0.4.0 // indirect
	github.com/andybalholm/brotli v1.2.3 // indirect
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/emersion/go-sasl v0.0.0-20200509203442-7bfe0ed36a21 // indirect
	github.com/huandu/xstrings v1.3.1 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/pires/go-proxyproto v0.15.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
