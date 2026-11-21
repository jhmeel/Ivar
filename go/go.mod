module github.com/ivar/ivar/go

go 1.24.7

require (
	github.com/ivar/ivar/sdk/go v0.0.0
	github.com/sigstore/sigstore v1.8.4
	github.com/theupdateframework/go-tuf/v2 v2.0.2
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/google/go-containerregistry v0.19.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/letsencrypt/boulder v0.0.0-20230907030200-6d76a0f91e1e // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.8.0 // indirect
	github.com/tetratelabs/wazero v1.9.0 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	golang.org/x/crypto v0.23.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	golang.org/x/term v0.20.0 // indirect
	gopkg.in/go-jose/go-jose.v2 v2.6.3 // indirect
)

replace github.com/ivar/ivar/sdk/go => ../sdk/go
