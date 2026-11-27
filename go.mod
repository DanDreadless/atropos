module github.com/DanDreadless/atropos

go 1.26.0

require (
	github.com/Velocidex/ordereddict v0.0.0-20230909174157-2aa49cc5d11d
	golang.org/x/sys v0.49.0
	modernc.org/sqlite v1.62.0
	www.velocidex.com/golang/evtx v0.2.0
	www.velocidex.com/golang/go-ese v0.2.1-0.20260812030448-458e8abf4a57
	www.velocidex.com/golang/go-ntfs v0.2.1
	www.velocidex.com/golang/go-prefetch v0.0.0-20260922101442-4bae97962980
	www.velocidex.com/golang/regparser v0.0.0-20250203141505-31e704a67ef7
)

require (
	github.com/Velocidex/json v0.0.0-20220224052537-92f3c0326e5a // indirect
	github.com/Velocidex/pkcs7 v0.0.0-20210524015001-8d1eee94a157 // indirect
	github.com/Velocidex/yaml/v2 v2.2.8 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	golang.org/x/text v0.3.7 // indirect
	modernc.org/libc v1.80.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
	www.velocidex.com/golang/binparsergen v0.1.1-0.20201101234514-bbdb29f9ee31 // indirect
	www.velocidex.com/golang/go-pe v0.1.1-0.20211006062218-8f6d1ad6b2d5 // indirect
)

replace www.velocidex.com/golang/evtx => ./third_party/evtx
