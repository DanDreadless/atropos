# Third-party notices

Atropos is built from the Go modules below, which are compiled into the binary, and from data published by the Unicode Consortium. Each module's full licence text is in its source repository and in the Go module cache (`go env GOMODCACHE`) after `go mod download`. A binary release should ship those licence texts alongside this file.

This list is the output of `go list -deps` for the main package. Refresh it when dependencies change:

```sh
go list -deps -f '{{with .Module}}{{.Path}} {{.Version}}{{end}}' . | sort -u
```

## Parsers

| Module | Version | Licence |
|---|---|---|
| www.velocidex.com/golang/evtx | v0.2.0 | Apache-2.0 |
| www.velocidex.com/golang/regparser | v0.0.0-20250203141505-31e704a67ef7 | Apache-2.0 |
| www.velocidex.com/golang/go-ntfs | v0.2.1 | Apache-2.0 |
| www.velocidex.com/golang/go-prefetch | v0.0.0-20260922101442-4bae97962980 | Apache-2.0 |
| www.velocidex.com/golang/go-ese | v0.2.1-0.20260812030448-458e8abf4a57 | Apache-2.0 |
| www.velocidex.com/golang/go-pe | v0.1.1-0.20211006062218-8f6d1ad6b2d5 | Apache-2.0 |
| www.velocidex.com/golang/binparsergen | v0.1.1-0.20201101234514-bbdb29f9ee31 | Apache-2.0 |
| github.com/Velocidex/ordereddict | v0.0.0-20230909174157-2aa49cc5d11d | Apache-2.0 |
| github.com/Velocidex/yaml/v2 | v2.2.8 | Apache-2.0 |
| github.com/Velocidex/json | v0.0.0-20220224052537-92f3c0326e5a | BSD-3-Clause (derived from the Go standard library) |
| github.com/Velocidex/pkcs7 | v0.0.0-20210524015001-8d1eee94a157 | MIT |

## Database

| Module | Version | Licence |
|---|---|---|
| modernc.org/sqlite | v1.62.0 | BSD-3-Clause; includes SQLite, which is in the public domain |
| modernc.org/libc | v1.80.1 | BSD-3-Clause |
| modernc.org/mathutil | v1.7.1 | BSD-3-Clause |
| modernc.org/memory | v1.12.1 | BSD-3-Clause |

## Supporting libraries

| Module | Version | Licence |
|---|---|---|
| golang.org/x/sys | v0.49.0 | BSD-3-Clause |
| golang.org/x/text | v0.3.7 | BSD-3-Clause |
| github.com/hashicorp/golang-lru | v0.5.4 | MPL-2.0 |
| github.com/pkg/errors | v0.8.1 | BSD-2-Clause |
| github.com/remyoudompheng/bigfft | v0.0.0-20230129092748-24d4a6f8daec | BSD-3-Clause |
| github.com/davecgh/go-spew | v1.1.2-0.20180830191138-d8f796af33cc | ISC |
| github.com/dustin/go-humanize | v1.1.0 | MIT |
| github.com/mattn/go-isatty | v0.0.24 | MIT |
| github.com/ncruces/go-strftime | v1.1.0 | MIT |

`github.com/hashicorp/golang-lru` is under the Mozilla Public License 2.0. It is used unmodified; its source is available at https://github.com/hashicorp/golang-lru.

The Go standard library and the embedded IANA time zone database (`time/tzdata`) are covered by the Go licence (BSD-3-Clause); the time zone database itself is in the public domain.

## Unicode CLDR data

`internal/timeutil/winzones_gen.go` maps Windows time zone names to IANA zones. It is derived from `windowsZones.xml` in the Unicode Common Locale Data Repository (territory `001` rows).

Copyright © 1991-present Unicode, Inc. All rights reserved. Distributed under the Unicode License v3 (https://www.unicode.org/license.txt):

> Permission is hereby granted, free of charge, to any person obtaining a copy of data files and any associated documentation (the "Data Files") or software and any associated documentation (the "Software") to deal in the Data Files or Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, and/or sell copies of the Data Files or Software, and to permit persons to whom the Data Files or Software are furnished to do so, provided that either (a) this copyright and permission notice appear with all copies of the Data Files or Software, or (b) this copyright and permission notice appear in associated Documentation.
>
> THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA FILES OR SOFTWARE.
>
> Except as contained in this notice, the name of a copyright holder shall not be used in advertising or otherwise to promote the sale, use or other dealings in these Data Files or Software without prior written authorization of the copyright holder.

## Jump list application identifiers

`internal/parsers/jumplist_appids.txt` names the application behind each jump list's identifier. It is `AppIDs.txt` from Eric Zimmerman's JumpList library (github.com/EricZimmerman/JumpList), embedded unchanged.

> The MIT License (MIT)
>
> Copyright (c) Eric R. Zimmerman
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Development only

`scripts/uicheck` uses `puppeteer-core` (Apache-2.0) to drive a browser. It is not part of the binary. Sample artefacts fetched by `scripts/fetch-testdata.sh` are not redistributed with Atropos.
