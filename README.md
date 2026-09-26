# cors-warden

Reviews CORS responses captured from your API and flags configurations that let an untrusted website read data it shouldn't — reflected origins, the `null` origin, lookalike domains slipping past a sloppy allowlist, and more.

CORS bugs are easy to introduce and hard to spot by reading headers one at a time. The classic mistake is a server that copies whatever `Origin` it receives into `Access-Control-Allow-Origin` and also sends `Access-Control-Allow-Credentials: true`. From that point on, any website a logged-in user visits can call your API as that user and read the response. cors-warden looks at the request/response pairs as a whole, compares them to the origins you actually trust, and explains what each finding means.

## What it detects

| Rule | Severity | Description |
|------|----------|-------------|
| `CORS001` | High → Critical | The server **reflects** an untrusted `Origin`. Critical when credentials are allowed. |
| `CORS002` | Medium → Critical | The server allows a specific untrusted origin (not reflected, but still wrong). |
| `CORS003` | High → Critical | The `null` origin is allowed — any page can produce it with a sandboxed iframe. |
| `CORS004` | Medium | `*` combined with credentials. Browsers reject it, but it signals intent, and the common "fix" is reflection. |
| `CORS005` | Info | `*` without credentials. Fine for public assets, worth knowing about elsewhere. |
| `CORS006` | Medium / High | An `http://` origin is trusted, so anyone on the network path can inject script into it. |
| `CORS008` | Low | `Access-Control-Allow-Origin` isn't a valid origin. |
| `CORS000` | Low | Origin echoed with credentials but no trust list was given, so it can't be classified. |

When an untrusted origin contains one of your trusted domains — `example.com.attacker.net`, `evilexample.com` — the finding says so. That pattern almost always means the server checks origins with `startsWith`, `endsWith` or a regex missing anchors.

## Installation

Requires Go 1.21 or newer.

```bash
go install github.com/httpEduardo/cors-warden/cmd/cors-warden@latest
```

Or from a clone:

```bash
git clone https://github.com/httpEduardo/cors-warden.git
cd cors-warden
make build   # ./bin/cors-warden
```

## Usage

```bash
cors-warden -input examples/responses.txt -trusted example.com
```

```text
Reviewed 9 CORS responses

  [CORS001] CRITICAL reflects untrusted origin https://evil.test with credentials, so that site can read authenticated responses
                     Origin: https://evil.test -> Allow-Origin: https://evil.test (line 5, https://api.example.com/orders)

  [CORS003] CRITICAL allows the "null" origin, which any page can obtain from a sandboxed iframe or data: URL
                     Origin: null -> Allow-Origin: null (line 8, https://api.example.com/export)

  [CORS001] HIGH     reflects untrusted origin https://example.com.attacker.net (it contains "example.com", which suggests a substring or suffix match in the allowlist check)
                     Origin: https://example.com.attacker.net -> Allow-Origin: https://example.com.attacker.net (line 7, https://api.example.com/catalog)
  ...

Summary: 4 critical, 2 high, 1 medium, 1 info
```

### Trusted origins

`-trusted` accepts two kinds of entries, repeated or comma-separated:

- **A bare domain** such as `example.com` trusts that domain and all its subdomains, **over HTTPS only**.
- **A full origin** such as `https://partner.io` or `http://localhost:3000` trusts exactly that origin.

```bash
cors-warden -input responses.txt -trusted example.com,https://partner.io
```

Without `-trusted`, the tool still reports structural problems (`null`, wildcard with credentials, invalid values), but it can't tell a legitimate echo from a reflection bug.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-input` | `responses.txt` | Observations file, or `-` for stdin |
| `-trusted` | | Trusted domain or origin (repeatable, comma-separated) |
| `-format` | `text` | `text` or `json` |
| `-fail-on` | `high` | Lowest severity that makes the command exit with `1` |
| `-version` | | Print the version |

Exit codes: `0` nothing at or above `-fail-on`, `1` findings at or above it, `2` bad arguments or unreadable input.

## Input format

One observation per line:

```
origin|allow_origin|allow_credentials[|endpoint]
```

| Field | Meaning |
|-------|---------|
| `origin` | The serialized `Origin` header sent, such as `https://app.example.com`, or `null` |
| `allow_origin` | The `Access-Control-Allow-Origin` value received (empty if absent) |
| `allow_credentials` | `true` or `false` (required) |
| `endpoint` | Optional URL, shown in the report |

Origins must contain only a scheme, host, and optional port; paths, credentials, query strings, and fragments are invalid.

Lines starting with `#` are comments. Malformed lines are reported on stderr with their line number and skipped.

### Collecting observations

A quick way to probe an endpoint with a few origins using `curl`:

```bash
url=https://api.example.com/me
for origin in https://app.example.com https://evil.test null https://example.com.evil.test; do
  headers=$(curl -s -o /dev/null -D - -H "Origin: $origin" "$url")
  acao=$(printf '%s' "$headers" | tr -d '\r' | awk -F': ' 'tolower($1)=="access-control-allow-origin"{print $2}')
  acac=$(printf '%s' "$headers" | tr -d '\r' | awk -F': ' 'tolower($1)=="access-control-allow-credentials"{print $2}')
  echo "$origin|$acao|${acac:-false}|$url"
done | cors-warden -input - -trusted example.com
```

Only probe systems you own or are authorized to test.

## Development

```bash
make test
make lint
```

`internal/cors/parse.go` handles input parsing and origin matching; `internal/cors/analyze.go` holds the rules. Each rule is covered by a table-driven test.

## References

- [PortSwigger — CORS vulnerabilities](https://portswigger.net/web-security/cors)
- [MDN — Cross-Origin Resource Sharing](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

## License

[MIT](LICENSE)
