# CORS Warden

CORS Warden reviews Access-Control headers and flags risky combinations.

## Quick start

```bash
go run main.go --input cors.txt
```

## Input format

Each line: `origin|allow_origin|allow_credentials`.

## Output

Findings highlight wildcard origins with credentials or reflective origins.
