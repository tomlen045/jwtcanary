# jwtcanary

**JWT verification weakness probe, in one file.** Nine probes, one command: `alg:none` passthrough, RS256 public-key-as-HMAC confusion, claim time boundaries, refresh-token replay. If your gateway accepts tokens it should not, jwtcanary catches it in the act. Zero dependencies, read-only by design.

## Why

JWT security lives or dies on one line of code: signature verification. And misconfigured verification is a recurring CVE theme — `alg:none` passthrough, RS256 public keys used as HMAC secrets, expired tokens accepted, refresh tokens replayable.

`jwtcanary` turns "kick the door" into a cron-able action:

```bash
python3 jwtcanary.py --target https://api.example.com/me \
                     --rs256-jwks-url https://sso.example.com/.well-known/jwks.json
echo $?    # 0=holding 1=confirmed weakness 2=suspicious
```

## Verdict matrix

**V1** (confirmed): server explicitly accepted a token it must reject (2xx + readable protected resource). **V2** (suspicious): weak-signal acceptance, needs human review. **I**: 40x rejection — defense holding. **SKIP**: no key / unreachable — never escalated to a finding.

Four probe families: none (2 variants) / confusion (random-key HMAC, RS256→HS256 with hand-built SPKI DER from jwks n/e — no cryptography needed, header-alg mismatch) / claims (expired 30d, nbf future, 10-year token, garbage) / refresh (fake RT, same-RT replay).

## Evidence chain

Every report carries a **launch ledger** (jti/alg/exp per test token), an **HTTP audit** (every request logged), and a **sha256 report signature** (post-hoc tampering detectable).

## Invariants

I1 no real credentials ever leave your machine except to the target you name; I2 test tokens exp ≤ 600s, jti prefix `jwtcanary-`; I3 V1 requires explicit server acceptance; I4 unreachable targets are never escalated; I5 read-only (GET/POST probes only); I6 signed reports; I7 key material never rendered into reports.

## Usage

```bash
python3 jwtcanary.py --target https://api.example.com/me
python3 jwtcanary.py --target ... --jwks-file ./sso_pub.pem
python3 jwtcanary.py --target ... --refresh https://sso.example.com/oauth/token \
                     --refresh-body 'grant_type=refresh_token&client_id=web&refresh_token={rt}'
curl -fsSL https://gcore.jsdelivr.net/gh/tomlen045/jwtcanary@main/install.sh | sh
```

## Self-test

```bash
python3 selftest.py    # 29 checks: unit invariants + openssl byte-exact SPKI anchoring + 6 mock-server e2e scenarios
```

Real-host verified against Keycloak 26.3: all 10 probes rejected, verdict CLEAN.

## Exit codes

0 = clean/unreachable · 1 = V1 confirmed · 2 = V2 suspicious.

## Scope

Use only against systems you own or are authorized to test in writing.

## License

MIT
