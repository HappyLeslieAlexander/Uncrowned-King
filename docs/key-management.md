# Key and Certificate Management

Operational procedures for the two secrets Uncrowned King relies on: the
**shared authentication secrets** (per key id) and the **server TLS/QUIC
certificate and private key**. Follow these for production deployments.

See also: [`threat-model.md`](threat-model.md), whitepaper §16.

## 1. Shared authentication secrets

Clients authenticate to the server with an HMAC challenge-response keyed by a
per-`key_id` shared secret. The server holds the list of credentials; each
client holds one.

### 1.1 Generation

- Use a **cryptographically random** secret of at least 32 bytes of entropy.
  For example: `openssl rand -base64 48` or `head -c 32 /dev/urandom | base64`.
- Assign a stable, non-secret `key_id` per client/tenant (used for log
  correlation and policy grouping — do not reuse across tenants).
- Never commit real secrets. The values in `examples/` are throwaway
  placeholders and must be replaced before any non-local use.

### 1.2 Server credential format

```toml
[[credentials]]
key_id = "tenant-a"
secret = "<long-random-secret>"
status = "active"          # active | disabled | retired
policy_group = "default"   # optional; must be non-empty printable text
# not_before = <unix-seconds>   # optional validity window
# not_after  = <unix-seconds>
```

- `status`: `active` credentials authenticate; `disabled` and `retired` do not.
- `not_before` / `not_after`: optional validity window; outside it the
  credential is inactive even if `active`.
- `key_id` values must be unique.

### 1.3 Storage and permissions

- Files containing secrets (server config, client config) must be readable
  only by the owning user. The process **rejects startup** if a secret- or
  key-bearing file is group/other readable, writable, or executable on Unix.
  Set `chmod 600`.
- Prefer delivering secrets via a secrets manager / sealed file with `0600`,
  not baked into images or version control.
- Secrets are zeroized in memory on drop and are never written to logs.

### 1.4 Rotation (zero-downtime)

1. Generate a new secret under a **new `key_id`** (do not overwrite the old
   secret in place).
2. Add the new `[[credentials]]` entry (`status = "active"`) to the server
   config alongside the existing one and `SIGHUP` the server (§3). Both
   credentials now authenticate.
3. Roll clients to the new `key_id`/secret (client config + `SIGHUP` the
   client, or restart).
4. Once all clients use the new credential, set the old entry to
   `status = "retired"` (or remove it) and `SIGHUP` the server.

Rotating by adding-then-retiring avoids a window where any legitimate client is
locked out.

### 1.5 Revocation and incident response

- **Immediate revocation**: set the compromised credential's `status =
  "disabled"` (or delete the entry) and `SIGHUP` the server. New handshakes
  with that key id are rejected at once.
- Existing authenticated sessions are not force-dropped by a credential change;
  to terminate them, restart the server (bounded graceful drain applies).
- Rotate the affected secret (§1.4) and audit logs for the key id
  (`key_id_hex` appears in `auth.success` events).

## 2. Server TLS/QUIC certificate and key

Both carriers (TLS/TCP and QUIC) share one certificate and private key and the
`uk/1` ALPN. TLS 1.3 is required.

### 2.1 Generation

- In production use a certificate from your CA / ACME provider for the server
  name clients will verify. The `examples/` self-signed recipe is for local
  development only.
- The private key file must be `0600` and owned by the service user; the
  process enforces this on startup and reload.

### 2.2 Client trust

- Clients validate the server certificate against `ca_cert_path`. Distribute
  the CA (or the pinned self-signed cert) to clients out of band.

### 2.3 Rotation (SIGHUP, zero-downtime)

1. Install the new certificate and key at the configured paths (write the new
   key, then the new cert; or rotate both atomically).
2. `SIGHUP` the server (§3). The reload **builds the new crypto material first
   and only swaps it in if it is valid**, so a bad cert/key pair fails the
   reload and leaves the running identity untouched.
3. **New** connections use the rotated identity; **existing** connections keep
   the identity they were accepted with, so in-flight sessions are not dropped.

A certificate present without its matching key (or vice versa) is rejected;
the previous identity keeps serving.

## 3. Applying changes: SIGHUP reload vs restart

On Unix, `SIGHUP` triggers an **atomic** reload of security-relevant
configuration on both the server and the client.

- **Server SIGHUP reloads**: certificate/key, credentials, policy, and
  `auth_skew_seconds`. The reload is all-or-nothing; on any validation error
  the previous configuration keeps running and the failure is recorded
  (`server.config.reload_failure`, reload-failure metric).
- **Client SIGHUP reloads**: server endpoints, CA, key id, secret, and
  new-session limits. Existing flows continue; new flows use the new
  configuration.
- **Requires a restart** (not reloadable): listener addresses (`listen`,
  `quic_listen`), resource-limit and timeout values, and the observability
  listener.

Verify a reload succeeded via the `server.config.reload_success` log event and
the security-generation / reload-success metrics before retiring old material.

## 4. Checklist

- [ ] Secrets ≥ 32 bytes entropy, unique `key_id` per client.
- [ ] Config and key files are `0600`, owned by the service user.
- [ ] No real secrets in version control or images.
- [ ] Rotation uses add-new → roll clients → retire-old.
- [ ] Revocation sets `status = "disabled"` (or removes) + `SIGHUP`.
- [ ] Production certificate from a real CA; CA distributed to clients.
- [ ] Reload success confirmed via logs/metrics before retiring old material.
