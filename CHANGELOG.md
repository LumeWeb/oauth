## 0.1.4 (2026-09-01)

### Features

- add RFC 9291 client id metadata document resolution

### Fixes

- gate CIMD fetches on allowlist alone, drop dead DNS SSRF block

## 0.1.3 (2026-08-31)

### Features

- surface bound resource and scope in access token validation

### Fixes

- carry scope through refresh token rotation in gorm adapter

## 0.1.2 (2026-08-30)

### Features

- add protected resource registry with flexible RFC 8707 validation

### Fixes

- emit resource_name from DisplayName in RFC 9728 metadata

## 0.1.1 (2026-08-30)

### Features

- add SetIssuer for runtime issuer reconfiguration
