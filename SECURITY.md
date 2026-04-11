# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| AETHER 0.2 (current) | ✅ |
| AETHER 0.1 | ✅ |

## Reporting a Vulnerability

Security vulnerabilities in the AETHER protocol, reference implementation, or beacon infrastructure should be reported **privately** — not as public GitHub issues.

**Preferred channel:** Use the encrypted response endpoint defined in `aether.json`:

1. Fetch `aether.json` and read `encryption.public_key`
2. Encrypt your report per AGS §15.7 (X25519 + ChaCha20-Poly1305)
3. POST to `https://aetherbeacon.io/respond` or the communication endpoint

This ensures only the operator can read the content.

**What to include:**
- Description of the vulnerability
- Affected component (protocol spec, Netlify functions, Ghost Seal tooling, registry)
- Proof of concept or reproduction steps if available
- Your assessment of severity and impact

**Response time:** You can expect an acknowledgement within 72 hours. We will keep you updated as the issue is investigated and resolved.

**Disclosure:** We follow coordinated disclosure. Please allow reasonable time for a fix to be deployed before public disclosure. We will credit reporters unless anonymity is requested.
