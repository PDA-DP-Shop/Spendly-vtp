# Spendly VTP v0.1

Experimental prototype for the Spendly Visual Transaction Protocol.

## Run locally

Use a local HTTPS server if you want camera access. For example, VS Code Live Server or:

```bash
python3 -m http.server 8000
```

Camera permissions generally require HTTPS (or localhost).

## GitHub Pages

1. Create a PRIVATE GitHub repository.
2. Upload `index.html`, `style.css`, and `app.js`.
3. Push to GitHub.
4. In GitHub: Settings → Pages.
5. Select **Deploy from a branch**.
6. Select your main branch and `/ (root)`.
7. Open the generated `https://...github.io/...` URL.
8. On iPhone/Safari, allow camera access.

## Prototype limitation

VTP v0.1 intentionally uses a guided scanner. The code must be aligned inside the scanner guide and shown reasonably front-on.

The next version should implement:
- automatic VTP detection
- perspective correction
- better error correction
- packet fragmentation/reassembly
- real key exchange
- benchmark tooling against QR/Data Matrix
- stronger authentication
- production-grade cryptography/key management

## Security warning

The demo uses a fixed prototype secret in JavaScript. This is NOT secure for production. Anyone who can inspect the source can recover it. It exists only to prove the visual encoding/decoding concept.

Do not use VTP v0.1 for real payments, financial credentials, or sensitive personal information.
