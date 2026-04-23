# ankhor-tools

Static browser-based tools site for compatible IIST / Ankhor devices.

This repository is structured to work as a small GitHub Pages website with a homepage and individual tool pages.

Current site structure:

- `index.html` - site homepage and tool navigation
- `style.css` - shared site styling
- `product-verification/` - first live tool page with a minimal WebSerial-based product verification utility

Planned future tool areas:

- FIDO2 Check
- C2PA Tools
- Key Pairing

Everything is kept static so it can be hosted directly from GitHub Pages without a build step.

The current `product-verification/` tool is intentionally narrow: it connects to supported devices over WebSerial, then exposes only `Get Info` and `TRNG` in the public page.
