# ankhor-tools

Static browser-based tools and documentation site for compatible IIST / Ankhor devices.

Current site structure:

- `index.html` - menu-style homepage
- `style.css` - shared styling
- `resources/` - logos, replaceable illustration assets, i18n strings, and vendored standalone web UI toolkit assets
- `product-verification/` - stable WebSerial-based product verification utility
- `scenarios/` - Ankhor Key Plus application scenario cookbook
- `command-reference/` - command family reference for CLI/API integrations
- `downloads/` - future packaged desktop tools and user software
- `contact/` - integration support contact page

Important:

The product-verification tool is intentionally narrow. It connects to supported devices over WebSerial and exposes only Get Info and TRNG in the public page.

FIDO2/MDS policy:

FIDO2 testing is currently handled by an external WebAuthn.io link from the homepage. This repository does not publish its own FIDO2 testing page, WebAuthn testing page, or MDS lookup tooling on this branch at this time. The `fidotest` branch must remain unmerged until the device is officially listed and approved for public metadata-related testing.

Everything is static and can be hosted directly from GitHub Pages without a build step.

UI toolkit:

The site uses a local copy of the web UI toolkit CSS and required assets under `resources/`:

- `resources/liquid-glass.css`
- `resources/background-light2.png`
- `resources/checkmark-white.svg`

Do not reference the sibling `../UI_toolkit` repository at runtime. Copy any needed toolkit updates into this repository so `ankhor-tools` remains standalone.
