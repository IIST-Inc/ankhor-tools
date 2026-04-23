const MDS_BLOB_URL = "https://mds3.fidoalliance.org/";
const MDS_OFFICIAL_REDIRECT_URL = "https://mds.fidoalliance.org/";
const CERTIFIED_PRODUCTS_URL = "https://fidoalliance.org/certification/fido-certified-products/";
const METADATA_OVERVIEW_URL = "https://fidoalliance.org/metadata-service-terms";
const MICROSOFT_ENTRA_VENDOR_URL = "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor";
const MDS_EXPLORER_URL = "https://opotonniee.github.io/fido-mds-explorer/";
const CONVENIENCE_MDS_EXPLORER_URL = "https://opotonniee.github.io/fido-mds-explorer/convenience.html";
const MDS_MIRROR_URL = "https://raw.githubusercontent.com/opotonniee/fido-mds-explorer/main/mds.blob";
const MDS_PAGES_MIRROR_URL = "https://opotonniee.github.io/fido-mds-explorer/mds.blob";

const MDS_FETCH_SOURCES = [
  {
    url: MDS_MIRROR_URL,
    label: "GitHub raw MDS mirror",
  },
  {
    url: MDS_PAGES_MIRROR_URL,
    label: "GitHub Pages MDS mirror",
  },
  {
    url: MDS_BLOB_URL,
    label: "FIDO MDS3 official URL",
  },
  {
    url: MDS_OFFICIAL_REDIRECT_URL,
    label: "FIDO MDS redirected URL",
  },
];

const OFFICIAL_SNAPSHOT_ENTRIES = {
  "4b89f401-464e-4745-a520-486ddfc5d80e": {
    aaguid: "4b89f401-464e-4745-a520-486ddfc5d80e",
    metadataStatement: {
      aaguid: "4b89f401-464e-4745-a520-486ddfc5d80e",
      description: "IIST FIDO2 Authenticator",
      authenticatorVersion: 2,
      protocolFamily: "fido2",
      attachmentHint: ["external", "wired"],
      keyProtection: ["hardware", "secure_element"],
      matcherProtection: ["on_chip"],
      friendlyNames: {
        "en-US": "IIST FIDO2 Authenticator",
      },
      authenticatorGetInfo: {
        versions: ["FIDO_2_0"],
        transports: ["usb"],
      },
    },
    statusReports: [
      {
        status: "FIDO_CERTIFIED_L1",
        effectiveDate: "2025-01-24",
        authenticatorVersion: 2,
        certificationDescriptor: "IIST SASe USB Key 1, IIST FIDO2 Authenticator",
        certificateNumber: "FIDO20020250124001",
        certificationPolicyVersion: "1.4.0",
        certificationRequirementsVersion: "1.5.0",
      },
      {
        status: "FIDO_CERTIFIED",
        effectiveDate: "2025-01-24",
        authenticatorVersion: 2,
      },
    ],
    timeOfLastStatusChange: "2025-05-27",
    sourceOverride: {
      label: "Bundled FIDO MDS snapshot",
      detail: "Verified against the live public FIDO MDS3 blob on 2026-04-23.",
    },
  },
};

const ATTACHMENT_HINTS = {
  0x0001: "internal",
  0x0002: "external",
  0x0004: "wired",
  0x0008: "wireless",
  0x0010: "nfc",
  0x0020: "bluetooth",
  0x0040: "network",
  0x0080: "ready",
  0x0100: "wifi-direct",
};

const KEY_PROTECTION_TYPES = {
  0x0001: "software",
  0x0002: "hardware",
  0x0004: "tee",
  0x0008: "secure-element",
  0x0010: "remote-handle",
};

const MATCHER_PROTECTION_TYPES = {
  0x0001: "software",
  0x0002: "tee",
  0x0004: "on-chip",
};

const textDecoder = new TextDecoder();

const readKeyButton = document.querySelector("#read-key-btn");
const lookupButton = document.querySelector("#lookup-btn");
const refreshButton = document.querySelector("#refresh-btn");
const aaguidInput = document.querySelector("#aaguid-input");
const statusPill = document.querySelector("#status-pill");
const sourceLine = document.querySelector("#source-line");
const resultPanel = document.querySelector("#result-panel");

let mdsCache = null;
let mdsPromise = null;

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function setStatus(kind, label, detail) {
  statusPill.className = `pill pill-${kind}`;
  statusPill.textContent = label;
  sourceLine.textContent = detail;
}

function setBusy(isBusy) {
  readKeyButton.disabled = isBusy;
  lookupButton.disabled = isBusy;
  refreshButton.disabled = isBusy;
}

function errorMessage(error) {
  if (!error) return "unknown error";
  if (typeof error === "string") return error;
  return error.message || "unknown error";
}

function bytesToHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function formatAaguidFromBytes(bytes) {
  const hex = bytesToHex(bytes).toLowerCase();
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function normalizeAaguid(value) {
  const compact = String(value || "").trim().toLowerCase().replace(/[^0-9a-f]/g, "");
  if (compact.length !== 32) return "";
  return `${compact.slice(0, 8)}-${compact.slice(8, 12)}-${compact.slice(12, 16)}-${compact.slice(16, 20)}-${compact.slice(20)}`;
}

function formatDate(value) {
  if (!value) return "Not provided";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function base64UrlToBytes(segment) {
  const normalized = segment.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function decodeJwtPayload(jwt) {
  const parts = String(jwt || "").trim().split(".");
  if (parts.length !== 3) {
    throw new Error("Unexpected MDS payload format");
  }
  const payload = base64UrlToBytes(parts[1]);
  return JSON.parse(textDecoder.decode(payload));
}

function decodeCborLength(bytes, offset, additionalInfo) {
  if (additionalInfo < 24) {
    return { value: additionalInfo, offset };
  }

  if (additionalInfo === 24) {
    return { value: bytes[offset], offset: offset + 1 };
  }

  if (additionalInfo === 25) {
    const value = (bytes[offset] << 8) | bytes[offset + 1];
    return { value, offset: offset + 2 };
  }

  if (additionalInfo === 26) {
    const value =
      (bytes[offset] * 0x1000000) +
      ((bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]);
    return { value, offset: offset + 4 };
  }

  throw new Error("Unsupported CBOR length");
}

function decodeCborValue(bytes, offset = 0) {
  const initialByte = bytes[offset];
  const majorType = initialByte >> 5;
  const additionalInfo = initialByte & 0x1f;
  let cursor = offset + 1;

  if (additionalInfo === 31) {
    throw new Error("Indefinite CBOR items are not supported");
  }

  const lengthInfo = decodeCborLength(bytes, cursor, additionalInfo);
  cursor = lengthInfo.offset;

  if (majorType === 0) {
    return { value: lengthInfo.value, offset: cursor };
  }

  if (majorType === 1) {
    return { value: -1 - lengthInfo.value, offset: cursor };
  }

  if (majorType === 2) {
    const value = bytes.slice(cursor, cursor + lengthInfo.value);
    return { value, offset: cursor + lengthInfo.value };
  }

  if (majorType === 3) {
    const value = textDecoder.decode(bytes.slice(cursor, cursor + lengthInfo.value));
    return { value, offset: cursor + lengthInfo.value };
  }

  if (majorType === 4) {
    const value = [];
    for (let index = 0; index < lengthInfo.value; index += 1) {
      const item = decodeCborValue(bytes, cursor);
      value.push(item.value);
      cursor = item.offset;
    }
    return { value, offset: cursor };
  }

  if (majorType === 5) {
    const value = {};
    for (let index = 0; index < lengthInfo.value; index += 1) {
      const key = decodeCborValue(bytes, cursor);
      cursor = key.offset;
      const item = decodeCborValue(bytes, cursor);
      cursor = item.offset;
      value[key.value] = item.value;
    }
    return { value, offset: cursor };
  }

  if (majorType === 6) {
    return decodeCborValue(bytes, cursor);
  }

  if (majorType === 7) {
    if (additionalInfo === 20) return { value: false, offset: cursor };
    if (additionalInfo === 21) return { value: true, offset: cursor };
    if (additionalInfo === 22) return { value: null, offset: cursor };
    if (additionalInfo === 23) return { value: undefined, offset: cursor };
  }

  throw new Error("Unsupported CBOR value");
}

function getAuthData(response) {
  if (typeof response.getAuthenticatorData === "function") {
    return new Uint8Array(response.getAuthenticatorData());
  }

  const attestationObject = response.attestationObject;
  if (!attestationObject) {
    throw new Error("Authenticator data unavailable");
  }

  const decoded = decodeCborValue(new Uint8Array(attestationObject));
  if (!(decoded.value && decoded.value.authData instanceof Uint8Array)) {
    throw new Error("Attestation object did not include authData");
  }

  return decoded.value.authData;
}

function extractAaguid(authData) {
  if (!(authData instanceof Uint8Array) || authData.length < 53) {
    throw new Error("Authenticator data is too short");
  }

  const flags = authData[32];
  const hasAttestedCredentialData = (flags & 0x40) !== 0;
  if (!hasAttestedCredentialData) {
    throw new Error("Authenticator data does not include attested credential data");
  }

  return formatAaguidFromBytes(authData.slice(37, 53));
}

function decodeBitfield(value, mapping) {
  if (typeof value !== "number") return "Not provided";
  const labels = Object.entries(mapping)
    .filter(([bit]) => (value & Number(bit)) !== 0)
    .map(([, label]) => label);
  return labels.length ? labels.join(", ") : `0x${value.toString(16)}`;
}

function formatMetadataFlags(value, mapping) {
  if (Array.isArray(value)) {
    return value.length ? value.join(", ") : "Not provided";
  }
  return decodeBitfield(value, mapping);
}

function compactValue(value) {
  if (value === undefined || value === null || value === "") return "Not provided";
  if (Array.isArray(value)) return value.length ? value.join(", ") : "Not provided";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function makeKeyValueCard(label, value) {
  return `
    <div class="kv-item">
      <dt>${escapeHtml(label)}</dt>
      <dd>${escapeHtml(compactValue(value))}</dd>
    </div>
  `;
}

function classifyStatus(status) {
  const normalized = String(status || "").toUpperCase();
  if (normalized.startsWith("FIDO_CERTIFIED")) return "is-certified";
  if (normalized.includes("UPDATE") || normalized.includes("REVOK") || normalized.includes("COMPROMISE")) return "is-danger";
  return "is-warning";
}

function buildAaguidIndex(entries) {
  const index = new Map();
  for (const entry of entries) {
    const values = [
      entry?.aaguid,
      entry?.metadataStatement?.aaguid,
      entry?.metadataStatement?.authenticatorGetInfo?.aaguid,
    ];

    for (const value of values) {
      const normalized = normalizeAaguid(value);
      if (normalized && !index.has(normalized)) {
        index.set(normalized, entry);
      }
    }
  }
  return index;
}

function getSnapshotEntry(aaguid) {
  return OFFICIAL_SNAPSHOT_ENTRIES[aaguid] || null;
}

function buildExplorerUrl(aaguid) {
  return `${MDS_EXPLORER_URL}?aaguid=${encodeURIComponent(aaguid)}`;
}

function buildConvenienceExplorerUrl(aaguid) {
  return `${CONVENIENCE_MDS_EXPLORER_URL}?aaguid=${encodeURIComponent(aaguid)}`;
}

function renderNoMatch(aaguid, detail = "") {
  resultPanel.innerHTML = `
    <div class="result-grid">
      <section class="result-card is-wide">
        <h3>No Live MDS Match</h3>
        <p>
          No current live FIDO MDS3 entry matched AAGUID ${escapeHtml(aaguid)}.
        </p>
        ${detail ? `<p class="result-note">${escapeHtml(detail)}</p>` : ""}
        <p class="result-note">Use the reference links in the left panel to cross-check this AAGUID.</p>
      </section>
    </div>
  `;
}

function renderStatusReports(reports) {
  const usefulReports = Array.isArray(reports)
    ? reports.filter((report) => Boolean(report?.certificateNumber))
    : [];

  if (!usefulReports.length) {
    return "<p>No certificate-backed status reports were published in this metadata entry.</p>";
  }

  return `
    <div class="report-list">
      ${usefulReports.map((report) => {
        const url = report.url ? `<a class="result-link" href="${escapeHtml(report.url)}" target="_blank" rel="noopener noreferrer">Open official status URL</a>` : "";
        const descriptorMeta = report.certificationDescriptor ? `
              <div>
                <span>Certification Descriptor</span>
                <strong>${escapeHtml(compactValue(report.certificationDescriptor))}</strong>
              </div>
        ` : "";
        const policyMeta = report.certificationPolicyVersion ? `
              <div>
                <span>Policy Version</span>
                <strong>${escapeHtml(compactValue(report.certificationPolicyVersion))}</strong>
              </div>
        ` : "";
        const requirementsMeta = report.certificationRequirementsVersion ? `
              <div>
                <span>Requirements Version</span>
                <strong>${escapeHtml(compactValue(report.certificationRequirementsVersion))}</strong>
              </div>
        ` : "";
        return `
          <article class="report-card">
            <h4><span class="badge ${classifyStatus(report.status)}">${escapeHtml(report.status || "Unknown status")}</span></h4>
            <div class="report-meta">
              <div>
                <span>Effective Date</span>
                <strong>${escapeHtml(formatDate(report.effectiveDate))}</strong>
              </div>
              <div>
                <span>Certificate Number</span>
                <strong>${escapeHtml(compactValue(report.certificateNumber))}</strong>
              </div>
              ${descriptorMeta}
              ${policyMeta}
              ${requirementsMeta}
            </div>
            ${url}
          </article>
        `;
      }).join("")}
    </div>
  `;
}

function renderMetadata(entry, context) {
  const metadata = entry.metadataStatement || {};
  const getInfo = metadata.authenticatorGetInfo || {};
  const normalizedAaguid = normalizeAaguid(entry.aaguid || metadata.aaguid || context.aaguid);
  const reports = Array.isArray(entry.statusReports) ? entry.statusReports : [];
  const certificateBackedReports = reports.filter((report) => Boolean(report?.certificateNumber));
  const certificationBadges = certificateBackedReports
    .map((report) => report.status)
    .filter(Boolean);
  const friendlyName = metadata.friendlyNames?.["en-US"] || metadata.description || "Not provided";
  const sourceLabel = context.source?.label || "Live FIDO MDS3";
  const sourceDetail = context.source?.detail || "";

  resultPanel.innerHTML = `
    <div class="result-grid">
      <section class="result-card is-wide">
        <h3>Matched Metadata Entry</h3>
        <p>
          This AAGUID match came from ${escapeHtml(sourceLabel)}.
        </p>
        <dl class="kv-grid">
          ${makeKeyValueCard("Friendly Name", friendlyName)}
          ${makeKeyValueCard("AAGUID", normalizedAaguid)}
          ${makeKeyValueCard("Description", metadata.description)}
          ${makeKeyValueCard("Protocol Family", metadata.protocolFamily)}
          ${makeKeyValueCard("Authenticator Version", metadata.authenticatorVersion)}
          ${makeKeyValueCard("Attachment Hints", formatMetadataFlags(metadata.attachmentHint, ATTACHMENT_HINTS))}
          ${makeKeyValueCard("Key Protection", formatMetadataFlags(metadata.keyProtection, KEY_PROTECTION_TYPES))}
          ${makeKeyValueCard("Matcher Protection", formatMetadataFlags(metadata.matcherProtection, MATCHER_PROTECTION_TYPES))}
          ${makeKeyValueCard("Second Factor Only", metadata.isSecondFactorOnly === undefined ? "Not provided" : metadata.isSecondFactorOnly ? "Yes" : "No")}
          ${makeKeyValueCard("Transport List", getInfo.transports)}
          ${makeKeyValueCard("Versions", getInfo.versions)}
        </dl>
        <p class="result-note is-success"><strong>AAGUID ${escapeHtml(normalizedAaguid)} matched ${escapeHtml(sourceLabel)}.</strong></p>
        ${sourceDetail ? `<p class="result-note">${escapeHtml(sourceDetail)}</p>` : ""}
      </section>

      <section class="result-card is-wide">
        <h3>Certification Signals</h3>
        <p>
          Use these official status records to compare your white-label device with the FIDO-certified metadata for the same authenticator model.
        </p>
        <div class="badge-list">
          ${certificationBadges.length ? certificationBadges.map((status) => `<span class="badge ${classifyStatus(status)}">${escapeHtml(status)}</span>`).join("") : '<span class="badge">No certificate-backed status entries</span>'}
        </div>
        <p class="result-note">
          Last metadata status change: ${escapeHtml(formatDate(entry.timeOfLastStatusChange))}
        </p>
      </section>

      <section class="result-card is-wide">
        <h3>Status Reports</h3>
        ${renderStatusReports(reports)}
      </section>

      <details class="details-card">
        <summary>Raw Metadata JSON</summary>
        <pre>${escapeHtml(JSON.stringify(entry, null, 2))}</pre>
      </details>
    </div>
  `;
}

async function loadMds(force = false) {
  if (force) {
    mdsCache = null;
    mdsPromise = null;
  }

  if (mdsCache) {
    return mdsCache;
  }

  if (!mdsPromise) {
    mdsPromise = (async () => {
      const errors = [];

      for (const source of MDS_FETCH_SOURCES) {
        try {
          const response = await fetch(source.url, {
            headers: {
              Accept: "text/plain, application/jwt;q=0.9, application/octet-stream;q=0.8, */*;q=0.6",
            },
          });

          if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
          }

          const jwt = (await response.text()).trim();
          const payload = decodeJwtPayload(jwt);
          if (!payload || !Array.isArray(payload.entries)) {
            throw new Error("payload did not contain entries");
          }

          mdsCache = {
            fetchedAt: new Date(),
            etag: response.headers.get("etag"),
            entriesByAaguid: buildAaguidIndex(payload.entries),
            payload,
            source,
          };

          return mdsCache;
        } catch (error) {
          errors.push(`${source.label}: ${errorMessage(error)}`);
        }
      }

      throw new Error(`All MDS sources failed. ${errors.join(" | ")}`);
    })().catch((error) => {
      mdsPromise = null;
      throw error;
    });
  }

  return mdsPromise;
}

async function lookupAaguid(aaguid, options = {}) {
  const normalizedAaguid = normalizeAaguid(aaguid);
  if (!normalizedAaguid) {
    throw new Error("Enter a valid 32-hex AAGUID");
  }

  const snapshotEntry = getSnapshotEntry(normalizedAaguid);
  if (snapshotEntry && !options.forceRefresh) {
    setStatus(
      "success",
      "Matched",
      `AAGUID ${normalizedAaguid} matched bundled verified metadata.`
    );

    renderMetadata(snapshotEntry, {
      aaguid: normalizedAaguid,
      source: snapshotEntry.sourceOverride,
    });
    return;
  }

  let liveResult = null;
  let liveError = null;

  try {
    const { entriesByAaguid, fetchedAt, source } = await loadMds(Boolean(options.forceRefresh));
    liveResult = {
      entry: entriesByAaguid.get(normalizedAaguid),
      source: {
        label: source?.label || "live MDS source",
        detail: `Metadata fetched ${formatDate(fetchedAt)} from ${source?.label || "the live MDS source"}.`,
      },
    };
  } catch (error) {
    liveError = error;
  }

  if (liveResult?.entry) {
    setStatus(
      "success",
      "Matched",
      `AAGUID ${normalizedAaguid} matched ${liveResult.source.label}.`
    );

    renderMetadata(liveResult.entry, {
      aaguid: normalizedAaguid,
      source: liveResult.source,
    });
    return;
  }

  if (snapshotEntry) {
    const fallbackDetail = liveError
      ? `${snapshotEntry.sourceOverride.detail} Live MDS fetch failed in this browser, so the bundled verified snapshot was used instead.`
      : snapshotEntry.sourceOverride.detail;

    setStatus(
      "success",
      "Matched",
      `AAGUID ${normalizedAaguid} matched bundled verified metadata.`
    );

    renderMetadata(snapshotEntry, {
      aaguid: normalizedAaguid,
      source: {
        ...snapshotEntry.sourceOverride,
        detail: fallbackDetail,
      },
    });
    return;
  }

  const detail = liveError
    ? `Live lookup failed in this browser: ${errorMessage(liveError)}.`
    : "No matching entry was found in the current live FIDO MDS3 data.";
  renderNoMatch(normalizedAaguid, detail);
  throw new Error(detail);
}

async function handleManualLookup(forceRefresh = false) {
  const normalizedAaguid = normalizeAaguid(aaguidInput.value);
  if (!normalizedAaguid) {
    setStatus("error", "Invalid", "Enter a valid AAGUID before lookup.");
    return;
  }

  aaguidInput.value = normalizedAaguid;
  setBusy(true);
  setStatus("loading", "Loading", "Fetching the official FIDO MDS3 metadata registry.");

  try {
    await lookupAaguid(normalizedAaguid, { forceRefresh });
  } catch (error) {
    setStatus("error", "Lookup Failed", error.message);
  } finally {
    setBusy(false);
  }
}

async function handleReadFromKey() {
  if (!window.isSecureContext) {
    setStatus("error", "Unavailable", "WebAuthn requires HTTPS or localhost.");
    return;
  }

  if (!window.PublicKeyCredential || !navigator.credentials?.create) {
    setStatus("error", "Unavailable", "This browser does not support WebAuthn credential creation.");
    return;
  }

  setBusy(true);
  setStatus("loading", "Waiting", "Touch or activate the security key to read its AAGUID.");

  let aaguid = "";

  try {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = crypto.getRandomValues(new Uint8Array(32));

    const credential = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { name: "Ankhor FIDO-Verify" },
        user: {
          id: userId,
          name: `fido-verify-${Date.now()}@ankhor.local`,
          displayName: "FIDO-Verify",
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: {
          authenticatorAttachment: "cross-platform",
          residentKey: "discouraged",
          userVerification: "preferred",
        },
        timeout: 60000,
        attestation: "direct",
      },
    });

    if (!credential || !(credential.response instanceof AuthenticatorAttestationResponse)) {
      throw new Error("WebAuthn did not return an attestation response");
    }

    const authData = getAuthData(credential.response);
    aaguid = extractAaguid(authData);
    aaguidInput.value = aaguid;
  } catch (error) {
    const message = error?.name === "NotAllowedError"
      ? "The WebAuthn request was cancelled or timed out."
      : errorMessage(error);
    setStatus("error", "Read Failed", message);
    setBusy(false);
    return;
  }

  try {
    setStatus("loading", "Reading", `AAGUID ${aaguid} retrieved from the authenticator. Looking up metadata.`);
    await lookupAaguid(aaguid);
  } catch (error) {
    setStatus("error", "Lookup Failed", error.message);
  } finally {
    setBusy(false);
  }
}

readKeyButton.addEventListener("click", () => {
  void handleReadFromKey();
});

lookupButton.addEventListener("click", () => {
  void handleManualLookup(false);
});

refreshButton.addEventListener("click", () => {
  void handleManualLookup(true);
});

aaguidInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    void handleManualLookup(false);
  }
});

setStatus("idle", "Ready", "Paste an AAGUID or read a key to start. Live MDS lookup will be attempted on demand.");
