/**
 * Standard Package URL (PURL) identity parsing, normalization, serialization, and legacy transition helpers (#71).
 *
 * Mirrors `scripts/purl_identity.py` with equivalent behavior across Python and JavaScript.
 */

const PURL_TYPE_RE = /^[a-z][a-z0-9.+-]*$/;
const QUALIFIER_KEY_RE = /^[a-z][a-z0-9._-]*$/;

export const NON_PACKAGE_NAMESPACES = new Set([
  "github",
  "gitlab",
  "bitbucket",
  "scope",
  "project",
  "app",
  "system",
]);

const LOWERCASE_NAME_TYPES = new Set([
  "pypi",
  "npm",
  "deb",
  "apk",
  "composer",
  "github",
  "bitbucket",
  "hex",
  "pub",
]);

const LOWERCASE_NAMESPACE_TYPES = new Set([
  "npm",
  "deb",
  "apk",
  "rpm",
  "composer",
  "github",
  "bitbucket",
]);

export const ECOSYSTEM_LABELS = {
  maven: "Java",
  npm: "JavaScript",
  pypi: "Python",
  nuget: ".NET",
  cargo: "Rust",
  golang: "Go",
  gem: "Ruby",
  composer: "PHP",
  deb: "Debian",
  rpm: "RPM",
  apk: "Alpine",
  docker: "Docker",
  oci: "OCI",
  generic: "Generic",
};

const RANGE_OR_UNRESOLVED_RE = /(?:^\s*$|^unspecified$|^latest$|^unknown$|^\*$|[\^~><=|()\[\]{}$]|\s+|\.(?:x|X|\*)$)/;

export function isVersionRangeOrUnresolved(version) {
  if (typeof version !== "string") return true;
  const raw = version.trim();
  if (!raw || RANGE_OR_UNRESOLVED_RE.test(raw)) return true;
  const lower = raw.toLowerCase();
  return ["unspecified", "latest", "unknown", "none", "null", "*"].includes(lower);
}

export function canonicalPackageName(namespace, name) {
  const ns = String(namespace || "").trim().toLowerCase();
  const raw = String(name || "").trim();
  if (ns === "pypi") return raw.replace(/[-_.]+/g, "-").toLowerCase();
  return raw;
}

export function canonicalNamespace(ecoType, meta) {
  const ns = String(ecoType || "").trim().toLowerCase();
  const raw = String(meta || "").trim().replace(/^\/+|\/+$/g, "");
  if (!raw || ns === "pypi") return "";
  if (ns === "npm") {
    return raw.startsWith("@") ? raw : `@${raw}`;
  }
  return raw;
}

export function canonicalRelease(namespace, release) {
  const value = String(release || "").trim();
  const ns = String(namespace || "").trim().toLowerCase();
  if ((ns === "npm" || ns === "pypi") && /^[vV](?=\d)/.test(value)) {
    return value.slice(1);
  }
  return value;
}

function encodePathSegment(segment) {
  return encodeURIComponent(segment).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function encodeVersion(version) {
  return encodeURIComponent(version)
    .replace(/%2B/gi, "+")
    .replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function encodeQualifierValue(val) {
  return encodeURIComponent(val)
    .replace(/%3A/gi, ":")
    .replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

export function formatPurl(ecoType, namespace = "", name = "", version = null, qualifiers = null, subpath = null) {
  if (ecoType && typeof ecoType === "object") {
    ({
      type: ecoType,
      namespace = "",
      name = "",
      version = null,
      qualifiers = null,
      subpath = null,
    } = ecoType);
  }
  const t = String(ecoType || "").trim().toLowerCase();
  if (!t || !PURL_TYPE_RE.test(t)) {
    throw new Error(`Invalid PURL type: ${JSON.stringify(ecoType)}`);
  }
  const normNs = canonicalNamespace(t, namespace);
  const normName = canonicalPackageName(t, name);
  if (!normName) {
    throw new Error(`Missing package name for PURL type ${JSON.stringify(t)}`);
  }
  if (t === "maven" && !normNs) {
    throw new Error(`Maven PURL requires groupId namespace for artifact ${JSON.stringify(normName)}`);
  }

  const pathParts = [];
  if (normNs) {
    for (const seg of normNs.split("/")) {
      if (seg) pathParts.push(encodePathSegment(seg));
    }
  }
  pathParts.push(encodePathSegment(normName));
  let base = `pkg:${t}/${pathParts.join("/")}`;

  const verStr = version !== null && version !== undefined ? String(version).trim() : "";
  if (verStr) {
    base += `@${encodeVersion(verStr)}`;
  }

  if (qualifiers && typeof qualifiers === "object") {
    const entries = Object.entries(qualifiers).sort(([a], [b]) =>
      String(a).trim().toLowerCase().localeCompare(String(b).trim().toLowerCase())
    );
    const qItems = [];
    for (const [k, v] of entries) {
      const kNorm = String(k || "").trim().toLowerCase();
      const vStr = String(v || "").trim();
      if (!kNorm || !vStr) continue;
      if (!QUALIFIER_KEY_RE.test(kNorm)) {
        throw new Error(`Invalid PURL qualifier key: ${JSON.stringify(k)}`);
      }
      qItems.push(`${kNorm}=${encodeQualifierValue(vStr)}`);
    }
    if (qItems.length) {
      base += `?${qItems.join("&")}`;
    }
  }

  const subStr = String(subpath || "").trim().replace(/^\/+|\/+$/g, "");
  if (subStr) {
    const subSegs = [];
    for (const seg of subStr.split("/")) {
      if (!seg || seg === "." || seg === "..") {
        throw new Error(`Invalid PURL subpath segment in ${JSON.stringify(subpath)}`);
      }
      subSegs.push(encodePathSegment(seg));
    }
    if (subSegs.length) {
      base += `#${subSegs.join("/")}`;
    }
  }

  return base;
}

export function parsePurlSpec(rawValue, options = {}) {
  const { requireVersion = false, rejectRanges = false, allowLegacyPipe = false } = options;
  if (typeof rawValue !== "string" || !rawValue.trim()) {
    return {
      valid: false,
      purl: String(rawValue || ""),
      package_purl: "",
      type: "unknown",
      ecosystem: "Unknown",
      namespace: "",
      name: "",
      version: "",
      qualifiers: {},
      subpath: "",
      key: "",
      library_coordinate: "",
      is_versioned: false,
      is_range: false,
      error: "Missing product identifier",
    };
  }

  const raw = rawValue.trim();

  if (allowLegacyPipe && !raw.startsWith("pkg:") && raw.includes("|")) {
    const parts = raw.split("|");
    if (parts.length === 4) {
      const [eco, meta, proj, rel] = parts;
      const ecoL = eco.trim().toLowerCase();
      if (NON_PACKAGE_NAMESPACES.has(ecoL)) {
        return {
          valid: false,
          purl: raw,
          package_purl: "",
          type: ecoL,
          ecosystem: ecoL,
          namespace: meta.trim(),
          name: proj.trim(),
          version: rel.trim(),
          qualifiers: {},
          subpath: "",
          key: "",
          library_coordinate: "",
          is_versioned: false,
          is_range: false,
          error: `Non-package identifier cannot be treated as a PURL: ${raw}`,
        };
      }
      try {
        const verP = formatPurl(ecoL, meta, proj, rel);
        return parsePurlSpec(verP, { requireVersion, rejectRanges });
      } catch (err) {
        return {
          valid: false,
          purl: raw,
          package_purl: "",
          type: ecoL || "other",
          ecosystem: ecoL || "Other",
          namespace: meta,
          name: proj,
          version: rel,
          qualifiers: {},
          subpath: "",
          key: "",
          library_coordinate: "",
          is_versioned: false,
          is_range: false,
          error: err.message,
        };
      }
    } else if (parts.length === 3 && !requireVersion) {
      const [eco, meta, proj] = parts;
      const ecoL = eco.trim().toLowerCase();
      if (NON_PACKAGE_NAMESPACES.has(ecoL)) {
        return {
          valid: false,
          purl: raw,
          package_purl: "",
          type: ecoL,
          ecosystem: ecoL,
          namespace: meta.trim(),
          name: proj.trim(),
          version: "",
          qualifiers: {},
          subpath: "",
          key: "",
          library_coordinate: "",
          is_versioned: false,
          is_range: false,
          error: `Non-package identifier cannot be treated as a PURL: ${raw}`,
        };
      }
      try {
        const pkgP = formatPurl(ecoL, meta, proj, null);
        return parsePurlSpec(pkgP, { requireVersion: false, rejectRanges });
      } catch (err) {
        return {
          valid: false,
          purl: raw,
          package_purl: "",
          type: ecoL || "other",
          ecosystem: ecoL || "Other",
          namespace: meta,
          name: proj,
          version: "",
          qualifiers: {},
          subpath: "",
          key: "",
          library_coordinate: "",
          is_versioned: false,
          is_range: false,
          error: err.message,
        };
      }
    }
  }

  if (!raw.startsWith("pkg:")) {
    return {
      valid: false,
      purl: raw,
      package_purl: "",
      type: "other",
      ecosystem: "Other",
      namespace: "",
      name: raw,
      version: "",
      qualifiers: {},
      subpath: "",
      key: "",
      library_coordinate: raw,
      is_versioned: false,
      is_range: false,
      error: `Unsupported or non-PURL product identifier: ${raw}`,
    };
  }

  let remainder = raw.slice(4);
  if (remainder.startsWith("/")) {
    return {
      valid: false,
      purl: raw,
      package_purl: "",
      type: "other",
      ecosystem: "Other",
      namespace: "",
      name: raw,
      version: "",
      qualifiers: {},
      subpath: "",
      key: "",
      library_coordinate: raw,
      is_versioned: false,
      is_range: false,
      error: `Invalid PURL authority slashes after pkg: scheme: ${raw}`,
    };
  }

  let subpath = "";
  const hashIdx = remainder.indexOf("#");
  if (hashIdx >= 0) {
    const rawSubpath = remainder.slice(hashIdx + 1).replace(/^\/+|\/+$/g, "");
    remainder = remainder.slice(0, hashIdx);
    if (rawSubpath) {
      const decodedSegs = [];
      for (const seg of rawSubpath.split("/")) {
        let dec;
        try {
          dec = decodeURIComponent(seg);
        } catch {
          return {
            valid: false,
            purl: raw,
            package_purl: "",
            type: "other",
            ecosystem: "Other",
            namespace: "",
            name: "",
            version: "",
            qualifiers: {},
            subpath: "",
            key: "",
            library_coordinate: "",
            is_versioned: false,
            is_range: false,
            error: `Malformed percent-encoding in subpath: ${raw}`,
          };
        }
        if (!dec || dec === "." || dec === ".." || dec.includes("/")) {
          return {
            valid: false,
            purl: raw,
            package_purl: "",
            type: "other",
            ecosystem: "Other",
            namespace: "",
            name: "",
            version: "",
            qualifiers: {},
            subpath: "",
            key: "",
            library_coordinate: "",
            is_versioned: false,
            is_range: false,
            error: `Invalid subpath in PURL: ${raw}`,
          };
        }
        decodedSegs.push(dec);
      }
      subpath = decodedSegs.join("/");
    }
  }

  const qualifiers = {};
  const qIdx = remainder.indexOf("?");
  if (qIdx >= 0) {
    const rawQs = remainder.slice(qIdx + 1);
    remainder = remainder.slice(0, qIdx);
    if (rawQs) {
      for (const pair of rawQs.split("&")) {
        if (!pair) continue;
        const eqIdx = pair.indexOf("=");
        if (eqIdx < 0) {
          return {
            valid: false,
            purl: raw,
            package_purl: "",
            type: "other",
            ecosystem: "Other",
            namespace: "",
            name: "",
            version: "",
            qualifiers: {},
            subpath: "",
            key: "",
            library_coordinate: "",
            is_versioned: false,
            is_range: false,
            error: `Malformed qualifier in PURL: ${raw}`,
          };
        }
        const kNorm = pair.slice(0, eqIdx).trim().toLowerCase();
        const vRaw = pair.slice(eqIdx + 1);
        if (!kNorm || !QUALIFIER_KEY_RE.test(kNorm)) {
          return {
            valid: false,
            purl: raw,
            package_purl: "",
            type: "other",
            ecosystem: "Other",
            namespace: "",
            name: "",
            version: "",
            qualifiers: {},
            subpath: "",
            key: "",
            library_coordinate: "",
            is_versioned: false,
            is_range: false,
            error: `Invalid qualifier key in PURL: ${raw}`,
          };
        }
        let vDec;
        try {
          vDec = decodeURIComponent(vRaw).trim();
        } catch {
          return {
            valid: false,
            purl: raw,
            package_purl: "",
            type: "other",
            ecosystem: "Other",
            namespace: "",
            name: "",
            version: "",
            qualifiers: {},
            subpath: "",
            key: "",
            library_coordinate: "",
            is_versioned: false,
            is_range: false,
            error: `Malformed percent-encoding in qualifier: ${raw}`,
          };
        }
        if (vDec) qualifiers[kNorm] = vDec;
      }
    }
  }

  const slashIdx = remainder.indexOf("/");
  if (slashIdx <= 0) {
    return {
      valid: false,
      purl: raw,
      package_purl: "",
      type: "other",
      ecosystem: "Other",
      namespace: "",
      name: raw,
      version: "",
      qualifiers: {},
      subpath: "",
      key: "",
      library_coordinate: raw,
      is_versioned: false,
      is_range: false,
      error: `Missing type/name separator in PURL: ${raw}`,
    };
  }

  const ecoType = remainder.slice(0, slashIdx).trim().toLowerCase();
  const pathAndVer = remainder.slice(slashIdx + 1);
  if (!ecoType || !PURL_TYPE_RE.test(ecoType) || !pathAndVer) {
    return {
      valid: false,
      purl: raw,
      package_purl: "",
      type: "other",
      ecosystem: "Other",
      namespace: "",
      name: raw,
      version: "",
      qualifiers: {},
      subpath: "",
      key: "",
      library_coordinate: raw,
      is_versioned: false,
      is_range: false,
      error: `Invalid ecosystem type in PURL: ${raw}`,
    };
  }

  const atIdx = pathAndVer.lastIndexOf("@");
  let rawPath = pathAndVer;
  let version = "";
  if (atIdx >= 0) {
    rawPath = pathAndVer.slice(0, atIdx);
    const rawVer = pathAndVer.slice(atIdx + 1);
    if (!rawVer) {
      return {
        valid: false,
        purl: raw,
        package_purl: "",
        type: ecoType,
        ecosystem: ECOSYSTEM_LABELS[ecoType] || ecoType,
        namespace: "",
        name: "",
        version: "",
        qualifiers,
        subpath,
        key: "",
        library_coordinate: "",
        is_versioned: false,
        is_range: false,
        error: `Empty version after '@' in PURL: ${raw}`,
      };
    }
    try {
      version = decodeURIComponent(rawVer).trim();
    } catch {
      return {
        valid: false,
        purl: raw,
        package_purl: "",
        type: ecoType,
        ecosystem: ECOSYSTEM_LABELS[ecoType] || ecoType,
        namespace: "",
        name: "",
        version: "",
        qualifiers,
        subpath,
        key: "",
        library_coordinate: "",
        is_versioned: false,
        is_range: false,
        error: `Malformed percent-encoding in version: ${raw}`,
      };
    }
  }

  if (!rawPath || rawPath.startsWith("/") || rawPath.endsWith("/") || rawPath.includes("//")) {
    return {
      valid: false,
      purl: raw,
      package_purl: "",
      type: ecoType,
      ecosystem: ECOSYSTEM_LABELS[ecoType] || ecoType,
      namespace: "",
      name: "",
      version,
      qualifiers,
      subpath,
      key: "",
      library_coordinate: "",
      is_versioned: Boolean(version),
      is_range: false,
      error: `Malformed package path in PURL: ${raw}`,
    };
  }

  const decodedSegments = [];
  for (const seg of rawPath.split("/")) {
    let dec;
    try {
      dec = decodeURIComponent(seg).trim();
    } catch {
      return {
        valid: false,
        purl: raw,
        package_purl: "",
        type: ecoType,
        ecosystem: ECOSYSTEM_LABELS[ecoType] || ecoType,
        namespace: "",
        name: "",
        version,
        qualifiers,
        subpath,
        key: "",
        library_coordinate: "",
        is_versioned: Boolean(version),
        is_range: false,
        error: `Malformed percent-encoding in package path: ${raw}`,
      };
    }
    if (!dec || dec.includes("/")) {
      return {
        valid: false,
        purl: raw,
        package_purl: "",
        type: ecoType,
        ecosystem: ECOSYSTEM_LABELS[ecoType] || ecoType,
        namespace: "",
        name: "",
        version,
        qualifiers,
        subpath,
        key: "",
        library_coordinate: "",
        is_versioned: Boolean(version),
        is_range: false,
        error: `Invalid path segment in PURL: ${raw}`,
      };
    }
    decodedSegments.push(dec);
  }

  const rawName = decodedSegments[decodedSegments.length - 1];
  const rawNs = decodedSegments.slice(0, -1).join("/");

  if (ecoType === "maven" && !rawNs) {
    return {
      valid: false,
      purl: raw,
      package_purl: "",
      type: ecoType,
      ecosystem: ECOSYSTEM_LABELS[ecoType] || ecoType,
      namespace: "",
      name: rawName,
      version,
      qualifiers,
      subpath,
      key: "",
      library_coordinate: rawName,
      is_versioned: Boolean(version),
      is_range: false,
      error: `Maven PURL requires both groupId namespace and artifactId name: ${raw}`,
    };
  }
  if (ecoType === "npm" && rawNs && (!rawNs.startsWith("@") || rawNs.includes("/"))) {
    return {
      valid: false,
      purl: raw,
      package_purl: "",
      type: ecoType,
      ecosystem: ECOSYSTEM_LABELS[ecoType] || ecoType,
      namespace: rawNs,
      name: rawName,
      version,
      qualifiers,
      subpath,
      key: "",
      library_coordinate: `${rawNs}/${rawName}`,
      is_versioned: Boolean(version),
      is_range: false,
      error: `npm PURL namespace must be a single @scope segment: ${raw}`,
    };
  }

  const normNs = canonicalNamespace(ecoType, rawNs);
  const normName = canonicalPackageName(ecoType, rawName);
  const isRange = version ? isVersionRangeOrUnresolved(version) : false;
  const pkgPurl = formatPurl(ecoType, normNs, normName, null);
  const key = normNs ? `${ecoType}/${normNs}/${normName}` : `${ecoType}/${normName}`;
  const coord = ecoType === "maven" && normNs ? `${normNs}:${normName}` : normNs ? `${normNs}/${normName}` : normName;

  if (requireVersion && !version) {
    return {
      valid: false,
      purl: raw,
      package_purl: pkgPurl,
      type: ecoType,
      ecosystem: ECOSYSTEM_LABELS[ecoType] || ecoType,
      namespace: normNs,
      name: normName,
      version: "",
      qualifiers,
      subpath,
      key,
      library_coordinate: coord,
      is_versioned: false,
      is_range: false,
      error: `Missing version in product PURL: ${raw}`,
    };
  }

  if (rejectRanges && version && isRange) {
    return {
      valid: false,
      purl: raw,
      package_purl: pkgPurl,
      type: ecoType,
      ecosystem: ECOSYSTEM_LABELS[ecoType] || ecoType,
      namespace: normNs,
      name: normName,
      version,
      qualifiers,
      subpath,
      key,
      library_coordinate: coord,
      is_versioned: true,
      is_range: true,
      error: `Version range or unresolved expression cannot be used as an exact artifact PURL: ${raw}`,
    };
  }

  const canonicalFull = formatPurl(ecoType, normNs, normName, version || null, qualifiers, subpath);
  return {
    valid: true,
    purl: canonicalFull,
    canonical_purl: canonicalFull,
    package_purl: pkgPurl,
    type: ecoType,
    ecosystem: ECOSYSTEM_LABELS[ecoType] || ecoType,
    namespace: normNs,
    name: normName,
    version,
    qualifiers,
    subpath,
    key,
    library_coordinate: coord,
    is_versioned: Boolean(version),
    is_range: isRange,
    error: null,
  };
}

export function makePackageId(namespace, meta, proj) {
  return formatPurl(namespace, meta, proj, null);
}

export function makeLibraryId(namespace, meta, proj, release, qualifiers = null, subpath = null) {
  const rel = String(release || "").trim();
  if (!rel) {
    throw new Error(`Release version is required to construct versioned library PURL for ${namespace}/${meta}/${proj}`);
  }
  return formatPurl(namespace, meta, proj, rel, qualifiers, subpath);
}

export function parseLibraryId(libraryId, { strict = false } = {}) {
  const empty = {
    namespace: "",
    meta: "",
    proj: "",
    release: "",
  };
  const raw = String(libraryId || "").trim();
  if (!raw) {
    if (strict) throw new Error("Empty library identifier");
    return empty;
  }
  if (raw.startsWith("pkg:")) {
    const parsed = parsePurlSpec(raw, { requireVersion: true, allowLegacyPipe: false });
    if (!parsed.valid) {
      if (strict) throw new Error(parsed.error || `Invalid library PURL: ${raw}`);
      return empty;
    }
    return {
      namespace: parsed.type,
      meta: parsed.namespace,
      proj: parsed.name,
      release: parsed.version,
    };
  }
  if (raw.includes("|")) {
    const parts = raw.split("|");
    if (parts.length !== 4) {
      if (strict) throw new Error(`Legacy pipe library ID must have 4 segments (namespace|meta|proj|release): ${raw}`);
      return empty;
    }
    const [ns, meta, proj, release] = parts;
    const nsL = ns.trim().toLowerCase();
    if (!nsL || NON_PACKAGE_NAMESPACES.has(nsL)) {
      if (strict) throw new Error(`Identifier ${raw} is not a package library ID`);
      return empty;
    }
    const normMeta = canonicalNamespace(nsL, meta);
    const normProj = canonicalPackageName(nsL, proj);
    const normRel = release.trim();
    if (!normProj || !normRel) {
      if (strict) throw new Error(`Incomplete legacy pipe library ID: ${raw}`);
      return empty;
    }
    return {
      namespace: nsL,
      meta: normMeta,
      proj: normProj,
      release: normRel,
    };
  }
  if (strict) {
    throw new Error(
      `Unsupported or ambiguous package coordinate ${JSON.stringify(raw)}: expected standard PURL ('pkg:...') or legacy 4-part pipe ID ('namespace|meta|proj|release').`
    );
  }
  return empty;
}

export function parsePackageId(packageId, { strict = false } = {}) {
  const empty = {
    namespace: "",
    meta: "",
    proj: "",
  };
  const raw = String(packageId || "").trim();
  if (!raw) {
    if (strict) throw new Error("Empty package identifier");
    return empty;
  }
  if (raw.startsWith("pkg:")) {
    const parsed = parsePurlSpec(raw, { requireVersion: false, allowLegacyPipe: false });
    if (!parsed.valid) {
      if (strict) throw new Error(parsed.error || `Invalid package PURL: ${raw}`);
      return empty;
    }
    return {
      namespace: parsed.type,
      meta: parsed.namespace,
      proj: parsed.name,
    };
  }
  if (raw.includes("|")) {
    const parts = raw.split("|");
    if (parts.length === 3 || parts.length === 4) {
      const [ns, meta, proj] = parts;
      const nsL = ns.trim().toLowerCase();
      if (!nsL || NON_PACKAGE_NAMESPACES.has(nsL)) {
        if (strict) throw new Error(`Identifier ${raw} is not a package ID`);
        return empty;
      }
      const normMeta = canonicalNamespace(nsL, meta);
      const normProj = canonicalPackageName(nsL, proj);
      if (!normProj) {
        if (strict) throw new Error(`Incomplete legacy package ID: ${raw}`);
        return empty;
      }
      return {
        namespace: nsL,
        meta: normMeta,
        proj: normProj,
      };
    }
  }
  if (strict) {
    throw new Error(
      `Unsupported or ambiguous package identifier ${JSON.stringify(raw)}: expected standard PURL ('pkg:...') or legacy pipe ID ('namespace|meta|proj').`
    );
  }
  return empty;
}

export function canonicalLibraryId(libraryId, { strict = false } = {}) {
  const raw = String(libraryId || "").trim();
  if (raw.startsWith("pkg:")) {
    const spec = parsePurlSpec(raw, { requireVersion: true, allowLegacyPipe: false });
    if (!spec.valid) {
      if (strict) throw new Error(spec.error || `Invalid library PURL: ${raw}`);
      return "";
    }
    const normRel = canonicalRelease(spec.type, spec.version);
    return formatPurl(spec.type, spec.namespace, spec.name, normRel, spec.qualifiers, spec.subpath);
  }
  const parsed = parseLibraryId(raw, { strict });
  if (!parsed.namespace || !parsed.proj || !parsed.release) return "";
  const normRel = canonicalRelease(parsed.namespace, parsed.release);
  return formatPurl(parsed.namespace, parsed.meta, parsed.proj, normRel);
}

export function canonicalPackageId(packageId, { strict = false } = {}) {
  const parsed = parsePackageId(packageId, { strict });
  if (!parsed.namespace || !parsed.proj) return "";
  return formatPurl(parsed.namespace, parsed.meta, parsed.proj, null);
}

export function sameArtifactPurl(left, right) {
  const a = parsePurlSpec(left, { requireVersion: true, rejectRanges: true, allowLegacyPipe: true });
  const b = parsePurlSpec(right, { requireVersion: true, rejectRanges: true, allowLegacyPipe: true });
  return Boolean(a.valid && b.valid && a.purl === b.purl);
}

export function samePackagePurl(left, right) {
  const a = parsePurlSpec(left, { requireVersion: false, allowLegacyPipe: true });
  const b = parsePurlSpec(right, { requireVersion: false, allowLegacyPipe: true });
  return Boolean(a.valid && b.valid && a.package_purl && a.package_purl === b.package_purl);
}
