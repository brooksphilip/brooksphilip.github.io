---
title: Why Trivy Shows Different Results (And Why It's Actually Worse)
date: 2025-11-24 11:44:00 +0000
categories: [Container Security, Scanners]
# tags: [trivy, grype]     # TAG names should always be lowercase
---

# Why Trivy Shows Different Results (And Why It's Actually Worse)

## Introduction

Lets first start by building two container images. One with a package manager and one without. 

With a Package manager

```bash
FROM alpine:3.19
RUN apk add --no-cache curl openssl
```

Without a Package manager

```bash
FROM alpine:3.19
RUN apk add --no-cache curl openssl && \
    rm -rf /var/cache/apk/* \
           /lib/apk/db/* \
           /etc/apk/
```

## Your Trivy Results

### WITHOUT Package Database
```
WARN: No OS package is detected.
pkg_num=0
Vulnerabilities: 0
```
**Result:** Clean scan, but with warnings

### WITH Package Database  
```
pkg_num=25
Vulnerabilities: 6 (3 MEDIUM, 3 LOW)
```
**Result:** Found vulnerabilities in busybox packages

## What's Happening

### Trivy's Detection Flow

```
┌─────────────────────────────────────────────────────────┐
│ 1. Check for OS Package Database                       │
│    - /lib/apk/db/installed (Alpine)                    │
│    - /var/lib/dpkg/status (Debian)                     │
│    - RPM DB (RHEL)                                      │
└─────────────────────────────────────────────────────────┘
                      │
                      ├─── Found? ──────► Parse packages ──► Query Trivy DB ──► Report CVEs
                      │
                      └─── Not Found? ──► STOP ──► Report 0 vulnerabilities
                                          (with warning)
```

### Without Package DB - Trivy Gives Up

```
WARN: No OS package is detected. Make sure you haven't deleted any files...
pkg_num=0
Vulnerabilities: 0
```

Trivy detects Alpine 3.19.9 but **cannot find any packages** because:
- `/lib/apk/db/installed` is deleted
- No other detection method for OS packages
- Falls back to **zero vulnerabilities** (false negative)

### With Package DB - Trivy Works Normally

```
pkg_num=25
Vulnerabilities: 6
```

Trivy reads `/lib/apk/db/installed` and finds all 25 packages, then reports CVEs.

## Why This Is Dangerous

### The Security Blind Spot

```
Hardened Image:
├── curl 8.14.1 (vulnerable to CVE-2025-9086 HIGH)
├── busybox 1.36.1 (vulnerable to CVE-2022-48174 CRITICAL)
└── openssl 3.1.4 (vulnerable to multiple CVEs)

Trivy without DB: "✓ Clean - 0 vulnerabilities"
Grype without DB: "✗ 10 vulnerabilities found"
```

This is why Grype is critical for hardened/distroless images!

## Comparison: Trivy vs Grype

### WITHOUT Package Database

| Scanner | Packages Found | Vulnerabilities | Detection Method |
|---------|----------------|-----------------|------------------|
| **Trivy** | 0 | 0 | ❌ None (gave up) |
| **Grype** | 3 | 10 (1 CRITICAL, 1 HIGH) | ✅ Binary fingerprinting |

### WITH Package Database

| Scanner | Packages Found | Vulnerabilities | Detection Method |
|---------|----------------|-----------------|------------------|
| **Trivy** | 25 | 6 (3 MEDIUM, 3 LOW) | ✅ APK database |
| **Grype** | 25 | 8 (2 MEDIUM, 6 LOW) | ✅ APK database |

## Why Trivy Shows Fewer CVEs Than Grype (Even WITH DB)

Looking at your results:
- **Trivy with DB:** 6 CVEs (busybox only)
- **Grype with DB:** 8 CVEs (busybox + curl + nghttp2)

Trivy is missing:
- `curl 8.14.1-r2` - CVE-2025-10966 (MEDIUM)
- `nghttp2-libs 1.58.0-r0` - CVE-2024-28182 (MEDIUM)

### Reasons for the Difference

1. **Database Update Timing**
   - Grype's DB may be more current
   - Trivy's Alpine DB may not have these CVEs yet

2. **Severity Filtering**
   - Trivy may filter out some CVEs by default
   - Different severity mappings between scanners

3. **CVE Acknowledgment**
   - Trivy only shows CVEs that Alpine officially tracks
   - Grype shows all NVD CVEs matching the version

## The Critical Difference

### Trivy Philosophy: "If I can't read the package DB, I won't guess"
- Conservative approach
- Avoids false positives
- **Creates massive false negatives** for hardened images
- Assumes missing DB = no packages = clean

### Grype Philosophy: "Let me try multiple detection methods"
- Aggressive approach  
- May have some false positives
- **Maintains visibility** on hardened images
- Assumes missing DB = need alternative detection

## Real-World Impact in Your Environment

## Why Both Scanners Are Valuable


## Technical Explanation: Why Trivy Can't Do Binary Fingerprinting

Trivy's architecture is optimized for speed via database lookups:

```go
// Simplified Trivy flow
if packageDB := findPackageDB(image); packageDB != nil {
    packages := parsePackageDB(packageDB)
    vulns := queryTrivyDB(packages)
    return vulns
} else {
    // No fallback for OS packages
    return []
}
```

Adding binary fingerprinting would:
- Significantly slow down scans
- Require maintaining binary signature databases
- Complicate the codebase
- Go against Trivy's "fast and simple" design philosophy

## Grype's Architecture

```go
// Simplified Grype flow
catalogers := []Cataloger{
    ApkCataloger,        // Try package DB first
    DpkgCataloger,
    RpmCataloger,
    BinaryFingerprinter, // Fall back to binary analysis
    FileMetadataAnalyzer,
}

packages := []
for cataloger := range catalogers {
    packages.append(cataloger.catalog(image))
}
return findVulnerabilities(packages)
```

## Bottom Line

**Trivy without package DB:** Reports 0 vulnerabilities ❌
**Grype without package DB:** Reports 10 vulnerabilities (including CRITICAL) ✅

**Which is correct?** Grype is correct. The vulnerabilities exist in the binaries, Trivy just can't see them.

This is exactly why you need Grype in your security stack for DoD environments where:
- Containers may be hardened/stripped
- Compliance requires comprehensive scanning  
- False negatives are worse than false positives
- Supply chain verification is critical

**My takeaway:** Never rely solely on Trivy for images where the package database might be removed. Always validate with Grype or a similar tool that does binary analysis.
