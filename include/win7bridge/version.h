/**
 * win7bridge/version.h - Win7Bridge project version and common macros.
 *
 * Target: Windows 7 SP1 (NT 6.1). This header is platform-independent and
 * must pass a native `gcc -fsyntax-only` check (no Windows SDK required).
 */
#ifndef WIN7BRIDGE_VERSION_H
#define WIN7BRIDGE_VERSION_H

/* ---- Project version ---- */
#define WIN7BRIDGE_VERSION_MAJOR 0
#define WIN7BRIDGE_VERSION_MINOR 1
#define WIN7BRIDGE_VERSION_PATCH 0

/* Composed version as a packed integer (MMmmpp) and a string. */
#define WIN7BRIDGE_VERSION_NUM(maj, min, pat) \
    ((maj) * 10000 + (min) * 100 + (pat))
#define WIN7BRIDGE_VERSION \
    WIN7BRIDGE_VERSION_NUM(WIN7BRIDGE_VERSION_MAJOR, \
                           WIN7BRIDGE_VERSION_MINOR, \
                           WIN7BRIDGE_VERSION_PATCH)

#define WIN7BRIDGE_VERSION_STRING "0.1.0"

/* ---- Win7 target subsystem version (NT 6.1 = Windows 7 SP1) ----
 * The PE loader on Win7 requires MajorSubsystemVersion <= 6.1; the
 * compatibility layer rewrites anything newer down to this value.
 */
#define WIN7_TARGET_MAJOR 6
#define WIN7_TARGET_MINOR 1

/* ---- supportedOS GUID constants (application manifest) ----
 * Sourced from docs/api-diff.md (Microsoft Learn application-manifests).
 * Win11 reuses the Win10 GUID.
 */
/* Windows 7  : {35138b9a-5d96-4fbd-8e2d-a2440225f93a} */
#define WIN7BRIDGE_GUID_WIN7  "35138b9a-5d96-4fbd-8e2d-a2440225f93a"
/* Windows 10 : {8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a} */
#define WIN7BRIDGE_GUID_WIN10 "8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a"

/* ---- Helper macros ---- */
#define WIN7BRIDGE_STRINGIFY(x) #x
#define WIN7BRIDGE_STRINGIFY2(x) WIN7BRIDGE_STRINGIFY(x)
#define WIN7BRIDGE_VERSION_STRING_FULL \
    WIN7BRIDGE_STRINGIFY2(WIN7BRIDGE_VERSION_MAJOR) "." \
    WIN7BRIDGE_STRINGIFY2(WIN7BRIDGE_VERSION_MINOR) "." \
    WIN7BRIDGE_STRINGIFY2(WIN7BRIDGE_VERSION_PATCH)

/* Mark a declaration/definition as exported by the compatibility layer.
 * Defined empty for now; later phases may attach __declspec(dllexport)/
 * visibility attributes without touching call sites.
 */
#define WIN7BRIDGE_API

/* Compile-time sanity: ensure the target really is Win7 (NT 6.1). */
#define WIN7BRIDGE_TARGET_IS_WIN7 \
    ((WIN7_TARGET_MAJOR) == 6 && (WIN7_TARGET_MINOR) == 1)

#endif /* WIN7BRIDGE_VERSION_H */
