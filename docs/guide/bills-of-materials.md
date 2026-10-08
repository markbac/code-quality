# Bills of materials

[Back to the guide contents](../../FWLENS_GUIDE.md)

## Software bill of materials (SBOM)

`fwlens sbom --config config.yaml` writes a [CycloneDX](https://cyclonedx.org) 1.6 JSON bill of
materials to `<output.exports_dir>/sbom.cdx.json` (`--output FILE` overrides). Listing `sbom` in
`output.formats` makes `fwlens report` write it too. It needs the project description only: no
libclang run and no package manager.

What goes in:

- **Application**: the first-party sources and the headers in the include paths, as the
  `firmware` component in `metadata`, with a SHA-256 over the sorted `path:sha256` lines of its
  files. Its version is `sbom.application_version`, else `git describe`, else left out.
- **Components**: one per directory directly below a `scope.sdk` or `scope.third_party_lib`
  fragment (SDK directories are `framework`, the rest `library`), plus each `sbom.components`
  entry. Files outside every scope list go to a component named after their top-level directory,
  classified `unknown`.
- **Version**, first match wins: a `VERSION` file, `library.json` or `package.json`, a version
  macro in a header (`FOO_VERSION "1.2.3"` or a MAJOR/MINOR/PATCH set), `git describe` when the
  directory is a git checkout. Otherwise the version is left out and
  `fwlens:version-source` says `unknown`; it is never guessed.
- **Licence**, first match wins: `SPDX-License-Identifier` headers, then a `LICENSE` or `COPYING`
  file recognised by its text (MIT, BSD-2/3, ISC, Apache-2.0, MPL-2.0, GPL and LGPL). Otherwise
  none is stated and `fwlens:license-source` says why.
- **Dependencies**: between components, and from the application, where an `#include` name
  resolves to exactly one owner.
- **Linked**: with `project.map_file`, `fwlens:linked` is `true` or `false` per component by
  whether any of its objects appear in the map; without it the value is `unknown`.

```yaml
sbom:
  application_version: "1.4.2"
  include_files: false          # true adds each source file with its SHA-256
  components:                   # declare what cannot be detected; these win over detection
    - name: FreeRTOS
      path: Lib/FreeRTOS        # relative to config.yaml
      version: "10.4.3"
      license: MIT
      supplier: Amazon
      purl: pkg:github/FreeRTOS/FreeRTOS-Kernel@V10.4.3
```

### A hand-kept components file

Firmware that is not in the source tree (a bootloader in protected flash, modem firmware
delivered as a binary, a second processor, the toolchain) goes in a `components.yaml`:

```yaml
sbom:
  components_file: sbom/components.yaml
  application_version: "2.0.1"
```

The file has a `metadata` section (supplier, author, last review), an optional `product`, and any
number of component lists; a section may hold lists itself (`application_firmware` with
`first_party` and `third_party`). Per component: `name`, `version`, `type` (`device`, `firmware`,
`operating-system`, `library`, `framework`, `application`, `toolchain`, `platform`, `container`,
`data`, `file`, `device-driver`), `supplier`, `supplier_url`, `supplier_contact`, `license`,
`spdx_expression`, `license_notes`, `purl`, `cpe`, `location`, `description`, `notes`,
`copyright`, `cve_checked` and `compliance_actions`.

With a `product` section the product becomes the described component and the scanned firmware
one of its parts. Empty values and `unknown` are left out of the SBOM and listed in each
component's `fwlens:gaps` property and in `fwlens:components-file-gaps`, so a missing version,
licence or CVE check stays visible. The same file format works with
[py-sbomkit](https://github.com/markbac/py-sbomkit) (`py-sbomkit . --components components.yaml`).

> **Note:** this is an inventory of what is in the source tree, taken before the build
> (`lifecycles: pre-build`). FWLens is not a package manager, so it cannot see how a binary was
> assembled; whether a component is in the firmware needs `project.map_file`.

## Cryptography bill of materials (CBOM)

`fwlens cbom --config config.yaml` writes a CycloneDX 1.6 cryptography bill of materials to
`<output.exports_dir>/cbom.cdx.json` (`--output FILE` overrides; `cbom` in `output.formats` does
the same from `report`). Each algorithm or protocol the code names becomes a
`cryptographic-asset` component with `cryptoProperties`, its occurrences (file and line, at most
50, with the total in `fwlens:occurrence-count`), and the library that provides it.

How it works: comments and string literals are removed from the source, then every identifier is
matched against a catalogue of library functions and constants (and, failing that, against keywords, see below). Bundled coverage is Mbed TLS,
OpenSSL, wolfSSL, TinyCrypt, libsodium, micro-ecc, the PSA Crypto API and the STM32 HAL crypto
peripherals. Each asset has an evidence kind in `fwlens:evidence-kind`:

| Kind | Meaning |
|---|---|
| `used` | an identifier from the catalogue (or from `cbom.apis`) appears in code |
| `keyword` | the words in an identifier name an algorithm, such as `cy_aes_encrypt`: low confidence |
| `file`, `embedded` | a certificate or key found as a file, or inside source code |
| `configured` | a catalogue macro such as `MBEDTLS_SHA256_C` is `#define`d |
| `library-present` | a matching `#include`, library directory, or file named in the project (an IAR `.ewp` file entry or additional linker library, so a precompiled `.a` counts), with no algorithm seen (library components) |
| `library-name-match` | a library path in `scope.sdk` or `scope.third_party_lib`, or a linker library, whose name suggests cryptography (`crypt`, `cipher`, `ssl`, `tls`, `aes`, `rsa` ...) but that is not in the catalogue. It is listed with a note, and no algorithms are reported for it until you add catalogue entries |

Key size and mode are read from names such as `EVP_aes_128_gcm`; a curve is taken from curve names
in the same file. TLS cipher suite names (`..._TLS_..._WITH_...`) are collected on one protocol
asset. `fwlens:weak` carries the reason on MD5, SHA-1, DES, 3DES, RC4, ECB mode, SSL 3.0, TLS 1.0 and
1.1, and cipher suites using RC4, DES, 3DES, NULL, EXPORT or MD5.

### Keyword autodetection

An identifier the catalogue does not list is split into words (`cy_aes_128_cbc_encrypt`,
`AesCbcDecrypt`, `app_hmac_sha256_init`) and matched against the phrases in
`fwlens/crypto/keywords.yaml`: AES, 3DES, SHA-1 to SHA-3, MD5, HMAC, CMAC, RSA, ECDSA, ECDH, EdDSA,
X25519, PBKDF2, HKDF, DRBG, SSL/TLS, SSH and others. It finds wrapper functions and vendor
libraries FWLens has no entry for. Those assets have evidence kind `keyword` and
`fwlens:confidence: low`, because a name is weaker evidence than a library function.

Whole words only, so `shared` is not SHA. Words that are common outside cryptography (`des`, `ecc`,
`tls`, `dsa`, `sha`, `aria`) only count when the same identifier also has a cryptographic word such
as `key`, `cipher`, `encrypt`, `hash` or `init`: `des_set_key` is DES, `des_addr` is not. Key size
and mode come from the name (`aes_128_ecb`). `#include` lines and TLS cipher suite names are skipped.

### API names in the config

Name the functions and macros your project calls, without a catalogue file (`CyL_...` below are placeholders, use the names from your library's header):

```yaml
cbom:
  apis:
    - {library: cycurlib, name: AES-CBC, identifiers: [CyL_Blk_Enc, CyL_Blk_Dec], mode: cbc}
    - {library: cycurlib, name: ECDSA signing, identifiers: ["CyL_Sig_*"], primitive: signature, functions: [sign]}
    - {name: Vendor hash, identifiers: [Vendor_Hash]}
```

Each item is a catalogue entry (`name` and `identifiers` or `config_macros` are required, a trailing
`*` is a prefix) plus `library`: an existing library such as `cycurlib`, or a new name. Leave out
`primitive`, `functions`, `mode`, `parameter_set` or `weak` and they are taken from the keywords in
the name or the identifiers, so `name: AES-CBC` is a block cipher. An entry with an error is reported
as `cbom.apis[N]`.

### Certificates and keys

Unless `cbom.certificates: false`, the CBOM also lists:

- certificate files in the project (`.pem`, `.crt`, `.cer`, `.der`, `.key`, `.csr`, `.p7b`, `.p12`,
  `.pfx`, `.jks`, `.keystore`), skipping folders in `scope.sdk` or `scope.third_party_lib` unless
  those are in `cbom.scan_scopes`
- PEM blocks inside C strings and DER certificates written as byte arrays in source
- calls that handle certificates: parsing, chain verification, trust anchors, own certificate,
  private key loading and server name checks (Mbed TLS, OpenSSL, wolfSSL)
- functions that may use certificates, found in two steps. Step one picks candidates: a function
  whose name or parameter list has `cert`, `certificate`, `x509`, `crl`, `ocsp` or `truststore`.
  Step two reads each body and follows calls, then gives a confidence, shown on the asset and in
  `fwlens:analysis` with the reason per function:

  | Confidence | Meaning |
  |---|---|
  | `high` | calls a certificate API directly (the catalogue, or an entry with `kind: certificate` in `cbom.apis`) |
  | `medium` | named like a certificate function and the body handles certificate data (a certificate word in a name, or a PEM or `.crt` string), or it calls a high or medium function up to two calls away, so a wrapper with an unrelated name is found |
  | `low` | named like a certificate function and nothing else seen, or called but defined outside the scanned files |

  The other words in the name give the usage (verify, parse, trust anchor, own certificate,
  hostname, private key). Variables such as `cert_len` and words such as `certification` do not
  count. `cbom.autodetect: false` turns the name steps off and keeps the API step. Functions are
  found lexically, so one reached through a function pointer or built by a macro is missed.

Certificates are read directly (subject, issuer, validity, signature algorithm, key type and size)
and appear as `certificate` assets, keys and keystores as `related-crypto-material`. `fwlens:weak`
flags a certificate that has expired or expires within `cbom.certificate_expiry_days` (default 90),
a SHA-1 or MD5 signature, an RSA key under 2048 bits, a private key or keystore stored in the
source tree or embedded in code, and `*_VERIFY_NONE` (verification switched off) or
`*_VERIFY_OPTIONAL`. The same certificate in a file and in source is one asset with both places.
Certificate chains are not followed and nothing is checked against a trust store or revocation list.

```yaml
cbom:
  scan_scopes: [first_party]       # boundary classes scanned; add sdk or third_party_lib to
                                   # include library sources (they will then report themselves)
  extra_catalog_dirs: [./crypto]   # more catalogue files, read after the bundled ones
  autodetect: true                 # keyword autodetection (false switches it off)
  ignore_identifiers: ["debug_*"]  # identifier patterns autodetection skips
  keywords:                        # more phrases: words in order, the rest is a catalogue entry
    - {match: ["zorb"], name: Zorb cipher, primitive: block-cipher}
  apis: []                         # function and macro names, see above
  certificates: true               # certificate and key discovery
  certificate_expiry_days: 90      # warn when a certificate expires within this many days
```

ESCRYPT CycurLIB is in the catalogue as a library only. Its algorithms are found by keyword
(`CyL_AES_...`) or, exactly, by listing its function names under `cbom.apis` with `library: cycurlib`.
A library with `entries: []` is allowed in a catalogue file.

A catalogue file names a `library` (`id`, `name`, `include_fragments`, `dir_names`) and a list of
`entries`. An entry needs `id`, `name` and `identifiers` (a trailing `*` is a prefix) or
`config_macros`, and may set `primitive`, `mode`, `parameter_set`, `curve`, `functions`, `weak`
(a reason), `hardware`, `curve_aware`, `mode_from_name`, `bits_from_name` and, for protocols,
`kind: protocol`, `protocol` and `version`. An entry with the same `id` in the same library
replaces the bundled one. The bundled files in `fwlens/crypto/catalog/` are the reference, and
a malformed file stops the run with its name and the field at fault.

> **Warning:** the CBOM reports detected usage only and is not a complete inventory. A static scan
> cannot see runtime configuration, the protocol version actually negotiated, key material,
> hardware peripherals driven through raw registers, or calls made through function pointers and
> wrapper layers. The document states this in `metadata.properties`. Read an empty result as "none
> found by name", not "none present".
