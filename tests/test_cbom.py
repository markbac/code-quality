"""CBOM generation (#93): CycloneDX 1.6 cryptographic assets found by a static scan."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

import main as fwlens_main
from fwlens.cbom import MAX_OCCURRENCES, build_cbom
from fwlens.config import ConfigError, load_config
from fwlens.crypto.catalog import bits_and_mode, load_catalog
from tests.cyclonedx import validate_bom

FILES = {
    "src/crypto.c": (
        '#include "mbedtls/aes.h"\n#include <openssl/evp.h>\n'
        "// mbedtls_md5_starts is only mentioned in this comment\n"
        'const char *s = "mbedtls_des_setkey_enc in a string";\n'
        "void f(void) {\n"
        "  mbedtls_aes_crypt_cbc(0);\n"
        "  EVP_EncryptInit_ex(0, EVP_aes_128_gcm(), 0, 0, 0);\n"
        "  EVP_sha1();\n"
        "  mbedtls_ecdsa_sign(0);\n"
        "  int curve = MBEDTLS_ECP_DP_SECP256R1;\n"
        "  (void)EVP_aes_256_ecb();\n"
        "}\n"
        "int suite = MBEDTLS_TLS_RSA_WITH_RC4_128_SHA;\n"
        "int good = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;\n"
    ),
    "src/main.c": "int main(void) { return 0; }\n",
    "Inc/mbedtls_config.h": "#define MBEDTLS_SHA256_C\n#undef MBEDTLS_DES_C\n",
    "Lib/mbedtls/library/sha256.c": "void mbedtls_sha256_starts(void) {}\n",
}


@pytest.fixture
def project(tmp_path):
    for name, text in FILES.items():
        f = tmp_path / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    return tmp_path


def make_config(root, extra=""):
    cfg = root / "config.yaml"
    cfg.write_text("project:\n  source_dir: .\nscope:\n  first_party: [src, Inc]\n  third_party_lib: [Lib]\n"
                   "tool:\n  target: native\n" + extra)
    return load_config(cfg)


def assets(doc):
    return {c["name"]: c for c in doc["components"] if c["type"] == "cryptographic-asset"}


def prop(component, name):
    return next((p["value"] for p in component["properties"] if p["name"] == name), None)


def test_cbom_validates_against_the_cyclonedx_1_6_schema(project):
    doc = build_cbom(make_config(project))
    validate_bom(doc)
    doc["components"][-1]["cryptoProperties"]["assetType"] = "bogus"
    with pytest.raises(Exception):
        validate_bom(doc)


def test_assets_come_from_code_not_from_comments_or_strings(project):
    found = assets(build_cbom(make_config(project)))
    assert "AES" in found and "AES-128-GCM" in found and "AES-256-ECB" in found
    assert "SHA-1" in found and "ECDSA (secp256r1)" in found
    assert "MD5" not in found and "DES" not in found           # comment and string only


def test_parameters_and_evidence(project):
    found = assets(build_cbom(make_config(project)))
    gcm = found["AES-128-GCM"]
    algo = gcm["cryptoProperties"]["algorithmProperties"]
    assert algo["primitive"] == "block-cipher" and algo["mode"] == "gcm" and algo["parameterSetIdentifier"] == "128"
    assert gcm["evidence"]["occurrences"] == [{"location": "src/crypto.c", "line": 7}]
    assert prop(gcm, "fwlens:evidence-kind") == "used"
    assert found["ECDSA (secp256r1)"]["cryptoProperties"]["algorithmProperties"]["curve"] == "secp256r1"


def test_weak_algorithms_and_modes_are_flagged(project):
    found = assets(build_cbom(make_config(project)))
    assert "collision" in prop(found["SHA-1"], "fwlens:weak")
    assert "ECB" in prop(found["AES-256-ECB"], "fwlens:weak")
    assert prop(found["AES-128-GCM"], "fwlens:weak") is None


def test_config_macros_count_only_when_defined(project):
    found = assets(build_cbom(make_config(project)))
    assert prop(found["SHA-256"], "fwlens:evidence-kind") == "configured"
    assert "DES" not in found                                   # #undef is not a configuration


def test_cipher_suites_are_listed_and_weak_ones_flagged(project):
    suites = assets(build_cbom(make_config(project)))["TLS cipher suites named in source"]
    names = [s["name"] for s in suites["cryptoProperties"]["protocolProperties"]["cipherSuites"]]
    assert "MBEDTLS_TLS_RSA_WITH_RC4_128_SHA" in names and "MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" in names
    weak = prop(suites, "fwlens:weak")
    assert "RC4" in weak and "AES_128_GCM" not in weak


def test_libraries_are_listed_and_provide_their_assets(project):
    doc = build_cbom(make_config(project))
    libs = {c["name"]: c for c in doc["components"] if c["type"] == "library"}
    assert set(libs) == {"Mbed TLS", "OpenSSL"}
    provides = {d["ref"]: d["provides"] for d in doc["dependencies"] if "provides" in d}
    assert any("crypto-mbedtls-aes" in r for r in provides["library-mbedtls"])
    app = next(d for d in doc["dependencies"] if d["ref"] == "application")
    assert len(app["dependsOn"]) == len(assets(doc))


def test_scan_scopes_extend_what_is_scanned(project):
    base = assets(build_cbom(make_config(project)))
    wider = assets(build_cbom(make_config(project, "cbom:\n  scan_scopes: [first_party, third_party_lib]\n")))
    assert "SHA-256" in base and "SHA-256" in wider
    assert wider["SHA-256"]["evidence"]["occurrences"] != base["SHA-256"]["evidence"]["occurrences"]


def test_the_document_says_it_is_detected_usage_only(project):
    meta = {p["name"]: p["value"] for p in build_cbom(make_config(project))["metadata"]["properties"]}
    assert "detected usage only, not a complete inventory" in meta["fwlens:completeness"]


def test_occurrences_are_capped_and_the_total_kept(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("void f(void) {\n" + "  EVP_sha256();\n" * 80 + "}\n")
    doc = build_cbom(make_config(tmp_path))
    sha = assets(doc)["SHA-256"]
    assert len(sha["evidence"]["occurrences"]) == MAX_OCCURRENCES
    assert prop(sha, "fwlens:occurrence-count") == "80" and prop(sha, "fwlens:occurrences-truncated")


def test_user_catalogue_adds_and_overrides_entries(project, tmp_path):
    extra = tmp_path / "extra"
    extra.mkdir()
    (extra / "mine.yaml").write_text(
        "library: {id: mbedtls, name: Mbed TLS}\n"
        "entries:\n"
        "  - {id: sha1, name: SHA-1, primitive: hash, identifiers: ['mbedtls_sha1*'], weak: 'house policy'}\n"
        "  - {id: vendor, name: VendorCipher, primitive: block-cipher, identifiers: ['vc_encrypt']}\n")
    (project / "src" / "v.c").write_text("void g(void){ vc_encrypt(); mbedtls_sha1_starts(0); }\n")
    doc = build_cbom(make_config(project, f"cbom:\n  extra_catalog_dirs: [{extra}]\n"))
    refs = {c["bom-ref"]: c for c in doc["components"]}
    assert "VendorCipher" in assets(doc)
    assert prop(refs["crypto-mbedtls-sha1"], "fwlens:weak") == "house policy"
    assert "collision" in prop(refs["crypto-openssl-sha1"], "fwlens:weak")      # other libraries untouched


def test_a_bad_catalogue_is_reported_with_its_file(tmp_path):
    (tmp_path / "bad.yaml").write_text("library: {id: x, name: X}\nentries:\n  - {id: a, name: A, primitive: nope, identifiers: [a]}\n")
    with pytest.raises(ConfigError, match=r"bad\.yaml.*primitive 'nope'"):
        load_catalog([tmp_path])


def test_bits_and_mode_from_names():
    assert bits_and_mode("EVP_aes_128_gcm") == ("128", "gcm")
    assert bits_and_mode("EVP_aes_256_xts") == ("256", "other")
    assert bits_and_mode("AES_encrypt") == (None, None)


def test_cli_writes_the_file_and_the_report_format_does_too(project, monkeypatch):
    make_config(project)
    monkeypatch.chdir(project)
    res = CliRunner().invoke(fwlens_main.cli, ["cbom", "--config", "config.yaml", "--output", "out/cbom.json"])
    assert res.exit_code == 0, res.output
    validate_bom(json.loads((project / "out" / "cbom.json").read_text()))
    out = " ".join(res.output.split())
    assert "flagged weak" in out and "detected usage only" in out
