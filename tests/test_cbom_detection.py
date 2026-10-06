"""CBOM keyword autodetection, API names in the YAML config, and certificate discovery."""

from __future__ import annotations

import base64
import shutil
from pathlib import Path

import pytest

from fwlens.cbom import build_cbom
from fwlens.config import ConfigError, load_config
from fwlens.crypto import certs
from fwlens.crypto.keywords import load_keywords
from tests.cyclonedx import validate_bom

CERTS = Path(__file__).parent / "fixtures" / "certs"


def make_config(root, extra=""):
    cfg = root / "config.yaml"
    cfg.write_text("project:\n  source_dir: .\nscope:\n  first_party: [src]\n  third_party_lib: [lib]\n"
                   "tool:\n  target: native\n" + extra)
    return load_config(cfg)


def write(root, files):
    for name, text in files.items():
        f = root / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)


def assets(doc):
    return {c["name"]: c for c in doc["components"] if c["type"] == "cryptographic-asset"}


def prop(component, name):
    return next((p["value"] for p in component["properties"] if p["name"] == name), None)


# --- keywords ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("token, names", [
    ("cy_aes_encrypt", {"AES"}),
    ("AesCbcDecrypt", {"AES"}),
    ("app_hmac_sha256_init", {"HMAC", "SHA-256"}),
    ("Sha1Update", {"SHA-1"}),
    ("des3_set_key", {"3DES"}),
    ("des_set_key", {"DES"}),
    ("ed25519_sign", {"EdDSA"}),
    ("rsa_pkcs1_verify", {"RSA"}),
    ("des_addr", set()),                # destination, not the cipher: no cryptographic word with it
    ("shared_state", set()),            # whole words only
    ("ecc_error_count", set()),         # ECC memory
    ("tls_get_value", set()),           # thread-local storage
])
def test_keywords_name_the_asset_from_words_in_the_identifier(token, names):
    assert {h.entry.name for h in load_keywords().match(token)} == names


def test_keywords_read_key_size_and_mode_from_the_name():
    hit = load_keywords().match("cy_aes_128_ecb_crypt")[0]
    assert (hit.entry.name, hit.bits, hit.mode) == ("AES", "128", "ecb")


def test_autodetected_assets_are_marked_low_confidence_and_can_be_switched_off_or_ignored(tmp_path):
    write(tmp_path, {"src/main.c": ("#include \"cycurlib/cy_aes.h\"\nvoid f(void){ cy_aes_128_cbc_encrypt(0); "
                                    "app_sha256_init(); debug_aes_trace(); }\n")})
    doc = build_cbom(make_config(tmp_path))
    found = assets(doc)
    assert {"AES-128-CBC", "SHA-256"} <= set(found)
    assert prop(found["AES-128-CBC"], "fwlens:evidence-kind") == "keyword"
    assert "low" in prop(found["AES-128-CBC"], "fwlens:confidence")
    assert "AES-128-CBC" not in str(prop(found["SHA-256"], "fwlens:identifiers"))
    validate_bom(doc)

    ignored = assets(build_cbom(make_config(tmp_path, "cbom:\n  ignore_identifiers: ['debug_*']\n")))
    assert "debug_aes_trace" not in str(ignored["AES-128-CBC"]["properties"]) and "AES" in " ".join(ignored)
    assert assets(build_cbom(make_config(tmp_path, "cbom:\n  autodetect: false\n"))) == {}


def test_extra_keywords_extend_the_bundled_ones(tmp_path):
    write(tmp_path, {"src/main.c": "void f(void){ vendor_zorb_encrypt(); }\n"})
    cfg = make_config(tmp_path, "cbom:\n  keywords:\n    - {match: [zorb], name: Zorb, primitive: block-cipher}\n")
    assert "Zorb" in assets(build_cbom(cfg))


# --- apis in the config -----------------------------------------------------------------------------------------

def test_api_names_from_the_config_are_catalogue_entries_of_their_library(tmp_path):
    write(tmp_path, {"src/main.c": "void f(void){ CyL_Blk_Enc(0); CyL_Sig_Make(0); }\n",
                     "lib/cycurlib/cycurlib.h": "void CyL_Blk_Enc(void*);\n"})
    extra = ("cbom:\n  autodetect: false\n  apis:\n"
             "    - {library: cycurlib, name: AES-CBC, identifiers: [CyL_Blk_Enc], mode: cbc}\n"
             "    - {library: cycurlib, name: ECDSA signing, identifiers: ['CyL_Sig_*'], primitive: signature,"
             " functions: [sign]}\n")
    doc = build_cbom(make_config(tmp_path, extra))
    found = assets(doc)
    assert prop(found["AES-CBC"], "fwlens:library") == "ESCRYPT CycurLIB"
    assert found["AES-CBC"]["cryptoProperties"]["algorithmProperties"]["primitive"] == "block-cipher"   # from the name
    assert found["ECDSA signing"]["cryptoProperties"]["algorithmProperties"]["cryptoFunctions"] == ["sign"]
    assert prop(found["AES-CBC"], "fwlens:evidence-kind") == "used"
    assert any(d["ref"] == "library-cycurlib" and len(d["provides"]) == 2 for d in doc["dependencies"] if "provides" in d)
    validate_bom(doc)


def test_api_entries_without_a_library_do_not_invent_a_library_component(tmp_path):
    write(tmp_path, {"src/main.c": "void f(void){ Vendor_Hash(0); }\n"})
    doc = build_cbom(make_config(tmp_path, "cbom:\n  autodetect: false\n  apis:\n"
                                           "    - {name: Vendor hash, identifiers: [Vendor_Hash], primitive: hash}\n"))
    assert "Vendor hash" in assets(doc)
    assert [c for c in doc["components"] if c["type"] == "library"] == []


def test_a_bad_api_entry_names_the_entry(tmp_path):
    write(tmp_path, {"src/main.c": "int x;\n"})
    with pytest.raises(ConfigError, match=r"cbom.apis\[1\]"):
        build_cbom(make_config(tmp_path, "cbom:\n  apis:\n    - {name: Broken}\n"))
    with pytest.raises(ConfigError, match="cbom.apis must be a list"):
        make_config(tmp_path, "cbom:\n  apis: nope\n")


# --- certificates -----------------------------------------------------------------------------------------------

def test_certificate_fields_are_read_from_the_der():
    now = certs.datetime(2026, 10, 6, tzinfo=certs.timezone.utc)
    good = certs.scan_file(CERTS / "good.pem", "good.pem", now, 90)[0].certificate
    assert good is not None
    assert (good.subject, good.key, good.signature, good.self_signed) == (
        "CN=meter.acme.example, O=Acme, C=GB", "RSA-2048", "sha256WithRSAEncryption", True)
    assert good.not_after.year == 2049
    ec = certs.scan_file(CERTS / "ec.der", "ec.der", now, 90)[0].certificate
    assert ec is not None and ec.key == "EC secp256r1" and ec.signature == "ecdsa-with-SHA256"


def test_checks_catch_expiry_weak_signatures_and_short_keys():
    now = certs.datetime(2026, 10, 6, tzinfo=certs.timezone.utc)
    expired = certs.scan_file(CERTS / "expired.pem", "expired.pem", now, 90)[0]
    assert any("expired 2020-01-01" in p for p in expired.problems)
    weak = certs.scan_file(CERTS / "weak.pem", "weak.pem", now, 90)[0]
    assert any("SHA-1" in p for p in weak.problems) and any("below 2048" in p for p in weak.problems)
    assert certs.scan_file(CERTS / "good.pem", "good.pem", now, 90)[0].problems == []
    soon = certs.datetime(2049, 11, 1, tzinfo=certs.timezone.utc)
    assert any("within 90 days" in p for p in certs.scan_file(CERTS / "good.pem", "good.pem", soon, 90)[0].problems)


def test_garbage_is_not_a_certificate():
    with pytest.raises(ValueError):
        certs.parse_certificate(b"\x30\x03\x02\x01\x00")
    assert certs.scan_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", "x", "file",
                           certs.datetime.now(certs.timezone.utc), 90)[0].name == "Certificate (unreadable)"


def _c_string(pem: str) -> str:
    return "\n".join(f'    "{line}\\n"' for line in pem.strip().splitlines())


def test_the_cbom_lists_certificates_keys_and_certificate_calls(tmp_path):
    for name in ("good.pem", "expired.pem", "weak.pem", "ec.der"):
        (tmp_path / "certs").mkdir(exist_ok=True)
        shutil.copy(CERTS / name, tmp_path / "certs" / name)
    (tmp_path / "certs" / "device.p12").write_bytes(b"\x30\x82\x00\x00")
    der = (CERTS / "ec.der").read_bytes()
    array = ", ".join(f"0x{b:02x}" for b in der)
    private = "-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(b"not a real key" * 4).decode() + "\n-----END PRIVATE KEY-----"
    write(tmp_path, {"src/main.c": (
        f"static const char ca_pem[] =\n{_c_string((CERTS / 'weak.pem').read_text())};\n"
        f"static const unsigned char ca_der[] = {{ {array} }};\n"
        f"static const char key_pem[] =\n{_c_string(private)};\n"
        "void f(void *c) {\n"
        "  mbedtls_x509_crt_parse(c, ca_der, sizeof ca_der);\n"
        "  mbedtls_ssl_conf_ca_chain(c, c, 0);\n"
        "  mbedtls_ssl_conf_authmode(c, MBEDTLS_SSL_VERIFY_NONE);\n"
        "}\n")})
    doc = build_cbom(make_config(tmp_path))
    comps = [c for c in doc["components"] if c["type"] == "cryptographic-asset"]
    by_kind = {}
    for c in comps:
        by_kind.setdefault(c["cryptoProperties"]["assetType"], []).append(c)
    names = {c["name"] for c in by_kind["certificate"]}
    assert {"CN=meter.acme.example, O=Acme, C=GB", "CN=old-ca.acme.example, O=Acme", "CN=legacy.acme.example, O=Acme",
            "CN=ec.acme.example, O=Acme"} <= names
    weak = {c["name"]: prop(c, "fwlens:weak") for c in comps if prop(c, "fwlens:weak")}
    assert "expired" in weak["CN=old-ca.acme.example, O=Acme"]
    legacy = next(c for c in comps if c["name"] == "CN=legacy.acme.example, O=Acme")
    assert prop(legacy, "fwlens:evidence-kind") == "embedded,file" and prop(legacy, "fwlens:occurrence-count") == "2"
    ec = next(c for c in comps if c["name"] == "CN=ec.acme.example, O=Acme")
    assert prop(ec, "fwlens:public-key") == "EC secp256r1" and prop(ec, "fwlens:evidence-kind") == "embedded,file"
    assert "embedded in source" in weak["Private key: src/main.c"]
    assert "keystore" in weak["Keystore: certs/device.p12"]
    assert "switched off" in weak["Certificate verification disabled"]
    usage = {prop(c, "fwlens:certificate-usage") for c in comps if prop(c, "fwlens:certificate-usage")}
    assert usage == {"parse", "trust-anchor", "verify-disabled"}
    validate_bom(doc)


def test_certificates_can_be_switched_off_and_library_folders_are_respected(tmp_path):
    (tmp_path / "certs").mkdir()
    shutil.copy(CERTS / "good.pem", tmp_path / "certs" / "good.pem")
    (tmp_path / "lib" / "vendor").mkdir(parents=True)
    shutil.copy(CERTS / "ec.pem", tmp_path / "lib" / "vendor" / "ec.pem")
    write(tmp_path, {"src/main.c": "int x;\n"})

    def found(extra=""):
        return {c["name"] for c in build_cbom(make_config(tmp_path, extra))["components"]
                if c.get("cryptoProperties", {}).get("assetType") == "certificate"}
    assert found() == {"CN=meter.acme.example, O=Acme, C=GB"}                # lib/ is third party, not scanned
    assert "CN=ec.acme.example, O=Acme" in found("cbom:\n  scan_scopes: [first_party, third_party_lib]\n")
    assert found("cbom:\n  certificates: false\n") == set()
