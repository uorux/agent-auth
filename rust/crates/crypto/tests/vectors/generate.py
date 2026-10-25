"""Known-answer vectors for agent-auth-crypto, produced by the Python
implementation (the source of truth for wire compatibility).

Run from the repository root with the project's venv:

    .venv/bin/python -I rust/crates/crypto/tests/vectors/generate.py

It writes python.json next to itself. It also checks, with the Python code,
the artifacts the Rust side produced (rust_sealed.txt: an envelope sealed by
EnvelopeSealer; rust_es256_token.txt: a token minted by TokenIssuer) and
records the outcome, so `cargo test` proves both directions. To refresh
those after changing python.json:

    cargo test -p agent-auth-crypto -- --ignored write_rust_artifacts
    .venv/bin/python -I rust/crates/crypto/tests/vectors/generate.py

Some inputs are random on every run (the RSA test key, envelope ids); the
file stays self-consistent, so regenerating is always safe.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[4]
sys.path.insert(0, str(REPO / "src"))

import jwt  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from agent_auth import crypto as api  # noqa: E402
from agent_auth.core import tokens  # noqa: E402
from agent_auth.daemon_common import crypto as dc  # noqa: E402
from agent_auth.daemon_common import hostexec, totp  # noqa: E402

out: dict = {}


def key_from_seed(byte: int):
    return dc.private_key_from_text(dc._b64(bytes([byte]) * 32))


# --- API keys ---------------------------------------------------------------
secret = "q8Uo2l3mZ_-xXvYkN0aB1cD2eF3gH4iJ5kL6mN7oP8Q"
full = f"aa_0123456789ab_{secret}"
key_id, parsed_secret = api.parse_api_key(full)
assert api.verify_secret(parsed_secret, api.hash_secret(secret))
out["api_key"] = {
    "full_key": full,
    "key_id": key_id,
    "secret": parsed_secret,
    "hash": api.hash_secret(secret),
}

# --- webhook ----------------------------------------------------------------
body = json.dumps({"type": "a2a_message", "thread_id": "t1", "from": "\u00e9l\u00e8ve"})
out["webhook"] = {
    "secret": "whsec-test-\u00e9",
    "body": body,
    "signature": api.sign_body("whsec-test-\u00e9", body.encode()),
}

# --- keys -------------------------------------------------------------------
k = dc.private_key_from_text(dc._b64(bytes(range(32))))
out["keys"] = {
    "private": dc.private_key_to_text(k),
    "public": dc.public_key_text(k),
    "fingerprint": dc.fingerprint(dc.public_key_text(k)),
}

# --- pairing ----------------------------------------------------------------
daemon_key, broker_key = key_from_seed(1), key_from_seed(2)
code = "K7QW-M3ZP-9HXT"
pk = dc.pairing_key(code)
out["pairing"] = {
    "code": code,
    "key": pk.hex(),
    "selector": dc.pairing_selector(pk),
    "role": "host",
    "name": "excelsior",
    "daemon_public": dc.public_key_text(daemon_key),
    "broker_public": dc.public_key_text(broker_key),
    "daemon_proof": dc.daemon_pair_proof(pk, "host", "excelsior", dc.public_key_text(daemon_key)),
    "broker_proof": dc.broker_pair_proof(
        pk, "host", "excelsior", dc.public_key_text(daemon_key), dc.public_key_text(broker_key)
    ),
}

# --- hello ------------------------------------------------------------------
bn, dn = dc._b64(bytes([3]) * 32), dc._b64(bytes(range(100, 132)))
p_d = json.dumps({"version": "0.1.0"})
p_b = json.dumps({"heartbeat_secs": 30})
out["hello"] = {
    "daemon_private": dc.private_key_to_text(daemon_key),
    "broker_private": dc.private_key_to_text(broker_key),
    "role": "sandbox",
    "name": "vm-1",
    "broker_nonce": bn,
    "daemon_nonce": dn,
    "daemon_params": p_d,
    "broker_params": p_b,
    "daemon_transcript": dc.hello_transcript("daemon", "sandbox", "vm-1", bn, dn, p_d).hex(),
    "session_id": dc.session_id("sandbox", "vm-1", bn, dn).hex(),
    "daemon_sig": dc.sign_hello(daemon_key, "daemon", "sandbox", "vm-1", bn, dn, p_d),
    "broker_sig": dc.sign_hello(broker_key, "broker", "sandbox", "vm-1", bn, dn, p_b),
}
assert dc.verify_hello(
    dc.public_key_text(daemon_key), out["hello"]["daemon_sig"], "daemon", "sandbox", "vm-1", bn, dn, p_d
)

# --- envelopes --------------------------------------------------------------
session = dc.session_id("host", "excelsior", bn, dn)
now = 1761400000.25
payload = {"type": "job.start", "job_id": "j1", "spec": {"argv": ["echo", "\u00e9\U0001F600"], "n": 3}}
sealed = dc.seal(
    broker_key, payload, sender="broker", audience="host:excelsior", session=session, seq=3, ttl=60, now=now
)
verifier = dc.EnvelopeVerifier(
    dc.public_key_text(broker_key), expected_sender="broker", expected_audience="host:excelsior", session=session
)
env = {
    "private": dc.private_key_to_text(broker_key),
    "session": session.hex(),
    "sender": "broker",
    "audience": "host:excelsior",
    "now": now,
    "payload": payload,
    "id": "0123456789abcdef0123456789abcdef",
    "python_sealed": sealed,
    "python_body": verifier.open(sealed, now=now),
}
rust_sealed = HERE / "rust_sealed.txt"
if rust_sealed.exists() and rust_sealed.read_text().strip():
    fresh = dc.EnvelopeVerifier(
        dc.public_key_text(broker_key), expected_sender="broker", expected_audience="host:excelsior", session=session
    )
    opened = fresh.open(rust_sealed.read_text().strip(), now=now)
    assert opened["seq"] == 7 and opened["spec"] == payload["spec"] and opened["id"] == env["id"], opened
    env["python_opened_rust_sealed"] = True
out["envelope"] = env

# --- TOTP -------------------------------------------------------------------
tsecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
out["totp"] = {
    "secret": tsecret,
    "codes": [{"step": s, "code": totp.code_at(tsecret, s)} for s in (0, 1, 59, 1000, 58713333, 2**33, 2**63)],
    "uri": totp.otpauth_uri(tsecret, "excelsior", "root-arm"),
}

# --- canonical JSON, digests, default dumps length ---------------------------
spec = {
    "kind": "run",
    "host": "excelsior",
    "tier": "user",
    "argv": ["sh", "-c", "echo 'h\u00e9llo' > /tmp/x\n\tdone"],
    "cwd": "/home/jrt",
    "env": {"LANG": "C.UTF-8", "A_B": "x\"y\\z"},
    "timeout": 600,
    "stdin": None,
}
canonical_values = [
    spec,
    {"b": 1, "a": 2, "\u00e9": 3, "Z": 4, "\U0001F600": 5, "\uffff": 6, "": 7},
    ["\x00\x01\x08\x09\x0a\x0b\x0c\x0d\x1f\x20\x7e\x7f\x80\xff", "\u2028\u2029", "/\\\"", "\ud7ff\ue000"],
    {"nested": {"deeper": [[], {}, [None, True, False]]}, "ints": [0, -1, 2**63 - 1, -(2**63), 2**64 - 1]},
    "",
    [],
    {},
    None,
]
out["canonical"] = [
    {
        "value": v,
        "canonical": json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
        "digest": hostexec.digest(v) if isinstance(v, dict) else __import__("hashlib").sha256(
            json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest(),
        "default_len": len(json.dumps(v)),
    }
    for v in canonical_values
]
float_values = [
    {"x": 1.5, "y": [1e16, 0.1, -0.0, 100.0, 5e-324, 1.7976931348623157e308, 1e-05, 0.0001, 123456789.125]},
    # Not 2.5e-308: serde_json (without its float_roundtrip feature) reads it
    # one ulp off, so its repr differs (see DEVIATIONS.md).
    [0.30000000000000004, 1e22, 12345678901234567.0, -2.5],
]
out["default_len"] = [
    {"value": v, "text": json.dumps(v, sort_keys=True), "len": len(json.dumps(v))} for v in float_values
]

# --- ES256 broker tokens ------------------------------------------------------
broker_signing = key_from_seed(9)
issuer = tokens.TokenIssuer(broker_signing, "https://broker.example/")
tnow = 1761400000
tokens.time.time = lambda: tnow  # mint() reads the clock
claims = {"grant": "g1", "server": "srv", "tools": ["a", "b"]}
ptoken, _ = issuer.mint(subject="agent-a", audience="mcp:srv", ttl_secs=300, claims=claims)
es = {
    "broker_private": dc.private_key_to_text(broker_signing),
    "issuer": "https://broker.example/",
    "kid": issuer.kid,
    "jwks": issuer.jwks(),
    "discovery": issuer.discovery(),
    "audience": "mcp:srv",
    "now": tnow,
    "claims": claims,
    "python_token": ptoken,
    "d_of_all_ones": ((int.from_bytes(b"\xff" * 48, "big") % (tokens._N - 1)) + 1).to_bytes(32, "big").hex(),
}
rust_token = HERE / "rust_es256_token.txt"
if rust_token.exists() and rust_token.read_text().strip():
    got = jwt.decode(
        rust_token.read_text().strip(),
        issuer._key.public_key(),
        algorithms=["ES256"],
        audience="mcp:srv",
        issuer=issuer.issuer,
        options={"require": ["exp", "iat", "sub", "aud", "iss"], "verify_exp": False, "verify_iat": False,
                 "verify_nbf": False},
    )
    assert got["grant"] == "g1", got
    es["python_verified_rust_token"] = True
out["es256"] = es

# --- GitHub App RS256 -----------------------------------------------------------
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pkcs1 = rsa_key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
).decode()
pkcs8 = rsa_key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
).decode()
gnow = 1761400000
out["github_app"] = {
    "pkcs1_pem": pkcs1,
    "pkcs8_pem": pkcs8,
    "app_id": "123456",
    "now": gnow,
    # Exactly what provisioners/github.py sends.
    "token": jwt.encode({"iat": gnow - 60, "exp": gnow + 540, "iss": "123456"}, pkcs1, algorithm="RS256"),
}

(HERE / "python.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
print("wrote", HERE / "python.json")
