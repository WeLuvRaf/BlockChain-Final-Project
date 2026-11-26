"""
Part (c): Hashing algorithms, digital signatures and security helpers.

Everything cryptographic used by the carbon credit ledger lives here:

* SHA-256 hashing over a *canonical* JSON encoding, so the same data always
  produces the same hash no matter how a dict happens to be ordered.
* ECDSA digital signatures on the secp256k1 curve (the curve used by Bitcoin
  and Ethereum) with SHA-256.  Every transaction and every block is signed.
* Addresses derived from public keys, so an account is identified by a short
  fingerprint instead of the full key.
* Merkle trees with RFC 6962 style domain separation, so a light client can
  prove one transaction is inside a block without downloading the whole block.
* Hashing of off-chain documents (MRV reports, sale contracts).  Only the hash
  goes on-chain, which keeps confidential details private but provable later
  (Proposal Q8 / Q9.4).
* Password-encrypted private key storage (key management, Proposal Q6).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, List, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

CURVE = ec.SECP256K1()
ADDRESS_PREFIX = "cc"  # "carbon credit"
ADDRESS_HEX_LENGTH = 40  # 160-bit fingerprint, like Ethereum addresses

# One-byte prefixes keep leaf hashes and internal-node hashes in different
# "domains".  Without them an attacker could present an internal node as if it
# were a leaf (a second-preimage attack on the tree).
_MERKLE_LEAF_PREFIX = b"\x00"
_MERKLE_NODE_PREFIX = b"\x01"

BytesLike = Union[bytes, str]


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------

def _to_bytes(data: BytesLike) -> bytes:
    return data.encode("utf-8") if isinstance(data, str) else data


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(data: BytesLike) -> str:
    """SHA-256 digest of bytes (or a UTF-8 string) as 64 hex characters."""
    return hashlib.sha256(_to_bytes(data)).hexdigest()


def hash_object(obj: Any) -> str:
    """SHA-256 of the canonical JSON form of any JSON-serialisable object."""
    return sha256_hex(canonical_json(obj))


def is_hex_hash(value: Any) -> bool:
    """True if value looks like a SHA-256 hex digest."""
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return value == value.lower()


def hash_document(content: BytesLike) -> str:
    """
    Fingerprint an off-chain document such as an MRV (measurement, reporting
    and verification) report or a private sale contract.  The document itself
    stays off-chain; only this hash is recorded on the ledger.
    """
    return sha256_hex(content)


def verify_document(content: BytesLike, expected_hash: str) -> bool:
    """Check that a document matches the hash stored on-chain."""
    return hmac.compare_digest(hash_document(content), str(expected_hash))


# --------------------------------------------------------------------------
# Merkle trees
# --------------------------------------------------------------------------

def _leaf(h: str) -> bytes:
    return hashlib.sha256(_MERKLE_LEAF_PREFIX + bytes.fromhex(h)).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_MERKLE_NODE_PREFIX + left + right).digest()


def merkle_root(leaf_hashes: List[str]) -> str:
    """
    Merkle root of a list of hex hashes.

    An unpaired node at the end of a level is carried up unchanged rather than
    duplicated.  Duplicating it (as Bitcoin does) lets two different
    transaction lists share one root (CVE-2012-2459).
    """
    if not leaf_hashes:
        return sha256_hex(b"")
    level = [_leaf(h) for h in leaf_hashes]
    while len(level) > 1:
        nxt = [_node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0].hex()


def merkle_proof(leaf_hashes: List[str], index: int) -> List[Tuple[str, str]]:
    """
    Proof that leaf_hashes[index] is in the tree: a list of (sibling_hex, side)
    where side is "L" if the sibling sits on the left, "R" if on the right.
    """
    if not 0 <= index < len(leaf_hashes):
        raise IndexError("leaf index out of range")
    level = [_leaf(h) for h in leaf_hashes]
    proof: List[Tuple[str, str]] = []
    pos = index
    while len(level) > 1:
        sibling = pos ^ 1
        if sibling < len(level):
            proof.append((level[sibling].hex(), "L" if sibling < pos else "R"))
        nxt = [_node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
        pos //= 2
    return proof


def verify_merkle_proof(leaf_hash: str, proof: List[Tuple[str, str]], root: str) -> bool:
    """Recompute the root from one leaf and its proof and compare."""
    try:
        acc = _leaf(leaf_hash)
        for sibling_hex, side in proof:
            sibling = bytes.fromhex(sibling_hex)
            if side == "L":
                acc = _node(sibling, acc)
            elif side == "R":
                acc = _node(acc, sibling)
            else:
                return False
        return hmac.compare_digest(acc.hex(), str(root))
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------
# Keys, addresses and digital signatures
# --------------------------------------------------------------------------

def _load_public_key(public_key_hex: str) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, bytes.fromhex(public_key_hex))


def is_valid_public_key(public_key_hex: Any) -> bool:
    """True if the value is a compressed secp256k1 public key on the curve."""
    if not isinstance(public_key_hex, str) or len(public_key_hex) != 66:
        return False
    try:
        _load_public_key(public_key_hex)
        return True
    except (ValueError, TypeError):
        return False


def address_from_public_key(public_key_hex: str) -> str:
    """Account address: 'cc' + the first 160 bits of SHA-256(public key)."""
    digest = hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()
    return ADDRESS_PREFIX + digest[:ADDRESS_HEX_LENGTH]


def is_valid_address(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if len(value) != len(ADDRESS_PREFIX) + ADDRESS_HEX_LENGTH or not value.startswith(ADDRESS_PREFIX):
        return False
    body = value[len(ADDRESS_PREFIX):]
    return all(c in "0123456789abcdef" for c in body)


def verify_signature(public_key_hex: str, data: BytesLike, signature_hex: str) -> bool:
    """
    Verify an ECDSA/SHA-256 signature.  Returns False (never raises) for a bad
    signature, a malformed key or malformed hex, so callers can treat any
    garbage input as "not signed".
    """
    try:
        key = _load_public_key(public_key_hex)
        key.verify(bytes.fromhex(signature_hex), _to_bytes(data), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class KeyPair:
    """
    An ECDSA secp256k1 key pair: one participant's identity on the ledger
    (registry, project developer, buyer, validator or governance member).
    """

    def __init__(self, private_key: Optional[ec.EllipticCurvePrivateKey] = None):
        self._private_key = private_key or ec.generate_private_key(CURVE)
        if not isinstance(self._private_key.curve, ec.SECP256K1):
            raise ValueError("only secp256k1 keys are supported")

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls()

    @property
    def public_key_hex(self) -> str:
        """33-byte compressed public key as hex (66 characters)."""
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        ).hex()

    @property
    def address(self) -> str:
        return address_from_public_key(self.public_key_hex)

    def sign(self, data: BytesLike) -> str:
        """Sign data with ECDSA/SHA-256 and return the DER signature as hex."""
        return self._private_key.sign(_to_bytes(data), ec.ECDSA(hashes.SHA256())).hex()

    def to_pem(self, password: Optional[str] = None) -> bytes:
        """
        Export the private key as PKCS#8 PEM.  With a password the key is
        encrypted at rest, so a stolen wallet file is useless on its own.
        """
        encryption: serialization.KeySerializationEncryption
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
        else:
            encryption = serialization.NoEncryption()
        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )

    @classmethod
    def from_pem(cls, pem: bytes, password: Optional[str] = None) -> "KeyPair":
        key = serialization.load_pem_private_key(
            pem, password=password.encode("utf-8") if password else None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("not an elliptic-curve private key")
        return cls(key)

    def __repr__(self) -> str:  # never print the private key
        return f"KeyPair(address={self.address})"
