"""
Part (b): Blockchain implementation for a carbon credit registry.

The ledger records the full life of every carbon credit (issuance, each change
of owner, retirement, and governed reversal) as signed transactions grouped
into hash-linked, signed blocks.  It follows the design in the research
proposal (Part 1):

* Public reads, permissioned writes (Q8).  Anyone can read and verify the
  chain.  Only accredited registries can issue credits, and only approved
  validator nodes can seal blocks.
* Energy-efficient consensus (Q8).  Proof of Authority: a block is valid only
  if it is signed by one of the validators named in the genesis block.  There
  is no proof-of-work mining.
* One unique global serial number per credit (Q9.2), e.g. RA-AMZ001-2024-000001.
* Double counting is rejected automatically (Q2):
    - a credit can only be moved or retired by its current owner;
    - a retired or cancelled credit can never move again;
    - a project belongs to one registry, so a second registry cannot issue
      credits for the same tonnes;
    - the same MRV evidence (report hash) cannot back two issuances;
    - credits cannot be issued for a future vintage (no ex-ante credits).
* Buffer pool (Q9.3).  A share of each issuance can be held back as insurance
  against reversals such as a forest fire.
* Governed corrections (Q9.3).  Cancelling credits or adding/removing a
  registry needs an M-of-N multi-signature from the governance group (for
  example standard body, host government and independent auditor).  The
  correction is a new visible transaction; nothing is erased.
* Off-chain evidence (Q8, Q9.4).  Only the SHA-256 hash of an MRV report is
  stored on-chain.

Typical use (see main() at the bottom for a full walkthrough):

    ledger = CarbonLedger.create(governance_keys=[...], threshold=2,
                                 validator_keys=[...], issuers=[...])
    tx = ledger.build_transaction(registry_kp, ISSUE, {...})
    ledger.submit(tx)
    ledger.seal_block(validator_kp)
"""

from __future__ import annotations

import copy
import json
import math
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from security import (
    KeyPair,
    address_from_public_key,
    canonical_json,
    hash_object,
    is_hex_hash,
    is_valid_address,
    is_valid_public_key,
    merkle_proof,
    merkle_root,
    verify_merkle_proof,
    verify_signature,
)

# Transaction types ---------------------------------------------------------
GENESIS = "GENESIS"
ADD_ISSUER = "ADD_ISSUER"
REVOKE_ISSUER = "REVOKE_ISSUER"
ISSUE = "ISSUE"
TRANSFER = "TRANSFER"
RETIRE = "RETIRE"
REVERSE = "REVERSE"

GOVERNANCE_TX_TYPES = {ADD_ISSUER, REVOKE_ISSUER, REVERSE}
TX_TYPES = {ADD_ISSUER, REVOKE_ISSUER, ISSUE, TRANSFER, RETIRE, REVERSE}

# Credit statuses -----------------------------------------------------------
ACTIVE = "ACTIVE"
RETIRED = "RETIRED"
CANCELLED = "CANCELLED"

BUFFER_POOL = "BUFFER_POOL"  # owner of buffer credits; no private key exists for it

# Limits --------------------------------------------------------------------
MAX_ISSUANCE = 100_000
MAX_SERIALS_PER_TX = 10_000
MAX_TXS_PER_BLOCK = 500
MAX_BUFFER_PERCENT = 50
MAX_CLOCK_SKEW = 300  # seconds a transaction may be ahead of its block
MAX_TEXT = 200
MIN_VINTAGE = 1990
MAX_TIMESTAMP = 32503680000  # year 3000

ZERO_HASH = "0" * 64
_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.]{0,39}$")
_TX_DOMAIN = "carbon-ledger/tx/v1"
_BLOCK_DOMAIN = "carbon-ledger/block/v1:"


class LedgerError(Exception):
    """Raised when a transaction or block breaks a ledger rule."""


def _valid_timestamp(value: Any) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value) and 0 <= value < MAX_TIMESTAMP)


# ==========================================================================
# Transactions
# ==========================================================================

@dataclass
class Transaction:
    """
    A signed instruction to change the ledger.

    tx_id is the hash of the signed body (type, sender, payload, nonce,
    timestamp) and deliberately excludes the signature, so a transaction's
    identity cannot be changed by re-encoding its signature.
    """

    tx_type: str
    sender: str  # sender's public key (hex); empty only for GENESIS
    payload: Dict[str, Any]
    nonce: int
    timestamp: float
    signature: str = ""
    approvals: List[Dict[str, str]] = field(default_factory=list)  # governance co-signatures

    def body(self) -> Dict[str, Any]:
        return {
            "tx_type": self.tx_type,
            "sender": self.sender,
            "payload": self.payload,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
        }

    @property
    def tx_id(self) -> str:
        return hash_object(self.body())

    def signing_bytes(self) -> bytes:
        # The domain tag stops a transaction signature from being replayed as
        # a block signature or as a signature in some other system.
        return canonical_json({"domain": _TX_DOMAIN, **self.body()})

    @property
    def sender_address(self) -> str:
        return address_from_public_key(self.sender) if self.sender else ""

    def sign(self, keypair: KeyPair) -> "Transaction":
        if keypair.public_key_hex != self.sender:
            raise LedgerError("only the sender can sign a transaction")
        self.signature = keypair.sign(self.signing_bytes())
        return self

    def approve(self, keypair: KeyPair) -> "Transaction":
        """Add a governance co-signature (for multi-signature actions)."""
        pk = keypair.public_key_hex
        if pk == self.sender or any(a.get("public_key") == pk for a in self.approvals):
            return self
        self.approvals.append({"public_key": pk, "signature": keypair.sign(self.signing_bytes())})
        return self

    def has_valid_signature(self) -> bool:
        return bool(self.sender) and verify_signature(self.sender, self.signing_bytes(), self.signature)

    def valid_signers(self) -> Set[str]:
        """Public keys (sender and approvers) whose signatures check out."""
        signers: Set[str] = set()
        data = self.signing_bytes()
        if self.has_valid_signature():
            signers.add(self.sender)
        for approval in self.approvals:
            pk, sig = approval.get("public_key", ""), approval.get("signature", "")
            if verify_signature(pk, data, sig):
                signers.add(pk)
        return signers

    def leaf_hash(self) -> str:
        """Merkle leaf: covers the whole transaction including signatures."""
        return hash_object(self.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        return {
            **self.body(),
            "signature": self.signature,
            "approvals": [dict(a) for a in self.approvals],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Transaction":
        if not isinstance(data, dict):
            raise LedgerError("malformed transaction: expected an object")
        try:
            approvals = data.get("approvals", [])
            if not isinstance(approvals, list):
                raise TypeError("approvals must be a list")
            parsed_approvals = []
            for approval in approvals:
                if not isinstance(approval, dict):
                    raise TypeError("each approval must be an object")
                public_key = approval["public_key"]
                signature = approval["signature"]
                if not isinstance(public_key, str) or not isinstance(signature, str):
                    raise TypeError("approval fields must be text")
                parsed_approvals.append({"public_key": public_key, "signature": signature})
            tx = cls(
                tx_type=data["tx_type"],
                sender=data["sender"],
                payload=copy.deepcopy(data["payload"]),
                nonce=data["nonce"],
                timestamp=data["timestamp"],
                signature=data.get("signature", ""),
                approvals=parsed_approvals,
            )
        except (KeyError, TypeError) as exc:
            raise LedgerError(f"malformed transaction: {exc}") from exc
        if not isinstance(tx.tx_type, str) or not isinstance(tx.sender, str) \
                or not isinstance(tx.payload, dict) or not isinstance(tx.signature, str) \
                or type(tx.nonce) is not int or not _valid_timestamp(tx.timestamp):
            raise LedgerError("malformed transaction: wrong field types")
        try:
            tx.signing_bytes()
        except (TypeError, ValueError) as exc:
            raise LedgerError(f"malformed transaction payload: {exc}") from exc
        return tx


# ==========================================================================
# Blocks
# ==========================================================================

@dataclass
class Block:
    """A batch of transactions, hash-linked to the previous block and signed by a validator."""

    index: int
    timestamp: float
    previous_hash: str
    transactions: List[Transaction]
    validator: str = ""  # validator's public key (hex); empty for genesis
    merkle_root: str = ""
    signature: str = ""

    def compute_merkle_root(self) -> str:
        return merkle_root([tx.leaf_hash() for tx in self.transactions])

    def header(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "validator": self.validator,
            "tx_count": len(self.transactions),
        }

    @property
    def hash(self) -> str:
        return hash_object(self.header())

    def _signing_bytes(self) -> bytes:
        return (_BLOCK_DOMAIN + self.hash).encode("utf-8")

    def seal(self, keypair: KeyPair) -> "Block":
        self.validator = keypair.public_key_hex
        self.merkle_root = self.compute_merkle_root()
        self.signature = keypair.sign(self._signing_bytes())
        return self

    def has_valid_signature(self) -> bool:
        return verify_signature(self.validator, self._signing_bytes(), self.signature)

    def to_dict(self) -> Dict[str, Any]:
        return {
            **self.header(),
            "hash": self.hash,
            "signature": self.signature,
            "transactions": [tx.to_dict() for tx in self.transactions],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Block":
        if not isinstance(data, dict):
            raise LedgerError("malformed block: expected an object")
        try:
            txs = data["transactions"]
            if not isinstance(txs, list):
                raise TypeError("transactions must be a list")
            block = cls(
                index=data["index"],
                timestamp=data["timestamp"],
                previous_hash=data["previous_hash"],
                transactions=[Transaction.from_dict(t) for t in txs],
                validator=data.get("validator", ""),
                merkle_root=data["merkle_root"],
                signature=data.get("signature", ""),
            )
        except (KeyError, TypeError) as exc:
            raise LedgerError(f"malformed block: {exc}") from exc
        if type(block.index) is not int or not _valid_timestamp(block.timestamp) \
                or not all(isinstance(v, str) for v in (block.previous_hash, block.validator,
                                                        block.merkle_root, block.signature)):
            raise LedgerError("malformed block: wrong field types")
        if block.index < 0 or not is_hex_hash(block.previous_hash) \
                or not is_hex_hash(block.merkle_root):
            raise LedgerError("malformed block: invalid index or hash")
        if "tx_count" in data and (type(data["tx_count"]) is not int
                                   or data["tx_count"] != len(block.transactions)):
            raise LedgerError("malformed block: transaction count does not match")
        try:
            computed_hash = block.hash
        except (TypeError, ValueError) as exc:
            raise LedgerError(f"malformed block: {exc}") from exc
        if "hash" in data and data["hash"] != computed_hash:
            raise LedgerError("malformed block: stored hash does not match its header")
        return block


# ==========================================================================
# World state (rebuilt by replaying the chain)
# ==========================================================================

def _check_text(payload: Dict[str, Any], key: str, required: bool = True) -> str:
    value = payload.get(key, "")
    if not isinstance(value, str):
        raise LedgerError(f"'{key}' must be text")
    value = value.strip()
    if required and not value:
        raise LedgerError(f"'{key}' is required")
    if len(value) > MAX_TEXT:
        raise LedgerError(f"'{key}' is longer than {MAX_TEXT} characters")
    return value


def _check_code(payload: Dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not _CODE_RE.match(value):
        raise LedgerError(f"'{key}' must be 1-40 letters, digits, '_' or '.'")
    return value


def _check_int(payload: Dict[str, Any], key: str, low: int, high: int) -> int:
    value = payload.get(key)
    if type(value) is not int or not low <= value <= high:
        raise LedgerError(f"'{key}' must be a whole number from {low} to {high}")
    return value


def _check_serials(payload: Dict[str, Any]) -> List[str]:
    serials = payload.get("serials")
    if not isinstance(serials, list) or not serials:
        raise LedgerError("'serials' must be a non-empty list")
    if len(serials) > MAX_SERIALS_PER_TX:
        raise LedgerError(f"at most {MAX_SERIALS_PER_TX} credits per transaction")
    if not all(isinstance(s, str) for s in serials):
        raise LedgerError("every serial must be text")
    if len(set(serials)) != len(serials):
        raise LedgerError("the same serial appears twice in one transaction")
    return serials


class LedgerState:
    """Current state of every credit, project, registry and account nonce."""

    def __init__(self) -> None:
        self.governance: List[str] = []  # public keys
        self.threshold: int = 0
        self.validators: List[str] = []  # public keys
        self.issuers: Dict[str, Dict[str, Any]] = {}  # address -> registry record
        self.projects: Dict[str, Dict[str, Any]] = {}
        self.credits: Dict[str, Dict[str, Any]] = {}  # serial -> credit record
        self.nonces: Dict[str, int] = {}  # address -> next expected nonce
        self.evidence: Dict[str, str] = {}  # MRV report hash -> issuing tx_id
        self.seen_tx_ids: Set[str] = set()

    def copy(self) -> "LedgerState":
        return copy.deepcopy(self)

    def expected_nonce(self, address: str) -> int:
        return self.nonces.get(address, 0)

    # -- genesis -----------------------------------------------------------

    def apply_genesis(self, tx: Transaction) -> None:
        if tx.tx_type != GENESIS:
            raise LedgerError("first transaction must be GENESIS")
        if not isinstance(tx.payload, dict) or tx.sender or tx.signature or tx.approvals \
                or type(tx.nonce) is not int or tx.nonce != 0 \
                or not _valid_timestamp(tx.timestamp):
            raise LedgerError("GENESIS transaction must be unsigned with nonce 0")
        try:
            tx.signing_bytes()
        except (TypeError, ValueError) as exc:
            raise LedgerError(f"GENESIS payload is not valid JSON data: {exc}") from exc
        cfg = tx.payload
        governance = cfg.get("governance")
        validators = cfg.get("validators")
        threshold = cfg.get("threshold")
        issuers = cfg.get("issuers", [])
        if not isinstance(governance, list) or not governance \
                or not all(is_valid_public_key(k) for k in governance) \
                or len(set(governance)) != len(governance):
            raise LedgerError("genesis needs a list of distinct, valid governance public keys")
        if type(threshold) is not int or not 1 <= threshold <= len(governance):
            raise LedgerError("governance threshold must be between 1 and the number of members")
        if not isinstance(validators, list) or not validators \
                or not all(is_valid_public_key(k) for k in validators) \
                or len(set(validators)) != len(validators):
            raise LedgerError("genesis needs a list of distinct, valid validator public keys")
        if not isinstance(issuers, list):
            raise LedgerError("genesis issuers must be a list")
        self.governance = list(governance)
        self.threshold = threshold
        self.validators = list(validators)
        for issuer in issuers:
            if not isinstance(issuer, dict):
                raise LedgerError("each genesis issuer must be an object")
            self._add_issuer(issuer, tx.tx_id)
        self.seen_tx_ids.add(tx.tx_id)

    # -- general transaction checks ------------------------------------------

    def apply(self, tx: Transaction, block_index: Optional[int] = None,
              block_time: Optional[float] = None) -> None:
        """
        Validate tx against the current state and, only if every rule passes,
        apply it.  Each handler checks everything before it changes anything,
        so a rejected transaction leaves the state untouched.
        """
        approvals_valid = (isinstance(tx.approvals, list)
                           and all(isinstance(a, dict)
                                   and isinstance(a.get("public_key"), str)
                                   and isinstance(a.get("signature"), str)
                                   for a in tx.approvals))
        if not isinstance(tx.tx_type, str) or not isinstance(tx.sender, str) \
                or not isinstance(tx.payload, dict) or not isinstance(tx.signature, str) \
                or type(tx.nonce) is not int or tx.nonce < 0 or not approvals_valid:
            raise LedgerError("malformed transaction: wrong field types")
        if tx.tx_type not in TX_TYPES:
            raise LedgerError(f"unknown transaction type '{tx.tx_type}'")
        if not _valid_timestamp(tx.timestamp):
            raise LedgerError("transaction timestamp is out of range")
        if not is_valid_public_key(tx.sender):
            raise LedgerError("sender is not a valid public key")
        if not tx.has_valid_signature():
            raise LedgerError("invalid digital signature: transaction was not signed by the sender "
                              "or was altered after signing")
        tx_id = tx.tx_id
        if tx_id in self.seen_tx_ids:
            raise LedgerError("replay rejected: this transaction is already on the ledger")
        sender = tx.sender_address
        expected = self.expected_nonce(sender)
        if tx.nonce != expected:
            raise LedgerError(f"bad nonce {tx.nonce} (expected {expected}); "
                              "possible replay or out-of-order transaction")

        event = {"tx_id": tx_id, "type": tx.tx_type, "block": block_index,
                 "timestamp": block_time if block_time is not None else tx.timestamp}

        handler = {
            ADD_ISSUER: self._apply_add_issuer,
            REVOKE_ISSUER: self._apply_revoke_issuer,
            ISSUE: self._apply_issue,
            TRANSFER: self._apply_transfer,
            RETIRE: self._apply_retire,
            REVERSE: self._apply_reverse,
        }[tx.tx_type]
        handler(tx, event)

        self.nonces[sender] = expected + 1
        self.seen_tx_ids.add(tx_id)

    def _require_governance(self, tx: Transaction) -> List[str]:
        if tx.sender not in self.governance:
            raise LedgerError(f"{tx.tx_type} can only be proposed by a governance member")
        signers = tx.valid_signers() & set(self.governance)
        if len(signers) < self.threshold:
            raise LedgerError(f"{tx.tx_type} needs {self.threshold} governance signatures, "
                              f"has {len(signers)}")
        return sorted(signers)

    def _owned_active(self, serials: List[str], owner: Optional[str]) -> None:
        """Check that every serial exists, is ACTIVE and (if given) is held by owner."""
        for serial in serials:
            credit = self.credits.get(serial)
            if credit is None:
                raise LedgerError(f"credit {serial} does not exist")
            if credit["status"] != ACTIVE:
                raise LedgerError(f"double counting rejected: credit {serial} is already "
                                  f"{credit['status']}")
            if owner is not None and credit["owner"] != owner:
                raise LedgerError(f"credit {serial} is not owned by the sender")

    # -- registries ----------------------------------------------------------

    def _add_issuer(self, data: Dict[str, Any], tx_id: str) -> None:
        public_key = data.get("public_key")
        if not is_valid_public_key(public_key):
            raise LedgerError("registry public key is not valid")
        name = _check_text(data, "name")
        standard = _check_code(data, "standard")
        address = address_from_public_key(public_key)
        existing = self.issuers.get(address)
        if existing and existing["active"]:
            raise LedgerError("this registry is already accredited")
        self.issuers[address] = {"address": address, "public_key": public_key, "name": name,
                                 "standard": standard, "active": True, "added_in": tx_id}

    def _apply_add_issuer(self, tx: Transaction, event: Dict[str, Any]) -> None:
        self._require_governance(tx)
        self._add_issuer(tx.payload, event["tx_id"])

    def _apply_revoke_issuer(self, tx: Transaction, event: Dict[str, Any]) -> None:
        self._require_governance(tx)
        address = tx.payload.get("address")
        issuer = self.issuers.get(address) if isinstance(address, str) else None
        if issuer is None or not issuer["active"]:
            raise LedgerError("no active registry with that address")
        _check_text(tx.payload, "reason")
        issuer["active"] = False
        issuer["revoked_in"] = event["tx_id"]

    # -- credit lifecycle ------------------------------------------------------

    def _apply_issue(self, tx: Transaction, event: Dict[str, Any]) -> None:
        p = tx.payload
        issuer = self.issuers.get(tx.sender_address)
        if issuer is None or not issuer["active"]:
            raise LedgerError("permission denied: only accredited registries can issue credits")

        project_id = _check_code(p, "project_id")
        project_name = _check_text(p, "project_name")
        country = _check_text(p, "country")
        methodology = _check_text(p, "methodology")
        tx_year = time.gmtime(tx.timestamp).tm_year
        vintage = _check_int(p, "vintage", MIN_VINTAGE, 9999)
        if vintage > tx_year:
            raise LedgerError(f"vintage {vintage} is in the future: credits can only be issued "
                              "for reductions that already happened")
        quantity = _check_int(p, "quantity", 1, MAX_ISSUANCE)
        buffer_percent = _check_int({"buffer_percent": p.get("buffer_percent", 0)},
                                    "buffer_percent", 0, MAX_BUFFER_PERCENT)
        owner = p.get("owner")
        if not is_valid_address(owner):
            raise LedgerError("'owner' must be a valid account address")
        evidence_hash = p.get("evidence_hash")
        if not is_hex_hash(evidence_hash):
            raise LedgerError("'evidence_hash' must be the SHA-256 hash of the MRV report")
        if evidence_hash in self.evidence:
            raise LedgerError("double issuance rejected: this MRV report already backs "
                              "another issuance")

        project = self.projects.get(project_id)
        if project is not None and project["issuer"] != issuer["address"]:
            other = self.issuers[project["issuer"]]["name"]
            raise LedgerError(f"double issuance rejected: project {project_id} is already "
                              f"registered with {other}")
        if project is not None:
            supplied = (project_name, country, methodology)
            recorded = (project["name"], project["country"], project["methodology"])
            if supplied != recorded:
                raise LedgerError(f"project {project_id} metadata does not match its registration")

        # All checks passed -- now change state.
        if project is None:
            project = {"project_id": project_id, "name": project_name, "country": country,
                       "methodology": methodology, "issuer": issuer["address"],
                       "standard": issuer["standard"], "issued_per_vintage": {},
                       "issuances": []}
            self.projects[project_id] = project

        buffer_qty = quantity * buffer_percent // 100
        start = project["issued_per_vintage"].get(str(vintage), 0) + 1
        serials = [f"{project['standard']}-{project_id}-{vintage}-{n:06d}"
                   for n in range(start, start + quantity)]
        for i, serial in enumerate(serials):
            in_buffer = i >= quantity - buffer_qty
            self.credits[serial] = {
                "serial": serial,
                "project_id": project_id,
                "vintage": vintage,
                "standard": project["standard"],
                "issuer": issuer["address"],
                "owner": BUFFER_POOL if in_buffer else owner,
                "status": ACTIVE,
                "buffer": in_buffer,
                "evidence_hash": evidence_hash,
                "history": [dict(event, to=BUFFER_POOL if in_buffer else owner)],
            }
        project["issued_per_vintage"][str(vintage)] = start + quantity - 1
        project["issuances"].append({"tx_id": event["tx_id"], "vintage": vintage,
                                     "quantity": quantity, "buffer": buffer_qty,
                                     "evidence_hash": evidence_hash,
                                     "first_serial": serials[0], "last_serial": serials[-1]})
        self.evidence[evidence_hash] = event["tx_id"]

    def _apply_transfer(self, tx: Transaction, event: Dict[str, Any]) -> None:
        serials = _check_serials(tx.payload)
        to = tx.payload.get("to")
        if not is_valid_address(to):
            raise LedgerError("'to' must be a valid account address")
        if to == tx.sender_address:
            raise LedgerError("cannot transfer credits to yourself")
        self._owned_active(serials, tx.sender_address)
        for serial in serials:
            credit = self.credits[serial]
            credit["owner"] = to
            credit["history"].append(dict(event, **{"from": tx.sender_address, "to": to}))

    def _apply_retire(self, tx: Transaction, event: Dict[str, Any]) -> None:
        serials = _check_serials(tx.payload)
        beneficiary = _check_text(tx.payload, "beneficiary")
        purpose = _check_text(tx.payload, "purpose", required=False)
        self._owned_active(serials, tx.sender_address)
        for serial in serials:
            credit = self.credits[serial]
            credit["status"] = RETIRED
            credit["retirement"] = {"tx_id": event["tx_id"], "by": tx.sender_address,
                                    "beneficiary": beneficiary, "purpose": purpose}
            credit["history"].append(dict(event, by=tx.sender_address, beneficiary=beneficiary))

    def _apply_reverse(self, tx: Transaction, event: Dict[str, Any]) -> None:
        signers = self._require_governance(tx)
        serials = _check_serials(tx.payload)
        reason = _check_text(tx.payload, "reason")
        self._owned_active(serials, None)
        for serial in serials:
            credit = self.credits[serial]
            credit["status"] = CANCELLED
            credit["cancellation"] = {"tx_id": event["tx_id"], "reason": reason,
                                      "approved_by": [address_from_public_key(k) for k in signers]}
            credit["history"].append(dict(event, reason=reason))


# ==========================================================================
# The ledger (chain + mempool + consensus)
# ==========================================================================

class CarbonLedger:
    """The carbon credit blockchain: chain, pending pool, validation and queries."""

    def __init__(self, chain: List[Block], state: LedgerState):
        self._chain = chain
        self._state = state
        self._pending: List[Transaction] = []
        self._pending_state = state.copy()  # state as if every pending tx were applied
        self._lock = threading.RLock()

    # -- construction / persistence ------------------------------------------

    @classmethod
    def create(cls, governance_keys: List[str], threshold: int, validator_keys: List[str],
               issuers: Iterable[Dict[str, str]] = ()) -> "CarbonLedger":
        """Start a new chain.  The genesis block fixes who governs and who validates."""
        config = {"governance": list(governance_keys), "threshold": threshold,
                  "validators": list(validator_keys), "issuers": [dict(i) for i in issuers]}
        genesis_tx = Transaction(GENESIS, "", config, 0, time.time())
        genesis = Block(0, genesis_tx.timestamp, ZERO_HASH, [genesis_tx])
        genesis.merkle_root = genesis.compute_merkle_root()
        state = cls._replay([genesis])
        return cls([genesis], state)

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {"chain": [b.to_dict() for b in self._chain],
                    "pending": [t.to_dict() for t in self._pending]}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CarbonLedger":
        """Load a chain, re-verifying every hash, signature and rule.  Raises if tampered."""
        if not isinstance(data, dict) or not isinstance(data.get("chain"), list):
            raise LedgerError("ledger file must contain a 'chain' list")
        chain = [Block.from_dict(b) for b in data["chain"]]
        ledger = cls(chain, cls._replay(chain))
        pending = data.get("pending", [])
        if not isinstance(pending, list):
            raise LedgerError("ledger file 'pending' value must be a list")
        for tx_data in pending:
            try:
                ledger.submit(Transaction.from_dict(tx_data))
            except LedgerError:
                pass  # stale pending transactions are dropped
        return ledger

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, allow_nan=False)

    @classmethod
    def load(cls, path: str) -> "CarbonLedger":
        with open(path, "r", encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise LedgerError(f"ledger file is not valid JSON: {exc.msg}") from exc
        return cls.from_dict(data)

    # -- read-only views -------------------------------------------------------

    @property
    def chain(self) -> List[Block]:
        with self._lock:
            return list(self._chain)

    @property
    def pending(self) -> List[Transaction]:
        with self._lock:
            return [Transaction.from_dict(tx.to_dict()) for tx in self._pending]

    @property
    def state(self) -> LedgerState:
        with self._lock:
            return self._state.copy()

    @property
    def last_block(self) -> Block:
        with self._lock:
            return self._chain[-1]

    @property
    def height(self) -> int:
        with self._lock:
            return len(self._chain)

    # -- writing -----------------------------------------------------------------

    def next_nonce(self, address: str) -> int:
        """Next nonce for an account, counting transactions still waiting in the pool."""
        with self._lock:
            return self._pending_state.expected_nonce(address)

    def build_transaction(self, keypair: KeyPair, tx_type: str, payload: Dict[str, Any]) -> Transaction:
        """Create and sign a transaction with the correct nonce.  Does not submit it."""
        if not isinstance(payload, dict):
            raise LedgerError("payload must be an object")
        tx = Transaction(tx_type, keypair.public_key_hex, copy.deepcopy(payload),
                         self.next_nonce(keypair.address), time.time())
        try:
            return tx.sign(keypair)
        except (TypeError, ValueError) as exc:
            raise LedgerError(f"payload is not valid JSON data: {exc}") from exc

    def submit(self, tx: Transaction) -> str:
        """
        Validate a transaction against the latest state (including pending
        transactions) and add it to the pool.  Raises LedgerError if any rule
        fails, so a double spend is rejected before it ever reaches a block.
        """
        with self._lock:
            if not isinstance(tx, Transaction):
                raise LedgerError("submit expects a Transaction")
            if tx.tx_type == GENESIS:
                raise LedgerError("GENESIS transactions are only allowed in block 0")
            if not _valid_timestamp(tx.timestamp) or tx.timestamp > time.time() + MAX_CLOCK_SKEW:
                raise LedgerError("transaction timestamp is in the future or invalid")
            try:
                # Snapshot the transaction so later caller mutations cannot alter
                # the already-validated mempool entry.
                stored_tx = Transaction.from_dict(tx.to_dict())
                self._pending_state.apply(stored_tx)  # atomic: raises without changing state
            except (TypeError, ValueError) as exc:
                raise LedgerError(f"payload is not valid JSON data: {exc}") from exc
            self._pending.append(stored_tx)
            return stored_tx.tx_id

    def seal_block(self, validator: KeyPair, max_txs: int = MAX_TXS_PER_BLOCK) -> Block:
        """Proof of Authority: an approved validator signs the next block of pending transactions."""
        with self._lock:
            if validator.public_key_hex not in self._state.validators:
                raise LedgerError("permission denied: not an authorised validator")
            if not self._pending:
                raise LedgerError("no pending transactions to put in a block")
            if type(max_txs) is not int or max_txs < 1:
                raise LedgerError("max_txs must be a positive whole number")
            index = len(self._chain)
            timestamp = max(time.time(), self.last_block.timestamp)

            new_state = self._state.copy()
            included: List[Transaction] = []
            for tx in self._pending[:min(max_txs, MAX_TXS_PER_BLOCK)]:
                try:
                    new_state.apply(tx, index, timestamp)
                    included.append(tx)
                except LedgerError:
                    pass  # should not happen: pool was validated on submit
            if not included:
                self._reset_pending([])
                raise LedgerError("no valid pending transactions")

            block = Block(index, timestamp, self.last_block.hash, included).seal(validator)
            self._chain.append(block)
            self._state = new_state
            included_ids = {t.tx_id for t in included}
            self._reset_pending([t for t in self._pending if t.tx_id not in included_ids])
            return block

    def _reset_pending(self, remaining: List[Transaction]) -> None:
        self._pending = []
        self._pending_state = self._state.copy()
        for tx in remaining:
            try:
                self._pending_state.apply(tx)
                self._pending.append(tx)
            except LedgerError:
                pass

    # -- validation ----------------------------------------------------------------

    @staticmethod
    def _replay(chain: List[Block]) -> LedgerState:
        """
        Rebuild the state from scratch, checking every block and transaction.
        This is what a new node does when it joins: it trusts nothing and
        verifies everything.
        """
        if not chain:
            raise LedgerError("chain is empty")
        genesis = chain[0]
        now = time.time()
        if type(genesis.index) is not int or genesis.index != 0 \
                or not _valid_timestamp(genesis.timestamp) \
                or genesis.timestamp > now + MAX_CLOCK_SKEW \
                or genesis.previous_hash != ZERO_HASH:
            raise LedgerError("block 0: invalid genesis header")
        if len(genesis.transactions) != 1 or genesis.validator or genesis.signature:
            raise LedgerError("block 0: genesis must hold exactly one unsigned GENESIS transaction")
        if genesis.merkle_root != genesis.compute_merkle_root():
            raise LedgerError("block 0: Merkle root mismatch (genesis was altered)")
        if genesis.transactions[0].timestamp != genesis.timestamp:
            raise LedgerError("block 0: transaction and block timestamps must match")
        state = LedgerState()
        state.apply_genesis(genesis.transactions[0])

        for i in range(1, len(chain)):
            block, prev = chain[i], chain[i - 1]
            if type(block.index) is not int or block.index != i:
                raise LedgerError(f"block {i}: wrong index {block.index}")
            if not _valid_timestamp(block.timestamp) or block.timestamp > now + MAX_CLOCK_SKEW:
                raise LedgerError(f"block {i}: timestamp is invalid or too far in the future")
            if block.previous_hash != prev.hash:
                raise LedgerError(f"block {i}: previous_hash does not match block {i - 1} "
                                  "(chain was altered)")
            if block.timestamp < prev.timestamp:
                raise LedgerError(f"block {i}: timestamp earlier than previous block")
            if not 1 <= len(block.transactions) <= MAX_TXS_PER_BLOCK:
                raise LedgerError(f"block {i}: must hold 1 to {MAX_TXS_PER_BLOCK} transactions")
            if block.merkle_root != block.compute_merkle_root():
                raise LedgerError(f"block {i}: Merkle root mismatch (a transaction was altered)")
            if block.validator not in state.validators:
                raise LedgerError(f"block {i}: sealed by an unauthorised validator")
            if not block.has_valid_signature():
                raise LedgerError(f"block {i}: invalid validator signature")
            for tx in block.transactions:
                if tx.timestamp > block.timestamp + MAX_CLOCK_SKEW:
                    raise LedgerError(f"block {i}: transaction {tx.tx_id[:12]} is from the future")
                try:
                    state.apply(tx, i, block.timestamp)
                except LedgerError as exc:
                    raise LedgerError(f"block {i}, tx {tx.tx_id[:12]}: {exc}") from exc
        return state

    def validate_chain(self) -> Tuple[bool, str]:
        """Full re-verification of the chain.  Returns (ok, message)."""
        with self._lock:
            try:
                self._replay(self._chain)
                return True, f"chain valid: {len(self._chain)} blocks verified"
            except (LedgerError, AttributeError, IndexError, TypeError, ValueError) as exc:
                return False, str(exc)

    def is_valid(self) -> bool:
        return self.validate_chain()[0]

    def audit(self) -> List[Dict[str, Any]]:
        """
        Per-block integrity report for the interface: which blocks have a
        broken hash link, Merkle root or signature.  Useful to show exactly
        where a tampered chain breaks.
        """
        report = []
        with self._lock:
            for i, block in enumerate(self._chain):
                try:
                    block_hash = block.hash
                except (AttributeError, TypeError, ValueError):
                    block_hash = "<invalid>"
                try:
                    merkle_ok = block.merkle_root == block.compute_merkle_root()
                except (AttributeError, TypeError, ValueError):
                    merkle_ok = False
                if i == 0:
                    try:
                        link_ok = block.previous_hash == ZERO_HASH
                        tx = block.transactions[0] if len(block.transactions) == 1 else None
                        sig_ok = (not block.validator and not block.signature and tx is not None
                                  and not tx.sender and not tx.signature and not tx.approvals)
                    except (AttributeError, TypeError):
                        link_ok = False
                        sig_ok = False
                else:
                    try:
                        link_ok = block.previous_hash == self._chain[i - 1].hash
                    except (AttributeError, TypeError, ValueError):
                        link_ok = False
                    try:
                        sig_ok = (block.validator in self._state.validators
                                  and block.has_valid_signature())
                    except (AttributeError, TypeError, ValueError):
                        sig_ok = False
                report.append({"index": i, "hash": block_hash, "hash_link_ok": link_ok,
                               "merkle_ok": merkle_ok, "signature_ok": sig_ok,
                               "ok": link_ok and merkle_ok and sig_ok})
        return report

    def replace_chain(self, candidate: List[Dict[str, Any]]) -> bool:
        """
        Fork choice when syncing with another node: adopt the candidate chain
        only if it shares our genesis, is longer, and fully validates.
        """
        with self._lock:
            try:
                if not isinstance(candidate, list):
                    return False
                blocks = [Block.from_dict(b) for b in candidate]
                if not blocks or blocks[0].hash != self._chain[0].hash:
                    return False
                if len(blocks) <= len(self._chain):
                    return False
                state = self._replay(blocks)
            except LedgerError:
                return False
            self._chain, self._state = blocks, state
            self._reset_pending(self._pending)
            return True

    # -- queries ---------------------------------------------------------------------

    def get_credit(self, serial: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            credit = self._state.credits.get(serial)
            return copy.deepcopy(credit) if credit else None

    def credit_history(self, serial: str) -> List[Dict[str, Any]]:
        """Every confirmed event in a credit's life, oldest first."""
        with self._lock:
            credit = self._state.credits.get(serial)
            return copy.deepcopy(credit["history"]) if credit else []

    def credits_owned(self, address: str, status: Optional[str] = ACTIVE,
                      project_id: Optional[str] = None) -> List[str]:
        """Serials held by an address (confirmed state), sorted."""
        with self._lock:
            return sorted(s for s, c in self._state.credits.items()
                          if c["owner"] == address
                          and (status is None or c["status"] == status)
                          and (project_id is None or c["project_id"] == project_id))

    def balance(self, address: str) -> Dict[str, int]:
        counts = {ACTIVE: 0, RETIRED: 0, CANCELLED: 0}
        with self._lock:
            for credit in self._state.credits.values():
                if credit["owner"] == address:
                    counts[credit["status"]] += 1
        return counts

    def select_serials(self, address: str, quantity: int,
                       project_id: Optional[str] = None) -> List[str]:
        """
        Pick `quantity` ACTIVE credits the address can spend right now
        (excluding ones already used by its pending transactions).
        Lets the interface say "transfer 40 credits" without listing serials.
        """
        if type(quantity) is not int:
            raise LedgerError("quantity must be a positive whole number")
        with self._lock:
            available = sorted(s for s, c in self._pending_state.credits.items()
                               if c["owner"] == address and c["status"] == ACTIVE
                               and (project_id is None or c["project_id"] == project_id))
        if quantity < 1 or quantity > len(available):
            raise LedgerError(f"only {len(available)} spendable credits available")
        return available[:quantity]

    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            project = self._state.projects.get(project_id)
            return copy.deepcopy(project) if project else None

    def list_projects(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [copy.deepcopy(p) for p in self._state.projects.values()]

    def list_issuers(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [copy.deepcopy(i) for i in self._state.issuers.values()]

    def find_transaction(self, tx_id: str) -> Optional[Tuple[Block, Transaction]]:
        with self._lock:
            for block in self._chain:
                for tx in block.transactions:
                    if tx.tx_id == tx_id:
                        block_copy = copy.deepcopy(block)
                        copied_tx = next(item for item in block_copy.transactions
                                         if item.tx_id == tx_id)
                        return block_copy, copied_tx
        return None

    def inclusion_proof(self, tx_id: str) -> Optional[Dict[str, Any]]:
        """Merkle proof that a transaction is in a block (for light clients / auditors)."""
        found = self.find_transaction(tx_id)
        if not found:
            return None
        block, tx = found
        leaves = [t.leaf_hash() for t in block.transactions]
        index = block.transactions.index(tx)
        return {"tx_id": tx_id, "leaf_hash": leaves[index], "block_index": block.index,
                "block_hash": block.hash, "merkle_root": block.merkle_root,
                "proof": merkle_proof(leaves, index)}

    @staticmethod
    def verify_inclusion(proof: Dict[str, Any]) -> bool:
        try:
            if not isinstance(proof, dict) or not isinstance(proof["proof"], list):
                return False
            path = []
            for item in proof["proof"]:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    return False
                path.append((item[0], item[1]))
            return verify_merkle_proof(proof["leaf_hash"], path, proof["merkle_root"])
        except (KeyError, TypeError, ValueError):
            return False

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            counts = {ACTIVE: 0, RETIRED: 0, CANCELLED: 0}
            for credit in self._state.credits.values():
                counts[credit["status"]] += 1
            return {"blocks": len(self._chain), "pending": len(self._pending),
                    "projects": len(self._state.projects),
                    "registries": sum(1 for i in self._state.issuers.values() if i["active"]),
                    "credits_issued": len(self._state.credits),
                    "credits_active": counts[ACTIVE], "credits_retired": counts[RETIRED],
                    "credits_cancelled": counts[CANCELLED]}


# ==========================================================================
# Command-line walkthrough
# ==========================================================================

def main() -> None:
    from security import hash_document

    def attempt(label: str, fn) -> None:
        try:
            fn()
            print(f"  [!] {label}: ACCEPTED (unexpected)")
        except LedgerError as exc:
            print(f"  [x] {label}: rejected -> {exc}")

    print("== Setting up participants ==")
    standard_body, government, auditor = KeyPair(), KeyPair(), KeyPair()
    validator_a, validator_b = KeyPair(), KeyPair()
    registry_a, registry_b = KeyPair(), KeyPair()
    developer, buyer, outsider = KeyPair(), KeyPair(), KeyPair()

    ledger = CarbonLedger.create(
        governance_keys=[k.public_key_hex for k in (standard_body, government, auditor)],
        threshold=2,
        validator_keys=[validator_a.public_key_hex, validator_b.public_key_hex],
        issuers=[{"public_key": registry_a.public_key_hex, "name": "Registry A", "standard": "RA"},
                 {"public_key": registry_b.public_key_hex, "name": "Registry B", "standard": "RB"}],
    )
    print(f"  genesis block {ledger.last_block.hash[:16]}...  (2-of-3 governance, 2 validators)")

    print("\n== 1. Registry A issues 100 credits (10% to the buffer pool) ==")
    mrv_report = "Project AMZ001 2024 monitoring report: 100 tCO2e avoided (satellite + field plots)"
    ledger.submit(ledger.build_transaction(registry_a, ISSUE, {
        "project_id": "AMZ001", "project_name": "Amazon Forest Protection", "country": "Brazil",
        "methodology": "REDD+ VM0048", "vintage": 2024, "quantity": 100, "buffer_percent": 10,
        "owner": developer.address, "evidence_hash": hash_document(mrv_report)}))
    ledger.seal_block(validator_a)
    print(f"  developer balance: {ledger.balance(developer.address)}")
    print(f"  buffer pool:       {ledger.balance(BUFFER_POOL)}")

    print("\n== 2. Developer sells 40 credits to a buyer ==")
    ledger.submit(ledger.build_transaction(developer, TRANSFER, {
        "serials": ledger.select_serials(developer.address, 40), "to": buyer.address}))
    ledger.seal_block(validator_b)
    print(f"  buyer balance: {ledger.balance(buyer.address)}")

    print("\n== 3. Buyer retires 25 credits for its net-zero claim ==")
    retired = ledger.select_serials(buyer.address, 25)
    ledger.submit(ledger.build_transaction(buyer, RETIRE, {
        "serials": retired, "beneficiary": "Example Corp", "purpose": "2025 net-zero claim"}))
    ledger.seal_block(validator_a)
    print(f"  buyer balance: {ledger.balance(buyer.address)}")

    print("\n== 4. Attacks the ledger rejects ==")
    attempt("re-sell a retired credit", lambda: ledger.submit(ledger.build_transaction(
        buyer, TRANSFER, {"serials": retired[:1], "to": outsider.address})))
    attempt("Registry B issues for the same project", lambda: ledger.submit(ledger.build_transaction(
        registry_b, ISSUE, {"project_id": "AMZ001", "project_name": "Amazon Forest Protection",
                            "country": "Brazil", "methodology": "REDD+", "vintage": 2024,
                            "quantity": 100, "owner": developer.address,
                            "evidence_hash": hash_document(mrv_report + " copy")})))
    attempt("reuse the same MRV report", lambda: ledger.submit(ledger.build_transaction(
        registry_a, ISSUE, {"project_id": "AMZ002", "project_name": "Copy", "country": "Brazil",
                            "methodology": "REDD+", "vintage": 2024, "quantity": 100,
                            "owner": developer.address, "evidence_hash": hash_document(mrv_report)})))
    attempt("non-registry issues credits", lambda: ledger.submit(ledger.build_transaction(
        outsider, ISSUE, {"project_id": "FAKE1", "project_name": "Fake", "country": "Nowhere",
                          "methodology": "none", "vintage": 2024, "quantity": 1000,
                          "owner": outsider.address, "evidence_hash": hash_document("fake")})))
    stolen = ledger.select_serials(buyer.address, 1)
    forged = Transaction(TRANSFER, buyer.public_key_hex, {"serials": stolen, "to": outsider.address},
                         ledger.next_nonce(buyer.address), time.time())
    forged.signature = outsider.sign(forged.signing_bytes())
    attempt("outsider forges the buyer's signature", lambda: ledger.submit(forged))
    honest = ledger.build_transaction(buyer, TRANSFER, {"serials": stolen, "to": developer.address})
    honest.payload["to"] = outsider.address
    attempt("payload altered after signing", lambda: ledger.submit(honest))
    attempt("reversal with only 1 of 2 signatures", lambda: ledger.submit(ledger.build_transaction(
        auditor, REVERSE, {"serials": ledger.credits_owned(BUFFER_POOL)[:5], "reason": "test"})))

    print("\n== 5. Forest fire: governance cancels 5 buffer credits (2-of-3 multisig) ==")
    reversal = Transaction(REVERSE, auditor.public_key_hex,
                           {"serials": ledger.credits_owned(BUFFER_POOL)[:5],
                            "reason": "Satellite data shows 5 ha burned in 2025"},
                           ledger.next_nonce(auditor.address), time.time())
    reversal.sign(auditor).approve(government)
    ledger.submit(reversal)
    ledger.seal_block(validator_b)
    print(f"  buffer pool: {ledger.balance(BUFFER_POOL)}")

    print("\n== 6. Audit trail of one credit ==")
    for event in ledger.credit_history(retired[0]):
        print(f"  block {event['block']}: {event['type']:<8} tx {event['tx_id'][:16]}...")
    proof = ledger.inclusion_proof(ledger.credit_history(retired[0])[-1]["tx_id"])
    print(f"  Merkle inclusion proof valid: {CarbonLedger.verify_inclusion(proof)}")
    print(f"  MRV report matches on-chain hash: "
          f"{hash_document(mrv_report) == ledger.get_credit(retired[0])['evidence_hash']}")

    print("\n== 7. Tamper detection ==")
    print(f"  before: {ledger.validate_chain()}")
    ledger.chain[2].transactions[0].payload["to"] = outsider.address
    print(f"  after editing block 2: {ledger.validate_chain()}")
    print(f"  broken blocks: {[b['index'] for b in ledger.audit() if not b['ok']]}")

    print(f"\n== Stats ==\n  {ledger.stats()}")


if __name__ == "__main__":
    main()
