"""
Unit tests for the blockchain core (blockchain.py) and the security layer
(security.py).  Run with:  python3 -m unittest -v test_blockchain
"""

import json
import os
import tempfile
import time
import unittest

from blockchain import (ACTIVE, ADD_ISSUER, BUFFER_POOL, CANCELLED, ISSUE, RETIRE, RETIRED,
                        REVERSE, REVOKE_ISSUER, TRANSFER, Block, CarbonLedger, LedgerError,
                        Transaction)
from security import (KeyPair, address_from_public_key, hash_document, hash_object,
                      is_hex_hash, is_valid_address, is_valid_public_key, merkle_proof, merkle_root,
                      sha256_hex, verify_document, verify_merkle_proof, verify_signature)


# --------------------------------------------------------------------------
# Security layer (part c)
# --------------------------------------------------------------------------

class TestHashing(unittest.TestCase):
    def test_sha256_known_vector(self):
        self.assertEqual(sha256_hex("abc"),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_hash_object_ignores_key_order(self):
        self.assertEqual(hash_object({"a": 1, "b": 2}), hash_object({"b": 2, "a": 1}))

    def test_hash_changes_with_one_character(self):
        self.assertNotEqual(hash_object({"to": "alice"}), hash_object({"to": "alicf"}))

    def test_non_finite_json_numbers_are_rejected(self):
        with self.assertRaises(ValueError):
            hash_object({"quantity": float("nan")})

    def test_hash_format_rejects_whitespace(self):
        self.assertFalse(is_hex_hash("00" * 31 + "  "))

    def test_python_only_json_values_are_rejected(self):
        with self.assertRaises(TypeError):
            hash_object({1: "value"})
        with self.assertRaises(TypeError):
            hash_object({"items": (1, 2)})

    def test_document_hash_verification(self):
        report = b"MRV report: 100 tCO2e"
        digest = hash_document(report)
        self.assertTrue(verify_document(report, digest))
        self.assertFalse(verify_document(b"MRV report: 900 tCO2e", digest))


class TestSignatures(unittest.TestCase):
    def setUp(self):
        self.alice, self.mallory = KeyPair(), KeyPair()

    def test_sign_and_verify(self):
        sig = self.alice.sign(b"hello")
        self.assertTrue(verify_signature(self.alice.public_key_hex, b"hello", sig))

    def test_wrong_key_or_message_fails(self):
        sig = self.alice.sign(b"hello")
        self.assertFalse(verify_signature(self.mallory.public_key_hex, b"hello", sig))
        self.assertFalse(verify_signature(self.alice.public_key_hex, b"hellO", sig))

    def test_garbage_input_returns_false(self):
        self.assertFalse(verify_signature("zz", b"x", "zz"))
        self.assertFalse(verify_signature(self.alice.public_key_hex, b"x", "00"))

    def test_address_format(self):
        self.assertTrue(is_valid_address(self.alice.address))
        self.assertEqual(self.alice.address, address_from_public_key(self.alice.public_key_hex))
        self.assertFalse(is_valid_address(BUFFER_POOL))

    def test_public_keys_have_one_canonical_encoding(self):
        self.assertTrue(is_valid_public_key(self.alice.public_key_hex))
        self.assertFalse(is_valid_public_key(self.alice.public_key_hex.upper()))

    def test_encrypted_key_round_trip(self):
        pem = self.alice.to_pem(password="correct horse")
        self.assertIn(b"ENCRYPTED", pem)
        self.assertEqual(KeyPair.from_pem(pem, "correct horse").address, self.alice.address)
        with self.assertRaises(Exception):
            KeyPair.from_pem(pem, "wrong password")

    def test_repr_hides_private_key(self):
        self.assertNotIn("PRIVATE", repr(self.alice))


class TestMerkle(unittest.TestCase):
    def test_every_leaf_has_valid_proof(self):
        for n in range(1, 10):
            leaves = [sha256_hex(str(i)) for i in range(n)]
            root = merkle_root(leaves)
            for i, leaf in enumerate(leaves):
                self.assertTrue(verify_merkle_proof(leaf, merkle_proof(leaves, i), root), (n, i))

    def test_proof_fails_for_other_leaf(self):
        leaves = [sha256_hex(str(i)) for i in range(5)]
        proof = merkle_proof(leaves, 2)
        self.assertFalse(verify_merkle_proof(sha256_hex("x"), proof, merkle_root(leaves)))

    def test_duplicated_last_leaf_changes_root(self):
        a, b, c = (sha256_hex(x) for x in "abc")
        self.assertNotEqual(merkle_root([a, b, c]), merkle_root([a, b, c, c]))


# --------------------------------------------------------------------------
# Blockchain (part b)
# --------------------------------------------------------------------------

class LedgerTestCase(unittest.TestCase):
    def setUp(self):
        self.gov = [KeyPair() for _ in range(3)]
        self.validator, self.validator2 = KeyPair(), KeyPair()
        self.registry_a, self.registry_b = KeyPair(), KeyPair()
        self.developer, self.buyer, self.outsider = KeyPair(), KeyPair(), KeyPair()
        self.ledger = CarbonLedger.create(
            governance_keys=[k.public_key_hex for k in self.gov], threshold=2,
            validator_keys=[self.validator.public_key_hex, self.validator2.public_key_hex],
            issuers=[{"public_key": self.registry_a.public_key_hex, "name": "Registry A",
                      "standard": "RA"},
                     {"public_key": self.registry_b.public_key_hex, "name": "Registry B",
                      "standard": "RB"}])

    def issue_payload(self, **overrides):
        payload = {"project_id": "AMZ001", "project_name": "Amazon Forest", "country": "Brazil",
                   "methodology": "REDD+", "vintage": 2024, "quantity": 100, "buffer_percent": 10,
                   "owner": self.developer.address,
                   "evidence_hash": hash_document(f"report {time.time()} {id(overrides)}")}
        payload.update(overrides)
        return payload

    def send(self, keypair, tx_type, payload, seal=True):
        tx_id = self.ledger.submit(self.ledger.build_transaction(keypair, tx_type, payload))
        if seal:
            self.ledger.seal_block(self.validator)
        return tx_id

    def issue(self, **overrides):
        return self.send(self.registry_a, ISSUE, self.issue_payload(**overrides))

    def governance_tx(self, tx_type, payload, signers):
        proposer = signers[0]
        tx = Transaction(tx_type, proposer.public_key_hex, payload,
                         self.ledger.next_nonce(proposer.address), time.time()).sign(proposer)
        for kp in signers[1:]:
            tx.approve(kp)
        return tx


class TestIssuance(LedgerTestCase):
    def test_issue_creates_unique_serials_and_buffer(self):
        self.issue()
        self.assertEqual(self.ledger.balance(self.developer.address)[ACTIVE], 90)
        self.assertEqual(self.ledger.balance(BUFFER_POOL)[ACTIVE], 10)
        credit = self.ledger.get_credit("RA-AMZ001-2024-000001")
        self.assertEqual(credit["owner"], self.developer.address)
        self.assertEqual(credit["status"], ACTIVE)

    def test_second_issuance_continues_numbering(self):
        self.issue(quantity=5, buffer_percent=0)
        self.issue(quantity=5, buffer_percent=0)
        self.assertIsNotNone(self.ledger.get_credit("RA-AMZ001-2024-000010"))
        self.assertEqual(len(self.ledger.state.credits), 10)

    def test_repeat_issuance_cannot_change_project_metadata(self):
        self.issue(quantity=1, buffer_percent=0)
        with self.assertRaisesRegex(LedgerError, "metadata does not match"):
            self.issue(project_name="A different project", quantity=1, buffer_percent=0)

    def test_only_accredited_registry_can_issue(self):
        with self.assertRaisesRegex(LedgerError, "permission denied"):
            self.send(self.outsider, ISSUE, self.issue_payload())

    def test_cross_registry_double_issuance_blocked(self):
        self.issue()
        with self.assertRaisesRegex(LedgerError, "already registered with Registry A"):
            self.send(self.registry_b, ISSUE, self.issue_payload())

    def test_same_mrv_report_cannot_back_two_issuances(self):
        evidence = hash_document("one report")
        self.issue(evidence_hash=evidence)
        with self.assertRaisesRegex(LedgerError, "MRV report already backs"):
            self.issue(project_id="AMZ002", evidence_hash=evidence)

    def test_future_vintage_rejected(self):
        with self.assertRaisesRegex(LedgerError, "future"):
            self.issue(vintage=time.gmtime().tm_year + 1)

    def test_bad_fields_rejected(self):
        bad = [{"quantity": 0}, {"quantity": "100"}, {"quantity": True}, {"owner": "bob"},
               {"evidence_hash": "abc"}, {"project_id": "has-dash"}, {"buffer_percent": 90},
               {"project_name": ""}]
        for override in bad:
            with self.assertRaises(LedgerError, msg=str(override)):
                self.send(self.registry_a, ISSUE, self.issue_payload(**override), seal=False)
        self.assertEqual(self.ledger.pending, [])


class TestTransferAndRetire(LedgerTestCase):
    def setUp(self):
        super().setUp()
        self.issue()

    def test_transfer_moves_ownership(self):
        serials = self.ledger.select_serials(self.developer.address, 40)
        self.send(self.developer, TRANSFER, {"serials": serials, "to": self.buyer.address})
        self.assertEqual(self.ledger.balance(self.buyer.address)[ACTIVE], 40)
        self.assertEqual(self.ledger.balance(self.developer.address)[ACTIVE], 50)

    def test_cannot_transfer_someone_elses_credits(self):
        serials = self.ledger.select_serials(self.developer.address, 1)
        with self.assertRaisesRegex(LedgerError, "not owned"):
            self.send(self.outsider, TRANSFER, {"serials": serials, "to": self.buyer.address})

    def test_double_spend_in_same_pool_rejected(self):
        serials = self.ledger.select_serials(self.developer.address, 1)
        self.send(self.developer, TRANSFER, {"serials": serials, "to": self.buyer.address},
                  seal=False)
        with self.assertRaisesRegex(LedgerError, "not owned"):
            self.send(self.developer, TRANSFER, {"serials": serials, "to": self.outsider.address},
                      seal=False)

    def test_retired_credit_can_never_move(self):
        serials = self.ledger.select_serials(self.developer.address, 3)
        self.send(self.developer, RETIRE, {"serials": serials, "beneficiary": "Example Corp"})
        self.assertEqual(self.ledger.get_credit(serials[0])["status"], RETIRED)
        with self.assertRaisesRegex(LedgerError, "already RETIRED"):
            self.send(self.developer, TRANSFER, {"serials": serials, "to": self.buyer.address})
        with self.assertRaisesRegex(LedgerError, "already RETIRED"):
            self.send(self.developer, RETIRE, {"serials": serials, "beneficiary": "Someone else"})

    def test_buffer_credits_cannot_be_moved_by_users(self):
        buffer = self.ledger.credits_owned(BUFFER_POOL)[:1]
        with self.assertRaisesRegex(LedgerError, "not owned"):
            self.send(self.developer, TRANSFER, {"serials": buffer, "to": self.buyer.address})

    def test_duplicate_serial_in_one_tx_rejected(self):
        s = self.ledger.select_serials(self.developer.address, 1)
        with self.assertRaisesRegex(LedgerError, "twice"):
            self.send(self.developer, TRANSFER, {"serials": s + s, "to": self.buyer.address})

    def test_credit_history_is_complete(self):
        serial = self.ledger.select_serials(self.developer.address, 1)
        self.send(self.developer, TRANSFER, {"serials": serial, "to": self.buyer.address})
        self.send(self.buyer, RETIRE, {"serials": serial, "beneficiary": "Example Corp"})
        self.assertEqual([e["type"] for e in self.ledger.credit_history(serial[0])],
                         [ISSUE, TRANSFER, RETIRE])


class TestSignaturesAndReplay(LedgerTestCase):
    def setUp(self):
        super().setUp()
        self.issue()
        self.serials = self.ledger.select_serials(self.developer.address, 1)

    def test_forged_signature_rejected(self):
        tx = Transaction(TRANSFER, self.developer.public_key_hex,
                         {"serials": self.serials, "to": self.outsider.address},
                         self.ledger.next_nonce(self.developer.address), time.time())
        tx.signature = self.outsider.sign(tx.signing_bytes())
        with self.assertRaisesRegex(LedgerError, "invalid digital signature"):
            self.ledger.submit(tx)

    def test_payload_altered_after_signing_rejected(self):
        tx = self.ledger.build_transaction(self.developer, TRANSFER,
                                           {"serials": self.serials, "to": self.buyer.address})
        tx.payload["to"] = self.outsider.address
        with self.assertRaisesRegex(LedgerError, "invalid digital signature"):
            self.ledger.submit(tx)

    def test_replayed_transaction_rejected(self):
        tx = self.ledger.build_transaction(self.developer, TRANSFER,
                                           {"serials": self.serials, "to": self.buyer.address})
        self.ledger.submit(tx)
        self.ledger.seal_block(self.validator)
        with self.assertRaises(LedgerError):
            self.ledger.submit(Transaction.from_dict(tx.to_dict()))

    def test_wrong_nonce_rejected(self):
        tx = Transaction(TRANSFER, self.developer.public_key_hex,
                         {"serials": self.serials, "to": self.buyer.address}, 5, time.time())
        with self.assertRaisesRegex(LedgerError, "nonce"):
            self.ledger.submit(tx.sign(self.developer))

    def test_failed_tx_does_not_consume_nonce(self):
        before = self.ledger.next_nonce(self.developer.address)
        with self.assertRaises(LedgerError):
            self.send(self.developer, TRANSFER, {"serials": ["NOPE"], "to": self.buyer.address})
        self.assertEqual(self.ledger.next_nonce(self.developer.address), before)

    def test_submitted_transaction_is_snapshotted(self):
        tx = self.ledger.build_transaction(
            self.developer, TRANSFER, {"serials": self.serials, "to": self.buyer.address})
        self.ledger.submit(tx)
        tx.payload["to"] = self.outsider.address
        self.ledger.seal_block(self.validator)
        self.assertEqual(self.ledger.get_credit(self.serials[0])["owner"], self.buyer.address)


class TestGovernance(LedgerTestCase):
    def setUp(self):
        super().setUp()
        self.issue()

    def test_reversal_needs_threshold_signatures(self):
        buffer = self.ledger.credits_owned(BUFFER_POOL)[:5]
        payload = {"serials": buffer, "reason": "forest fire"}
        with self.assertRaisesRegex(LedgerError, "needs 2 governance signatures"):
            self.ledger.submit(self.governance_tx(REVERSE, payload, self.gov[:1]))
        self.ledger.submit(self.governance_tx(REVERSE, payload, self.gov[:2]))
        self.ledger.seal_block(self.validator)
        self.assertEqual(self.ledger.balance(BUFFER_POOL), {ACTIVE: 5, RETIRED: 0, CANCELLED: 5})
        self.assertEqual(len(self.ledger.get_credit(buffer[0])["cancellation"]["approved_by"]), 2)

    def test_outsider_approvals_do_not_count(self):
        tx = self.governance_tx(REVERSE, {"serials": self.ledger.credits_owned(BUFFER_POOL)[:1],
                                          "reason": "x"}, [self.gov[0], self.outsider])
        with self.assertRaisesRegex(LedgerError, "has 1"):
            self.ledger.submit(tx)

    def test_non_governance_cannot_propose(self):
        with self.assertRaisesRegex(LedgerError, "governance member"):
            self.ledger.submit(self.governance_tx(
                REVERSE, {"serials": self.ledger.credits_owned(BUFFER_POOL)[:1], "reason": "x"},
                [self.outsider, self.gov[0], self.gov[1]]))

    def test_retired_credit_cannot_be_reversed(self):
        serial = self.ledger.select_serials(self.developer.address, 1)
        self.send(self.developer, RETIRE, {"serials": serial, "beneficiary": "Example Corp"})
        with self.assertRaisesRegex(LedgerError, "RETIRED"):
            self.ledger.submit(self.governance_tx(REVERSE, {"serials": serial, "reason": "x"},
                                                  self.gov[:2]))

    def test_add_and_revoke_registry(self):
        new_registry = KeyPair()
        self.ledger.submit(self.governance_tx(ADD_ISSUER, {
            "public_key": new_registry.public_key_hex, "name": "Registry C", "standard": "RC"},
            self.gov[1:]))
        self.ledger.seal_block(self.validator)
        self.send(new_registry, ISSUE, self.issue_payload(project_id="KEN01"))
        self.assertIsNotNone(self.ledger.get_credit("RC-KEN01-2024-000001"))

        self.ledger.submit(self.governance_tx(REVOKE_ISSUER, {
            "address": new_registry.address, "reason": "accreditation withdrawn"}, self.gov[:2]))
        self.ledger.seal_block(self.validator)
        with self.assertRaisesRegex(LedgerError, "permission denied"):
            self.send(new_registry, ISSUE, self.issue_payload(project_id="KEN01"))


class TestChainIntegrity(LedgerTestCase):
    def setUp(self):
        super().setUp()
        self.issue()
        serials = self.ledger.select_serials(self.developer.address, 10)
        self.send(self.developer, TRANSFER, {"serials": serials, "to": self.buyer.address})
        self.send(self.buyer, RETIRE, {"serials": serials[:5], "beneficiary": "Example Corp"})

    def test_valid_chain(self):
        ok, msg = self.ledger.validate_chain()
        self.assertTrue(ok, msg)
        self.assertTrue(all(b["ok"] for b in self.ledger.audit()))

    def test_blocks_are_hash_linked(self):
        for prev, block in zip(self.ledger.chain, self.ledger.chain[1:]):
            self.assertEqual(block.previous_hash, prev.hash)

    def test_editing_a_transaction_is_detected(self):
        self.ledger.chain[2].transactions[0].payload["to"] = self.outsider.address
        ok, msg = self.ledger.validate_chain()
        self.assertFalse(ok)
        self.assertIn("block 2", msg)
        self.assertEqual([b["index"] for b in self.ledger.audit() if not b["ok"]], [2])

    def test_recomputing_merkle_root_breaks_signature_and_link(self):
        block = self.ledger.chain[2]
        block.transactions[0].payload["to"] = self.outsider.address
        block.merkle_root = block.compute_merkle_root()
        self.assertFalse(self.ledger.is_valid())
        report = {b["index"]: b for b in self.ledger.audit()}
        self.assertFalse(report[2]["signature_ok"])
        self.assertFalse(report[3]["hash_link_ok"])

    def test_tampering_with_genesis_governance_detected(self):
        self.ledger.chain[0].transactions[0].payload["threshold"] = 1
        self.assertFalse(self.ledger.is_valid())

    def test_non_finite_in_memory_tampering_is_reported(self):
        self.ledger.chain[1].transactions[0].payload["quantity"] = float("nan")
        ok, _ = self.ledger.validate_chain()
        self.assertFalse(ok)
        self.assertFalse(self.ledger.audit()[1]["ok"])

    def test_unauthorised_validator_cannot_seal(self):
        self.ledger.submit(self.ledger.build_transaction(
            self.buyer, RETIRE, {"serials": self.ledger.select_serials(self.buyer.address, 1),
                                 "beneficiary": "x"}))
        with self.assertRaisesRegex(LedgerError, "not an authorised validator"):
            self.ledger.seal_block(self.outsider)

    def test_rogue_block_signed_by_outsider_rejected_on_load(self):
        data = self.ledger.to_dict()
        rogue_tx = self.ledger.build_transaction(
            self.buyer, RETIRE, {"serials": self.ledger.select_serials(self.buyer.address, 1),
                                 "beneficiary": "x"})
        block = Block(self.ledger.height, time.time(), self.ledger.last_block.hash, [rogue_tx])
        data["chain"].append(block.seal(self.outsider).to_dict())
        with self.assertRaisesRegex(LedgerError, "unauthorised validator"):
            CarbonLedger.from_dict(data)

    def test_future_block_rejected_on_load(self):
        data = self.ledger.to_dict()
        tx = self.ledger.build_transaction(
            self.buyer, RETIRE, {"serials": self.ledger.select_serials(self.buyer.address, 1),
                                 "beneficiary": "x"})
        block = Block(self.ledger.height, time.time() + 600, self.ledger.last_block.hash, [tx])
        data["chain"].append(block.seal(self.validator).to_dict())
        with self.assertRaisesRegex(LedgerError, "future"):
            CarbonLedger.from_dict(data)

    def test_merkle_inclusion_proof(self):
        tx_id = self.ledger.chain[3].transactions[0].tx_id
        proof = self.ledger.inclusion_proof(tx_id)
        self.assertTrue(CarbonLedger.verify_inclusion(json.loads(json.dumps(proof))))
        proof["leaf_hash"] = sha256_hex("fake")
        self.assertFalse(CarbonLedger.verify_inclusion(proof))

    def test_save_and_load_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ledger.json")
            self.ledger.save(path)
            loaded = CarbonLedger.load(path)
        self.assertEqual(loaded.last_block.hash, self.ledger.last_block.hash)
        self.assertEqual(loaded.stats(), self.ledger.stats())

    def test_tampered_file_refused_on_load(self):
        data = self.ledger.to_dict()
        data["chain"][1]["transactions"][0]["payload"]["quantity"] = 1_000_000
        with self.assertRaises(LedgerError):
            CarbonLedger.from_dict(data)

    def test_malformed_file_refused_on_load(self):
        for junk in ([], {"chain": "x"}, {"chain": [1]}, {"chain": [{"index": 0}]}):
            with self.assertRaises(LedgerError, msg=str(junk)):
                CarbonLedger.from_dict(junk)
        data = self.ledger.to_dict()
        data["chain"][2]["timestamp"] = float("nan")
        with self.assertRaises(LedgerError):
            CarbonLedger.from_dict(data)

        data = self.ledger.to_dict()
        data["chain"][1]["tx_count"] += 1
        with self.assertRaises(LedgerError):
            CarbonLedger.from_dict(data)

        data = self.ledger.to_dict()
        data["pending"] = "not a list"
        with self.assertRaises(LedgerError):
            CarbonLedger.from_dict(data)

    def test_malformed_inclusion_proof_returns_false(self):
        self.assertFalse(CarbonLedger.verify_inclusion({}))
        self.assertFalse(CarbonLedger.verify_inclusion({"leaf_hash": "x", "proof": ["bad"],
                                                        "merkle_root": "y"}))

    def test_longer_valid_chain_replaces_shorter(self):
        other = CarbonLedger.from_dict({"chain": self.ledger.to_dict()["chain"][:2]})
        self.assertTrue(other.replace_chain(self.ledger.to_dict()["chain"]))
        self.assertEqual(other.last_block.hash, self.ledger.last_block.hash)
        self.assertFalse(self.ledger.replace_chain(other.to_dict()["chain"][:2]))


if __name__ == "__main__":
    unittest.main()
