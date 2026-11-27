"""Exercise the Streamlit interface with the real carbon ledger."""

import unittest
from datetime import datetime, timezone
from pathlib import Path

from streamlit.testing.v1 import AppTest

from app import create_demo
from blockchain import ISSUE
from security import hash_document

APP_PATH = Path(__file__).with_name("app.py")


class RegistryAppTests(unittest.TestCase):
    def setUp(self):
        self.app = AppTest.from_file(str(APP_PATH)).run()
        self.assertFalse(self.app.exception)

    def test_issue_requires_evidence(self):
        self.app.radio[0].set_value("Issue").run()
        self.app.button[0].click().run()
        self.assertEqual(self.app.error[0].value, "Upload an MRV report.")

    def test_transfer_retire_lookup_and_verify(self):
        ledger, validator, accounts = create_demo()
        payload = {
            "project_id": "P1",
            "project_name": "Forest restoration",
            "country": "Canada",
            "methodology": "Forest monitoring",
            "vintage": datetime.now(timezone.utc).year,
            "quantity": 1,
            "owner": accounts["Developer"].address,
            "evidence_hash": hash_document(b"Sample monitoring report"),
        }
        transaction = ledger.build_transaction(accounts["Registry A"], ISSUE, payload)
        ledger.submit(transaction)
        ledger.seal_block(validator)
        serial = ledger.get_project("P1")["issuances"][0]["first_serial"]
        self.app.session_state["registry_demo"] = (ledger, validator, accounts)

        self.app.radio[0].set_value("Transfer").run()
        self.app.text_input[0].set_value(serial)
        self.app.button[0].click().run()
        self.assertFalse(self.app.exception)
        self.assertEqual(ledger.get_credit(serial)["owner"], accounts["Buyer"].address)
        self.assertIn("Transferred", self.app.success[0].value)

        self.app.radio[0].set_value("Retire").run()
        self.app.text_input[0].set_value(serial)
        self.app.selectbox[0].set_value("Buyer")
        self.app.text_input[1].set_value("Example Corp")
        self.app.checkbox[0].check()
        self.app.button[0].click().run()
        self.assertFalse(self.app.exception)
        self.assertEqual(ledger.get_credit(serial)["status"], "RETIRED")
        self.assertIn("Retired", self.app.success[0].value)

        self.app.radio[0].set_value("Look up").run()
        self.assertFalse(self.app.exception)
        self.assertEqual(len(self.app.dataframe[0].value), 3)

        self.app.radio[0].set_value("Verify ledger").run()
        self.app.button[0].click().run()
        self.assertIn("4 blocks verified", self.app.success[0].value)


if __name__ == "__main__":
    unittest.main()