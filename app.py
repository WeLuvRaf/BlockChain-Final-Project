"""Streamlit interface for the carbon credit registry classroom demo."""

from datetime import datetime, timezone

import streamlit as st

from blockchain import (
    ISSUE,
    MAX_BUFFER_PERCENT,
    MAX_ISSUANCE,
    MIN_VINTAGE,
    RETIRE,
    TRANSFER,
    CarbonLedger,
    LedgerError,
)
from security import KeyPair, hash_document


def create_demo():
    governance = KeyPair()
    validator = KeyPair()
    accounts = {name: KeyPair() for name in ("Registry A", "Developer", "Buyer")}
    ledger = CarbonLedger.create(
        governance_keys=[governance.public_key_hex],
        threshold=1,
        validator_keys=[validator.public_key_hex],
        issuers=[
            {
                "public_key": accounts["Registry A"].public_key_hex,
                "name": "Registry A",
                "standard": "RA",
            }
        ],
    )
    return ledger, validator, accounts


def show_history(ledger):
    with st.form("lookup"):
        serial = st.text_input(
            "Credit serial", value=st.session_state.get("lookup_id", "")
        )
        submitted = st.form_submit_button("Look up credit", type="primary")

    if submitted:
        st.session_state.lookup_id = serial.strip()

    serial = st.session_state.get("lookup_id")
    if not serial:
        if submitted:
            st.error("Enter a credit serial.")
        return

    credit = ledger.get_credit(serial)
    if credit is None:
        st.info(f"No record found for {serial}.")
        return

    project = ledger.get_project(credit["project_id"])
    st.subheader(serial)
    st.write(f"{project['name']} · {credit['vintage']}")
    st.write(f"Status · {credit['status'].title()}")
    st.text(f"Owner · {credit['owner']}")
    st.text(f"MRV evidence SHA-256 · {credit['evidence_hash']}")
    st.subheader("Transaction history")
    st.dataframe(ledger.credit_history(serial), hide_index=True)


def issue_fields(accounts):
    st.caption("Issuing registry · Registry A")
    project_id = st.text_input("Project ID", placeholder="AMZ001").strip()
    project_name = st.text_input("Project name").strip()
    country = st.text_input("Country").strip()
    methodology = st.text_input("Methodology").strip()
    year = datetime.now(timezone.utc).year
    vintage = st.number_input("Vintage", MIN_VINTAGE, year, year)
    quantity = st.number_input("Quantity", 1, MAX_ISSUANCE, 1)
    buffer_percent = st.number_input("Buffer percentage", 0, MAX_BUFFER_PERCENT, 0)
    owner = st.selectbox("Initial owner", ["Developer", "Buyer"])
    report = st.file_uploader("MRV report (only its SHA-256 hash is recorded)")

    payload = {
        "project_id": project_id,
        "project_name": project_name,
        "country": country,
        "methodology": methodology,
        "vintage": vintage,
        "quantity": quantity,
        "buffer_percent": buffer_percent,
        "owner": accounts[owner].address,
    }
    if report is not None:
        payload["evidence_hash"] = hash_document(report.getvalue())
    return payload


def show_write_form(ledger, validator, accounts, action):
    with st.form(action):
        if action == ISSUE:
            signer = "Registry A"
            payload = issue_fields(accounts)
        else:
            serial = st.text_input(
                "Credit serial", value=st.session_state.get("lookup_id", "")
            ).strip()
            signer = st.selectbox("Signing account", ["Developer", "Buyer", "Registry A"])
            payload = {"serials": [serial]}

            if action == TRANSFER:
                recipient = st.selectbox("New owner", ["Buyer", "Developer", "Registry A"])
                payload["to"] = accounts[recipient].address
            else:
                payload["beneficiary"] = st.text_input("Beneficiary").strip()
                payload["purpose"] = st.text_input("Purpose (optional)").strip()
                confirmed = st.checkbox("Confirm permanent retirement")

        submitted = st.form_submit_button(f"{action.title()} credit", type="primary")

    if not submitted:
        return
    if action == ISSUE and "evidence_hash" not in payload:
        st.error("Upload an MRV report.")
        return
    if action != ISSUE and not serial:
        st.error("Enter a credit serial.")
        return
    if action == RETIRE and not confirmed:
        st.error("Confirm the retirement before submitting.")
        return

    try:
        transaction = ledger.build_transaction(accounts[signer], action, payload)
        tx_id = ledger.submit(transaction)
        block = ledger.seal_block(validator)
    except LedgerError as error:
        st.error(str(error))
        return

    if action == ISSUE:
        issuance = ledger.get_project(payload["project_id"])["issuances"][-1]
        serial = issuance["first_serial"]
        last_serial = issuance["last_serial"]
        issued = serial if serial == last_serial else f"{serial} through {last_serial}"
        st.success(f"Issued {issued} in block {block.index}.")
    else:
        verb = "Transferred" if action == TRANSFER else "Retired"
        st.success(f"{verb} {serial} in block {block.index}.")

    st.session_state.lookup_id = serial
    st.caption(f"Transaction ID · {tx_id}")


def main():
    st.set_page_config(page_title="Carbon Credit Registry", layout="centered")
    st.title("Carbon Credit Registry")
    st.caption("Classroom demo. Signing accounts and records belong to this browser session.")

    if "registry_demo" not in st.session_state:
        st.session_state.registry_demo = create_demo()
    ledger, validator, accounts = st.session_state.registry_demo

    view = st.radio(
        "Registry actions",
        ["Look up", "Issue", "Transfer", "Retire", "Verify ledger"],
        horizontal=True,
        label_visibility="collapsed",
    )

    if view == "Look up":
        show_history(ledger)
    elif view == "Verify ledger":
        if st.button("Verify blockchain", type="primary"):
            valid, detail = ledger.validate_chain()
            if valid:
                st.success(detail)
            else:
                st.error(detail)
    else:
        show_write_form(ledger, validator, accounts, view.upper())


if __name__ == "__main__":
    main()