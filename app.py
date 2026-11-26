import streamlit as st

class PreviewLedger:
    """Session-local sample records for trying the interface."""

    def __init__(self):
        self.history = {}

    def issue_credit(self, *, credit_id, project, owner, actor):
        if actor != "registry":
            raise PermissionError("Only the registry can issue credits in the preview.")
        if credit_id in self.history:
            raise ValueError("That credit ID is already registered.")
        self.history[credit_id] = [
            dict(action="Issued", owner=owner, project=project, status="Active", actor=actor)
        ]

    def get_credit_history(self, credit_id):
        return self.history.get(credit_id, [])

    def _record_change(self, credit_id, actor, action, status, new_owner=None):
        entries = self.get_credit_history(credit_id)
        if not entries:
            raise ValueError("Credit ID not found.")
        latest = entries[-1]
        if latest["status"] == "Retired":
            raise ValueError("This credit has already been retired.")
        if latest["owner"] != actor:
            raise PermissionError("Only the current owner can perform this action.")
        if new_owner == actor:
            raise ValueError("Choose a different owner.")
        entries.append(
            dict(latest, action=action, owner=new_owner or actor, status=status, actor=actor)
        )

    def transfer_credit(self, *, credit_id, new_owner, actor):
        self._record_change(credit_id, actor, "Transferred", "Active", new_owner)

    def retire_credit(self, *, credit_id, actor):
        self._record_change(credit_id, actor, "Retired", "Retired")


def get_backend():
    try:
        from blockchain import Ledger
    except ModuleNotFoundError as error:
        if error.name != "blockchain":
            raise
        if "preview_ledger" not in st.session_state:
            st.session_state.preview_ledger = PreviewLedger()
        return st.session_state.preview_ledger, True
    if "registry_ledger" not in st.session_state:
        st.session_state.registry_ledger = Ledger()
    return st.session_state.registry_ledger, False


def show_history(ledger):
    with st.form("lookup"):
        credit_id = st.text_input("Credit ID", placeholder="CC-001")
        submitted = st.form_submit_button("Look up credit", type="primary")
    if submitted:
        st.session_state.lookup_id = credit_id.strip()
    credit_id = st.session_state.get("lookup_id")
    if credit_id is None:
        return
    if not credit_id:
        st.error("Enter a credit ID.")
        return
    history = ledger.get_credit_history(credit_id)
    if not history:
        st.info(f"No record found for {credit_id}.")
        return
    latest = history[-1]
    project, owner, status = st.columns(3)
    project.metric("Project", latest["project"])
    owner.metric("Current owner", latest["owner"])
    status.metric("Status", latest["status"])
    st.subheader("Transaction history")
    st.dataframe(history, hide_index=True)


def show_write_form(ledger, action):
    with st.form(action):
        credit_id = st.text_input("Credit ID", placeholder="CC-001")
        actor_label = "Issuing registry ID" if action == "Issue" else "Current owner ID"
        actor = st.text_input(actor_label)
        fields = dict(credit_id=credit_id.strip(), actor=actor.strip())
        if action == "Issue":
            fields["project"] = st.text_input("Project name").strip()
            fields["owner"] = st.text_input("Initial owner ID").strip()
        elif action == "Transfer":
            fields["new_owner"] = st.text_input("New owner ID").strip()
        else:
            confirmed = st.checkbox("I confirm that this credit should be permanently retired.")
        submitted = st.form_submit_button(f"{action} credit", type="primary")
    if not submitted:
        return
    if not all(fields.values()):
        st.error("Complete all fields.")
        return
    if action == "Retire" and not confirmed:
        st.error("Confirm the retirement before submitting.")
        return
    operations = {
        "Issue": (ledger.issue_credit, "issued"),
        "Transfer": (ledger.transfer_credit, "transferred"),
        "Retire": (ledger.retire_credit, "retired"),
    }
    operation, result = operations[action]
    try:
        operation(**fields)
    except (ValueError, PermissionError) as error:
        st.error(str(error))
    else:
        st.session_state.lookup_id = fields["credit_id"]
        st.success(f"Credit {fields['credit_id']} {result}. Open Look up to see its history.")


def main():
    st.set_page_config(page_title="Carbon Credit Registry", layout="centered")
    st.title("Carbon Credit Registry")
    ledger, preview = get_backend()
    if preview:
        st.info("Interface preview. Use registry as the issuing registry ID. Records last for this session.")
    view = st.radio(
        "Registry actions", ["Look up", "Issue", "Transfer", "Retire", "Verify ledger"],
        horizontal=True, label_visibility="collapsed",
    )
    if view == "Look up":
        show_history(ledger)
    elif view == "Verify ledger":
        if preview:
            st.info("Ledger verification becomes available after the blockchain is connected.")
        elif st.button("Verify blockchain", type="primary"):
            if ledger.verify_chain():
                st.success("The blockchain passed verification.")
            else:
                st.error("The blockchain failed verification.")
    else:
        show_write_form(ledger, view)


if __name__ == "__main__":
    main()