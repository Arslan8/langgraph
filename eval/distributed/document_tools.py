"""Tools for the immutable-language document-reporting workflow."""

from __future__ import annotations

from langchain_core.tools import tool
from langgraph.prebuilt.security.inprocess import read_text


@tool("summarize_documents")
def summarize_documents(policy_path: str, procedure_path: str) -> str:
    """Read two granted documents and return a bounded compliance summary."""
    policy = read_text(policy_path)
    procedure = read_text(procedure_path)
    if policy == "retain seven years":  # noqa: SIM102 - required language subset
        if procedure == "retain seven years":
            return "approved: policy and procedure both require seven-year retention"
    return "manual review: policy and procedure differ"
