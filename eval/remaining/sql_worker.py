"""Broker client; generated SQL remains data, never worker executable code."""

from langgraph.prebuilt.security import object_request


def run(operation, query, selector):
    return object_request("sales", operation, selector, {"query": query})
