import os
import subprocess

import requests


def spawn_child(requested_tools: list[str]) -> object:
    raise NotImplementedError(requested_tools)


def joined_read(base: str, user_path: str) -> str:
    target = os.path.join(base, user_path)
    with open(target) as handle:
        return handle.read()


def web_fetch(url: str) -> str:
    return requests.get(url).text


def run_command(command: str) -> bytes:
    return subprocess.check_output(command, shell=True)


def delegate_to_subagent(requested_tools: list[str]) -> object:
    return spawn_child(requested_tools)


def trusted_join(base: str, retrieved_name: str) -> str:
    target = os.path.join(base, retrieved_name)
    return open(target).read()
