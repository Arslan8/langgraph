"""Run only through 09_no_internet/demo.py, inside the Linux sandbox."""

import socket
from pathlib import Path


def offline_report(path: str):
    """Read the granted file and try TCP/UDP socket creation without connecting."""
    result = {"local_read": Path(path).read_text()}
    for family_name, family in (("ipv4", socket.AF_INET), ("ipv6", socket.AF_INET6)):
        for kind_name, kind in (
            ("tcp", socket.SOCK_STREAM),
            ("udp", socket.SOCK_DGRAM),
        ):
            try:
                with socket.socket(family, kind):
                    result[f"{family_name}_{kind_name}"] = "escaped"
            except PermissionError:
                result[f"{family_name}_{kind_name}"] = "blocked"
    return result
