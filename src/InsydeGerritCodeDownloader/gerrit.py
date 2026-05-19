#
#  Copyright 2026, Tony Cheng. All rights reserved.
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

import difflib
import os
import posixpath

from collections.abc import Iterator
from contextlib import contextmanager
from paramiko import AutoAddPolicy, SSHClient, SSHConfig
from scp import SCPClient
from urllib.parse import urlparse, urlunparse

from .console import ColoredMessage


@contextmanager
def create_ssh_client(host: str) -> Iterator[SSHClient]:
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())

    try:
        config = SSHConfig.from_path(
            os.path.normpath(os.path.expanduser("~/.ssh/config"))
        )
        result = config.lookup(host)
        hostname = result.get("hostname") or host
        port = int(result.get("port", 29418))
        ssh.load_system_host_keys(
            os.path.normpath(os.path.expanduser("~/.ssh/known_hosts"))
        )
        ssh.connect(
            hostname,
            port,
            result.get("user", None),
            key_filename=result.get("identityfile"),
        )

    except Exception as e:
        raise RuntimeError(f"Failed to establish SSH connection to {host}!") from e

    try:
        yield ssh
    finally:
        ssh.close()


def get_commit_msg_hook(host: str, folder_path: str) -> None:
    try:
        with create_ssh_client(host) as ssh:
            transport = ssh.get_transport()
            if transport is None:
                raise RuntimeError(f"Failed to open SSH transport to {host}.")

            with SCPClient(transport) as scp:
                try:
                    scp.get(
                        "hooks/commit-msg", os.path.join(folder_path, ".git/hooks/")
                    )
                    ColoredMessage.print(
                        f"Note: The commit-msg hook from {host} has been added to {folder_path}."
                    )

                except Exception as e:
                    ColoredMessage.print(
                        f"Warning: Failed to get commit-msg hook from {host}: {e}"
                    )

    except Exception as e:
        ColoredMessage.print(str(e))
        return


def fetch_gerrit_projects() -> list[str]:
    try:
        with create_ssh_client("gerrit.insyde.com") as ssh:
            _, stdout, stderr = ssh.exec_command("gerrit ls-projects", timeout=5)
            err = stderr.read().decode().strip()
            if err:
                raise RuntimeError(f"Failed to execute command: gerrit ls-projects!")

            return stdout.read().decode("utf-8").strip().splitlines()

    except Exception as e:
        ColoredMessage.print(f"Error: {str(e)}")
        return []


def get_suggest_url(url: str) -> str | None:
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    if hostname is None or "insyde" not in hostname.lower():
        return None

    path = parsed_url.path.lstrip("/")

    known_paths = fetch_gerrit_projects()
    if not known_paths:
        return None

    match = difflib.get_close_matches(path, known_paths, n=1, cutoff=0.7)
    if not match:
        return None

    corrected_path = posixpath.join("/", match[0])
    new_parts = parsed_url._replace(path=corrected_path)
    return urlunparse(new_parts)
