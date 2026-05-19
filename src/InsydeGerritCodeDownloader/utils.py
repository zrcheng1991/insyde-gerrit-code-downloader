#
#  Copyright 2026, Tony Cheng. All rights reserved.
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

import os

from pathlib import Path
from xml.etree.ElementTree import Element


def display_path(path: str) -> str:
    return os.path.normpath(os.path.relpath(path)) if os.path.isabs(path) else path


def safe_join(base_path: str, *paths: str) -> str:
    base_path = os.path.realpath(base_path)
    target_path = os.path.realpath(os.path.join(base_path, *paths))

    if os.path.commonpath([base_path, target_path]) != base_path:
        raise ValueError(
            f"Resolved path '{target_path}' is outside of project root '{base_path}'."
        )

    return target_path


def get_optional_text(
    element: Element | None, path: str, default: str | None = None
) -> str | None:
    if element is None:
        return default

    node = element.find(path)
    if node is None or node.text is None:
        return default

    text = node.text.strip()
    return text if text else default


def get_required_text(element: Element | None, path: str, context: str) -> str:
    text = get_optional_text(element, path)
    if text is None:
        raise ValueError(f"{context} is missing required field '{path}'.")

    return text


def chmod_recursive(directory, mode):
    directory_path = Path(directory)
    for item in directory_path.rglob("*"):
        item.chmod(mode)
