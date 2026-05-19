#
#  Copyright 2026, Tony Cheng. All rights reserved.
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

import os
import shutil
import xml.etree.ElementTree as ET

from enum import Enum
from packaging.version import InvalidVersion, Version
from urllib.parse import urlparse
from xml.etree.ElementTree import Element

from git import Repo

from .console import ColoredMessage
from .git_ops import (
    checkout_to_tag,
    clone_repository,
    get_repository_name,
    is_git_repository,
    to_ssh,
    update_repository,
)
from .utils import chmod_recursive, get_optional_text, get_required_text, safe_join


class ToolAction(Enum):
    CLONE_REPOSITORY = 1
    UPDATE_REPOSITORY = 2
    UNDEFINED = 3


class ExecutionContext:
    def __init__(self):
        self.action: ToolAction = ToolAction.UNDEFINED
        self.file: str = "Project.pfc"
        self.project_path: str | None = None
        self.override_dict: dict[str, str] = {}
        self.omit_submodules: bool = False
        self.dry_run: bool = False


def check_dependency(
    target_name: str,
    target_version: str,
    feature_dict: dict,
    fork_dependency_dict: dict,
    fork_repository_dict: dict,
) -> tuple[bool, str | None, str | None]:
    exception = ["Kernel-EDK2", "Kernel-Base", "Kernel-BaseToolsBin"]

    version = feature_dict.get(target_name, None)
    if version is None:
        version = fork_dependency_dict.get(target_name, None)

    warning = None
    if version is None:
        fork_repository = fork_repository_dict.get(target_name, None)
        if fork_repository is not None:
            version = fork_repository.get("version", None)
            dependency_name = fork_repository.get("dependency_name", None)
            repository_url = fork_repository.get("repository_url", None)
            warning = (
                f"Warning: Fork URL points to {target_name}, "
                f"but the dependency name is {dependency_name}.\n"
                f"Note: Treat {target_name} as satisfied by {repository_url}."
            )

    if version is None:
        if target_name in exception:
            target_name = target_name.replace("-", "_")
            for feature in list(feature_dict.keys()):
                if str(feature).startswith(target_name):
                    version = feature_dict.get(feature, None)
                    break
            if version is None:
                for dependency in list(fork_dependency_dict.keys()):
                    if str(dependency).startswith(target_name):
                        version = fork_dependency_dict.get(dependency, None)
                        break

    if version:
        try:
            satisfied = Version(version) >= Version(target_version)
        except InvalidVersion as e:
            ColoredMessage.print(
                f"Warning: Unable to compare dependency version for {target_name}: {e}"
            )
            return False, version, None

        return (
            satisfied,
            version if not satisfied else None,
            warning if satisfied else None,
        )
    else:
        return False, None, None


def collect_fork_dependency_dict(feature_list: list[Element]) -> tuple[dict, dict]:
    fork_dependency_dict = {}
    fork_repository_dict = {}

    for feature in feature_list:
        feature_name = get_optional_text(feature, "Name", "Unknown")
        for fork in feature.findall("./Fork"):
            repository = fork.find("Repository")

            for dependency in fork.findall("Dependency"):
                name = get_optional_text(dependency, "Name")
                version = get_optional_text(dependency, "Version")
                if name is None or version is None:
                    ColoredMessage.print(
                        f"Warning: Fork dependency of {feature_name} is incomplete."
                    )
                    continue

                if name in fork_dependency_dict and fork_dependency_dict[name] != version:
                    ColoredMessage.print(
                        f"Warning: Fork dependency {name} is described more than once."
                    )

                fork_dependency_dict[name] = version

                if repository is None:
                    continue

                url = get_optional_text(repository, "Url")
                if url is None:
                    continue

                repository_name = get_repository_name(url)
                if (
                    repository_name in fork_repository_dict
                    and fork_repository_dict[repository_name]["version"] != version
                ):
                    ColoredMessage.print(
                        f"Warning: Fork repository {repository_name} is described more than once."
                    )

                fork_repository_dict[repository_name] = {
                    "dependency_name": name,
                    "repository_url": url,
                    "version": version,
                }

    return fork_dependency_dict, fork_repository_dict


def get_repository_tag(repository: Element | None) -> str:
    tag = get_optional_text(repository, "Tag")
    if tag is None:
        ColoredMessage.print(
            "Note: Repository tag is not described, use master as default."
        )
        return "master"

    return tag


def remove_unused_feature(
    project_path: str, incoming_roots: list[str], dry_run: bool = False
) -> None:
    current_pfc = os.path.join(project_path, "Project.pfc")
    if not os.path.exists(current_pfc):
        return

    xml_tree = ET.parse(current_pfc)
    root_element = xml_tree.getroot()

    current_roots = []
    for feature in root_element.findall("./Feature"):
        root = get_optional_text(feature, "Root")
        if root is not None:
            current_roots.append(root)

    diff1 = [root for root in current_roots if root not in incoming_roots]
    diff2 = [root for root in incoming_roots if root not in current_roots]
    diff = sorted(diff1 + diff2)
    if diff:
        for root in diff:
            try:
                path = safe_join(project_path, root)
            except ValueError as e:
                ColoredMessage.print(f"Warning: {e}")
                continue

            if os.path.isdir(path) and is_git_repository(path):
                if dry_run:
                    ColoredMessage.print(
                        f"Note: [DRY-RUN] Removing unused feature {os.path.relpath(path)}."
                    )
                else:
                    ColoredMessage.print(f"Note: Removing {os.path.relpath(path)}")
                    chmod_recursive(path, 0o777)
                    shutil.rmtree(path)


def process_pfc(context: ExecutionContext) -> None:
    if context.action == ToolAction.UNDEFINED:
        ColoredMessage.print("Error: Invalid tool action detected!")
        return

    xml_tree = ET.parse(context.file)
    root_element = xml_tree.getroot()

    if context.dry_run:
        ColoredMessage.print(
            "Note: [DRY-RUN] Repository access is allowed, but clone/update/remove operations will be skipped."
        )

    base_path = context.project_path if context.project_path else os.getcwd()

    root_element[:] = sorted(
        root_element,
        key=lambda feature: get_required_text(feature, "Root", "Feature"),
    )

    feature_dict = {}
    feature_list = root_element.findall("./Feature")

    if context.action == ToolAction.UPDATE_REPOSITORY:
        roots = [
            get_required_text(element, "Root", "Feature") for element in feature_list
        ]
        remove_unused_feature(base_path, roots, dry_run=context.dry_run)

    for feature in feature_list:
        name = get_required_text(feature, "Name", "Feature")
        version = get_required_text(feature, "Version", f"Feature {name}")
        feature_dict[name] = version
    fork_dependency_dict, fork_repository_dict = collect_fork_dependency_dict(
        feature_list
    )

    requirements = []
    dependency_warnings = []

    for feature in feature_list:
        name = get_required_text(feature, "Name", "Feature")
        root = os.path.normpath(get_required_text(feature, "Root", f"Feature {name}"))
        root_path = safe_join(base_path, root)

        for dependency in feature.findall("Dependency"):
            target_name = get_required_text(
                dependency, "Name", f"Dependency of {name}"
            )
            target_version = get_required_text(
                dependency, "Version", f"Dependency {target_name} of {name}"
            )
            satisfied, version, warning = check_dependency(
                target_name,
                target_version,
                feature_dict,
                fork_dependency_dict,
                fork_repository_dict,
            )
            if warning:
                dependency_warnings.append(warning)
            if not satisfied:
                requirements.append((target_name, target_version, version))
        if dependency_warnings:
            for warning in dependency_warnings:
                for message in warning.splitlines():
                    ColoredMessage.print(message)
            dependency_warnings.clear()
        if requirements:
            ColoredMessage.print(f"Warning: Dependency of {name} is not satisfied!")
            for req in requirements:
                if req[2] is None:
                    message = f"Requires {req[0]} at {req[1]}, but it was not found."
                else:
                    message = (
                        f"Requires {req[0]} at {req[1]}, but {req[2]} was detected."
                    )
                ColoredMessage.print(f"Note: {message}")
            requirements.clear()

        for repository in feature.findall("Repository"):
            repository_type = get_required_text(
                repository, "Type", f"Repository of {name}"
            )
            if repository_type.casefold() != "git".casefold():
                continue

            url = to_ssh(get_required_text(repository, "Url", f"Repository of {name}"))
            tag = get_repository_tag(repository)

            if context.override_dict:
                tag = context.override_dict.get(urlparse(url).path[1:], tag)

            if context.dry_run:
                clone_repository(
                    url,
                    root_path,
                    tag,
                    omit_submodules=context.omit_submodules,
                    dry_run=True,
                )
                continue

            if os.path.isdir(root_path):
                if is_git_repository(root_path):
                    update_repository(
                        root_path, tag, omit_submodules=context.omit_submodules
                    )
                    continue
                else:
                    ColoredMessage.print(
                        f"Note: Removing {os.path.relpath(root_path)}"
                    )
                    chmod_recursive(root_path, 0o777)
                    shutil.rmtree(root_path)

            clone_repository(
                url,
                root_path,
                tag,
                omit_submodules=context.omit_submodules,
                dry_run=context.dry_run,
            )

        """
        Note: This is a workaround for H2O Kernel 5.7,
              .gitmodules is not found in some repositories that contain submodules.
              Problematic repositories are listed below:

              Board\\Intel\\RaptorLakePBoardPkg\\BIOS
              Insyde\\InsydeModulePkg\\Library\\OpensslLib\\openssl
        """
        for external in feature.findall("External"):
            repository = external.find("./Repository")
            repository_type = get_required_text(
                repository, "Type", f"External repository of {name}"
            )
            if repository_type.casefold() != "git".casefold():
                continue
            source_dir = get_required_text(external, "SourceDir", f"External of {name}")
            folder_path = safe_join(root_path, source_dir)
            url = get_required_text(repository, "Url", f"External repository of {name}")
            url = to_ssh(url) if "insyde".casefold() in url.casefold() else url
            tag = get_repository_tag(repository)

            if context.override_dict:
                tag = context.override_dict.get(urlparse(url).path[1:], tag)

            if context.dry_run:
                clone_repository(
                    url,
                    folder_path,
                    tag,
                    shallow=True,
                    omit_submodules=True,
                    dry_run=True,
                )
                continue

            if os.path.isdir(folder_path) and is_git_repository(folder_path):
                repo = Repo(folder_path)
                try:
                    if checkout_to_tag(repo, tag, fetch=False) is None:
                        continue
                finally:
                    repo.close()

            if os.path.isdir(folder_path) and os.listdir(folder_path):
                ColoredMessage.print(f"Note: Removing {os.path.relpath(folder_path)}")
                chmod_recursive(folder_path, 0o777)
                shutil.rmtree(folder_path)

            clone_repository(
                url,
                folder_path,
                tag,
                shallow=True,
                omit_submodules=True,
                dry_run=context.dry_run,
            )
