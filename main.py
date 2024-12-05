#
#  Copyright (c) 2024, Tony Cheng. All rights reserved.
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

import argparse
import colorful as cf
import git
import os
import shutil
import subprocess
import tarfile
import xml.etree.ElementTree as ET

from argparse import ArgumentParser
from enum import Enum
from git import Repo, RemoteProgress
from io import TextIOWrapper
import git.exc
from packaging.version import Version
from paramiko import SSHClient, SSHConfig
from pathlib import Path
from rich import console, progress
from scp import SCPClient
from typing import Union, Optional
from urllib.parse import urlparse
from xml.etree.ElementTree import Element


# global variables
project_tag = None
project_url = None
project_path = None
override_dict = {}
omit_submodules = False


class ToolAction(Enum):
    CLONE_REPOSITORY = 1
    UPDATE_REPOSITORY = 2


class ColoredMessage:
    color_dict = {"NOTE": cf.dimGrey, "WARNING": cf.orange, "ERROR": cf.orangeRed}

    @staticmethod
    def print(message: str) -> None:
        message_level = message.split(":", 2)[0].strip()
        color_code = ColoredMessage.color_dict.get(message_level.upper(), None)
        if color_code is None:
            print(message)
        else:
            print(f"{color_code}{message}{cf.reset}")


class GitProgressBar(RemoteProgress):
    opcode_desc = {
        RemoteProgress.BEGIN: "",
        RemoteProgress.END: "",
        RemoteProgress.COUNTING: "Counting objects",
        RemoteProgress.COMPRESSING: "Compressing objects",
        RemoteProgress.WRITING: "Writing objects",
        RemoteProgress.RECEIVING: "Receiving objects",
        RemoteProgress.RESOLVING: "Resolving deltas",
        RemoteProgress.FINDING_SOURCES: "Finding sources",
        RemoteProgress.CHECKING_OUT: "Checking out",
    }

    def __init__(self, fetching: bool = False) -> None:
        super().__init__()
        self.pbar = progress.Progress(
            progress.SpinnerColumn(),
            progress.TextColumn("[progress.description]{task.description}"),
            progress.BarColumn(),
            progress.TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            "ET",
            progress.TimeElapsedColumn(),
            progress.TextColumn("{task.fields[message]}"),
            console=console.Console(),
            transient=False,
        )
        self.task_id = None
        self.pbar.start()
        self.fetching = fetching
        self.spinner_task = None

    def __del__(self) -> None:
        if self.fetching and self.spinner_task:
            self.pbar.remove_task(self.spinner_task)
        self.pbar.stop()

    def update(
        self,
        op_code: int,
        cur_count: Union[str, float],
        max_count: Union[str, float, None] = None,
        message: str = "",
    ) -> None:
        if op_code & RemoteProgress.BEGIN == RemoteProgress.BEGIN:
            op_code = op_code & ~RemoteProgress.BEGIN

            if op_code & RemoteProgress.COUNTING == RemoteProgress.COUNTING:
                if isinstance(cur_count, float):
                    max_count = cur_count * 10

            if max_count is not None and isinstance(max_count, float):
                if self.fetching and self.spinner_task:
                    self.pbar.remove_task(self.spinner_task)
                self.task_id = self.pbar.add_task(
                    description=f"{self.opcode_desc[op_code]}",
                    total=max_count,
                    visible=True,
                    message="",
                )
                if self.fetching:
                    self.spinner_task = self.pbar.add_task(
                        description="(Processing)",
                        total=None,
                        message="please wait for a while",
                    )

        if op_code & RemoteProgress.END == RemoteProgress.END:
            op_code = op_code & ~RemoteProgress.END

        if self.task_id is not None and isinstance(cur_count, float):
            self.pbar.update(self.task_id, completed=cur_count, message=message)


def fetch_with_progress(
    folder_path: str, url: str, commit_id: str, depth: int = 1
) -> bool:
    url_path = urlparse(url).path[1:] if "insyde".casefold() in url.casefold() else url
    print(f"Fetching {commit_id} from {url_path} with depth={depth}:")

    command = f"git fetch --depth {depth} origin {commit_id} --progress"
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=folder_path,
        text=True,
    )

    pbar = GitProgressBar(fetching=True)

    complete = False
    while True:
        stderr = process.stderr.readline().strip()

        if stderr.find("FETCH_HEAD") != -1:
            complete = True

        if not stderr and process.poll() is not None:
            break

        pbar._parse_progress_line(stderr)

    result = process.returncode == 0 and complete

    return result


def get_commit_msg_hook(host: str, folder_path: str) -> None:
    ssh = SSHClient()

    try:
        config = SSHConfig.from_path(
            os.path.normpath(os.path.expanduser("~/.ssh/config"))
        )
        result = config.lookup(host)
        ssh.load_system_host_keys(
            os.path.normpath(os.path.expanduser("~/.ssh/known_hosts"))
        )
        ssh.connect(
            result.get("hostname"),
            result.get("port", 29418),
            result.get("user", None),
            key_filename=result.get("identityfile"),
        )
    except Exception as e:
        ColoredMessage.print(f"Error: Failed to connect to {host}!")
        return

    scp = SCPClient(ssh.get_transport())
    try:
        scp.get("hooks/commit-msg", os.path.join(folder_path, ".git/hooks/"))
        ColoredMessage.print(
            f"Note: The commit-msg hook from {host} has been added to {folder_path}."
        )
    except Exception as e:
        ColoredMessage.print(f"Warning: Failed to get commit-msg hook from {host}!")

    scp.close()


def checkout_to_tag(repo: Repo, tag: str, fetch: bool = False) -> Optional[str]:
    if fetch:
        repo.git.fetch("--all")

    if tag.casefold() == "Trunk".casefold():
        ColoredMessage.print(
            f'Note: Tag "{tag}" is invalid for GIT, replace it with master.'
        )
        tag = "master"

    url_path = urlparse(repo.remotes[0].url).path[1:]
    tag = override_dict.get(url_path, tag)
    folder_path = os.path.relpath(repo.working_dir)

    for tag_ref in repo.tags:
        if tag_ref.name == tag and tag_ref.commit == repo.head.commit:
            ColoredMessage.print(
                f"Note: {folder_path} is already at {tag}, skip checking out"
            )
            return None

    if os.path.isfile(os.path.join(repo.git_dir, "shallow")):
        ColoredMessage.print(
            f"Note: {folder_path} is a shallow repository, skip checking out"
        )
        return tag

    print(f"Checking out {folder_path} to {tag}")
    if tag != "master":
        path = f"refs/tags/{tag}"
        refs = str(repo.git.ls_remote("--refs")).splitlines()
        paths = [ref.split()[1] for ref in refs]

        if path in paths:
            repo.git.checkout(tag, "--detach")
        else:
            ColoredMessage.print(f"Warning: Tag {tag} is not available!")
    else:
        repo.git.checkout(tag)

    return tag


def clone_submodules(repo: Repo, folder_path: str) -> None:
    for submodule in repo.submodules:
        folder_path = os.path.normpath(os.path.join(folder_path, submodule.path))
        url = (
            to_ssh(submodule.url)
            if "insyde".casefold() in submodule.url.casefold()
            else submodule.url
        )

        submodule_repo = Repo.init(folder_path)
        submodule_repo.create_remote("origin", url)
        result = fetch_with_progress(folder_path, url, submodule.hexsha)

        if result:
            print(f"Checking out {folder_path} to FETCH_HEAD")
            submodule_repo.git.checkout("FETCH_HEAD")
        else:
            ColoredMessage.print(f"Warning: Failed to fetch from server!")
        submodule_repo.close()
    pass


def clone_repository(
    url: str, folder_path: str, tag: str = None, shallow: bool = False
) -> None:
    global omit_submodules

    url_path = urlparse(url).path[1:] if "insyde".casefold() in url.casefold() else url

    if shallow and tag is not None:
        print(f"Cloning {url_path} ({tag}) to {folder_path}:")
        repo = Repo.clone_from(url, folder_path, GitProgressBar(), branch=tag, depth=1)
    else:
        print(f"Cloning {url_path} to {folder_path}:")
        repo = Repo.clone_from(url, folder_path, GitProgressBar())

        if tag is not None:
            tag = checkout_to_tag(repo, tag)
            if tag == "master":
                get_commit_msg_hook(urlparse(url).hostname, folder_path)

    if len(repo.submodules) > 0 and not omit_submodules:
        clone_submodules(repo, folder_path)

    repo.close()


def chmod_recursive(directory, mode):
    directory_path = Path(directory)
    for item in directory_path.rglob(
        "*"
    ):  # recursively visit all files and subdirectories
        item.chmod(mode)


def remove_all_submodules(repo: Repo) -> None:
    for submodule in repo.submodules:
        path = os.path.join(repo.working_dir, submodule.path)
        if os.path.exists(path):
            ColoredMessage.print(f"Note: Removing {os.path.relpath(path)}")
            chmod_recursive(path, 0o777)
            shutil.rmtree(path)


def update_repository(folder_path: str, tag: str) -> None:
    global omit_submodules

    repo = git.Repo(folder_path)

    if len(repo.submodules) > 0:
        remove_all_submodules(repo)

    tag = checkout_to_tag(repo, tag, True)
    if tag:
        if tag == "master":
            get_commit_msg_hook(urlparse(repo.remotes[0].url).hostname, folder_path)

    if len(repo.submodules) > 0 and not omit_submodules:
        clone_submodules(repo, folder_path)

    repo.close()


def to_ssh(url: str) -> str:
    parsed_url = urlparse(url)
    if parsed_url.scheme == "ssh":
        return url
    if parsed_url.hostname:
        if "insyde" not in parsed_url.hostname.lower():
            return parsed_url._replace(scheme="ssh").geturl()
    else:
        ColoredMessage.print(f"Warning: {url} might not be a valid URL!")
        return url

    nodes = parsed_url.path.split("/")

    # remove trailing ".git" in last node
    if nodes[-1].endswith(".git"):
        nodes[-1] = nodes[-1][:-4]

    # build new path without node "/a"
    filtered_path = "/".join(node for node in nodes if node != "a")

    return f"ssh://gerrit.insyde.com:29418{filtered_path}"


def check_dependency(
    target_name: str, target_version: str, feature_dict: dict
) -> tuple[bool, Union[str, None]]:
    exception = ["Kernel-EDK2", "Kernel-Base", "Kernel-BaseToolsBin"]

    version = feature_dict.get(target_name, None)

    if version is None:
        if target_name in exception:
            target_name = target_name.replace("-", "_")
            for feature in list(feature_dict.keys()):
                if str(feature).startswith(target_name):
                    version = feature_dict.get(feature, None)
                    break

    if version:
        satisfied = Version(version) >= Version(target_version)
        return satisfied, version if not satisfied else None
    else:
        return False, None


def is_git_repository(folder_path: str) -> bool:
    try:
        repo = git.Repo(folder_path)
        result = not repo.bare
        repo.close()
        return result
    except git.exc.InvalidGitRepositoryError:
        return False


def remove_unused_feature(incoming_roots: list[Element]) -> None:
    global project_path

    current_pfc = os.path.join(project_path, "Project.pfc")
    if not os.path.exists(current_pfc):
        return

    xml_tree = ET.parse(current_pfc)
    root_element = xml_tree.getroot()

    current_roots = [element.text for element in root_element.findall("./Feature/Root")]

    diff1 = [root for root in current_roots if root not in incoming_roots]
    diff2 = [root for root in incoming_roots if root not in current_roots]
    diff = sorted(diff1 + diff2)
    if diff:
        for path in diff:
            path = os.path.join(os.getcwd(), path)
            if os.path.isdir(path) and is_git_repository(path):
                ColoredMessage.print(f"Note: Removing {os.path.relpath(path)}")
                chmod_recursive(path, 0o777)
                shutil.rmtree(path)


def process_pfc(file_path: Union[str, TextIOWrapper], action: ToolAction) -> None:
    global project_tag
    global project_url
    global omit_submodules

    xml_tree = ET.parse(file_path)
    root_element = xml_tree.getroot()

    # sort elements to ensure that the top-level folder is created first
    root_element[:] = sorted(
        root_element, key=lambda feature: feature.find("Root").text
    )

    feature_dict = {}
    feature_list = root_element.findall("./Feature")

    if action == ToolAction.UPDATE_REPOSITORY:
        roots = [element.find("Root").text for element in feature_list]
        remove_unused_feature(roots)

    for feature in feature_list:
        feature_dict[feature.find("Name").text] = feature.find("Version").text

    requirements = []

    for feature in feature_list:
        name = feature.find("Name").text
        root = os.path.normpath(f"{feature.find("Root").text}")

        for dependency in feature.findall("Dependency"):
            target_name = dependency.find("Name").text
            target_version = dependency.find("Version").text
            satisfied, version = check_dependency(
                target_name, target_version, feature_dict
            )
            if not satisfied:
                requirements.append((target_name, target_version, version))
        if requirements:
            ColoredMessage.print(f"Warning: Dependency of {name} is not satisfied!")
            for req in requirements:
                if req[2] is None:
                    message = f"Requires {req[0]} at {req[1]}, but it was not found."
                else:
                    message = (
                        f"Requires {req[0]} at {req[1]}, but {req[2]} was detected."
                    )
                print(cf.dimGrey(message))
            requirements.clear()

        for repository in feature.findall("Repository"):
            if repository.find("Type").text.casefold() != "git".casefold():
                continue

            if action == ToolAction.UPDATE_REPOSITORY:
                if os.path.isdir(root) and is_git_repository(root):
                    update_repository(root, repository.find("Tag").text)
                    continue

            url = to_ssh(repository.find("Url").text)
            clone_repository(
                url,
                root,
                (repository.find("Tag").text if url != project_url else project_tag),
            )

        """
        Note: This is a workaround for H2O Kernel 5.7,
              .gitmodules is not found in some repositories that contain submodules.
              Problematic repositories are listed below:

              Board\\Intel\\RaptorLakePBoardPkg\\BIOS
              Insyde\\InsydeModulePkg\\Library\\OpensslLib\\openssl
        """
        original_state = omit_submodules
        omit_submodules = True
        for external in feature.findall("External"):
            if external.find("./Repository/Type").text.casefold() != "git".casefold():
                continue
            source_dir = external.find("SourceDir").text
            folder_path = os.path.normpath(os.path.join(root, source_dir))
            url = external.find("./Repository/Url").text
            url = to_ssh(url) if "insyde".casefold() in url.casefold() else url
            tag = external.find("./Repository/Tag").text

            if os.path.isdir(folder_path) and is_git_repository(folder_path):
                repo = Repo(folder_path)
                if checkout_to_tag(repo, tag, False) is None:
                    repo.close()
                    continue

            if os.path.isdir(folder_path) and os.listdir(folder_path):
                ColoredMessage.print(f"Note: Removing {os.path.relpath(folder_path)}")
                chmod_recursive(folder_path, 0o777)
                shutil.rmtree(folder_path)

            clone_repository(url, folder_path, tag, True)
        omit_submodules = original_state


def fetch_file_from_remote(url: str, tag: str, file: str, to_path: str = "."):
    output_file = f"{file}.tar"

    try:
        command = f"git archive --format=tar --output={output_file} --remote={url} {tag} {file}"
        git.Git().execute(command)
    except git.exc.GitCommandError as e:
        ColoredMessage.print(f"Error: Failed to fetch {file} from {url}!")
        return

    tf = tarfile.open(name=output_file, mode="r")
    tf.extractall(path=to_path, filter="data")
    tf.close()

    if os.path.exists(file):
        os.remove(output_file)
    else:
        ColoredMessage.print(f"Warning: File:{file} does not exist after unzipping.")


def main():
    global project_url
    global project_tag
    global project_path
    global override_dict
    global omit_submodules

    preparser = ArgumentParser(add_help=False)

    action_group = preparser.add_mutually_exclusive_group()
    action_group.add_argument(
        "-c",
        "--clone",
        action="store_true",
        help="Clone repositories with remote Project.pfc.",
    )
    action_group.add_argument(
        "-ru",
        "--remote-update",
        action="store_true",
        help="Update repositories with remote Project.pfc.",
    )
    action_group.add_argument(
        "-lu",
        "--local-update",
        action="store_true",
        help="Update repositories with a local Project.pfc.",
    )

    args, _ = preparser.parse_known_args()

    parser = ArgumentParser(prog=f"Insyde Gerrit Code Downloader", parents=[preparser])
    parser.add_argument("-v", "--version", action="version", version="%(prog)s 1.0b1")

    action_group.required = True
    parser._mutually_exclusive_groups.append(action_group)

    parser.add_argument(
        "-u",
        "--url",
        required=(args.clone),
        type=str,
        nargs="?",
        help="The URL of the remote repository.",
    )
    parser.add_argument(
        "-p",
        "--project-path",
        required=(args.remote_update or args.local_update),
        type=str,
        nargs="?",
        help="The path to the project folder.",
    )
    parser.add_argument(
        "-f",
        "--file",
        required=(args.local_update),
        type=argparse.FileType("r", encoding="utf-8"),
        nargs="?",
        help="The path to the local Project.pfc.",
    )
    parser.add_argument(
        "-t",
        "--tag",
        required=(args.clone or args.remote_update),
        type=str,
        nargs="?",
        help="The desired tag string.",
    )
    parser.add_argument(
        "-o",
        "--override",
        type=str,
        nargs="*",
        action="extend",
        help="Override repository tags described in Project.pfc.",
    )
    parser.add_argument(
        "--omit-submodules",
        help="Omit submodules in repositories.",
        action="store_true",
    )

    args = parser.parse_args()

    if args.override and len(args.override) > 0:
        if len(args.override) % 2 != 0:
            print("Argument -o/--override requires key-value pairs.")
            return
        for index in range(0, len(args.override), 2):
            override_dict[args.override[index]] = args.override[index + 1]

    omit_submodules = args.omit_submodules

    if args.clone:
        project_url = to_ssh(args.url)
    else:
        project_path = os.path.normpath(os.path.join(os.getcwd(), args.project_path))
        if args.remote_update:
            try:
                repo = git.Repo(project_path)
                project_url = repo.remotes[0].url
                repo.close()
            except git.exc.NoSuchPathError:
                ColoredMessage.print(f"Error: {project_path} is not found!")
            except git.exc.InvalidGitRepositoryError:
                ColoredMessage.print(
                    f"Error: {project_path} is not a valid GIT repository!"
                )

    if not args.local_update:
        project_tag = args.tag
        fetch_file_from_remote(project_url, project_tag, "Project.pfc")

    if args.clone:
        print(
            f"Clone repositories with the Project.pfc from {project_url} (Tag: {project_tag})"
        )
        process_pfc("Project.pfc", ToolAction.CLONE_REPOSITORY)
    else:
        if args.remote_update:
            print(
                f"Update repositories with the remote Project.pfc from {project_url} (Tag: {project_tag})"
            )
            process_pfc("Project.pfc", ToolAction.UPDATE_REPOSITORY)
        elif args.local_update:
            print(f'Update repositories with a local Project.pfc: "{args.file.name}"')
            process_pfc(args.file, ToolAction.UPDATE_REPOSITORY)


if __name__ == "__main__":
    main()
