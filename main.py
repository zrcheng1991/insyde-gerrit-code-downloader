#
#  Copyright (c) 2024 - 2025, Tony Cheng. All rights reserved.
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

import colorful as cf
import difflib
import git
import git.exc
import os
import posixpath
import shutil
import subprocess
import tarfile
import xml.etree.ElementTree as ET

from argparse import ArgumentParser
from contextlib import contextmanager
from enum import Enum
from git import Repo, RemoteProgress
from packaging.version import Version
from paramiko import SSHClient, SSHConfig, AutoAddPolicy
from pathlib import Path
from rich import console, progress
from scp import SCPClient
from typing import Union, Optional
from urllib.parse import urlparse, urlunparse
from xml.etree.ElementTree import Element

# global settings
cf.use_256_ansi_colors()


class ToolAction(Enum):
    CLONE_REPOSITORY = 1
    UPDATE_REPOSITORY = 2
    UNDEFINED = 3


class ExecutionContext:
    def __init__(self):
        self.action: ToolAction = ToolAction.UNDEFINED
        self.file: str = "Project.pfc"
        self.project_path: Optional[str] = None
        self.override_dict: dict = {}
        self.omit_submodules: bool = False
        self.dry_run: bool = False


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
    folder_path: str, url: str, commit_id: str = None, depth: int = 1
) -> bool:
    url_path = urlparse(url).path[1:] if "insyde".casefold() in url.casefold() else url

    if commit_id is not None and depth != 0:
        print(f"Fetching {commit_id} from {url_path} with depth={depth}:")
        command = [
            "git",
            "fetch",
            f"--depth={depth}",
            "origin",
            commit_id,
            "--progress",
        ]
    else:
        print(f"Fetching from {url_path}")
        command = ["git", "fetch", "origin", "--progress"]

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


@contextmanager
def create_ssh_client(host: str):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())

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
        raise RuntimeError(f"Failed to establish SSH connection to {host}!")

    try:
        yield ssh
    finally:
        ssh.close()


def get_commit_msg_hook(host: str, folder_path: str) -> None:
    try:
        with create_ssh_client(host) as ssh:
            with SCPClient(ssh.get_transport()) as scp:
                try:
                    scp.get(
                        "hooks/commit-msg", os.path.join(folder_path, ".git/hooks/")
                    )
                    ColoredMessage.print(
                        f"Note: The commit-msg hook from {host} has been added to {folder_path}."
                    )

                except:
                    ColoredMessage.print(
                        f"Warning: Failed to get commit-msg hook from {host}!"
                    )

    except Exception as e:
        ColoredMessage.print(str(e))
        return


def checkout_to_tag(repo: Repo, tag: str, fetch: bool = False) -> Optional[str]:
    if fetch:
        repo.git.fetch("--all")

    if tag.casefold() == "Trunk".casefold():
        ColoredMessage.print(
            f'Note: Tag "{tag}" is invalid for GIT, replace it with master.'
        )
        tag = "master"

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
            repo.remotes.origin.fetch(tags=True, force=True)
            repo.git.checkout(tag, detach=True)
        else:
            ColoredMessage.print(f"Warning: Tag {tag} is not available!")
    else:
        repo.git.checkout(tag)

    return tag


def is_relative_url(url: str) -> bool:
    parsed_url = urlparse(url)
    if parsed_url.scheme != "" or parsed_url.path.startswith("/"):
        return False
    return True


def resolve_relative_url(base: str, rel_path: str) -> str:
    parsed_base = urlparse(base)
    path = posixpath.normpath(posixpath.join(parsed_base.path, rel_path))
    parsed_base = parsed_base._replace(path=path)
    return urlunparse(parsed_base)


def clone_submodules(repo: Repo, folder_path: str, absorbgitdirs: bool) -> None:
    for submodule in repo.submodules:
        folder_path = os.path.normpath(os.path.join(folder_path, submodule.path))
        url = (
            to_ssh(submodule.url)
            if "insyde".casefold() in submodule.url.casefold()
            else submodule.url
        )
        if is_relative_url(url):
            url = resolve_relative_url(repo.remotes.origin.url.strip(".git"), url)

        if absorbgitdirs:
            submodule_repo = Repo.init(folder_path)
            submodule_repo.create_remote("origin", url)
            tag_shas = {tag.commit.hexsha for tag in repo.tags}
            if submodule.hexsha in tag_shas:
                result = fetch_with_progress(folder_path, url, submodule.hexsha)
                if result:
                    print(f"Checking out {folder_path} to FETCH_HEAD")
                    submodule_repo.git.checkout("FETCH_HEAD")
                else:
                    ColoredMessage.print(f"Warning: Failed to fetch from server!")
            else:
                fetch_with_progress(folder_path, url)
                print(f"Checking out {folder_path} to {submodule.hexsha}")
                submodule_repo.git.checkout(submodule.hexsha)

            submodule_repo.close()
        else:
            repo.git.config(
                "--file=.gitmodules", f"submodule.{submodule.path}.url", url
            )
            print(f"Initializing submodule {submodule.path} ({submodule.hexsha})")
            repo.git.submodule("update", "--init", f"{submodule.path}")


def is_git_url_valid(url: str) -> bool:
    try:
        subprocess.check_output(["git", "ls-remote", url], stderr=subprocess.DEVNULL)
        return True
    except:
        return False


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


def get_suggest_url(url: str) -> str:
    parsed_url = urlparse(url)

    if "insyde" not in parsed_url.hostname.lower():
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


def clone_repository(
    url: str,
    folder_path: str,
    tag: str = None,
    shallow: bool = False,
    omit_submodules: bool = False,
) -> None:
    if not is_git_url_valid(url):
        suggest_url = get_suggest_url(url)
        if not suggest_url:
            ColoredMessage.print(
                f"Warning: {url} is not valid, skip cloning the repository."
            )
            return
        else:
            ColoredMessage.print(
                f"Warning: {url} is not valid.\n Retry with {suggest_url}..."
            )
            url = suggest_url

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
        clone_submodules(repo, folder_path, (tag != "master"))

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
        if os.path.isdir(path):
            ColoredMessage.print(f"Note: Removing {os.path.relpath(path)}")
            chmod_recursive(path, 0o777)
            shutil.rmtree(path)


def update_repository(
    folder_path: str, tag: str, omit_submodules: bool = False
) -> None:
    repo = git.Repo(folder_path)

    if len(repo.submodules) > 0:
        remove_all_submodules(repo)

    tag = checkout_to_tag(repo, tag, True)
    if tag:
        if tag == "master":
            get_commit_msg_hook(urlparse(repo.remotes[0].url).hostname, folder_path)

    if len(repo.submodules) > 0 and not omit_submodules:
        clone_submodules(repo, folder_path, (tag != "master"))

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

        try:
            repo.git.ls_remote()
        except git.exc.GitCommandError as e:
            url = repo.remotes["origin"].url
            url_path = (
                urlparse(url).path[1:] if "insyde".casefold() in url.casefold() else url
            )
            ColoredMessage.print(
                f"Warning: Remote repository at '{url_path.rstrip("/")}' is no longer available!"
            )
            result = False

        repo.close()
        return result
    except git.exc.InvalidGitRepositoryError:
        return False


def remove_unused_feature(project_path: str, incoming_roots: list[Element]) -> None:
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


def process_pfc(context: ExecutionContext) -> None:
    if context.action == ToolAction.UNDEFINED:
        ColoredMessage.print("Error: Invalid tool action detected!")
        return

    if context.dry_run:
        ColoredMessage.print("Note: [DRY-RUN] No action will be taken.")
        return

    xml_tree = ET.parse(context.file)
    root_element = xml_tree.getroot()

    # sort elements to ensure that the top-level folder is created first
    root_element[:] = sorted(
        root_element, key=lambda feature: feature.find("Root").text
    )

    feature_dict = {}
    feature_list = root_element.findall("./Feature")

    if context.action == ToolAction.UPDATE_REPOSITORY:
        roots = [element.find("Root").text for element in feature_list]
        remove_unused_feature(context.project_path, roots)

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
                ColoredMessage.print(f"Note: {message}")
            requirements.clear()

        for repository in feature.findall("Repository"):
            if repository.find("Type").text.casefold() != "git".casefold():
                continue

            url = to_ssh(repository.find("Url").text)
            tag = repository.find("Tag").text

            if context.override_dict:
                tag = context.override_dict.get(urlparse(url).path[1:], tag)

            if os.path.isdir(root):
                if is_git_repository(root):
                    update_repository(
                        root, tag, omit_submodules=context.omit_submodules
                    )
                    continue
                else:
                    ColoredMessage.print(f"Note: Removing {os.path.relpath(root)}")
                    chmod_recursive(root, 0o777)
                    shutil.rmtree(root)

            clone_repository(url, root, tag, omit_submodules=context.omit_submodules)

        """
        Note: This is a workaround for H2O Kernel 5.7,
              .gitmodules is not found in some repositories that contain submodules.
              Problematic repositories are listed below:

              Board\\Intel\\RaptorLakePBoardPkg\\BIOS
              Insyde\\InsydeModulePkg\\Library\\OpensslLib\\openssl
        """
        for external in feature.findall("External"):
            if external.find("./Repository/Type").text.casefold() != "git".casefold():
                continue
            source_dir = external.find("SourceDir").text
            folder_path = os.path.normpath(os.path.join(root, source_dir))
            url = external.find("./Repository/Url").text
            url = to_ssh(url) if "insyde".casefold() in url.casefold() else url
            tag = external.find("./Repository/Tag").text

            if context.override_dict:
                tag = context.override_dict.get(urlparse(url).path[1:], tag)

            if os.path.isdir(folder_path) and is_git_repository(folder_path):
                repo = Repo(folder_path)
                if checkout_to_tag(repo, tag, fetch=False) is None:
                    repo.close()
                    continue

            if os.path.isdir(folder_path) and os.listdir(folder_path):
                ColoredMessage.print(f"Note: Removing {os.path.relpath(folder_path)}")
                chmod_recursive(folder_path, 0o777)
                shutil.rmtree(folder_path)

            clone_repository(url, folder_path, tag, shallow=True, omit_submodules=True)


def fetch_file_from_remote(url: str, tag: str, file: str, to_path: str = ".") -> None:
    output_file = f"{file}.tar"

    try:
        command = [
            "git",
            "archive",
            "--format=tar",
            f"--output={output_file}",
            f"--remote={url}",
            tag,
            file,
        ]
        git.Git().execute(command)
    except git.exc.GitCommandError as e:
        raise ConnectionError(f"Failed to fetch {file} from {url}!")

    if os.stat(f"{output_file}").st_size == 0:
        raise FileNotFoundError(f"Unable to get {file} from server!")

    tf = tarfile.open(name=output_file, mode="r")
    tf.extractall(path=to_path, filter="data")
    tf.close()

    if os.path.exists(file):
        os.remove(output_file)


def main():
    parser = ArgumentParser(prog=f"Insyde Gerrit Code Downloader")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s 1.0b3")

    action_group = parser.add_mutually_exclusive_group(required=True)
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

    parser.add_argument(
        "-u",
        "--url",
        type=str,
        nargs="?",
        help="The URL of the remote repository.",
    )
    parser.add_argument(
        "-p",
        "--project-path",
        type=str,
        nargs="?",
        help="The path to the project folder.",
    )
    parser.add_argument(
        "-t",
        "--tag",
        type=str,
        nargs="?",
        help="The desired tag string.",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        nargs="?",
        help="The path to the local Project.pfc.",
    )
    parser.add_argument(
        "-o",
        "--override",
        type=str,
        nargs="*",
        action="extend",
        default=[],
        help="Override repository tags described in Project.pfc.",
    )
    parser.add_argument(
        "--omit-submodules",
        help="Omit submodules in repositories.",
        action="store_true",
    )

    # debug arguments
    parser.add_argument(
        "--dry-run",
        help="Validate arguments only; no files read or actions performed.",
        action="store_true",
    )

    args = parser.parse_args()

    # check requirements
    if args.clone:
        if not (args.url and args.tag) and not args.file:
            parser.error(
                "Clone requires either -u/--url together with -t/--tag, or -f/--file."
            )
        elif args.file and (args.url or args.tag):
            parser.error("Cannot use -f/--file together with -u/--url or -t/--tag.")
    elif args.remote_update:
        if not (args.project_path and args.tag):
            parser.error("Remote update requires both -p/--project and -t/--tag.")
    elif args.local_update:
        if not (args.project_path and args.file):
            parser.error("Local update requires both -p/--project and -f/--file.")

    if args.override and len(args.override) > 0:
        if len(args.override) % 2 != 0:
            parser.error("Argument -o/--override requires key-value pairs.")

    context = ExecutionContext()

    for index in range(0, len(args.override), 2):
        context.override_dict[args.override[index]] = args.override[index + 1]

    context.omit_submodules = args.omit_submodules
    context.dry_run = args.dry_run

    # initialize arguments
    project_url = ""
    project_path = ""

    if args.clone:
        if args.url:
            project_url = to_ssh(args.url)
    else:
        project_path = os.path.normpath(os.path.join(os.getcwd(), args.project_path))
        if args.remote_update and not args.dry_run:
            try:
                repo = git.Repo(project_path)
                project_url = repo.remotes[0].url
                repo.close()
            except git.exc.NoSuchPathError:
                ColoredMessage.print(f"Error: {project_path} is not found!")
                return
            except git.exc.InvalidGitRepositoryError:
                ColoredMessage.print(
                    f"Error: {project_path} is not a valid GIT repository!"
                )
                return

    if args.tag and not args.local_update:
        if args.tag.casefold() == "master".casefold():
            context.override_dict[f"{urlparse(project_url).path[1:]}"] = "master"

        if not args.dry_run:
            try:
                fetch_file_from_remote(project_url, args.tag, "Project.pfc")
            except Exception as e:
                ColoredMessage.print(f"Error: {e}")
                return

    if args.clone:
        context.action = ToolAction.CLONE_REPOSITORY
        if args.file:
            context.file = args.file
            print(f"Clone repositories with file: {args.file}")
        else:
            print(
                f"Clone repositories with the Project.pfc from {project_url} (Tag: {args.tag})"
            )
    else:
        context.action = ToolAction.UPDATE_REPOSITORY
        context.project_path = project_path
        if args.remote_update:
            print(
                f"Update repositories with the Project.pfc from {project_url} (Tag: {args.tag})"
            )
        elif args.local_update:
            context.file = args.file
            print(f"Update repositories with file: {args.file}")

    process_pfc(context)


if __name__ == "__main__":
    main()
