#
#  Copyright 2026, Tony Cheng. All rights reserved.
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

import os
import posixpath
import shutil
import subprocess
import tarfile

from urllib.parse import urlparse, urlunparse

from git import Git, RemoteProgress, Repo
from git.exc import GitCommandError, InvalidGitRepositoryError, NoSuchPathError
from rich import console, progress

from .console import ColoredMessage
from .gerrit import get_commit_msg_hook, get_suggest_url
from .utils import chmod_recursive, display_path


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
        self.pbar: progress.Progress = progress.Progress(
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
        self._closed = False

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        if self.fetching and self.spinner_task:
            self.pbar.remove_task(self.spinner_task)
        self.pbar.stop()
        self._closed = True

    def update(
        self,
        op_code: int,
        cur_count: str | float,
        max_count: str | float | None = None,
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
    folder_path: str, url: str, commit_id: str | None = None, depth: int = 1
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

    if process.stderr is None:
        raise RuntimeError("Failed to capture git fetch progress.")

    pbar = GitProgressBar(fetching=True)

    try:
        complete = False
        while True:
            stderr = process.stderr.readline().strip()

            if stderr.find("FETCH_HEAD") != -1:
                complete = True

            if not stderr and process.poll() is not None:
                break

            pbar._parse_progress_line(stderr)

        return process.returncode == 0 and complete
    finally:
        pbar.close()


def checkout_to_tag(repo: Repo, tag: str, fetch: bool = False) -> str | None:
    if not tag or not tag.strip():
        ColoredMessage.print(
            "Note: Repository tag is not described, use master as default."
        )
        tag = "master"

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
        submodule_path = os.path.normpath(os.path.join(folder_path, submodule.path))
        url = (
            to_ssh(submodule.url)
            if "insyde".casefold() in submodule.url.casefold()
            else submodule.url
        )
        if is_relative_url(url):
            url = resolve_relative_url(repo.remotes.origin.url.removesuffix(".git"), url)

        if absorbgitdirs:
            os.makedirs(submodule_path, exist_ok=True)
            submodule_repo = Repo.init(submodule_path)
            submodule_repo.create_remote("origin", url)
            tag_shas = {tag.commit.hexsha for tag in repo.tags}
            if submodule.hexsha in tag_shas:
                result = fetch_with_progress(submodule_path, url, submodule.hexsha)
                if result:
                    print(f"Checking out {submodule_path} to FETCH_HEAD")
                    submodule_repo.git.checkout("FETCH_HEAD")
                else:
                    ColoredMessage.print(f"Warning: Failed to fetch from server!")
            else:
                fetch_with_progress(submodule_path, url)
                print(f"Checking out {submodule_path} to {submodule.hexsha}")
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
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def fetch_file_from_remote(url: str, tag: str, file: str, to_path: str = ".") -> None:
    os.makedirs(to_path, exist_ok=True)
    output_file = os.path.join(to_path, f"{os.path.basename(file)}.tar")

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
        Git().execute(command)
    except GitCommandError as e:
        detail = str(e).strip()
        raise ConnectionError(f"Failed to fetch {file} from {url}: {detail}") from e

    if os.stat(f"{output_file}").st_size == 0:
        raise FileNotFoundError(f"Unable to get {file} from server!")

    try:
        with tarfile.open(name=output_file, mode="r") as tf:
            tf.extractall(path=to_path, filter="data")
    finally:
        if os.path.exists(output_file):
            os.remove(output_file)


def clone_repository(
    url: str,
    folder_path: str,
    tag: str | None = None,
    shallow: bool = False,
    omit_submodules: bool = False,
    dry_run: bool = False,
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
    folder_display_path = display_path(folder_path)

    if dry_run:
        if shallow and tag is not None:
            print(f"[DRY-RUN] Cloning {url_path} ({tag}) to {folder_display_path}:")
        else:
            print(f"[DRY-RUN] Cloning {url_path} to {folder_display_path}:")
            if tag is not None:
                print(f"[DRY-RUN] Checking out {folder_display_path} to {tag}")
        return

    repo = None
    progress_bar = GitProgressBar()
    try:
        if shallow and tag is not None:
            print(f"Cloning {url_path} ({tag}) to {folder_display_path}:")
            repo = Repo.clone_from(
                url, folder_path, progress_bar, branch=tag, depth=1
            )
        else:
            print(f"Cloning {url_path} to {folder_display_path}:")
            repo = Repo.clone_from(url, folder_path, progress_bar)
    finally:
        progress_bar.close()

    if repo is None:
        raise RuntimeError(f"Failed to clone {url_path} to {folder_display_path}.")

    try:
        if not shallow and tag is not None:
            tag = checkout_to_tag(repo, tag)
            if tag == "master":
                host = urlparse(url).hostname
                if host is None:
                    ColoredMessage.print(
                        f"Warning: Unable to determine host from {url}."
                    )
                else:
                    get_commit_msg_hook(host, folder_path)

        if len(repo.submodules) > 0 and not omit_submodules:
            clone_submodules(repo, folder_path, (tag != "master"))

    finally:
        if repo is not None:
            repo.close()


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
    repo = Repo(folder_path)

    try:
        checked_out_tag = checkout_to_tag(repo, tag, True)
        if checked_out_tag == "master":
            host = urlparse(repo.remotes[0].url).hostname
            if host is None:
                ColoredMessage.print(
                    f"Warning: Unable to determine host from {repo.remotes[0].url}."
                )
            else:
                get_commit_msg_hook(host, folder_path)

        if len(repo.submodules) > 0 and not omit_submodules:
            remove_all_submodules(repo)
            clone_submodules(repo, folder_path, (checked_out_tag != "master"))
    finally:
        repo.close()


def to_ssh(url: str) -> str:
    parsed_url = urlparse(url)
    if parsed_url.scheme == "ssh":
        return url
    if parsed_url.hostname:
        if "insyde" not in parsed_url.hostname.lower():
            return url
    else:
        ColoredMessage.print(f"Warning: {url} might not be a valid URL!")
        return url

    nodes = parsed_url.path.split("/")

    if nodes[-1].endswith(".git"):
        nodes[-1] = nodes[-1][:-4]

    filtered_path = "/".join(node for node in nodes if node != "a")

    return f"ssh://gerrit.insyde.com:29418{filtered_path}"


def get_repository_name(url: str) -> str:
    repository_name = posixpath.basename(urlparse(url).path.rstrip("/"))
    if repository_name.endswith(".git"):
        repository_name = repository_name[:-4]
    return repository_name


def is_git_repository(folder_path: str) -> bool:
    repo = None
    try:
        repo = Repo(folder_path)
        return not repo.bare
    except (InvalidGitRepositoryError, NoSuchPathError):
        return False
    finally:
        if repo is not None:
            repo.close()
