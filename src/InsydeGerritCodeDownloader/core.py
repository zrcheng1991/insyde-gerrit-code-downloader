#
#  Copyright 2026, Tony Cheng. All rights reserved.
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

import os
import tempfile

from argparse import Namespace
from collections.abc import Sequence
from urllib.parse import urlparse

from git import Repo
from git.exc import InvalidGitRepositoryError, NoSuchPathError

from .console import ColoredMessage
from .config import initialize_argument_parser, validate_arguments
from .git_ops import fetch_file_from_remote, to_ssh
from .pfc import ExecutionContext, ToolAction, process_pfc


def run(args: Namespace) -> None:
    context = ExecutionContext()
    print(f"Workspace: {context.workspace}")

    for index in range(0, len(args.override), 2):
        context.override_dict[args.override[index]] = args.override[index + 1]

    context.omit_submodules = args.omit_submodules
    context.dry_run = args.dry_run
    temporary_directory = None

    project_url = ""

    if args.clone:
        if args.url:
            project_url = to_ssh(args.url)
    elif args.remote_update:
        repository_path = os.path.normpath(os.path.join(os.getcwd(), args.project_path))
        if args.remote_update:
            repo = None
            try:
                repo = Repo(repository_path)
                project_url = repo.remotes[0].url
            except NoSuchPathError:
                ColoredMessage.print(f"Error: {repository_path} is not found!")
                return
            except InvalidGitRepositoryError:
                ColoredMessage.print(
                    f"Error: {repository_path} is not a valid GIT repository!"
                )
                return
            finally:
                if repo is not None:
                    repo.close()

    if args.tag and not args.local_update:
        if args.tag.casefold() == "master".casefold():
            context.override_dict[f"{urlparse(project_url).path[1:]}"] = "master"

        try:
            if args.dry_run:
                temporary_directory = tempfile.TemporaryDirectory()
                fetch_file_from_remote(
                    project_url, args.tag, "Project.pfc", temporary_directory.name
                )
                context.file = os.path.join(temporary_directory.name, "Project.pfc")
            else:
                fetch_file_from_remote(project_url, args.tag, "Project.pfc")
        except Exception as e:
            ColoredMessage.print(f"Error: {e}")
            if temporary_directory is not None:
                temporary_directory.cleanup()
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
        if args.remote_update:
            print(
                f"Update repositories with the Project.pfc from {project_url} (Tag: {args.tag})"
            )
        elif args.local_update:
            if args.project_path:
                context.file = os.path.join(args.project_path, "Project.pfc")
            elif args.file:
                context.file = args.file
            print(f"Update repositories with file: {context.file}")

    try:
        process_pfc(context)
    except ValueError as e:
        ColoredMessage.print(f"Error: {e}")
    finally:
        if temporary_directory is not None:
            temporary_directory.cleanup()


def main(argv: Sequence[str] | None = None) -> None:
    parser = initialize_argument_parser()
    args = validate_arguments(parser, argv)
    run(args)
