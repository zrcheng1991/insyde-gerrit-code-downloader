#
#  Copyright 2026, Tony Cheng. All rights reserved.
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

from argparse import ArgumentParser, Namespace
from collections.abc import Sequence

PROGRAM_NAME = "Insyde Gerrit Code Downloader"
VERSION = "1.0b4"

REQUIRED_MAJOR = 3
REQUIRED_MINOR = 12


def initialize_argument_parser(prog_name: str = PROGRAM_NAME) -> ArgumentParser:
    parser = ArgumentParser(prog=prog_name)
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {VERSION}"
    )

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
    parser.add_argument(
        "--dry-run",
        help="Resolve Project.pfc and validate repositories without clone/update/remove operations.",
        action="store_true",
    )

    return parser


def validate_arguments(
    parser: ArgumentParser, argv: Sequence[str] | None = None
) -> Namespace:
    args = parser.parse_args(argv)

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
        if not (args.project_path or args.file):
            parser.error("Local update requires -p/--project or -f/--file.")
        elif args.project_path and args.file:
            parser.error("Cannot use -p/--project together with -f/--file.")

    if args.override and len(args.override) > 0:
        if len(args.override) % 2 != 0:
            parser.error("Argument -o/--override requires key-value pairs.")

    return args
