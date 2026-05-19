# Insyde Gerrit Code Downloader

This is a tool for cloning and updating an entire project described by a Project.pfc.

## Table of Contents
- [Release Note](#release-note)
- [Features](#features)
- [Limitations](#limitations)
- [Project Layout](#project-layout)
- [Usage](#usage)
  - [Overview of the options](#overview-of-the-options)
  - [Prerequisites](#prerequisites)
  - [Cloning Project](#cloning-project)
  - [Updating Project](#updating-project)
- [Reference Documents](#reference-documents)

---

## Release Note
| Date | Version | Comment |
| :--- | :--- | :--- |
| 2024/12/04 | v1.0-beta.1 | Initial release. |
| 2025/04/15 | (n/a) | - Added remote check & force fetch before checkout. <br> - Fixed color display in Windows Terminal. |
| 2025/04/25 | v1.0-beta.2 | - Solved problems of not working in Linux. <br> - Optimized access to submodules. |
| 2025/06/12 | v1.0-beta.3 | - Introduce URL typo auto-correction feature. <br> - Support for -f/--file in clone mode. <br> - Enhance arguments checking mechanism. <br> - Introduce --dry-run for validating arguments. |
| 2026/05/19 | v1.0-beta.4 | - Refactored into a `src/` based Python package. <br> - Added `python -m InsydeGerritCodeDownloader` support. <br> - Reorganized modules and cleaned up Pylance/type-check warnings. |

## Terms and Abbreviations
| Term | Description |
| :--- | :--- |
| PFC | Project Feature Catalog |

## Features
- Supports cloning the entire project described by a Project.pfc.
- Supports checking out existing project to a desired tag using remote/local Project.pfc.
- Supports overriding tag of features while cloning/updating.
- Supports omitting submodules while cloning/updating.
- Check dependencies for each features described in Project.pfc.
- Supports checking fork dependencies described in Project.pfc.
- Supports cloning/updating external repositories described in Project.pfc.
- Suggests a possible Gerrit URL when the provided repository URL is not valid.
- Automatically get commit-msg hook from host if checking out to master branch.

## Limitations
- Supports accessing Insyde Gerrit Server through SSH only.
- Users must set up SSH configuration for this tool to work properly.

## Project Layout
The application source now lives under `src/InsydeGerritCodeDownloader/`:

```text
src/InsydeGerritCodeDownloader/
  __main__.py      # python -m entry point
  core.py          # command orchestration
  config.py        # argparse setup, validation, and constants
  pfc.py           # Project.pfc parsing and feature processing
  git_ops.py       # clone/update/submodule/archive Git operations and progress display
  gerrit.py        # Gerrit SSH helpers
  console.py       # colored output helper
  utils.py         # path and XML utility functions
```

## Usage
### Overview of the options
The following is the text of the description exported by `argparse`:
```bash
usage: Insyde Gerrit Code Downloader [-h] [-v] (-c | -ru | -lu) [-u [URL]]
                                     [-p [PROJECT_PATH]] [-t [TAG]]
                                     [-f [FILE]] [-o [OVERRIDE ...]]
                                     [--omit-submodules] [--dry-run]

options:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -c, --clone           Clone repositories with remote Project.pfc.
  -ru, --remote-update  Update repositories with remote Project.pfc.
  -lu, --local-update   Update repositories with a local Project.pfc.
  -u, --url [URL]       The URL of the remote repository.
  -p, --project-path [PROJECT_PATH]
                        The path to the project folder.
  -t, --tag [TAG]       The desired tag string.
  -f, --file [FILE]     The path to the local Project.pfc.
  -o, --override [OVERRIDE ...]
                        Override repository tags described in Project.pfc.
  --omit-submodules     Omit submodules in repositories.
  --dry-run             Resolve Project.pfc and validate repositories without
                        clone/update/remove operations.
```

### Prerequisites
- The tool uses the information provided by your SSH Configuration File to connect to the remote server.<br>
Please make sure you are able to access to the remote site first.<br>
  - The SSH Configuration File should be `~/.ssh/config`, a sample is available in <a href="#appendix-a-sample-ssh-configuration-file">Appendix A</a>.
  - Public keys of remote sites should be `~/.ssh/known_hosts`.
  - Please use command `ssh -T [URL]` in command prompt to test the connection.

- The tool clones the entire project to where it exists. Therefore, please copy the executable file to the folder where you want to save the project.
- If you want to run from Python source, please use `pip install -r requirements.txt` to install the required dependency modules.
- To enable package/module execution, install the project in editable mode:
  ```bash
  python -m pip install -e .
  python -m InsydeGerritCodeDownloader -h
  ```
- During local development without installing the package, add `src` to `PYTHONPATH` first:
  ```powershell
  $env:PYTHONPATH = "src"
  python -m InsydeGerritCodeDownloader -h
  ```
- To generate the Windows executable from source, run:
  ```bat
  build.bat
  ```
  The script creates `.venv-win`, installs build dependencies, generates `InsydeGerritCodeDownloader.exe`, copies it to the project root, and cleans temporary build output.
- To clean local build artifacts, run:
  ```bat
  build.bat /clean
  ```
  This removes `build/`, `dist/`, `.venv/`, `.venv-win/`, `.venv-linux/`, `__pycache__/`, and generated `.spec` files.

> [!NOTE]
> This tool was developed using Python **3.13.0**. It is recommended that you use the same (or newer) version to ensure proper execution.
> Otherwise, Python **3.12.0** is the lowest supported version.

### Cloning Project
Assume that the board package name of the project is `H2O-Kernel/Kernel_RaptorLake_PBoard_Rev5.7`, and the desired tag is `05.70.48`.
You can clone the entire project with following command:

```bash
InsydeGerritCodeDownloader.exe -c -u ssh://gerrit.insyde.com:29418/H2O-Kernel/Kernel_RaptorLake_PBoard_Rev5.7 -t 05.70.48
```

The tool will gets the Project.pfc from the board package on the server, and then parse it to work.
When the job starts, you will see the following message:

```bash
Clone repositories with the Project.pfc from ssh://gerrit.insyde.com:29418/H2O-Kernel/Kernel_RaptorLake_PBoard_Rev5.7 (Tag: 05.70.48)
Cloning H2O-Kernel/Kernel_BaseToolsBin_Rev5.7 to BaseTools:
  Counting objects  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% ET 0:00:00 done
  Finding sources   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% ET 0:00:00
⠏ Receiving objects ━━━━━━━━━━━━━━━━━━━━━╸━━━━━━━━━━━━━━━━━━  54% ET 0:00:15 65.30 MiB | 4.27 MiB/s
```

There will be multiple progress bars representing the GIT operation and its progress.

In addition, you can still clone the entire project with following command:

```bash
InsydeGerritCodeDownloader.exe -c -f Project.pfc
```

This assists developers in writing a Project.pfc and verifying its correctness.

> [!NOTE]
> To override tags of features, you can provide `-o/--override` with feature name and desired tag as key-value pairs to the tool.<br>
> For example, if feature `InsydePlatformInfoPkg` is set to `02.01.08.0007` in Project.pfc, but you want to use a newer tag, the command will be as following:
> ```bash
> InsydeGerritCodeDownloader.exe ... -o InsydePlatformInfoPkg 02.01.08.0009
> ```
> It will clone tag `02.01.08.0009` instead.

> [!NOTE]
> By default, it will clone submodules for each repository excepts for the "externals".
> If you would like to omit the submodules, just provide --omit-submodules to the tool.

> [!NOTE]
> If a Gerrit repository URL is not valid, the tool will try to suggest a similar repository URL and retry with it.

> [!NOTE]
> External repositories described in Project.pfc will be cloned shallowly without submodules.

> [!NOTE]
> To inspect the resolved operations without changing local repositories, append `--dry-run` to clone or update commands.
> The tool will still read Project.pfc and validate repository access, but clone, update, and remove operations will be skipped.
> ```bash
> InsydeGerritCodeDownloader.exe -c -f Project.pfc --dry-run
> InsydeGerritCodeDownloader.exe -ru -p Board\Intel\RaptorLakePBoardPkg -t 05.70.42 --dry-run
> ```

> [!CAUTION]
> This tool checks dependencies for each features described in Project.pfc.
> Fork dependencies described in Project.pfc are also checked.
> If any of the features do not meet the requirements, it will prompt and display the following message:
> ```bash
> Warning: Dependency of Kernel-Base is not satisfied!
> Requires Kernel-Base at 05.53.09, but 05.50.52 was detected.
> ```
> Or, if the feature is not listed in the Project.pfc:
> ```bash
> Requires Kernel-Base at 05.53.09, but it was not found.
> ```
> Even if it doesn't pass the dependency check, the tool will continue without breaking the process, so users can switch between them manually later.

### Updating Project
Assume that the path to local project package is `Board\Intel\RaptorLakePBoardPkg` and the desired tag is `05.70.42`.
You can update the entire project with following command:

```bash
InsydeGerritCodeDownloader.exe -ru -p Board\Intel\RaptorLakePBoardPkg -t 05.70.42
```

However, if you want to update the entire project with a local Project.pfc.
You can update the entire project with following command:

```bash
InsydeGerritCodeDownloader.exe -lu -p Board\Intel\RaptorLakePBoardPkg -f Project.pfc
```

> [!CAUTION]
> Before updating the entire project, please make sure the working trees of all repositories are clean.

> [!NOTE]
> The tool will remove submodules before checking out a repository to tag.
> Because the submodule is cloned shallowly, it does not have a complete history.

When updating (or switching) to a tag, The tool compares the local and remote Project.pfc to find the different features. For those different features, if the path specified in `<Root>` exists and it is a valid GIT repository, the tool will remove it before updating.

When removing the folders, you will see the following message:
```bash
Note: Removing Board\Intel\RaptorLakePBoardPkg\BIOS
```

If a repository is no need to switch to a different tag, you will see the following message:
```bash
Note: Insyde\InsydeModulePkg\Library\OpensslLib\openssl is already at openssl-3.0.15, skip checking out
```

## Reference Documents
- InsydeH2O Feature Packaging Technical Reference Revision 0.82

## Appendix A: Sample SSH Configuration File
```text
Host gerrit.insyde.com
  Hostname gerrit.insyde.com
  Port 29418
  User tony.cheng
  IdentitiesOnly yes
  IdentityFile ~/.ssh/id_ed25519_insyde

Host github.com
  Hostname github.com
  User git
  IdentitiesOnly yes
  IdentityFile ~/.ssh/id_ed25519_github
```
