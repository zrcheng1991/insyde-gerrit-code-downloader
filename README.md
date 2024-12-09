# Insyde Gerrit Code Downloader

This is a tool for cloning and updating an entire project described by a Project.pfc.

## Table of Contents
- [Release Note](#release-note)
- [Features](#features)
- [Limitations](#limitations)
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
| 2024/12/04 | 1.0 | Initial release. |

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
- Automatically get commit-msg hook from host if checking out to master branch.

## Limitations
- Supports accessing Insyde Gerrit Server through SSH only.
- Users must set up SSH configuration for this tool to work properly.

## Usage
### Overview of the options
The following is the text of the description exported by `argparse`:
```bash
usage: Insyde Gerrit Code Downloader [-h] (-c | -ru | -lu) [-v] [-u [URL]] [-p [PROJECT_PATH]] [-f [FILE]] [-t [TAG]] [-o [OVERRIDE ...]] [--omit-submodules]

options:
  -h, --help            show this help message and exit
  -c, --clone           Clone repositories with remote Project.pfc.
  -ru, --remote-update  Update repositories with remote Project.pfc.
  -lu, --local-update   Update repositories with a local Project.pfc.
  -v, --version         show program's version number and exit
  -u, --url [URL]       The URL of the remote repository.
  -p, --project-path [PROJECT_PATH]
                        The path to the project folder.
  -f, --file [FILE]     The path to the local Project.pfc.
  -t, --tag [TAG]       The desired tag string.
  -o, --override [OVERRIDE ...]
                        Override repository tags described in Project.pfc.
  --omit-submodules     Omit submodules in repositories.
```

### Prerequisites
- The tool uses the information provided by your SSH Configuration File to connect to the remote server.<br>
Please make sure you are able to access to the remote site first.<br>
  - The SSH Configuration File should be `~/.ssh/config`, a sample is available in <a href="#appendix-a-sample-ssh-configuration-file">Appendix A</a>.
  - Public keys of remote sites should be `~/.ssh/known_hosts`.
  - Please use command `ssh -T [URL]` in command prompt to test the connection.

- The tool clones the entire project to where it exists. Therefore, please copy the executable file to the folder where you want to save the project.
- If you want to run the Python script directly, please use `pip install -r requirements.txt` to install the required dependency modules.

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

> [!CAUTION]
> This tool checks dependencies for each features described in Project.pfc.
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