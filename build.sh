#!/usr/bin/env bash

OUTPUT_NAME=InsydeGerritCodeDownloader
OUTPUT_FILE_NAME="$OUTPUT_NAME"
DIST_DIR=dist
VENV_DIR=.venv-linux
ENTRY_POINT=src/InsydeGerritCodeDownloader/__main__.py

if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    BUILD_SCRIPT_SOURCED=1
else
    BUILD_SCRIPT_SOURCED=0
fi

show_usage() {
    echo "Usage:"
    echo "  source build.sh          Generate $DIST_DIR/$OUTPUT_FILE_NAME"
    echo "  source build.sh clean    Remove build artifacts and virtual environments"
    echo "  bash build.sh            Generate $DIST_DIR/$OUTPUT_FILE_NAME"
}

remove_dir() {
    if [ -d "$1" ]; then
        echo "[INFO] Removing $1"
        rm -rf "$1"
    fi
}

clean_artifacts() {
    echo "[INFO] Cleaning build artifacts..."
    remove_dir build
    remove_dir dist
    remove_dir .venv
    remove_dir .venv-win
    remove_dir .venv-linux

    find . -type d -name __pycache__ -prune -exec rm -rf {} +
    rm -f ./*.spec

    echo "[INFO] Clean completed."
}

deactivate_venv() {
    if declare -F deactivate >/dev/null 2>&1; then
        deactivate >/dev/null 2>&1 || true
    fi
}

main() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || return 1
    cd "$script_dir" || return 1

    case "${1:-}" in
        clean|--clean|/clean)
            clean_artifacts
            return 0
            ;;
        -h|--help|"/?")
            show_usage
            return 0
            ;;
        "")
            ;;
        *)
            echo "[ERROR] Unknown option: $1"
            show_usage
            return 1
            ;;
    esac

    local python_bin="${PYTHON:-python3}"
    if ! command -v "$python_bin" >/dev/null 2>&1; then
        if command -v python >/dev/null 2>&1; then
            python_bin=python
        else
            echo "[ERROR] Python 3.12 or higher is required."
            return 1
        fi
    fi

    if ! "$python_bin" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)"; then
        echo "[ERROR] Python 3.12 or higher is required."
        return 1
    fi

    if [ ! -d "$VENV_DIR" ]; then
        echo "[INFO] Creating Python Virtual Environment in $VENV_DIR"
        "$python_bin" -m venv "$VENV_DIR" || {
            echo "[ERROR] Failed to create Python Virtual Environment."
            return 1
        }
    fi

    if [ ! -f "$VENV_DIR/bin/activate" ]; then
        echo "[ERROR] Failed to find $VENV_DIR/bin/activate."
        return 1
    fi

    source "$VENV_DIR/bin/activate" || {
        echo "[ERROR] Failed to activate Python Virtual Environment."
        return 1
    }

    python -m pip install --upgrade pip || {
        echo "[ERROR] Failed to upgrade pip."
        deactivate_venv
        return 1
    }

    if [ -f requirements.txt ]; then
        python -m pip install -r requirements.txt || {
            echo "[ERROR] Failed to install requirements.txt."
            deactivate_venv
            return 1
        }
    else
        echo "[ERROR] requirements.txt was not found."
        deactivate_venv
        return 1
    fi

    echo "[INFO] Start generating $OUTPUT_FILE_NAME"
    pyinstaller -F "$ENTRY_POINT" -n "$OUTPUT_NAME" --distpath "$DIST_DIR" --paths src --collect-data colorful || {
        echo "[ERROR] Failed to generate $OUTPUT_FILE_NAME."
        deactivate_venv
        return 1
    }

    if [ -f "$DIST_DIR/$OUTPUT_FILE_NAME" ]; then
        echo "[INFO] Generated $DIST_DIR/$OUTPUT_FILE_NAME"
    else
        echo "[ERROR] Failed to find $DIST_DIR/$OUTPUT_FILE_NAME."
        deactivate_venv
        return 1
    fi

    rm -rf build
    rm -f "$OUTPUT_NAME.spec"
    rm -f "$OUTPUT_FILE_NAME.spec"

    deactivate_venv
    return 0
}

main "$@"
BUILD_SCRIPT_STATUS=$?

if [ "$BUILD_SCRIPT_SOURCED" -eq 1 ]; then
    return "$BUILD_SCRIPT_STATUS"
fi

exit "$BUILD_SCRIPT_STATUS"
