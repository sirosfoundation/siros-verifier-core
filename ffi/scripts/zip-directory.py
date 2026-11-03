#!/usr/bin/env python3
"""Write a deterministic ZIP containing all files below a directory."""

from pathlib import Path
import sys
import zipfile


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} OUTPUT.zip DIRECTORY")
    output = Path(sys.argv[1])
    source = Path(sys.argv[2])
    if not source.is_dir():
        raise SystemExit(f"not a directory: {source}")
    files = sorted(path for path in source.rglob("*") if path.is_file())
    if not files:
        raise SystemExit(f"refusing to package an empty directory: {source}")
    with zipfile.ZipFile(output, "w") as archive:
        for path in files:
            info = zipfile.ZipInfo(path.relative_to(source).as_posix(), (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes(), compresslevel=9)


if __name__ == "__main__":
    main()
