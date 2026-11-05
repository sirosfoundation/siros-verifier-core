#!/usr/bin/env python3
"""Write a deterministic ZIP, optionally preserving the source directory name."""

from pathlib import Path
import sys
import zipfile


def main() -> None:
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "--include-root"):
        raise SystemExit(f"usage: {sys.argv[0]} OUTPUT.zip DIRECTORY [--include-root]")
    output = Path(sys.argv[1])
    source = Path(sys.argv[2])
    include_root = len(sys.argv) == 4
    if not source.is_dir():
        raise SystemExit(f"not a directory: {source}")
    files = sorted(path for path in source.rglob("*") if path.is_file())
    if not files:
        raise SystemExit(f"refusing to package an empty directory: {source}")
    with zipfile.ZipFile(output, "w") as archive:
        for path in files:
            base = source.parent if include_root else source
            info = zipfile.ZipInfo(path.relative_to(base).as_posix(), (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes(), compresslevel=9)


if __name__ == "__main__":
    main()
