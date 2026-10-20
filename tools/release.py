"""
Release checks used by the release workflow.

Usage:
    python tools/release.py check v0.2.0   # prints GitHub Actions outputs
    python tools/release.py notes 0.2.0    # changelog section
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INIT = ROOT / 'keycard_bunker' / '__init__.py'
CHANGELOG = ROOT / 'CHANGELOG.md'

VERSION_LINE = re.compile(r"^__version__ = '([^']+)'$", re.M)
PRERELEASE = re.compile(r'(a|b|rc)\d+$')


def read_version() -> str:
    match = VERSION_LINE.search(INIT.read_text())
    if match is None:
        raise ValueError(f'No __version__ line in {INIT}')
    return match.group(1)


def changelog_section(version: str) -> str | None:
    match = re.search(
        rf'^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|^\[|\Z)',
        CHANGELOG.read_text(), re.M | re.S)
    return match.group(1).strip() if match else None


def check(tag: str) -> list[str]:
    errors = []
    version = tag.removeprefix('v')
    package_version = read_version()
    if version != package_version:
        errors.append(f'Tag {tag} does not match __version__ {package_version}')
    if not changelog_section(version):
        errors.append(f'CHANGELOG.md has no [{version}] section')
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('check').add_argument('tag')
    sub.add_parser('notes').add_argument('version')
    args = parser.parse_args()

    if args.command == 'check':
        errors = check(args.tag)
        for error in errors:
            print(error, file=sys.stderr)
        if errors:
            return 1
        version = args.tag.removeprefix('v')
        print(f'version={version}')
        print(f'prerelease={str(PRERELEASE.search(version) is not None).lower()}')
        return 0

    notes = changelog_section(args.version)
    if notes is None:
        print(f'CHANGELOG.md has no [{args.version}] section', file=sys.stderr)
        return 1
    print(notes)
    return 0


if __name__ == '__main__':
    sys.exit(main())
