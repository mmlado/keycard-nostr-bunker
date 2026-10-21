import ast
import importlib.metadata
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / 'keycard_nostr_bunker'


def imported_top_levels() -> set[str]:
    names = set()
    for path in PACKAGE.glob('*.py'):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names.update(alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split('.')[0])
    return names - set(sys.stdlib_module_names) - {PACKAGE.name}


def declared() -> set[str]:
    deps = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['dependencies']
    return {dep.split('>')[0].split('=')[0].split('<')[0].split('~')[0].strip().lower()
            for dep in deps}


@pytest.mark.parametrize('module', sorted(imported_top_levels()))
def test_every_import_is_a_declared_dependency(module):
    # An editable install, like a local keycard-py checkout, records no import names;
    # those distributions are named after their import.
    distributions = importlib.metadata.packages_distributions().get(module) or [module]
    assert {d.lower() for d in distributions} & declared(), (
        f'{module} is imported but none of {distributions} is in pyproject.toml')
