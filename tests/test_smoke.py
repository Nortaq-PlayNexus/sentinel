import importlib
import pkgutil
import pytest

import sentinel

def test_package_importable():
    assert sentinel is not None

def test_import_all_submodules():
    errors = []
    for mod in pkgutil.walk_packages(sentinel.__path__, sentinel.__name__ + "."):
        try:
            importlib.import_module(mod.name)
        except Exception as exc:
            errors.append(f"{mod.name}: {exc}")
    if errors:
        pytest.fail("Submodule import failures:\n" + "\n".join(errors))