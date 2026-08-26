import pytest

try:
    import sentinel
except ImportError:
    sentinel = None

def test_package_importable():
    if sentinel is None:
        pytest.skip("sentinel requires optional dependencies not installed")
    assert sentinel is not None