"""
Shared pytest fixtures for the extelf test suite.

All tests run with `tests/extelf/` as the working directory so that relative
paths like `"./challenge"` and `"complex_structs.h"` resolve correctly.
"""
import os
import pytest
from pathlib import Path

from doglib.extelf import CHeader, ExtendedELF

TEST_DIR = Path(__file__).parent


@pytest.fixture(scope="session", autouse=True)
def change_to_test_dir():
    """Change cwd to the test directory for the whole session."""
    original = os.getcwd()
    os.chdir(TEST_DIR)
    yield
    os.chdir(original)


@pytest.fixture(scope="session")
def headers(change_to_test_dir):
    """CHeader loaded from complex_structs.h (compiled once per session)."""
    return CHeader("complex_structs.h")


@pytest.fixture(scope="session")
def chal_elf(change_to_test_dir):
    """ExtendedELF for the compiled challenge binary."""
    return ExtendedELF("./challenge")
