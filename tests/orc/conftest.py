"""
Shared pytest fixtures for the orc test suite.

All tests run with `tests/orc/` as the working directory so that relative
paths like `"./challenge"` and `"complex_structs.h"` resolve correctly.
"""
import os
import pytest
from pathlib import Path

from pwnlib.elf.elf import ELF
from doglib.orc import ORCHeader, ORC
import doglib._hijack  # patches sym_obj, resolve_field, orc onto ELF

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
    """ORCHeader loaded from complex_structs.h (compiled once per session)."""
    return ORCHeader("complex_structs.h")


@pytest.fixture(scope="session")
def chal_elf(change_to_test_dir):
    """ORC for the compiled challenge binary (DWARF only)."""
    return ORC("./challenge")


@pytest.fixture(scope="session")
def chal_pwn_elf(change_to_test_dir):
    """Pwntools ELF for the challenge binary (has symbols + orc bridge)."""
    return ELF("./challenge", checksec=False)
