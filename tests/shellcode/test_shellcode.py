"""Tests for doglib.shellcode — ShellcodeSet and the minshell set."""
import pytest
from doglib.shellcode import minshell, runcmd
from doglib.shellcode._base import ShellcodeSet


EXPECTED_ARCHES = {"aarch64", "amd64", "arm", "armeb", "i386", "mips", "mipsel", "powerpc", "ppcel"}


class TestShellcodeSetArches:
    def test_arches_returns_list(self):
        assert isinstance(minshell.arches, list)

    def test_arches_nonempty(self):
        assert len(minshell.arches) > 0

    def test_expected_arches_present(self):
        assert EXPECTED_ARCHES == set(minshell.arches)


class TestShellcodeSetLoad:
    @pytest.mark.parametrize("arch", sorted(EXPECTED_ARCHES))
    def test_attr_returns_bytes(self, arch):
        blob = getattr(minshell, arch)
        assert isinstance(blob, bytes)
        assert len(blob) > 0

    def test_amd64_cached(self):
        a = minshell.amd64
        b = minshell.amd64
        assert a is b

    def test_unknown_arch_raises(self):
        with pytest.raises(AttributeError, match="No shellcode for arch"):
            _ = minshell.riscv64

    def test_private_attr_raises(self):
        with pytest.raises(AttributeError):
            _ = minshell._nonexistent


class TestShellcodeSetIteration:
    def test_iter_yields_all_arches(self):
        seen = {arch for arch, _ in minshell}
        assert seen == EXPECTED_ARCHES

    def test_iter_values_are_bytes(self):
        for arch, blob in minshell:
            assert isinstance(blob, bytes), f"arch={arch} did not return bytes"
            assert len(blob) > 0


class TestShellcodeSetRepr:
    def test_repr_contains_name(self):
        assert "minshell" in repr(minshell)

    def test_repr_contains_arches(self):
        assert "amd64" in repr(minshell)


class TestShellcodeSetContextIntegration:
    def test_for_context_amd64(self):
        from pwnlib.context import context
        with context.local(arch="amd64"):
            blob = minshell.for_context()
        assert blob == minshell.amd64

    def test_for_context_i386(self):
        from pwnlib.context import context
        with context.local(arch="i386"):
            blob = minshell.for_context()
        assert blob == minshell.i386

    def test_for_context_unknown_raises(self):
        from pwnlib.context import context
        with context.local(arch="riscv32"):
            with pytest.raises(AttributeError, match="No shellcode for pwntools arch"):
                minshell.for_context()


class TestShellcodeSetExtensibility:
    def test_instantiation(self):
        s = ShellcodeSet("minshell")
        assert "amd64" in s.arches

    def test_repr(self):
        s = ShellcodeSet("minshell")
        assert repr(s).startswith("ShellcodeSet(")


class TestRuncmd:
    def test_returns_bytes(self):
        result = runcmd("ls")
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_default_ctx_is_i386(self):
        assert runcmd("ls") == runcmd("ls", ctx="i386")

    def test_arm_ctx(self):
        from pwnlib.exception import PwnlibException
        try:
            result = runcmd("ls", ctx="arm")
        except PwnlibException as e:
            if "Could not find" in str(e):
                pytest.skip("arm cross-binutils not installed")
            raise
        assert isinstance(result, bytes)
        assert len(result) > 0
