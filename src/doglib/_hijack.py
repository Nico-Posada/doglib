# adding more methods to existing pwntools features
# feel free to merge this (or the rest of this library i don't care)
from pwnlib.tubes.tube import tube
from pwnlib.elf.elf import ELF
from functools import cached_property
from .extelf import ExtendedELF
from .asm import kasm

def _get_func_name(func):
    if isinstance(func, property):
        return func.fget.__name__
    if isinstance(func, cached_property):
        return func.func.__name__
    return func.__name__

def patch(target_cls, force=False):
    def decorator(func):
        name = _get_func_name(func)
        if not force and hasattr(target_cls, name):
            raise AttributeError(
                f"patch: {target_cls.__name__} already has attribute '{name}'. "
                f"Use force=True to override."
            )
        setattr(target_cls, name, func)
        if isinstance(func, cached_property):
            func.__set_name__(target_cls, name)
        return func
    return decorator


# ---- tube -------------------------------------------------------------
@patch(tube)
def readlineafter(self, needle):
    self.readuntil(needle)
    return self.readline()

@patch(tube)
def readuntildrop(self, needle):
    return self.readuntil(needle, drop=True)

_cdelim = b':'

@patch(tube)
def sendlinecolon(self, dat):
    self.sendlineafter(_cdelim, dat)

@patch(tube)
def sendaftercolon(self, dat):
    self.sendafter(_cdelim, dat)

@patch(tube)
def sendintcolon(self, dat):
    self.sendlineafter(_cdelim, str(dat).encode())

@patch(tube)
def readlinecolon(self):
    self.readuntil(_cdelim)
    return self.readline()

@patch(tube)
def readint(self,base=0):
    return int(self.recv(),base)

@patch(tube)
def readlineint(self,base=0):
    return int(self.readline(),base)

# shorthands
tube.sla = tube.sendlineafter
tube.sl = tube.sendline
tube.sa = tube.sendafter
tube.s = tube.send
tube.ru = tube.readuntil
tube.rl = tube.readline
tube.slc = tube.sendlinecolon
tube.sc = tube.sendaftercolon
tube.sic = tube.sendintcolon
tube.rla = tube.readlineafter
tube.rld = tube.readlinecolon
tube.rud = tube.readuntildrop
tube.ri = tube.readint
tube.rli = tube.readlineint

# ---- elf -------------------------------------------------------------
@patch(ELF)
def gadget(self, asm):
    asm = kasm[self.arch](asm)
    return next(self.search(asm,executable=True))

@patch(ELF)
@property
def binsh(self):
    return next(self.search(b"/bin/sh\0"))

@patch(ELF)
@cached_property
def extelf(self):
    return ExtendedELF(self.path)

@patch(ELF)
@property
def symo(self):
    return self.extelf.sym_obj

@patch(ELF)
def onegadgets(self, level=100):
    import subprocess, shutil
    if shutil.which('one_gadget') is None:
        raise FileNotFoundError("one_gadget not found in PATH")
    result = subprocess.run(['one_gadget', '-r', '-l', str(int(level)), self.path], capture_output=True, text=True)
    out = result.stdout.strip()
    if not out or out.startswith('[OneGadget]'):
        raise RuntimeError(f"one_gadget failed: {out}")
    offsets = [int(x) for x in out.split()]
    if self.pie:
        offsets = [self.address + o for o in offsets]
    return offsets

# maybe add more extelf stuff l8r