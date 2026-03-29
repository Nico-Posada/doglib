from pwn import *

from doglib.misc import *
from doglib.heap import *
from doglib.io_file import *
from doglib.muney import *
from doglib.ezrop import *
from doglib.asm import *
from doglib.shellcode import *
from doglib.pow import *
from doglib.log import *
from doglib.dumpelf import *
from doglib.extelf import *
import doglib._hijack

from doglib import extelf as _extelf
def __getattr__(name):
    if name in ("C", "C32", "C64"):
        return getattr(_extelf, name)
    raise AttributeError(name)
