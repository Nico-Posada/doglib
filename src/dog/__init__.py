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

# C / C32 / C64 are lazy singletons in doglib.extelf (they spin up GCC on first
# access, so we keep them lazy).  They are NOT included in "from dog import *"
# but work fine as:  from dog import C64  — or —  import dog; dog.C64
from doglib import extelf as _extelf


def __getattr__(name):
    if name in ("C", "C32", "C64"):
        return getattr(_extelf, name)
    raise AttributeError(name)
