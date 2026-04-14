from ._cheader import ORCHeader

class CTypes(ORCHeader):
    def __init__(self, bits=None):
        from importlib.resources import files
        header_src = files('doglib.data.orc').joinpath('ctypes_builtin.h')
        super().__init__(str(header_src), bits=bits)
