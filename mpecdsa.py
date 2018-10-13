from _mpecdsa_cffi import lib, ffi

class KeyGen1:
    def __init__(self, inst):
        assert ffi.typeof("struct KeyGenFirstMsg *") is ffi.typeof(inst)
        self.inst = inst

    @staticmethod
    def create_commitments():
        return KeyGen1(lib.p1_keygen1_new_create_commitments())

    def __del__(self):
        lib.p1_keygen1_delete(self.inst)

if __name__ == "__main__":
    print("test")
    KeyGen1.create_commitments()
