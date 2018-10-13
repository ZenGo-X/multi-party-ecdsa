from _mpecdsa_cffi import lib, ffi
from json import loads, dumps

class P1KeyGen1:
    def __init__(self, inst):
        # warning, cbindgen lets the names collide as of Oct 2018
        assert ffi.typeof("struct KeyGenFirstMsg *") is ffi.typeof(inst)
        self.inst = inst

    @staticmethod
    def create_commitments():
        return P1KeyGen1(lib.p1_keygen1_new_create_commitments())

    def __del__(self):
        lib.p1_keygen1_delete(self.inst)

class DLogProof:
    def __init__(self, inst):
        assert ffi.typeof("struct DLogProof *") is ffi.typeof(inst)
        self.inst = inst

    def __del__(self):
        lib.d_log_proof_delete(self.inst)

    def serialize(self):
        c_str = lib.d_log_proof_serialize(self.inst)
        py_str = ffi.string(c_str)
        lib.c_str_delete(c_str)
        return loads(py_str)

    @staticmethod
    def deserialize(json):
        asc = dumps(json).encode('ascii')
        c_str = ffi.new('char[]', asc) # freed by cffi
        obj = lib.d_log_proof_nullable_new_deserialize(c_str)
        if obj == ffi.cast('struct DLogProof *', 0):
            raise Exception('could not deserialize')
        return DLogProof(obj)

class P2KeyGen1:
    def __init__(self):
        self.inst = lib.p2_keygen1_new_create()

    @property
    def d_log_proof(self):
        return DLogProof(lib.p2_keygen1_d_log_proof(self.inst))

    def __del__(self):
        lib.p2_keygen1_delete(self.inst)

class P1KeyGen2:
    def __init__(self, inst):
        self.inst = inst

    @staticmethod
    def verify_and_decommit(p1_keygen1, d_log_proof):
        assert type(d_log_proof) is DLogProof
        assert type(p1_keygen1) is P1KeyGen1
        ptr = lib.p1_keygen2_nullable_new_verify_and_decommit(p1_keygen1.inst, d_log_proof.inst)
        if ptr == ffi.cast('struct KeyGenSecondMsg *', 0):
            raise Exception('could not verify_and_decommit')
        return P1KeyGen2(ptr)

    def __del__(self):
        lib.p2_keygen2_delete(self.inst)

if __name__ == "__main__":
    print("starting test")
    p1k1 = P1KeyGen1.create_commitments()
    d1 = P2KeyGen1().d_log_proof
    #ser = d1.serialize()
    #try:
    #    bajts = bytes.fromhex(ser['pk']['x'])
    #except ValueError: # not hex
    #    raise Exception(ser)
    #x = int.from_bytes(bajts, 'big')
    #ser['pk']['x'] = hex(x + 1)[2:]
    #d2 = DLogProof.deserialize(ser)
    #assert d2.serialize() != d1.serialize()
    #try:
    #    P1KeyGen2.verify_and_decommit(p1k1, d2)
    #except:
    #    pass
    #else:
    #    assert False
    try:
        DLogProof.deserialize({})
    except:
        pass
    else:
        assert False
    P1KeyGen2.verify_and_decommit(p1k1, d1)
    print("test passed")
