from _mpecdsa_cffi import lib, ffi
from json import loads, dumps

class GE:
    def __init__(self, inst):
        assert ffi.typeof("struct GE *") is ffi.typeof(inst)
        self.inst = inst

    def __del__(self):
        lib.ge_delete(self.inst)

class BigInt:
    def __init__(self, inst):
        assert ffi.typeof("struct BigInt *") is ffi.typeof(inst)
        self.inst = inst

    def __del__(self):
        lib.bigint_delete(self.inst)

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

    @property
    def public_share(self):
        return GE(lib.p1_keygen1_public_share(self.inst))

    @property
    def pk_commitment(self):
        return BigInt(lib.p1_keygen1_pk_commitment(self.inst))

    @property
    def zk_pok_commitment(self):
        return BigInt(lib.p1_keygen1_zk_pok_commitment(self.inst))

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

    @property
    def public_share(self):
        return GE(lib.p2_keygen1_public_share(self.inst))

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
        lib.p1_keygen2_delete(self.inst)

    @property
    def pk_commitment_blind_factor(self):
        return BigInt(lib.p1_keygen2_pk_commitment_blind_factor(self.inst))

    @property
    def zk_pok_blind_factor(self):
        return BigInt(lib.p1_keygen2_zk_pok_blind_factor(self.inst))

    @property
    def public_share(self):
        return GE(lib.p1_keygen2_public_share(self.inst))

    @property
    def d_log_proof(self):
        return DLogProof(lib.p1_keygen2_d_log_proof(self.inst))

class P2KeyGen2:
    def __init__(self, inst):
        self.inst = inst

    @staticmethod
    def verify_commitments_and_dlog_proof(
        pk_com,
        zk_pok,
        zk_pok_blind,
        public_share,
        pk_com_blind_party,
        d_log_proof,
    ):
        assert type(pk_com) is BigInt
        assert type(zk_pok) is BigInt
        assert type(zk_pok_blind) is BigInt
        assert type(public_share) is GE
        assert type(pk_com_blind_party) is BigInt
        assert type(d_log_proof) is DLogProof
        ptr = lib.p2_keygen2_nullable_new_verify_commitments_and_dlog_proof(pk_com.inst, zk_pok.inst, zk_pok_blind.inst, public_share.inst, pk_com_blind_party.inst, d_log_proof.inst)
        if ptr == ffi.cast('struct KeyGenSecondMsg *', 0):
            raise Exception('could not verify_commitments_and_dlog_proof')
        return P2KeyGen2(ptr)

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
    p1k2 = P1KeyGen2.verify_and_decommit(p1k1, d1)
    #swapping the first two parameters like this shouldn't panic go:
    #P2KeyGen2.verify_commitments_and_dlog_proof(
    #    p1k1.zk_pok_commitment,
    #    p1k1.pk_commitment,
    #    p1k2.zk_pok_blind_factor,
    #    p1k2.public_share,
    #    p1k2.pk_commitment_blind_factor,
    #    p1k2.d_log_proof,
    #)
    P2KeyGen2.verify_commitments_and_dlog_proof(
        p1k1.pk_commitment,
        p1k1.zk_pok_commitment,
        p1k2.zk_pok_blind_factor,
        p1k2.public_share,
        p1k2.pk_commitment_blind_factor,
        p1k2.d_log_proof,
    )

    print("test passed")
