#!/usr/bin/env python3
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

class EncryptionKey:
    def __init__(self, inst):
        assert ffi.typeof("struct EncryptionKey *") is ffi.typeof(inst)
        self.inst = inst

    def __del__(self):
        lib.encryption_key_delete(self.inst)

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

class P1PaillierKeyPair:
    def __init__(self, inst):
        self.inst = inst

    @staticmethod
    def generate_keypair_and_encrypted_share(p1k1):
        assert type(p1k1) is P1KeyGen1
        return P1PaillierKeyPair(lib.p1_paillier_pair_new_generate_keypair_and_encrypted_share(p1k1.inst))

    def __del__(self):
        lib.p1_paillier_pair_delete(self.inst)

    @property
    def ek(self):
        return EncryptionKey(lib.p1_paillier_pair_ek(self.inst))

    @property
    def encrypted_share(self):
        return BigInt(lib.p1_paillier_pair_encrypted_share(self.inst))

    @staticmethod
    def generate_proof_correct_key(p1pkp, challenge):
        assert type(p1pkp) is P1PaillierKeyPair
        assert type(challenge) is Challenge
        obj = lib.p1_paillier_pair_nullable_generate_proof_correct_key(p1pkp.inst, challenge.inst)
        if obj == ffi.cast('struct CorrectKeyProof *', 0):
            raise Exception('could not make correct key proof')
        return CorrectKeyProof(obj)

    def generate_range_proof(self, p1k1):
        assert type(p1k1) is P1KeyGen1
        res = lib.p1_paillier_pair_generate_range_proof(self.inst, p1k1.inst)
        encrypted_pairs = EncryptedPairs(lib.range_tuple_1(res))
        challenge = ChallengeBits(lib.range_tuple_2(res))
        proof = Proof(lib.range_tuple_3(res))
        lib.range_tuple_delete(res)
        return encrypted_pairs, challenge, proof

class EncryptedPairs:
    def __init__(self, inst):
        assert ffi.typeof("struct EncryptedPairs *") is ffi.typeof(inst)
        self.inst = inst

    def __del__(self):
        lib.encrypted_pairs_delete(self.inst)

class ChallengeBits:
    def __init__(self, inst):
        assert ffi.typeof("struct ChallengeBits *") is ffi.typeof(inst)
        self.inst = inst

    def __del__(self):
        lib.challenge_bits_delete(self.inst)

class Proof:
    def __init__(self, inst):
        assert ffi.typeof("struct Proof *") is ffi.typeof(inst)
        self.inst = inst

    def __del__(self):
        lib.proof_delete(self.inst)

class CorrectKeyProof:
    def __init__(self, inst):
        assert ffi.typeof("struct CorrectKeyProof *") is ffi.typeof(inst)
        self.inst = inst

    def __del__(self):
        lib.correct_key_proof_delete(self.inst)

class Challenge:
    def __init__(self, inst):
        assert ffi.typeof("struct Challenge *") is ffi.typeof(inst)
        self.inst = inst

    def __del__(self):
        lib.challenge_delete(self.inst)

class ChalVeriPair:
    def __init__(self, inst):
        assert ffi.typeof("struct ChalVeriPair *") is ffi.typeof(inst)
        self.inst = inst

    def __del__(self):
        lib.chal_veri_pair_delete(self.inst)

    @property
    def challenge(self):
        return Challenge(lib.chal_veri_pair_challenge(self.inst))

    @property
    def verification_aid(self):
        return VerificationAid(lib.chal_veri_pair_verification_aid(self.inst))

class VerificationAid:
    def __init__(self, inst):
        assert ffi.typeof("struct VerificationAid *") is ffi.typeof(inst)
        self.inst = inst

    def __del__(self):
        lib.verification_aid_delete(self.inst)

class P2PaillierPublic:
    def __init__(self, ek, encrypted_secret_share):
        self.inst = lib.p2_paillier_public_new(ek.inst, encrypted_secret_share.inst)

    def __del__(self):
        lib.p2_paillier_public_delete(self.inst)

    def generate_correct_key_challenge(self):
        return ChalVeriPair(lib.chal_veri_pair_new(self.inst))

    @staticmethod
    def verify_correct_key(c_k_p, veri_aid):
        assert type(c_k_p) is CorrectKeyProof
        assert type(veri_aid) is VerificationAid
        if not lib.p2_paillier_public_verify_correct_key(c_k_p.inst, veri_aid.inst):
            raise Exception('invalid correct key')

    def verify_range_proof(self, challenge_bits, encrypted_pairs, proof):
        assert type(challenge_bits) is ChallengeBits
        assert type(encrypted_pairs) is EncryptedPairs
        assert type(proof) is Proof
        if not lib.p2_paillier_public_verify_range_proof(self.inst, challenge_bits.inst, encrypted_pairs.inst, proof.inst):
            raise Exception('error verifying range proof')

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

    p1pkp = P1PaillierKeyPair.generate_keypair_and_encrypted_share(p1k1)
    p1pkp.ek
    p1pkp.encrypted_share

    p2paillierpub = P2PaillierPublic(p1pkp.ek, encrypted_secret_share=p1pkp.encrypted_share)

    challenge_verification_pair =\
     p2paillierpub.generate_correct_key_challenge()
    proof_result = P1PaillierKeyPair.generate_proof_correct_key(p1pkp, challenge_verification_pair.challenge)

    P2PaillierPublic.verify_correct_key(proof_result, challenge_verification_pair.verification_aid)

    encrypted_pairs, challenge_bits, proof = p1pkp.generate_range_proof(p1k1)

    p2paillierpub.verify_range_proof(challenge_bits, encrypted_pairs, proof)

    print("test passed")
