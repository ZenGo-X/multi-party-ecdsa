import os.path
from cffi import FFI
ffibuilder = FFI()

prelude = """
typedef struct GE GE;
typedef struct BigInt BigInt;
typedef struct DLogProof DLogProof;
"""

with open("libmulti_party_ecdsa.h") as f:
    ffibuilder.cdef(prelude + "\n".join(x for x in f.readlines() if not x.startswith("#include")))
    #l = f.readlines()

#extern_c_line_indices = [num for num, i in enumerate(l) if 'extern "C"' in i]
#
#first, second = extern_c_line_indices
#relevant_declarations = l[first+1:second]
#
#ffibuilder.cdef("\n".join(relevant_declarations))

ffibuilder.set_source("_mpecdsa_cffi", prelude +
"""
     #include "libmulti_party_ecdsa.h"   // the C header of the library
""",
     library_dirs=['.'],
     libraries=['multi_party_ecdsa'])   # library name, for the linker

if __name__ == "__main__":
    ffibuilder.compile(
        verbose=True,
        )
