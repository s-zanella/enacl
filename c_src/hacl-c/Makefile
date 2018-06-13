.PHONY: clean

# For Generic 64-bit
CCOPTS = -Ofast -march=native -mtune=native -m64 -fwrapv -fomit-frame-pointer -funroll-loops

# For Generic 32-bit
CCOPTS32 = -Ofast -mtune=generic -m32 -fwrapv -fomit-frame-pointer -funroll-loops

LIBFLAGS=$(CCOPTS) -fPIC -I . -fvisibility=hidden
LIBFLAGS32=$(CCOPTS32) -fPIC -DKRML_NOUINT128 -Wno-unused-function
OTHER=-shared

# Files

FILES = Hacl_Chacha20_Vec128.c Hacl_Salsa20.c Hacl_Salsa20.h Hacl_Chacha20.c Hacl_Chacha20.h Hacl_Poly1305_32.c Hacl_Poly1305_32.h Hacl_Poly1305_64.c Hacl_Poly1305_64.h AEAD_Poly1305_64.c AEAD_Poly1305_64.h Hacl_SHA2_256.c Hacl_SHA2_256.h Hacl_SHA2_384.c Hacl_SHA2_384.h Hacl_SHA2_512.c Hacl_SHA2_512.h Hacl_HMAC_SHA2_256.c Hacl_HMAC_SHA2_256.h Hacl_HMAC_SHA2_512.c Hacl_HMAC_SHA2_512.h Hacl_Ed25519.c Hacl_Ed25519.h Hacl_Curve25519.c Hacl_Curve25519.h Hacl_Chacha20Poly1305.c Hacl_Chacha20Poly1305.h Hacl_Policies.c Hacl_Policies.h NaCl.c NaCl.h ehacl.c

# Dynamic 64-bit library

libehacl.so: $(FILES)
	$(CC) $(LIBFLAGS) -c FStar_UInt128.c -o FStar_UInt128.o
	$(CC) $(LIBFLAGS) -c Hacl_Salsa20.c -o Hacl_Salsa20.o
	$(CC) $(LIBFLAGS) -c Hacl_Chacha20.c -o Hacl_Chacha20.o
	$(CC) $(LIBFLAGS) -c Hacl_Chacha20_Vec128.c -o Hacl_Chacha20_Vec128.o
	$(CC) $(LIBFLAGS) -c Hacl_Poly1305_32.c -o Hacl_Poly1305_32.o
	$(CC) $(LIBFLAGS) -c Hacl_Poly1305_64.c -o Hacl_Poly1305_64.o
	$(CC) $(LIBFLAGS) -c AEAD_Poly1305_64.c -o AEAD_Poly1305_64.o
	$(CC) $(LIBFLAGS) -c Hacl_SHA2_256.c -o Hacl_SHA2_256.o
	$(CC) $(LIBFLAGS) -c Hacl_SHA2_384.c -o Hacl_SHA2_384.o
	$(CC) $(LIBFLAGS) -c Hacl_SHA2_512.c -o Hacl_SHA2_512.o
	$(CC) $(LIBFLAGS) -c Hacl_HMAC_SHA2_256.c -o Hacl_HMAC_SHA2_256.o
	$(CC) $(LIBFLAGS) -c Hacl_HMAC_SHA2_512.c -o Hacl_HMAC_SHA2_512.o
	$(CC) $(LIBFLAGS) -c Hacl_Ed25519.c -o Hacl_Ed25519.o
	$(CC) $(LIBFLAGS) -c Hacl_Curve25519.c -o Hacl_Curve25519.o
	$(CC) $(LIBFLAGS) -c Hacl_Chacha20Poly1305.c -o Hacl_Chacha20Poly1305.o
	$(CC) $(LIBFLAGS) -c Hacl_Unverified_Random.c -o Hacl_Unverified_Random.o
	$(CC) $(OTHER) $(LIBFLAGS) -I ../../test/test-files -I . -Wall \
	FStar_UInt128.o  Hacl_Chacha20_Vec128.c Hacl_Salsa20.o Hacl_Poly1305_32.o Hacl_Poly1305_64.o Hacl_Chacha20.o AEAD_Poly1305_64.o Hacl_Chacha20Poly1305.o Hacl_SHA2_256.o Hacl_SHA2_384.o Hacl_SHA2_512.o Hacl_HMAC_SHA2_256.o Hacl_HMAC_SHA2_512.o Hacl_Ed25519.o Hacl_Curve25519.o kremlib.c Hacl_Policies.c NaCl.c Hacl_Unverified_Random.o ehacl.c \
	  -o libehacl.so

# Static 64-bit library

libehacl.a: $(FILES)
	$(CC) $(LIBFLAGS) -c FStar_UInt128.c -o FStar_UInt128.o
	$(CC) $(LIBFLAGS) -c Hacl_Salsa20.c -o Hacl_Salsa20.o
	$(CC) $(LIBFLAGS) -c Hacl_Chacha20.c -o Hacl_Chacha20.o
	$(CC) $(LIBFLAGS) -c Hacl_Chacha20_Vec128.c -o Hacl_Chacha20_Vec128.o
	$(CC) $(LIBFLAGS) -c Hacl_Poly1305_32.c -o Hacl_Poly1305_32.o
	$(CC) $(LIBFLAGS) -c Hacl_Poly1305_64.c -o Hacl_Poly1305_64.o
	$(CC) $(LIBFLAGS) -c AEAD_Poly1305_64.c -o AEAD_Poly1305_64.o
	$(CC) $(LIBFLAGS) -c Hacl_SHA2_256.c -o Hacl_SHA2_256.o
	$(CC) $(LIBFLAGS) -c Hacl_SHA2_384.c -o Hacl_SHA2_384.o
	$(CC) $(LIBFLAGS) -c Hacl_SHA2_512.c -o Hacl_SHA2_512.o
	$(CC) $(LIBFLAGS) -c Hacl_HMAC_SHA2_256.c -o Hacl_HMAC_SHA2_256.o
	$(CC) $(LIBFLAGS) -c Hacl_HMAC_SHA2_512.c -o Hacl_HMAC_SHA2_512.o
	$(CC) $(LIBFLAGS) -c Hacl_Ed25519.c -o Hacl_Ed25519.o
	$(CC) $(LIBFLAGS) -c Hacl_Curve25519.c -o Hacl_Curve25519.o
	$(CC) $(LIBFLAGS) -c Hacl_Chacha20Poly1305.c -o Hacl_Chacha20Poly1305.o
	$(CC) $(LIBFLAGS) -c Hacl_Unverified_Random.c -o Hacl_Unverified_Random.o
	$(CC) $(OTHER) $(LIBFLAGS) -I ../../test/test-files -I . -Wall \
	  Hacl_Salsa20.o Hacl_Poly1305_32.o Hacl_Poly1305_64.o Hacl_Chacha20.o Hacl_Chacha20_Vec128.o AEAD_Poly1305_64.o Hacl_Chacha20Poly1305.o Hacl_SHA2_256.o Hacl_SHA2_384.o Hacl_SHA2_512.o Hacl_HMAC_SHA2_256.o Hacl_HMAC_SHA2_512.o Hacl_Ed25519.o Hacl_Curve25519.o kremlib.c Hacl_Policies.c NaCl.c Hacl_Unverified_Random.o ehacl.c \
	  -o libehacl.a

clean:
	rm -rf *~ *.exe *.out *.o *.so *.a
