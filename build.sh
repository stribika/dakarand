cd scrypt-1.1.6
./configure; make
cd ..
gcc  -o dakarand dakarand.c -I scrypt-1.1.6 -I scrypt-1.1.6/lib/scryptenc/ -I scrypt-1.1.6/lib/util/ -I scrypt-1.1.6/lib/crypto scrypt-1.1.6/scrypt-sha256.o scrypt-1.1.6/scrypt-crypto_aesctr.o scrypt-1.1.6/scrypt-scryptenc.o scrypt-1.1.6/scrypt-memlimit.o scrypt-1.1.6/scrypt-scryptenc_cpuperf.o scrypt-1.1.6/scrypt-warn.o scrypt-1.1.6/scrypt-crypto_scrypt-nosse.o -lcrypto -lrt


