CC=gcc -std=c89 -Wall
DEFINES=-DINLINE="" -DSTATIC=static


ppenc.o: ppenc.c ppenc.h
	$(CC) -c $(DEFINES) ppenc.c -o ppenc.o

hash.o: hash.c hash.h
	$(CC) -c $(DEFINES) hash.c -o hash.o

cprng.o: cprng.c cprng.h
	$(CC) -c $(DEFINES) cprng.c -o cprng.o

blockcipher.o: blockcipher.c blockcipher.h
	$(CC) -c $(DEFINES) blockcipher.c -o blockcipher.o

example-client-bin: example-client/client.c ppenc.o hash.o cprng.o blockcipher.o
	$(CC) example-client/client.c ppenc.o hash.o cprng.o blockcipher.o -o example-client-bin
