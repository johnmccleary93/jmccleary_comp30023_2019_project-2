output: crack.o
	 gcc crack.o -o crack

crack.o: crack.c sha256.h sha256.c
	gcc -c crack.c

clean:
	 rm *.o output
