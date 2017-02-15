IDIR	=./crypto
CC	=gcc
CFLAGS 	=-I$(IDIR)
CFLAGS 	+=-I.
CFLAGS 	+=--std=c99

gen_c: gen_check_code.c 
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *.o *~ 
