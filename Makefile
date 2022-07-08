CFLAGS=-std=c11 -g -static
#SRCS=$(wildcard *.c)
SRCS=main.c
OBJS=$(SRCS:.c=.o)

predb: $(OBJS)
	$(CC) -o predb $(OBJS) $(LDFLAGS)

clean:
	rm -f predb *.o *~

.PHONY: clean
