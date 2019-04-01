LIBS  = -lnetfilter_queue -lnfnetlink -lsqlite3 -lcap-ng -lpthread -lresolv -lcurl

CFLAGS = -Os -s -D_NO_DATABASE -D_NO_PRIVDROP -D_GNU_SOURCE --std=c99 -I./ -Wall

SRC = $(wildcard *.c)
OBJ = $(patsubst %.c,%.o,$(wildcard *.c))

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

dnsfilter: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *.o dnsfilter
