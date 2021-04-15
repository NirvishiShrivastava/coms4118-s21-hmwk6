CC = gcc
CFLAGS = -g -Wall

.PHONY: all clean

all: map_pages inspect_pages

map_pages: map_pages.c
	$(CC) $(CFLAGS) -o $@ $<

inspect_pages: inspect_pages.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f map_pages inspect_pages
