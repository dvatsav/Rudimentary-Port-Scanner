CC=g++
CFLAGS=-lpthread
STD=c++11

all: fmap

fmap: fmap.cpp
	$(CC) -std=$(STD) $< -o $@ $(CFLAGS)

clean:
	rm fmap
