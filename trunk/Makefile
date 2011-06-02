# Makefile for oddsock
# Copyright 2011 Stephen Larew

CC=clang
ifeq ($(mode),release)
	FLAGS_OPTS = -O2
else
	mode = debug
	FLAGS_OPTS = -g -O0 -DDEBUG
endif
CFLAGS = -Wall -ansi -pedantic $(FLAGS_OPTS)
INCLUDES = -I/usr/local/include
LFLAGS = -Wall -L/usr/local/lib $(FLAGS_OPTS)
LIBS = -levent_core

SRCS = main.c \
	   util.c \
	   socks5.c
OBJS = $(SRCS:.c=.o)

TARGET = oddsock

.PHONY: depend clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LFLAGS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	-rm -f *.o *~ $(TARGET)

depend: $(SRCS)
	makedepend $(INCLUDES) $^

# DO NOT DELETE
