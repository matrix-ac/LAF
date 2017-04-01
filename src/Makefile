CC 	= gcc
CFLAGS	= -fsanitize=address,undefined -pedantic -Wall -Wextra -Werror -Werror=format-security -Werror=array-bounds -g -Wformat -Wformat-security
LDLIBS	= -lnfnetlink -lnetfilter_queue

all: main.c procs.c
	$(CC) $(CFLAGS) main.c procs.c -o laf $(LDLIBS)