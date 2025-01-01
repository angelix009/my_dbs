CC = cc
CFLAGS = -std=c99 -pedantic -Wall -Wextra -Wvla -Werror

all: my_nm

my_nm: my_nm.c
	$(CC) $(CFLAGS) -o my_nm my_nm.c

clean:
	rm -f my_nm *.o
