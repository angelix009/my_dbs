CFLAGS = -std=c99 -pedantic -Wall -Wextra -Wvla -Werror
PROG = my_db
TEST = test

all: $(PROG) $(TEST)

$(PROG):
	gcc $(CFLAGS) -D_POSIX_C_SOURCE=200809L my_db.c -o $(PROG)

$(TEST):
	gcc $(CFLAGS) -static test.c -o $(TEST)

clean:
	rm -f $(PROG) $(TEST)
