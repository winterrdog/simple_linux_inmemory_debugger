CC = gcc
CFLAGS = -Wextra -O2
SRCS = process_attacker.c
OBJS = $(SRCS:.c=.o)
BIN = process_attacker

.PHONY: clean

all: $(BIN)

# Make object files but don't link them yet
$(OBJS): $(SRCS)
	@$(CC) $(CFLAGS) -c -o $@ $<

# Link and create executable
$(BIN): $(OBJS)
	@$(CC) $(CFLAGS) -o $@ $^

# clean up any hanging and scattered object and executable files
clean:
	@$(RM) $(OBJS) $(BIN)
