CC = gcc
CFLAGS = -Wall -Werror -Wextra

SRCS = aes.c
OBJS = $(SRCS:.c=.o)
LIB = libblockbreakers

TEST = test-block-breakers
TEST_SRCS = test.c
TEST_OBJS = $(TEST_SRCS:.c=.o)

all: $(LIB) $(TEST)

%.o: %.c
	$(CC) $(CFLAGS) -I . -c $< -o $@

$(LIB): $(OBJS)
	ar -rc $(LIB).a $(OBJS)

$(TEST): $(LIB) $(TEST_OBJS)
	$(CC) $(TEST_OBJS) -L. -lblockbreakers -o $@

clean:
	rm -f $(OBJS) $(TEST_OBJS) $(LIB).a $(TEST)
