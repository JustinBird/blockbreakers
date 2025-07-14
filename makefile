CC = gcc
CFLAGS = -Wall -Werror -Wextra

SRCS = aes.c
OBJS = $(SRCS:.c=.o)
LIB_NAME=blockbreakers
LIB_FILE = lib$(LIB_NAME).a

TEST = test-block-breakers
TEST_SRCS = test.c
TEST_OBJS = $(TEST_SRCS:.c=.o)

all: $(LIB) $(TEST)

%.o: %.c
	$(CC) $(CFLAGS) -I . -c $< -o $@

$(LIB_FILE): $(OBJS)
	ar -rc $(LIB_FILE) $(OBJS)

$(TEST): $(LIB_FILE) $(TEST_OBJS)
	$(CC) $(TEST_OBJS) -L. -l$(LIB_NAME) -o $@

clean:
	rm -f $(OBJS) $(TEST_OBJS) $(LIB_FILE) $(TEST)
