CC 	= clang
CFLAGS	= -Wall
LDFLAGS	=

all: kfw

kfw: kfw-user.o
	$(CC) -o $@ $(LDFLAGS) $^

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) $^
