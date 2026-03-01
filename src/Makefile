TARGET = safekey

CC     = gcc
CFLAGS = -O0 -Wall -g -ansi
STATIC = -static

OBJS := totp.o filesystem.c \
	sha1.o hmac.o


all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(STATIC) $^ -o $@

clean:
	rm -f $(TARGET) *.o
