include ../../config.mk

CC := $(CROSS_COMPILE)gcc
CFLAGS = -Wall -O2
TARGET = toctou_test

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
