CC ?= $(CROSS_COMPILE)gcc
CFLAGS = -Wall -O2
TARGET = toctou_test

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

install: $(TARGET)
	cp $(TARGET) /home/dreams200260/mytee_sec252/out/

.PHONY: all clean install
