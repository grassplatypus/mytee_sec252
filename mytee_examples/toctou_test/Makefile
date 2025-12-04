CC = arm-linux-gnueabihf-gcc
CFLAGS = -Wall -O2
TARGET = toctou_test

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

install: $(TARGET)
	cp $(TARGET) /home/grassplatypus/mytee_sec252/out/

.PHONY: all clean install
