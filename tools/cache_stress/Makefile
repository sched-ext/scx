CC ?= gcc
CFLAGS ?= -O2 -Wall -pthread
LDFLAGS ?= -lm -lpthread
TARGET = cache_stress

$(TARGET): cache_stress.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: clean