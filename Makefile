

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=gnu11 \
          -D_FILE_OFFSET_BITS=64 \
          -I./include \
          $(shell pkg-config --cflags fuse3)
LDFLAGS = $(shell pkg-config --libs fuse3) \
          -L/usr/lib/x86_64-linux-gnu \
          -lcrypto \
          -lpthread

SRCS   = src/encryptfs.c src/crypto.c
TARGET = encryptfs


BACKING ?= /tmp/efs_backing
MOUNT   ?= /tmp/efs_mount
PASS    ?= changeme

.PHONY: all clean test mount unmount demo deps-check

all: deps-check $(TARGET)

$(TARGET): $(SRCS) include/encryptfs.h include/crypto.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)
	@echo ""
	@echo "  [✓] Built: ./$(TARGET)"
	@echo "  Usage: ./$(TARGET) <backing_dir> <mountpoint> --password=<pass> -f"
	@echo ""


deps-check:
	@pkg-config --exists fuse3 || \
	  (echo "[!] libfuse3-dev missing. Run: sudo apt install libfuse3-dev" && exit 1)
	@echo "[✓] fuse3 found: $(shell pkg-config --modversion fuse3)"
	@test -f /usr/lib/x86_64-linux-gnu/libcrypto.so || \
	  ln -sf /usr/lib/x86_64-linux-gnu/libcrypto.so.3 \
	         /usr/lib/x86_64-linux-gnu/libcrypto.so 2>/dev/null || \
	  (echo "[!] libssl-dev missing. Run: sudo apt install libssl-dev" && exit 1)
	@echo "[✓] OpenSSL (libcrypto) found"

test: $(TARGET)
	@chmod +x tests/test_encryptfs.sh
	@bash tests/test_encryptfs.sh

mount: $(TARGET)
	@mkdir -p $(BACKING) $(MOUNT)
	@echo "Mounting $(BACKING) → $(MOUNT) ..."
	./$(TARGET) $(BACKING) $(MOUNT) --password=$(PASS) -f

unmount:
	@fusermount3 -u $(MOUNT) 2>/dev/null && echo "Unmounted $(MOUNT)" || \
	  echo "$(MOUNT) was not mounted"


demo: $(TARGET)
	@echo ""
	@echo "════════════ encryptfs DEMO ════════════"
	@BACKING=/tmp/efs_demo_back_$$$$ && MOUNT=/tmp/efs_demo_mnt_$$$$ && \
	 mkdir -p $$BACKING $$MOUNT && \
	 ./$(TARGET) $$BACKING $$MOUNT --password=DemoPass123 &>/tmp/efs_log & \
	 sleep 1 && \
	 echo "hello world" > $$MOUNT/test.txt && \
	 echo "" && \
	 echo "=== Virtual (decrypted) ===" && \
	 cat $$MOUNT/test.txt && \
	 echo "" && \
	 
	 echo "=== Backing file (raw hex) ===" && \
	 xxd $$BACKING/test.txt | head -5 && \
	 echo "" && \
	 fusermount3 -u $$MOUNT && \
	 rm -rf $$BACKING $$MOUNT && \
	 echo "Demo complete."

clean:
	rm -f $(TARGET)
	@echo "[✓] Cleaned"
