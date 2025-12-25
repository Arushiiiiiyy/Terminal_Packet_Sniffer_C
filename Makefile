# C-Shark Makefile
CC = gcc
CFLAGS = -Wall -Wextra -g -O2
LDFLAGS = -lpcap


# Target executable name
TARGET = cshark

# Source files
SRCS = cshark_main.c \
       cshark_sniffer.c \
       cshark_decoder.c \
       cshark_utils.c \
       cshark_inspector.c \
       cshark_hexdump.c

# Object files
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

# Build the executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)
	@echo "Build complete! Run with: sudo ./$(TARGET)"
	@echo "Build complete! Run with: sudo ./$(TARGET)"

# Compile source files to object files
%.o: %.c headers.h
	$(CC) $(CFLAGS) -c $< -o $@

# Specific dependencies
cshark_main.o: cshark_main.c headers.h
cshark_sniffer.o: cshark_sniffer.c headers.h
cshark_decoder.o: cshark_decoder.c headers.h
cshark_utils.o: cshark_utils.c headers.h
cshark_inspector.o: cshark_inspector.c headers.h
cshark_hexdump.o: cshark_hexdump.c headers.h

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)
	@echo "Clean complete!"

# Install (optional - requires root)
install: $(TARGET)
	@echo "Installing $(TARGET) to /usr/local/bin..."
	@sudo cp $(TARGET) /usr/local/bin/
	@echo "Installation complete!"

# Uninstall (optional)
uninstall:
	@echo "Removing $(TARGET) from /usr/local/bin..."
	@sudo rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstall complete!"

# Run the program (requires sudo)
run: $(TARGET)
	sudo ./$(TARGET)

# Debug with valgrind
debug: $(TARGET)
	sudo valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET)

# Help target
help:
	@echo "C-Shark Makefile Targets:"
	@echo "  make         - Build the C-Shark executable"
	@echo "  make clean   - Remove object files and executable"
	@echo "  make run     - Build and run C-Shark (requires sudo)"
	@echo "  make install - Install to /usr/local/bin (requires sudo)"
	@echo "  make debug   - Run with valgrind for memory debugging"
	@echo "  make help    - Display this help message"

.PHONY: all clean install uninstall run debug help
