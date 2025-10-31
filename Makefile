.PHONY: all build build-release test clean example run-example

# Build library in debug mode
build:
	cargo build

# Build library in release mode
build-release:
	cargo build --release

# Run tests
test:
	cargo test

# Compile C example
example: build-release
	gcc -o example example.c \
		-I. \
		-L./target/release \
		-lpq_bindings_c_rust \
		-lpthread -ldl -lm \
		-Wl,-rpath,./target/release

# Run example
run-example: example
	./example

# Clean
clean:
	cargo clean
	rm -f example
	rm -rf include

# Build everything (library + example)
all: build-release example
