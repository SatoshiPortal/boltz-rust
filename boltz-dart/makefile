.DEFAULT_GOAL := help
PROJECTNAME=$(shell basename "$(PWD)")
SOURCES=$(sort $(wildcard ./src/*.rs ./src/**/*.rs))
OS_NAME=$(shell uname | tr '[:upper:]' '[:lower:]')
PATH := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(OS_NAME)-x86_64/bin:$(PATH)

SHELL := /bin/bash

# ##############################################################################
# # GENERAL
# ##############################################################################

.PHONY: help
help: makefile
	@echo
	@echo " Available actions in "$(PROJECTNAME)":"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo

## init: Install missing dependencies.
.PHONY: init
init:
	rustup target add aarch64-apple-ios x86_64-apple-ios
	#rustup target add armv7-apple-ios armv7s-apple-ios i386-apple-ios ## deprecated
	rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
	@if [ $$(uname) == "Darwin" ] ; then cargo install cargo-lipo ; fi
	cargo install cbindgen
## :

# ##############################################################################
# # RECIPES
# ##############################################################################

## all: Compile iOS, Android and bindings targets
all: ios android bindings

## ios: Compile the iOS universal library
ios: target/universal/release/libboltzdart.a

target/universal/release/libboltzdart.a: $(SOURCES) ndk-home
	@if [ $$(uname) == "Darwin" ] ; then \
		cargo lipo --release ; \
		else echo "Skipping iOS compilation on $$(uname)" ; \
	fi
	@echo "[DONE] $@"

## android: Compile the android targets (arm64, armv7 and i686)
android: target/aarch64-linux-android/release/libboltzdart.so target/armv7-linux-androideabi/release/libboltzdart.so target/i686-linux-android/release/libboltzdart.so target/x86_64-linux-android/release/libboltzdart.so

target/aarch64-linux-android/release/libboltzdart.so: $(SOURCES) ndk-home
	cargo build --target aarch64-linux-android --release
	@echo "[DONE] $@"

target/armv7-linux-androideabi/release/libboltzdart.so: $(SOURCES) ndk-home
	cargo build --target armv7-linux-androideabi --release
	@echo "[DONE] $@"

target/i686-linux-android/release/libboltzdart.so: $(SOURCES) ndk-home
	cargo  build --target i686-linux-android --release 
	@echo "[DONE] $@"

target/x86_64-linux-android/release/libboltzdart.so: $(SOURCES) ndk-home
	cargo build --target x86_64-linux-android --release
	@echo "[DONE] $@"

.PHONY: ndk-home
ndk-home:
	@if [ ! -d "${ANDROID_NDK_HOME}" ] ; then \
		echo "Error: Please, set the ANDROID_NDK_HOME env variable to point to your NDK folder" ; \
		exit 1 ; \
	fi

## bindings: Generate the .h file for iOS
bindings: target/bindings.h

target/bindings.h: $(SOURCES)
	cbindgen $^ -c cbindgen.toml | grep -v \#include | uniq > $@
	@echo "[DONE] $@"

## :

# ##############################################################################
# # OTHER
# ##############################################################################

## clean:
.PHONY: clean
clean:
	cargo clean
	rm -f target/bindings.h target/bindings.src.h

## test:
.PHONY: test
test:
	cargo test