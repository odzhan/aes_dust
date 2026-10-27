# Convenience Makefile that wraps common CMake workflows.

.DEFAULT_GOAL := build

# Configurable variables (override like: make BUILD_TYPE=Debug)
BUILD_DIR ?= build
BUILD_TYPE ?= Release
GEN ?=
PREFIX ?= $(CURDIR)/dist

# Feature toggles (ON/OFF)
WERROR ?= OFF
BUILD_TESTING ?= ON
SHARED ?= OFF

CMAKE ?= cmake
CTEST ?= ctest

GEN_OPT := $(if $(GEN),-G "$(GEN)",)

CMAKE_FLAGS := \
  -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
  -DAES_DUST_ENABLE_WERROR=$(WERROR) \
  -DBUILD_TESTING=$(BUILD_TESTING) \
  -DBUILD_SHARED_LIBS=$(SHARED)

.PHONY: help all configure build test install clean distclean

help:
	@echo "Targets:"
	@echo "  make [build]          - Configure and build ($(BUILD_TYPE)) into $(BUILD_DIR)"
	@echo "  make all              - Alias for build"
	@echo "  make configure        - Run the CMake configure step"
	@echo "  make test             - Run ctest from $(BUILD_DIR)"
	@echo "  make install          - Install to PREFIX=$(PREFIX)"
	@echo "  make clean            - Clean via the generated build tool"
	@echo "  make distclean        - Remove $(BUILD_DIR) only"
	@echo ""
	@echo "Variables:"
	@echo "  BUILD_TYPE  (Release|Debug|RelWithDebInfo|MinSizeRel)"
	@echo "  BUILD_DIR   (default: build)"
	@echo "  GEN         (e.g. \"Ninja\" or \"Unix Makefiles\")"
	@echo "  WERROR      (ON|OFF, default: OFF)"
	@echo "  BUILD_TESTING (ON|OFF, default: ON)"
	@echo "  SHARED      (ON|OFF, default: OFF)"
	@echo "  PREFIX      (install prefix, default: $(PREFIX))"

all: build

configure:
	$(CMAKE) -S . -B "$(BUILD_DIR)" $(GEN_OPT) $(CMAKE_FLAGS)

build: configure
	$(CMAKE) --build "$(BUILD_DIR)" --config $(BUILD_TYPE) --parallel

test: build
	$(CMAKE) -E chdir "$(BUILD_DIR)" $(CTEST) -C $(BUILD_TYPE) --output-on-failure

install: build
	$(CMAKE) --install "$(BUILD_DIR)" --config $(BUILD_TYPE) --prefix "$(PREFIX)"

clean:
	-$(CMAKE) --build "$(BUILD_DIR)" --target clean --config $(BUILD_TYPE)

distclean:
	$(CMAKE) -E remove_directory "$(BUILD_DIR)"

