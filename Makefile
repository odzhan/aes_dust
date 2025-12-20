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

CONFIG_CACHE := $(BUILD_DIR)/CMakeCache.txt
GEN_OPT := $(if $(GEN),-G "$(GEN)",)

CMAKE_FLAGS := \
  -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
  -DAES_DUST_ENABLE_WERROR=$(WERROR) \
  -DBUILD_TESTING=$(BUILD_TESTING) \
  -DBUILD_SHARED_LIBS=$(SHARED)

.PHONY: help all configure build test install clean distclean \
        preset-release preset-debug preset-vs2022 \
        build-release build-debug build-vs2022 \
        test-release test-debug compact

help:
	@echo "Targets:"
	@echo "  make [build]          - Configure and build ($(BUILD_TYPE)) into $(BUILD_DIR)"
	@echo "  make all              - Alias for build"
	@echo "  make configure        - Run the CMake configure step"
	@echo "  make test             - Run ctest from $(BUILD_DIR)"
	@echo "  make install          - Install to PREFIX=$(PREFIX)"
	@echo "  make clean            - Clean via the generated build tool"
	@echo "  make distclean        - Remove $(BUILD_DIR) and the install tree"
	@echo ""
	@echo "Preset shortcuts (require CMakePresets.json):"
	@echo "  make preset-release   - cmake --preset ninja-release"
	@echo "  make build-release    - cmake --build --preset build-release"
	@echo "  make test-release     - ctest --preset test-release"
	@echo "  make preset-debug     - cmake --preset ninja-debug"
	@echo "  make build-debug      - cmake --build --preset build-debug"
	@echo "  make test-debug       - ctest --preset test-debug"
	@echo "  make preset-vs2022    - cmake --preset vs2022"
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

$(CONFIG_CACHE): CMakeLists.txt
	$(CMAKE) -S . -B $(BUILD_DIR) $(GEN_OPT) $(CMAKE_FLAGS)

configure: $(CONFIG_CACHE)
	@echo "CMake configure step complete (cache: $(CONFIG_CACHE))"

build: $(CONFIG_CACHE)
	$(CMAKE) --build $(BUILD_DIR) --config $(BUILD_TYPE) --parallel

test: build
	$(CTEST) --test-dir $(BUILD_DIR) -C $(BUILD_TYPE) --output-on-failure

install: build
	$(CMAKE) --install $(BUILD_DIR) --prefix "$(PREFIX)"

clean:
	-$(CMAKE) --build $(BUILD_DIR) --target clean --config $(BUILD_TYPE)

distclean:
	$(CMAKE) -E rm -rf "$(BUILD_DIR)" "$(PREFIX)"

preset-release:
	$(CMAKE) --preset ninja-release

build-release:
	$(CMAKE) --build --preset build-release --parallel

test-release:
	$(CTEST) --preset test-release --output-on-failure

preset-debug:
	$(CMAKE) --preset ninja-debug

build-debug:
	$(CMAKE) --build --preset build-debug --parallel

test-debug:
	$(CTEST) --preset test-debug --output-on-failure

preset-vs2022:
	$(CMAKE) --preset vs2022

compact:
	$(MAKE) -C src/compact
