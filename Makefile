# DO NOT SUBMIT THIS FILE
#
# When submitting your project, this file will be overwritten
# by the automated build and test system.

###
# Variables
# (can be overridden from command-line)

CC = gcc
CLANG_TIDY = clang-tidy
FLAWFINDER = flawfinder
AFL_FUZZ = afl-fuzz
AFL_CC = afl-gcc

SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
TEST_DIR := tests
FUZZ_INPUT_DIR := fuzz-inputs
FUZZ_OUTPUT_DIR := fuzz-outputs
FUZZ_MAIN := $(SRC_DIR)/fuzz_main.c

# The target executable.
# This executable is created by linking together all object files
# obtained from a .c file in the `src` directory; so exactly one
# .c file should contain a `main` function.
# Alternative implementations of main can be wrapped in #ifdefs, as
# long as exactly one is compiled; then they can be selected by
# supplying `-D` flags to `make` and thence to the compiler.
# See e.g. `alternate_main.c`
TARGET = $(BIN_DIR)/app
TEST_TARGET = $(BIN_DIR)/run_tests
FUZZ_TARGET = $(BIN_DIR)/fuzz

SRC_FILES := $(shell find $(SRC_DIR) -name "*.c")
TEST_FILES := $(shell find $(TEST_DIR) -name "*.c")
TEST_SRC_FILES := $(filter-out %_main.c, $(SRC_FILES))
FUZZ_FILES := $(TEST_SRC_FILES)

OBJ_FILES := $(SRC_FILES:.c=.o)
OBJ_FILES := $(subst $(SRC_DIR),$(BUILD_DIR),$(OBJ_FILES))

SRC_DIRS := $(shell find $(SRC_DIR) -type d)
INC_FLAGS := $(addprefix -I, $(SRC_DIRS))

# get compiler flags for installed libraries using pkg-config.
PKG_DEPS := $(shell cat libraries.txt | grep -v '^\#' | xargs)

# Set PKG_CFLAGS to empty if no dependencies are found, otherwise
# use pkg-config to get the compiler flags for the dependencies
PKG_CFLAGS := $(if $(strip $(PKG_DEPS)),$(shell pkg-config --cflags $(PKG_DEPS)))

# Set PKG_LDFLAGS to empty if no dependencies are found, otherwise
# use pkg-config to get the linker flags for the dependencies
PKG_LDFLAGS := $(if $(strip $(PKG_DEPS)),$(shell pkg-config --libs $(PKG_DEPS)))

# You may wish to add additional compiler flags or linker flags here
# (e.g. to change the optimization level, enable sanitizers, etc.)
# This is helpful when testing your code locally, even though we will
# not necessarily use the same flags when testing your code.
DEBUG = -g -fno-omit-frame-pointer
SANFLAGS = -fsanitize=undefined,address
EXTRA_CFLAGS = -pedantic-errors -Werror=implicit-function-declaration -Werror=vla  -Wconversion \
	-fno-common -Wstrict-aliasing -Werror=strict-aliasing -Wformat=2 -Werror=format \
	-Wreturn-type -Werror=return-type
CFLAGS = $(DEBUG) $(EXTRA_CFLAGS) -std=c11 -pedantic-errors -Wall -Wextra $(INC_FLAGS) $(PKG_CFLAGS)
LDFLAGS = $(PKG_LDFLAGS)

###
# Targets

all: $(TARGET)

# Link executable
$(TARGET): $(OBJ_FILES)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(SANFLAGS) $(OBJ_FILES) -o $(TARGET) $(LDFLAGS)

# Compile source files

# c
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(SANFLAGS) $(INC_FLAGS) -MMD -MP -c $< -o $@

# targets for each object file
$(foreach obj_file,$(OBJ_FILES),$(eval $(obj_file):))

# Install dependencies
install-dependencies:
	cat apt-packages.txt | sudo ./scripts/install-deps.sh

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_FILES) $(TEST_SRC_FILES)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(SANFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
	rm -f $(TEST_TARGET)
	rm -f $(FUZZ_TARGET)

tidy:
	@$(foreach src, $(SRC_FILES), \
		echo "Running clang-tidy on $(src)"; \
		$(CLANG_TIDY) $(src) -- $(CFLAGS) -Wno-unknown-warning-option || exit $$?; )

flawfinder:
	$(FLAWFINDER) $(SRC_FILES)

fuzz: $(FUZZ_TARGET)
	$(AFL_FUZZ) -d -i $(FUZZ_INPUT_DIR) -o $(FUZZ_OUTPUT_DIR) -- $(FUZZ_TARGET) @@

$(FUZZ_TARGET): $(FUZZ_FILES) $(FUZZ_MAIN)
	@mkdir -p $(BIN_DIR)
	$(AFL_CC) -O2 $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: all clean

.DELETE_ON_ERROR:

# Include automatically generated dependency files (.d)
-include $(OBJ_FILES:.o=.d)

