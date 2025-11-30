CC     ?= cc
CFLAGS += -O3 -Wall -Wextra -Werror=pedantic -Werror=vla -Iinclude
LDFLAGS ?=

HDR := $(wildcard src/*.h)
SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)


SHADER_COMMON := common.comp keygen_common.comp signing_common.comp
SHADER_MAIN   := signing_wots_tips_precompute.comp signing_xmss_leaves_precompute.comp \
                 signing_xmss_merkle_sign.comp signing_fors_leaves_gen.comp \
                 signing_fors_merkle_sign.comp signing_wots_sign.comp keygen_wots_tips.comp \
                 keygen_xmss_leaves.comp keygen_xmss_roots.comp verify.comp

SHADER_DIR    := src/shaders
SHADER_COMMON := $(addprefix $(SHADER_DIR)/,$(SHADER_COMMON))
SHADER_MAIN   := $(addprefix $(SHADER_DIR)/,$(SHADER_MAIN))

SPV        := $(SHADER_MAIN:.comp=.spv)
SHADER_HDR := $(SHADER_MAIN:.comp=.h)

# shader targets
GLSLC ?= glslangValidator

# glslangValidator prints file names when compiling unless we give it the --quiet flag.
ifeq ($(GLSLC), glslangValidator)
	GLSLCFLAGS += --quiet --target-env vulkan1.2
else ifeq ($(GLSLC), glslc)
	GLSLCFLAGS += --target-env=vulkan1.2
endif


# SLH-DSA code target
lib/libslhvk.a: $(OBJ)
	@mkdir -p lib
	ar rcs -o $@ $(OBJ)

%.o: %.c $(HDR) $(SHADER_HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

%.spv: %.comp $(SHADER_COMMON)
	$(GLSLC) $(GLSLCFLAGS) -o $@ $<

$(SHADER_DIR)/%.h: $(SHADER_DIR)/%.spv
	cd $(SHADER_DIR) && xxd -i $*.spv $*.h

# This is needed to tell make that the shader header files are targets to be built.
$(SHADER_HDR):


TEST_RUNNER     := tests/runner
TEST_RUNNER_SRC := $(TEST_RUNNER).c
UNIT_TEST_SRC   := $(wildcard tests/bin/unit/*.c)
UNIT_TEST_BIN   := $(UNIT_TEST_SRC:.c=.test)
BENCH_TEST_SRC  := $(wildcard tests/bin/bench/*.c)
BENCH_TEST_BIN  := $(BENCH_TEST_SRC:.c=.test)
TEST_VENDOR_SRC := tests/vendor/cJSON.c
TEST_VENDOR_OBJ := $(TEST_VENDOR_SRC:.c=.o)
TEST_HDR        := tests/utils.h tests/acvp.h
TEST_CFLAGS     := $(CFLAGS) -Llib
TEST_VEC_DIR    := tests/vectors

.PHONY: build-tests
build-tests: $(UNIT_TEST_BIN) $(BENCH_TEST_BIN) $(TEST_RUNNER)

%.test: %.c $(TEST_HDR) $(HDR) lib/libslhvk.a $(TEST_VENDOR_OBJ)
	$(CC) $(TEST_CFLAGS) $(LDFLAGS) -o $@ $< $(TEST_VENDOR_OBJ) -lslhvk -lvulkan

# Build test binaries
$(UNIT_TEST_BIN):
$(BENCH_TEST_BIN):

# build libcjson object (and don't rebuild it unnecessarily)
tests/vendor/cJSON.o: tests/vendor/cJSON.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(TEST_RUNNER): $(TEST_RUNNER_SRC) $(TEST_HDR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

.PHONY: unit-san
unit-san: CFLAGS += -fsanitize=address,undefined,leak -fno-omit-frame-pointer
unit-san: LDFLAGS += -fsanitize=address,undefined,leak
unit-san: clean build-tests
	./$(TEST_RUNNER) tests/bin/unit

.PHONY: build-tests-san
build-tests-san: CFLAGS += -fsanitize=address,undefined,leak -fno-omit-frame-pointer
build-tests-san: LDFLAGS += -fsanitize=address,undefined,leak
build-tests-san: clean build-tests

.PHONY: test
test: $(TEST_RUNNER) $(UNIT_TEST_BIN) $(TEST_VEC_DIR) $(BENCH_TEST_BIN)
	./$(TEST_RUNNER) tests/bin/unit tests/bin/bench

.PHONY: unit
unit: $(TEST_RUNNER) $(UNIT_TEST_BIN) $(TEST_VEC_DIR)
	./$(TEST_RUNNER) tests/bin/unit

.PHONY: bench
bench: $(TEST_RUNNER) $(BENCH_TEST_BIN)
	./$(TEST_RUNNER) tests/bin/bench

$(TEST_VEC_DIR):
	./download_test_vectors.py

BUILD_OUTPUTS := $(OBJ) $(TEST_VENDOR_OBJ) lib $(SHADER_DIR)/*.h $(SHADER_DIR)/*.spv \
                 tests/bin/*/*.test $(TEST_RUNNER)

.PHONY: clean
clean:
	rm -rf $(BUILD_OUTPUTS)
