CC     ?= cc
CFLAGS += -O3 -Wall -Wextra -Werror=pedantic -Werror=vla -Iinclude

HDR := $(wildcard src/*.h)
SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)


SHADER_COMMON := common.comp signing_common.comp
SHADER_MAIN   := wots_tips_precompute.comp xmss_leaves_precompute.comp xmss_merkle_sign.comp
SHADER_MAIN   += fors_leaves_gen.comp fors_merkle_sign.comp wots_sign.comp
SHADER_MAIN   += keygen_wots_tips.comp keygen_xmss_leaves.comp keygen_xmss_roots.comp

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
TEST_SRC        := $(wildcard tests/bin/*.c)
TEST_BIN        := $(TEST_SRC:.c=.test)
TEST_VENDOR_SRC := tests/vendor/cJSON.c
TEST_VENDOR_OBJ := $(TEST_VENDOR_SRC:.c=.o)
TEST_HDR        := tests/utils.h tests/acvp.h
TEST_CFLAGS     := $(CFLAGS) -Isrc -Llib
TEST_VEC_DIR    := tests/vectors

%.test: %.c $(TEST_HDR) $(HDR) lib/libslhvk.a $(TEST_VENDOR_OBJ)
	$(CC) $(TEST_CFLAGS) -o $@ $< $(TEST_VENDOR_OBJ) -lslhvk -lvulkan

# Build test binaries
$(TEST_BIN):

$(TEST_RUNNER): $(TEST_RUNNER_SRC) $(TEST_HDR)
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: test
test: $(TEST_RUNNER) $(TEST_BIN) $(TEST_VEC_DIR)
	./$(TEST_RUNNER)

$(TEST_VEC_DIR):
	./download_test_vectors.py

.PHONY: clean
clean:
	rm -rf $(OBJ) lib $(SHADER_DIR)/*.h $(SHADER_DIR)/*.spv tests/bin/*.test $(TEST_RUNNER) $(TEST_VEC_DIR)
