# Makefile for musashi

BUILD_DIR = build
GEN_DIR = gen
DIST_DIR = dist

CFLAGS    = -D_CRT_SECURE_NO_WARNINGS /Ox

GEN_INPUT = musashi\m68k_in.c

GEN_SRC = $(GEN_DIR)\m68kopdm.c $(GEN_DIR)\m68kopnz.c $(GEN_DIR)\m68kops.c
GEN_HDR = $(GEN_DIR)\m68kops.h
GEN_FILES = $(GEN_SRC) $(GEN_HDR)

GEN_TOOL_SRC = musashi\m68kmake.c
GEN_TOOL = m68kmake

PYTHON = python
#PYTHON = python-dbg

.PHONY: all clean_gen clean_gen clean_all
.PHONY: do_gen do_build_inplace do_test do_dev do_install

do_build_inplace: do_gen
	$(PYTHON) setup.py build_ext -i

do_test: do_gen
	$(PYTHON) setup.py test

do_install: do_gen
	$(PYTHON) setup.py install

do_dev: do_gen
	$(PYTHON) setup.py develop --user

clean: clean_gen
	rmdir /S $(BUILD_DIR)

clean_all: clean
	rmdir /S $(DIST_DIR)

do_gen: $(BUILD_DIR)\$(GEN_TOOL) $(GEN_DIR) $(GEN_FILES)

$(BUILD_DIR)\$(GEN_TOOL): $(BUILD_DIR) $(GEN_TOOL_SRC)
	CL $(CFLAGS) /Fo$@ /Fe$@ $(GEN_TOOL_SRC)

$(BUILD_DIR):
	mkdir $(BUILD_DIR)

$(GEN_DIR):
	mkdir $(GEN_DIR)

$(GEN_FILES): $(BUILD_DIR)\$(GEN_TOOL) $(GEN_DIR) $(GEN_INPUT)
	$(BUILD_DIR)\$(GEN_TOOL) gen $(GEN_INPUT)

clean_gen:
	rmdir /S $(GEN_DIR)

