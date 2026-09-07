# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

# change the following path to the root directory of bpftime
BPFTROOT := path/to/bpftime

OUTPUT := .output
CLANG ?= clang
CC ?= gcc

LIBBPF_SRC := $(abspath $(BPFTROOT)/third_party/libbpf/src)
BPFTOOL_SRC := $(abspath $(BPFTROOT)/third_party/bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
	| sed 's/arm.*/arm/' \
	| sed 's/aarch64/arm64/' \
	| sed 's/ppc64le/powerpc/' \
	| sed 's/mips.*/mips/' \
	| sed 's/riscv64/riscv/' \
	| sed 's/loongarch64/loongarch/')

VMLINUX := $(abspath $(BPFTROOT)/third_party/vmlinux/$(ARCH)/vmlinux.h)

INCLUDES := -I$(OUTPUT) -I$(BPFTROOT)third_party/libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' "$(1)" "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))" "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all clean
all: uprobe post

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build BPF object for uprobe
$(OUTPUT)/uprobe.bpf.o: uprobe.bpf.c uprobe.h $(LIBBPF_OBJ) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -Xlinker --export-dynamic -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-c $< -o $(OUTPUT)/uprobe.tmp.bpf.o
	$(Q)$(BPFTOOL) gen object $@ $(OUTPUT)/uprobe.tmp.bpf.o

# Generate skeleton
$(OUTPUT)/uprobe.skel.h: $(OUTPUT)/uprobe.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build uprobe userspace object
$(OUTPUT)/uprobe.o: uprobe.c uprobe.h $(OUTPUT)/uprobe.skel.h | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Build uprobe executable
uprobe: $(OUTPUT)/uprobe.o $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

# Build post with no flags
post: post.c
	$(Q)gcc post.c -o post

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) uprobe post

.DELETE_ON_ERROR:
.SECONDARY:
