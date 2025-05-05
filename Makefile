KERNEL_HEADERS := /lib/modules/$(shell uname -r)/build
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')


OBJ_DIR = ./obj
BIN_DIR = ./bin
SRC_DIR = ./src
SKEL_DIR = ./skeleton
INC_DIR = ./include

BPF_SRC_DIR = $(SRC_DIR)/ebpf
BPF_OBJ_DIR = $(OBJ_DIR)/ebpf

USR_SRC_DIR = $(SRC_DIR)/usr
USR_OBJ_DIR = $(OBJ_DIR)/usr

KMOD_DIR = $(SRC_DIR)/kmod

LD_SRC_DIR = $(SRC_DIR)/ld

INCLUDE += \
	-I $(INC_DIR) \
	-I $(SKEL_DIR) 
	# -I $(KERNEL_HEADERS)/include \
	# -I $(KERNEL_HEADERS)/arch/$(ARCH)/include \
	# -I /usr/include/asm-generic 

BPF_SKELETON += \
	kprobe_fsync \
	tracepoint

BPF_SRC += \
	$(BPF_SRC_DIR)/maps.bpf.c \
	$(BPF_SRC_DIR)/kprobe.bpf.c \
	$(BPF_SRC_DIR)/tracepoint.bpf.c \
	$(BPF_SRC_DIR)/lsm.bpf.c

USER_APP_SRC += \
	$(USR_SRC_DIR)/monitor.c \
	$(USR_SRC_DIR)/attach.c \
	$(USR_SRC_DIR)/mktrap.c \
	$(USR_SRC_DIR)/entropy.c -lm

LD_SRC += \
	$(LD_SRC_DIR)/preload.c



CFLAGS += \
	-g \
	-O2 \
	-target bpf \
	-mllvm \
	-bpf-stack-size=1024 \
	-D__TARGET_ARCH_$(ARCH) \



V = 0
ifeq ($(V),1)
	Q =
else
	Q = @
endif

G_S = \033[0;32m
G_L = \033[0m

RUNFILE = monitor_ransomware

TARGET_BPF_OBJ = \
    $(patsubst $(BPF_SRC_DIR)/%.bpf.c, $(BPF_OBJ_DIR)/%.bpf.o, $(BPF_SRC))

TARGET_BPF_SKEL = \
	$(patsubst $(BPF_OBJ_DIR)/%.bpf.o, $(SKEL_DIR)/%.skel.h, $(TARGET_BPF_OBJ))

TARGET_USER_APP = \
	$(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(USER_APP_SRC))

all: runfile

runfile: debug make_setting $(TARGET_BPF_OBJ) $(TARGET_BPF_SKEL) $(TARGET_USER_APP) make_kprobe
	$(Q)clang -o $(RUNFILE) $(INCLUDE) $(TARGET_USER_APP) -lbpf -lelf 
	$(info [ $(shell echo "$(G_S)OK$(G_L)") ] : Build $(RUNFILE) )

# Build BPF code
$(BPF_OBJ_DIR)/%.bpf.o: $(BPF_SRC_DIR)/%.bpf.c
	$(Q)clang $(INCLUDE) $(CFLAGS) \
		-c $< -o $@
	$(info [ $(shell echo "$(G_S)OK$(G_L)") ] : Compile $< -> $@)

# Generate BPF skeletons
$(SKEL_DIR)/%.skel.h: $(BPF_OBJ_DIR)/%.bpf.o
	$(Q)bpftool gen skeleton $< > $@
	$(info [ $(shell echo "$(G_S)OK$(G_L)") ] : Generate $@)

$(USR_OBJ_DIR)/%.o: $(USR_SRC_DIR)/%.c
	$(Q)clang -c $< -o $@  $(INCLUDE)
	$(info [ $(shell echo "$(G_S)OK$(G_L)") ] : Compile $< -> $@ )



debug:       
	$(info )
	$(info -----[DEBUG]-----)
	$(info BPF_SRC_DIR = $(BPF_SRC_DIR))
	$(info TARGET_BPF_OBJ = $(TARGET_BPF_OBJ))
	$(info TARGET_BPF_SKEL = $(TARGET_BPF_SKEL))
	$(info TARGET_USER_APP = $(TARGET_USER_APP))
	$(info -----[DEBUG DONE]----- )

make_setting:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BPF_OBJ_DIR)
	@mkdir -p $(USR_OBJ_DIR)
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(SKEL_DIR)
	$(info [ $(shell echo "$(G_S)OK$(G_L)") ] : Make Directory )


obj-m += $(KMOD_DIR)/kprb_dents.o

KDIR := /lib/modules/$(shell uname -r)/build

CCV = x86_64-linux-gnu-gcc-13

make_kprobe: make_ld_preload
	make -C $(KDIR) M=$(PWD) CC=$(CCV) modules


make_ld_preload:
	gcc -shared -fPIC -o $(LD_SRC_DIR)/preload.so $(LD_SRC_DIR)/preload.c -ldl

clean: clean_kprobe
	@rm -rf $(BIN_DIR)
	@rm -rf $(OBJ_DIR)
	@rm -rf $(SKEL_DIR)
	@rm -f $(RUNFILE)
	$(info [ $(shell echo "$(G_S)OK$(G_L)") ]: Clean)


clean_kprobe: clean_ld_preload
	$(shell rmmod --force ./src/kmod/kprb_dents.ko)
	make -C $(KDIR) M=$(PWD) CC=$(CCV) clean

clean_ld_preload:
	@rm -rf $(LD_SRC_DIR)/preload.so