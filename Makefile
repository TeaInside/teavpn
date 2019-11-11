
COMPILER = gcc
LINKER = gcc
NASM_COMPILER = nasm
BIN_FILE = teavpn
LIBS = -lpthread
SOURCE_DIR = src/
ROOT_DEPDIR = .deps
STD_FLAG =
CONSTANTS = 
INCLUDE = -Iinclude/

ifeq (${RELEASE_MODE},1)
	LINKER_FLAGS  = ${STD_FLAG} ${INCLUDE} -Wall -fno-stack-protector -Ofast ${CONSTANTS} -no-pie -o
	COMPILER_FLAGS = ${STD_FLAG} ${INCLUDE} -Wall -fno-stack-protector -Ofast ${CONSTANTS} -c -no-pie -o
	NASM_COMPILE_FLAG = -f elf64 -O3 -o
else
	LINKER_FLAGS  = ${STD_FLAG} ${INCLUDE} -Wall -fstack-protector-strong -ggdb3 -O0 -DTEAVPN_DEBUG ${CONSTANTS} -no-pie -o
	COMPILER_FLAGS = ${STD_FLAG} ${INCLUDE} -Wall -fstack-protector-strong -ggdb3 -O0 -DTEAVPN_DEBUG ${CONSTANTS} -c -no-pie -o
	NASM_COMPILE_FLAG = -f elf64 -O0 -o
endif

SOURCES  = $(shell find ${SOURCE_DIR} -name '*.c')
SOURCES += $(shell find ${SOURCE_DIR} -name '*.cpp')
SOURCES += $(shell find ${SOURCE_DIR} -name '*.S')

NASM_SOURCES  = $(shell find ${SOURCE_DIR} -name '*.asm')
NASM_OBJECTS  = $(NASM_SOURCES:%=%.o)

OBJECTS = $(SOURCES:%=%.o)
SOURCES_DIR = $(shell find ${SOURCE_DIR} -type d)

DEPDIR = ${SOURCES_DIR:%=${ROOT_DEPDIR}/%}
DEPFLAGS = -MT $@ -MMD -MP -MF ${ROOT_DEPDIR}/$*.d
DEPFILES = ${SOURCES:%=${ROOT_DEPDIR}/%.d}

all: ${BIN_FILE}

${ROOT_DEPDIR}:
	mkdir -p $@

${DEPDIR}: | ${ROOT_DEPDIR}
	mkdir -p $@

${OBJECTS}: | ${DEPDIR}
	${COMPILER} ${DEPFLAGS} ${COMPILER_FLAGS} $@ ${@:%.o=%}

${NASM_OBJECTS}:
	${NASM_COMPILER} ${NASM_COMPILE_FLAG} $@ ${@:%.o=%}

${BIN_FILE}: ${OBJECTS} ${NASM_OBJECTS}
	${LINKER} ${LINKER_FLAGS} ${BIN_FILE} ${OBJECTS} ${NASM_OBJECTS} ${LIBS}


-include ${DEPFILES}

release:
	echo ${OBJECTS}
	make clean
	make RELEASE_MODE=1 ${RELEASE_FLAGS} ${MAKE_ARG}
	#strip -s ${BIN_FILE}

clean:
	rm -rf ${DEPFILES}
	rm -rf ${OBJECTS}
	rm -rf ${BIN_FILE}
