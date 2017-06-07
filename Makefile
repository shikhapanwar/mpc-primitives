
BIN=bin
SRC=primitives

# compiler settings
CC=g++
#COMPILER_OPTIONS=-O2
COMPILER_OPTIONS= -std=c++11#-fPIC -mavx -maes -mpclmul -DRDTSC -DTEST=AES128

DEBUG_OPTIONS=-g3 -ggdb #-Wall -Wextra 

BATCH=

ARCHITECTURE = $(shell uname -m)
ifeq (${ARCHITECTURE},x86_64)
MIRACL_MAKE:=linux64
GNU_LIB_PATH:=x86_64
else
MIRACL_MAKE:=linux
GNU_LIB_PATH:=i386
endif

INCLUDE=#-I..  -I/usr/include/glib-2.0/ -I/usr/lib/${GNU_LIB_PATH}-linux-gnu/glib-2.0/include `pkg-config --cflags glib-2.0`


LIBRARIES=-lgmp -lgmpxx -lpthread  -L /usr/lib  -lssl -lcrypto #-lglib-2.0 `pkg-config --libs glib-2.0`
CFLAGS= -lboost_system -lboost_filesystem

# all source files and corresponding object files 
SOURCES_CORE := $(shell find ${CORE} -type f -name '*.cpp' -not -path '*/Miracl/*')
OBJECTS_CORE := $(SOURCES_CORE:.cpp=.o)
# directory for primitives src
SOURCES_PRIM=${SRC}/src/*.cpp
OBJECTS_PRIM=${SRC}/src/*.o
# directory for Utils
SOURCES_UTIL=${SRC}/utils/*.cpp
OBJECTS_UTIL=${SRC}/utils/*.o
# directory for the Miracl submodule and library
MIRACL_LIB_DIR=${SRC}/externals/miracl_lib
SOURCES_MIRACL=${SRC}/externals/Miracl/*
OBJECTS_MIRACL=${MIRACL_LIB_DIR}/*.o
MIRACL_LIB=${SRC}/externals/miracl_lib/miracl.a


all: miracl core bench
	@echo "make all done."


core:${OBJECTS_CORE}

%.o:%.cpp
	${CC} -c $< ${COMPILER_OPTIONS} ${CFLAGS} ${DEBUG_OPTIONS} ${LIBRARIES}-o $@

bench:  
	${CC} -o test.exe test.cpp ${OBJECTS_PRIM} ${OBJECTS_MIRACL} ${CFLAGS} ${DEBUG_OPTIONS} ${LIBRARIES} ${MIRACL_LIB} ${INCLUDE} ${COMPILER_OPTIONS} ${OBJECTS_UTIL}


# this will create a copy of the files in ${SOURCES_MIRACL} and its sub-directories and put them into ${MIRACL_LIB_DIR} without sub-directories, then compile it
miracl:	${MIRACL_LIB_DIR}/miracl.a

# copy Miracl files to a new directory ($Primitives/miracl_lib/), call the build script and delete everything except the archive, header and object files.
${MIRACL_LIB_DIR}/miracl.a: ${SOURCES_MIRACL}
	@find ${SRC}/externals/Miracl/ -type f -exec cp '{}' ${SRC}/externals/miracl_lib \;
	@cd ${SRC}/externals/miracl_lib/; bash ${MIRACL_MAKE}; find . -type f -not -name '*.a' -not -name '*.h' -not -name '*.o' -not -name '.git*'| xargs rm

# only clean example objects, test object and binaries
clean:
	rm -f *.exe ${OBJECTS_UTIL} ${OBJECTS_PRIM}

# this will clean everything: example objects, test object and binaries and the Miracl library
cleanall: clean
	rm -f ${OBJECTS_MIRACL} ${MIRACL_LIB_DIR}/*.a
