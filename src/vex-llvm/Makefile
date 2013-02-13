include config.mk

CFLAGS  = $(shell llvm-config-3.1 --cxxflags) -O0
LIBS	= $(shell llvm-config-3.1 --libs)
LDFLAGS = $(shell llvm-config-3.1 --ldflags)

CFLAGS  += -I$(LIBVEX_INSTALL_PATH)/include/valgrind
LDFLAGS += -L$(LIBVEX_INSTALL_PATH)/lib/valgrind -lvex-amd64-linux

ANALYZER = vex-llvm

all: $(ANALYZER)

%: %.cpp
	g++ -pthread -ggdb3 -std=c++0x -o $@ $(CFLAGS) $< $(LIBS) $(LDFLAGS)

test: $(ANALYZER)
	make -C ../../test ANALYZER=$(shell pwd)/$(ANALYZER)

clean:
	rm -f $(ANALYZER)

.PHONY: test clean
