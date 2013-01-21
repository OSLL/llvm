LLVMCFG := llvm-config-3.1

CFLAGS  := $(shell $(LLVMCFG) --cxxflags) -O0
LIBS	:= $(shell $(LLVMCFG) --libs)
LDFLAGS := $(shell $(LLVMCFG) --ldflags)

all: llvm-analyze

%: %.cpp
	g++ -pthread -std=c++0x -ggdb3 -o $@ $(CFLAGS) $< $(LIBS) $(LDFLAGS)

test: llvm-analyze
	make -C ../../../test

clean:
	rm llvm-analyze

.PHONY: test clean
