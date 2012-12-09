LLVMCFG := llvm-config-3.1

CFLAGS  := $(shell $(LLVMCFG) --cxxflags) -O0
LIBS	:= $(shell $(LLVMCFG) --libs)
LDFLAGS := $(shell $(LLVMCFG) --ldflags)

all: llvm-disasm llvm-analyze

%: %.cpp
	g++ -pthread -ggdb3 -o $@ $(CFLAGS) $< $(LIBS) $(LDFLAGS) 

clean:
	rm llvm-disasm
