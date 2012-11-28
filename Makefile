LLVMCFG := llvm-config-3.1

CFLAGS  := $(shell $(LLVMCFG) --cxxflags) -O0
LIBS	:= $(shell $(LLVMCFG) --libs)
LDFLAGS := $(shell $(LLVMCFG) --ldflags)

llvm-disasm: llvm-disasm.cpp
#	g++ -pthread -ggdb3 -o $@ $(CFLAGS) $(LDFLAGS) $< $(LIBS) -ldl -lLLVMMSP430AsmPrinter -lLLVMMipsAsmPrinter -lLLVMPowerPCAsmPrinter
	g++ -pthread -ggdb3 -o $@ $(CFLAGS) $< $(LDFLAGS) $(LIBS)

clean:
	rm llvm-disasm
