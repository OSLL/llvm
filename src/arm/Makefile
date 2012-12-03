 LLVMCFG := llvm-config

CFLAGS  := $(shell $(LLVMCFG) --cxxflags) -O0
LIBS	:= $(shell $(LLVMCFG) --libs)
LDFLAGS := $(shell $(LLVMCFG) --ldflags)

disassembler: disassembler.cpp
#	g++ -pthread -ggdb3 -o $@ $(CFLAGS) $(LDFLAGS) $< $(LIBS) -ldl -lLLVMMSP430AsmPrinter -lLLVMMipsAsmPrinter -lLLVMPowerPCAsmPrinter
	g++ -o $@ $(CFLAGS) $<  $(LIBS) $(LDFLAGS)

