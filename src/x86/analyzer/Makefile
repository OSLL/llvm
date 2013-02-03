LLVMCFG := llvm-config-3.1

CFLAGS  := $(shell $(LLVMCFG) --cxxflags) -O0
LIBS	:= $(shell $(LLVMCFG) --libs)
LDFLAGS := $(shell $(LLVMCFG) --ldflags)

CXXOBJ	:= disasm.o disasm_wrap.o
MLOBJ	:= analyze.cma test.cmxo

ALL		:= $(CXXOBJ) $(MLOBJ) llvm-analyze

all: $(ALL)
#all: llvm-analyze

%.o: %.cpp
	g++ -c -pthread -std=c++0x -ggdb3 -o $@ $(CFLAGS) $<

%_wrap.o: %_wrap.cpp
	ocamlc -c -cc "g++ $(CFLAGS)" -o $@ $<

dll_%_wrap.so: %_wrap.o %.o
	ocamlmklib -o $(patsubst dll%.so,%,$@) $^ $(LIBS) -lstdc++ $(LDFLAGS)

%.mli: %.ml
	ocamlc -i $< > $@

%.cmi: %.mli
	ocamlc -c -o $@ $<

%.cmo: %.ml
	ocamlc -c -o $@ $<

test.cmxo: test.cmo analyze.cma
	ocamlc -dllpath . -o $@ $< analyze.cma

analyze.cma: analyze.cmo dll_disasm_wrap.so
	ocamlc -a -o $@ $< -dllib -l_disasm_wrap

test: llvm-analyze
	make -C ../../../test

llvm-analyze: llvm-analyze.o
	g++ -o $@ $< $(LIBS) $(LDFLAGS)

clean:
	rm -f $(ALL)
	rm -f *.mli
	rm -f *.cm*
	rm -f *.so
	rm -f *.a
	rm -f *.o

.PHONY: test clean
