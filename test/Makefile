LLVM-VER ?= -3.1
LLVM-AS  := llvm-as$(LLVM-VER)
LLVM-LD  := llvm-ld$(LLVM-VER) -native
GEN-BC   := clang -c -flto 
GEN-O    := gcc -c -O1

CASES := matrix

REFS  := $(patsubst %,ref_%,$(CASES))
TESTS := $(patsubst %,test_%,$(CASES))
DOITS := $(patsubst %,do_%,$(CASES))

ANALYZER := ../src/x86/analyzer/llvm-analyze


.SECONDARY:

all: $(ANALYZER) $(DOITS)

%.llbc: %.c
	$(GEN-BC) -o $@ $<

ref_%.llbc: %.c
	$(GEN-BC) -o $@ $<

%.o: %.c
	$(GEN-O) -o $@ $<

test_%.ll: %.o
	$(ANALYZER) $< $@

test_%.llbc: test_%.ll
	$(LLVM-AS) -o $@ $<

ref_%: ref_%.llbc main-%.llbc
	$(LLVM-LD) -o $@ $^
	rm $@.bc

test_%: test_%.llbc main-%.llbc
	$(LLVM-LD) -o $@ $^
	rm $@.bc

do_%: ref_% test_%
	./do_test $^

$(ANALYZER):
	make -C $(shell dirname $@) $(shell basename $@)

clean:
	rm -f *.ll *.llbc *.o
	rm $(REFS) $(TESTS)

.PHONY: all clean

.SUFFIXES:
