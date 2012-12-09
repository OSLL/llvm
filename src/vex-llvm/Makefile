CFLAGS  = $(shell llvm-config-3.1 --cxxflags)	$(shell pkg-config --cflags valgrind) -O0
LIBS	= $(shell llvm-config-3.1 --libs)
LDFLAGS = $(shell llvm-config-3.1 --ldflags)

LDFLAGS += -L/home/alex/stud/phd/install/lib/valgrind -lvex-amd64-linux

all: vex-llvm

%: %.cpp
	g++ -pthread -ggdb3 -std=c++0x -o $@ $(CFLAGS) $< $(LIBS) $(LDFLAGS)

clean:
	rm llvm-vex
