#include <deque>
#include <string>

#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/MCInst.h>

// ----------------------------------------------------------------------------

typedef std::deque<llvm::MCInst> InstList;

struct Symbol {
	std::string name;
	InstList insts;

	Symbol(const char* _name)
		: name(_name) { }
};

typedef std::deque<Symbol> SymbolList;

// ----------------------------------------------------------------------------

int disassemble(const char* objname, SymbolList& result);

// ----------------------------------------------------------------------------

extern llvm::MCSubtargetInfo*	STI;
extern llvm::MCRegisterInfo*	MRI;
extern llvm::MCInstrInfo*		MII;
