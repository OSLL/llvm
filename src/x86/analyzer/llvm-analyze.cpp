#include <elf.h>

#include <cstdio>
#include <cstring>
#include <cctype>

#include <string>
#include <deque>
#include <set>

#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/MemoryObject.h>
#include "llvm/Support/DataTypes.h"
#include <llvm/ADT/StringRef.h>
#include <llvm/ADT/OwningPtr.h>
#include <llvm/ADT/Triple.h>
#include <llvm/MC/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/MCExpr.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/system_error.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/Casting.h>

// ----------------------------------------------------------------------------

struct LinearBlock {
	uint64_t begin, end;

	LinearBlock(uint64_t _begin, uint64_t _end) :
		begin(_begin),
		end(_end) { }
};

// ----------------------------------------------------------------------------

static llvm::MCSubtargetInfo*	sti;
static llvm::MCDisassembler*	disasm;
static llvm::MCRegisterInfo*	mri;
static llvm::MCInstrInfo*		mii;

// ----------------------------------------------------------------------------

class StringRefMemoryObject : public llvm::MemoryObject {
	llvm::StringRef Bytes;

public:
	StringRefMemoryObject(llvm::StringRef bytes) : Bytes(bytes) {}

	uint64_t getBase() const { return 0; }
	uint64_t getExtent() const { return Bytes.size(); }

	int readByte(uint64_t Addr, uint8_t *Byte) const {
		if (Addr >= getExtent())
		 return -1;
		*Byte = Bytes[Addr];
		return 0;
	}
};

// ----------------------------------------------------------------------------

static void printInst(const llvm::MCInst& inst) {
	const llvm::MCInstrDesc& id = mii->get(inst.getOpcode());
	llvm::outs() << mii->getName(inst.getOpcode()) << " (" << inst.getNumOperands() << ") ";

	for (int iop = 0; iop < inst.getNumOperands(); ++iop) {
		const llvm::MCOperand& op = inst.getOperand(iop);

		if (op.isReg()) {
			unsigned reg = op.getReg();
			const char* rcName;
			char clsn[128];

			if (id.OpInfo[iop].RegClass < mri->getNumRegClasses()) {
				const llvm::MCRegisterClass& rc = mri->getRegClass(id.OpInfo[iop].RegClass);
				rcName = rc.getName();
			} else {
				snprintf(clsn, sizeof(clsn), "CLS%d", id.OpInfo[iop].RegClass);
				rcName = clsn;
			}
			llvm::outs() << mri->getName(reg) << "(" << rcName << ", " << (uint64_t)id.OpInfo[iop].OperandType << ")";
		} else if (op.isImm()) {
			llvm::outs() << op.getImm() << "(" << (uint64_t)id.OpInfo[iop].OperandType << ")";
		} else {
			llvm::outs() << "<UNK>";
		}

		llvm::outs() << ", ";
	}

	llvm::outs() << "\n";
}

static void disassembleLinearBlock(	const llvm::MemoryObject& data, 
									uint64_t start, uint64_t end,
									std::deque<llvm::MCInst>& result) {

	uint64_t ptr = start;
	uint64_t instSize;	

	for (;;) {
		llvm::MCInst inst;

		if (ptr < start || ptr >= end) {
			break;
		}

		if (disasm->getInstruction(inst, instSize, data, ptr, llvm::nulls(), llvm::nulls()) != llvm::MCDisassembler::Success) {
			llvm::errs() << "failed to disassemble at " << ptr << "\n";
			break;
		}

		ptr += instSize;

		result.push_back(inst);
		const llvm::MCInstrDesc& id = mii->get(inst.getOpcode());

		if (id.isUnconditionalBranch() || id.isConditionalBranch())
			break;
	}
}

static int disassembleSymbol(	const llvm::object::SymbolRef& sym,
								std::deque<llvm::MCInst>& result) {

	llvm::StringRef secName, symName, contents;
	uint64_t secBase, secSize, symAddr, symSize, symEnd, ptr;
	llvm::object::section_iterator isec = llvm::object::section_iterator(llvm::object::SectionRef());
	llvm::error_code ec;

	sym.getSection(isec);
	const llvm::object::SectionRef& sec = *isec;
	
	sec.getName(secName);	
	sym.getName(symName);

	llvm::outs() << "Disassembling the symbol " << symName << "\n";

	if (sec.getContents(contents)) {
		llvm::errs() << secName << ": failed to get the section contents\n";
		return 1;
	}

	if (sec.getAddress(secBase)) {
		llvm::errs() << secName << ": failed to get the section contents\n";
		return 1;
	}

	if (sec.getSize(secSize)) {
		llvm::errs() << secName << ": failed to get the section size\n";
		return 1;
	}

	if (sym.getAddress(symAddr)) {
		llvm::errs() << secName << ": " << symName << ": failed to get the symbol address\n";
		return 1;
	}

	if (sym.getSize(symSize)) {
		llvm::errs() << secName << ": " << symName << ": failed to get the symbol size\n";
		return 1;
	}

	StringRefMemoryObject moContents(contents);
	symAddr -= secBase;
	symEnd = symAddr + symSize;
	ptr = symAddr;

	disassembleLinearBlock(moContents, symAddr, symEnd, result);

	return 0;
}


static void analyzeStackReferences(std::deque<llvm::MCInst>& block) {

	typedef std::deque<llvm::MCInst>::iterator InstIter;

	for (InstIter it = block.begin(); it != block.end(); ++it) {
		llvm::MCInst& inst = *it;
		const llvm::MCInstrDesc& id = mii->get(inst.getOpcode());
		llvm::StringRef iname = mii->getName(inst.getOpcode());

		for (unsigned iop = 0; iop < inst.getNumOperands(); ++iop) {
			if (id.OpInfo[iop].OperandType == llvm::MCOI::OPERAND_MEMORY) {
				const llvm::MCOperand& op = inst.getOperand(iop);

				if (op.isReg() && strcmp(mri->getName(op.getReg()), "RBP") == 0)
					printInst(inst);

				iop += 5;
				break;
			}
		}
	}
}

static int analyzeSymbol(const llvm::object::SymbolRef& sym) {
	std::deque<llvm::MCInst> block;

	disassembleSymbol(sym, block);
	analyzeStackReferences(block);	
}

// ----------------------------------------------------------------------------

int main(int argc, char** argv) {
	llvm::llvm_shutdown_obj Y;
	llvm::error_code ec;
	std::string se;
	std::string file;

	if (argc < 2) {
		llvm::errs() << "Usage llvm-disasm <file>\n";
		return 1;
	}

	llvm::InitializeAllTargetInfos();
	llvm::InitializeAllTargetMCs();
	llvm::InitializeAllAsmParsers();
	llvm::InitializeAllDisassemblers();

	file = argv[1];

	llvm::OwningPtr<llvm::object::Binary> bin;
	ec = llvm::object::createBinary(file, bin);
	if (ec) {
		llvm::errs() << file << ": " << ec.message() << "\n";
		return 1;
	}

	if (!bin->isELF()) {
		llvm::errs() << file << " isn't an object file\n";
		return 1;
	}

	llvm::object::ObjectFile* obj = llvm::dyn_cast<llvm::object::ObjectFile>(bin.get());
	if (!obj) {
		llvm::errs() << file << ": failed to cast to llvm::ObjectFile\n";
		return 1;
	}

	llvm::Triple tri;
	tri.setArch(llvm::Triple::ArchType(obj->getArch()));
	std::string targetName = tri.str();
	const llvm::Target* target = llvm::TargetRegistry::lookupTarget(targetName, se);
	if (!target) {
		llvm::errs() << file << ": failed to get the target descriptor for " << targetName << "\n";
		return 1;
	}

	sti = target->createMCSubtargetInfo(targetName, "", "");
	if (!sti) {
		llvm::errs() << file << ": " << ": to get the subtarget info!\n";
		return 1;
	}

	disasm = target->createMCDisassembler(*sti);
	if (!disasm) {
		llvm::errs() << file << ": " << ": to get the disassembler!\n";
		return 1;
	}

	mii = target->createMCInstrInfo();
    if (!mii) {
		llvm::errs() << file << ": no instruction info for target\n";
		return 1;
    }

	mri = target->createMCRegInfo(targetName);
    if (!mri) {
		llvm::errs() << file << ": no register info for target\n";
		return 1;
    }

	for (llvm::object::section_iterator i = obj->begin_sections(), e = obj->end_sections();
		 i != e; 
		 i.increment(ec)) {

		if (ec) {
			llvm::errs() << "Failed to increment the section iterator!\n";
			return 1;
		}

		bool isText;
		llvm::StringRef secName;

		if (i->getName(secName)) {
			llvm::errs() << file << ": failed to get the section name\n";
			break;
		}

		if (i->isText(isText)) {
			llvm::errs() << file << ": " << secName << ": failed to determine the section type\n";
			break;
		}

		if (!isText) {
			continue;
		}

	
		std::set<llvm::object::SymbolRef> symbols;

		for (llvm::object::symbol_iterator isym = obj->begin_symbols();
										   isym != obj->end_symbols();
										   isym.increment(ec)) {
			bool res;
			llvm::StringRef symName;
			llvm::object::SymbolRef::Type symType;

			if (ec) {
				llvm::errs() << "Failed to increment the symbol iterator!\n";
				return 1;		
			}

			if (isym->getName(symName)) {
				llvm::errs() << file << ": " << secName << ": failed to get the symbol name!\n";
				return 1;
			}

			/*
			uint64_t secSize, secBase, symAddr;

			i->getAddress(secBase);
			i->getSize(secSize);
			isym->getAddress(symAddr);

			
			if (i->containsSymbol(*isym, res)) {
				llvm::errs() << file << ": " << secName << ": " << symName << ": failed to check whether the symbol is in the section!\n";
				return 1;
			}

			if (!res) {
				continue;
			}
			
			if (symAddr < secBase || symAddr >= secBase + secSize) {
				continue;
			}
			*/

			llvm::object::section_iterator i2 = llvm::object::section_iterator(llvm::object::SectionRef());
			isym->getSection(i2);
			if (i2 != i) {
				continue;
			}

			if (isym->getType(symType)) {
				llvm::errs() << file << ": " << secName << ": " << symName << ": failed to get the symbol type!\n";
				return 1;
			}

			if (symType != llvm::object::SymbolRef::ST_Function) {
				continue;
			}

			symbols.insert(*isym);
		}

		for (std::set<llvm::object::SymbolRef>::const_iterator	isym = symbols.begin();
																isym != symbols.end();
																++isym) {
			if (analyzeSymbol(*isym)) {
				return 1;
			}
		}
	}

	return 0;
}
