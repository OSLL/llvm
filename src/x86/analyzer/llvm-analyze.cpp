#include <elf.h>

#include <cstdio>
#include <cstring>
#include <cctype>

#include <string>
#include <deque>
#include <set>
#include <map>

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

#include <llvm-c/Core.h>

// ----------------------------------------------------------------------------

struct LinearBlock {
	uint64_t begin, end;

	LinearBlock(uint64_t _begin, uint64_t _end) :
		begin(_begin),
		end(_end) { }
};


typedef std::deque<llvm::MCInst>::iterator InstIter;

// ----------------------------------------------------------------------------

static llvm::MCSubtargetInfo*	STI;
static llvm::MCDisassembler*	disasm;
static llvm::MCRegisterInfo*	MRI;
static llvm::MCInstrInfo*		MII;


static LLVMBuilderRef			llvmBuilder;	

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
	const llvm::MCInstrDesc& id = MII->get(inst.getOpcode());
	llvm::outs() << MII->getName(inst.getOpcode()) << " (" << inst.getNumOperands() << ") ";

	for (int iop = 0; iop < inst.getNumOperands(); ++iop) {
		const llvm::MCOperand& op = inst.getOperand(iop);

		if (op.isReg()) {
			unsigned reg = op.getReg();
			const char* rcName;
			char clsn[128];

			if (id.OpInfo[iop].RegClass < MRI->getNumRegClasses()) {
				const llvm::MCRegisterClass& rc = MRI->getRegClass(id.OpInfo[iop].RegClass);
				rcName = rc.getName();
			} else {
				snprintf(clsn, sizeof(clsn), "CLS%d", id.OpInfo[iop].RegClass);
				rcName = clsn;
			}
			llvm::outs() << MRI->getName(reg) << "(" << rcName << ", " << (uint64_t)id.OpInfo[iop].OperandType << ")";
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
		const llvm::MCInstrDesc& id = MII->get(inst.getOpcode());

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
	for (InstIter it = block.begin(); it != block.end(); ++it) {
		llvm::MCInst& inst = *it;
		const llvm::MCInstrDesc& id = MII->get(inst.getOpcode());
		llvm::StringRef iname = MII->getName(inst.getOpcode());

		for (unsigned iop = 0; iop < inst.getNumOperands(); ++iop) {
			if (id.OpInfo[iop].OperandType == llvm::MCOI::OPERAND_MEMORY) {
				const llvm::MCOperand& op = inst.getOperand(iop);

				if (op.isReg() && strcmp(MRI->getName(op.getReg()), "RBP") == 0) {
					LLVMBuildAlloca(llvmBuilder, LLVMInt32Type(), "");

					//printInst(inst);
				}

				iop += 5;
				break;
			}
		}
	}
}


// ----------------------------------------------------------------------------

typedef std::map<std::string, LLVMValueRef>::const_iterator ValRef;

static std::map<std::string, LLVMValueRef> locals;
static std::map<std::string, LLVMValueRef> regs;

static std::string getLocalName(const llvm::MCInst& inst, unsigned iop) {
	const llvm::MCOperand& op = inst.getOperand(iop);

	if (op.isReg() && strcmp(MRI->getName(op.getReg()), "RBP") == 0) {
		char buf[128];

		snprintf(buf, sizeof(buf), "local_%x", -inst.getOperand(iop + 3).getImm());
		return std::string(buf);
	} else {
		return std::string("UNK");
	}
}

static LLVMValueRef getLocal(const std::string& name) {
	ValRef ref = locals.find(name);
	if (ref != locals.end()) {
		return ref->second;
	} else {
		LLVMValueRef res = LLVMBuildAlloca(llvmBuilder, LLVMInt32Type(), name.c_str());
		locals[name] = res;
		return res;
	}
}

static const char* getRegName(const llvm::MCOperand& op) {
	return MRI->getName(op.getReg());
}

static std::string getReg64Name(const llvm::MCOperand& op) {
	const char* regName = getRegName(op);

	if (regName[0] == 'E') {
		char reg64Name[8];
		snprintf(reg64Name, sizeof(reg64Name), "R%s", regName + 1);
		return reg64Name;
	} else {
		return regName;
	}
}

static LLVMValueRef getRegVal(const llvm::MCOperand& op) {
	const char* regName = getRegName(op);

	if (regName[0] == 'E') {
		char reg64Name[8];

		snprintf(reg64Name, sizeof(reg64Name), "R%s", regName + 1);
		return LLVMBuildIntCast(llvmBuilder, regs[reg64Name], LLVMInt32Type(), "");
	}

	return regs[regName];
}

struct Operand {
	enum Size {
		S8,
		S16,
		S32,
		S64
	};

	llvm::MCOI::OperandType storage;
	Size					size;

	std::string  name;

	union {
		LLVMValueRef val;

		struct {
			LLVMValueRef base;
			LLVMValueRef index;
			LLVMValueRef scale;
			LLVMValueRef disp;
		};
	};


	static LLVMTypeRef getIntType(Size size) {
		switch (size) {
		case S32:
			return LLVMInt32Type();

		case S64:
			return LLVMInt64Type();

		default:
			abort();
		}
	}

	Operand() { }

	Operand(LLVMValueRef vr, Size sz = S64) {
		val = vr;
		size = sz;
	}
	

	LLVMValueRef get() const {
		switch (storage) {
		case llvm::MCOI::OPERAND_MEMORY:
			return LLVMBuildLoad(llvmBuilder, getLocal(name), "");

		case llvm::MCOI::OPERAND_REGISTER:
			if (size == S64) {
				return regs[name];
			} else {
				return LLVMBuildIntCast(llvmBuilder, regs[name], getIntType(size), "");
			}

		default:
			return val;
		}
	}

	std::string adviceName() const {
		if (storage == llvm::MCOI::OPERAND_REGISTER) {
			return name;
		}

		return std::string();
	}

	void store(const Operand& op) {
		switch (storage) {
		case llvm::MCOI::OPERAND_MEMORY:
			LLVMBuildStore(llvmBuilder, get(), op.get());
			break;

		case llvm::MCOI::OPERAND_REGISTER:
			LLVMValueRef rhs;

			if (op.size != S64) {
				rhs = LLVMBuildIntCast(llvmBuilder, op.get(), LLVMInt64Type(), "");
			} else {
				rhs = op.get();
			}

			regs[name] = rhs;
			break;

		default:
			llvm::outs() << "storage is " << storage << "\n";
			abort();
		}
	}
};


static Operand::Size getRegSize(const llvm::MCOperand& op) {
	const char* regName = getRegName(op);

	if (regName[0] == 'E') {
		return Operand::S32;
	} else if (regName[0] == 'R') {
		return Operand::S64;
	} else if (regName[1] == 'X') {
		return Operand::S16;
	} else if (regName[1] == 'L' || regName[1] == 'H') {
		return Operand::S8;
	}

	return Operand::S16;
}

static void parseOperands(const llvm::MCInst& inst, std::deque<Operand>& operands) {
	const llvm::MCInstrDesc& id = MII->get(inst.getOpcode());

	for (unsigned i = 0; i < inst.getNumOperands(); ) {
		Operand op;
		const llvm::MCOperand& cop = inst.getOperand(i);

		op.storage = (llvm::MCOI::OperandType)id.OpInfo[i].OperandType;

		switch (id.OpInfo[i].OperandType) {
		case llvm::MCOI::OPERAND_UNKNOWN:
			i += 5;
			break;

		case llvm::MCOI::OPERAND_MEMORY:
			op.name = getLocalName(inst, i);
			op.size = Operand::S32;
			i += 5;
			break;

		case llvm::MCOI::OPERAND_REGISTER:
			op.name = getReg64Name(cop);
			op.size = getRegSize(cop);
			i++;
			break;

		case llvm::MCOI::OPERAND_IMMEDIATE:
			op.size = Operand::S32;
			op.val = LLVMConstInt(LLVMInt32Type(), cop.getImm(), 0);
			i++;
			break;

		default:
			llvm::outs() << "Storage is " << op.storage << "\n";
			printInst(inst);
			abort();
		}

		operands.push_back(op);
	}
}

static void translateBlock(std::deque<llvm::MCInst>& block) {

	for (InstIter it = block.begin(); it != block.end(); ++it) {
		llvm::MCInst& inst = *it;
		const llvm::MCInstrDesc& id = MII->get(inst.getOpcode());
		llvm::StringRef iname = MII->getName(inst.getOpcode());
		std::deque<Operand> ops;

		parseOperands(inst, ops);

		if (iname.startswith("MOV")) {
			ops[0].store(ops[1]);
		} else if (iname.startswith("IMUL")) {
			ops[0].store(Operand(LLVMBuildMul(llvmBuilder, ops[1].get(), ops[2].get(), "")));
		}
	}
}

static int analyzeSymbol(const llvm::object::SymbolRef& sym) {
	std::deque<llvm::MCInst> block;

	disassembleSymbol(sym, block);
	translateBlock(block);
	//analyzeStackReferences(block);

	return 0;
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

	STI = target->createMCSubtargetInfo(targetName, "", "");
	if (!STI) {
		llvm::errs() << file << ": " << ": to get the subtarget info!\n";
		return 1;
	}

	disasm = target->createMCDisassembler(*STI);
	if (!disasm) {
		llvm::errs() << file << ": " << ": to get the disassembler!\n";
		return 1;
	}

	MII = target->createMCInstrInfo();
    if (!MII) {
		llvm::errs() << file << ": no instruction info for target\n";
		return 1;
    }

	MRI = target->createMCRegInfo(targetName);
    if (!MRI) {
		llvm::errs() << file << ": no register info for target\n";
		return 1;
    }


	llvmBuilder = LLVMCreateBuilder();

	LLVMModuleRef llvmModule = LLVMModuleCreateWithName("test");
	LLVMTypeRef mainType = LLVMFunctionType(LLVMInt32Type(), NULL, 0, 0);
	LLVMValueRef mainFn = LLVMAddFunction(llvmModule, "main", mainType);
	LLVMBasicBlockRef blk = LLVMAppendBasicBlock(mainFn, "");
	LLVMPositionBuilderAtEnd(llvmBuilder, blk);

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

	LLVMDumpModule(llvmModule);

	LLVMDisposeModule(llvmModule);
	LLVMDisposeBuilder(llvmBuilder);

	return 0;
}
