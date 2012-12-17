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


static std::string getLocalName(const llvm::MCInst& inst, unsigned iop) {
	const llvm::MCOperand& op = inst.getOperand(iop);

	if (op.isReg() && strcmp(MRI->getName(op.getReg()), "RBP") == 0) {
		char buf[128];

		snprintf(buf, 128, "local_%x", -inst.getOperand(iop + 3).getImm());
		return std::string(buf);
	} else {
		return std::string("UNK");
	}
}

static const char* getRegName(const llvm::MCInst& inst, unsigned iop) {
	return MRI->getName(inst.getOperand(iop).getReg());
}

static void translateBlock(std::deque<llvm::MCInst>& block) {
	typedef std::map<std::string, LLVMValueRef>::const_iterator ValRef;

	std::map<std::string, LLVMValueRef> locals;
	std::map<std::string, LLVMValueRef> regs;

	for (InstIter it = block.begin(); it != block.end(); ++it) {
		llvm::MCInst& inst = *it;
		const llvm::MCInstrDesc& id = MII->get(inst.getOpcode());
		llvm::StringRef iname = MII->getName(inst.getOpcode());

		if (iname.startswith("MOV")) {
			LLVMValueRef lhs;
			unsigned iop = 0;

			if (id.OpInfo[0].OperandType == llvm::MCOI::OPERAND_MEMORY) {
				std::string localName = getLocalName(inst, 0);
				ValRef pval = locals.find(localName); 
				if (pval == locals.end()) {
					lhs = LLVMBuildAlloca(llvmBuilder, LLVMInt32Type(), localName.c_str());
					locals[localName] = lhs;
				} else {
					lhs = pval->second;
				}

				if (id.OpInfo[5].OperandType == llvm::MCOI::OPERAND_IMMEDIATE) {
					const llvm::MCOperand& op = inst.getOperand(5);
					LLVMBuildStore(llvmBuilder, lhs, LLVMConstInt(LLVMInt32Type(), op.getImm(), 0));
				}

				if (id.OpInfo[5].OperandType == llvm::MCOI::OPERAND_REGISTER) {
					LLVMBuildStore(llvmBuilder, lhs, regs[getRegName(inst, 5)]);
				}

			} else if (id.OpInfo[0].OperandType == llvm::MCOI::OPERAND_REGISTER) {
				LLVMValueRef rhs;

				printInst(inst);
				
				if (id.OpInfo[1].OperandType == llvm::MCOI::OPERAND_IMMEDIATE) {
					rhs = LLVMConstInt(LLVMInt32Type(), inst.getOperand(1).getImm(), 0);
				} else if (id.OpInfo[1].OperandType == llvm::MCOI::OPERAND_MEMORY) {
					ValRef pval = locals.find(getLocalName(inst, 1));
					if (pval == locals.end()) {
						llvm::outs() << "No such local " << getLocalName(inst, 1) << "\n";
						break;
					}

					rhs = LLVMBuildLoad(llvmBuilder, pval->second, getRegName(inst, 0));
				} else {
					continue;
				}

				regs[getRegName(inst, 0)] = rhs;
			}
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
