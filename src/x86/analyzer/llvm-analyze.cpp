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

#include <llvm/Module.h>
#include <llvm/Function.h>
#include <llvm/Constant.h>
#include <llvm/Support/IRBuilder.h>

// ----------------------------------------------------------------------------

struct LinearBlock {
	uint64_t begin, end;

	LinearBlock(uint64_t _begin, uint64_t _end) :
		begin(_begin),
		end(_end) { }
};


typedef std::deque<llvm::MCInst>::iterator InstIter;
typedef llvm::IRBuilder<> LLVMBuilder;

// ----------------------------------------------------------------------------

static llvm::MCSubtargetInfo*	STI;
static llvm::MCDisassembler*	disasm;
static llvm::MCRegisterInfo*	MRI;
static llvm::MCInstrInfo*		MII;

static llvm::LLVMContext		llvmCtx;
static LLVMBuilder*				llvmBuilder;

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

/*
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
*/

// ----------------------------------------------------------------------------

/*
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

static LLVMValueRef getRegVal(const llvm::MCOperand& op) {
	const char* regName = getRegName(op);

	if (regName[0] == 'E') {
		char reg64Name[8];

		snprintf(reg64Name, sizeof(reg64Name), "R%s", regName + 1);
		return LLVMBuildIntCast(llvmBuilder, regs[reg64Name], LLVMInt32Type(), "");
	}

	return regs[regName];
}
*/

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

// ----------------------------------------------------------------------------

class Context {
public:
	llvm::Value* getLocal(const std::string& name, llvm::Type* type) {
		ValRef ref = _locals.find(name);
		if (ref != _locals.end()) {
			return ref->second;
		} else if (type) {
			llvm::Value* res = llvmBuilder->CreateAlloca(type, NULL, name);
			_locals[name] = res;
			return res;
		} else {
			llvm::errs() << "No type specified!\n";
			abort();
		}
	}

	llvm::Value* getReg(const std::string& name) {
		ValRef it = _regs.find(name);
		if (it == _regs.end()) {
			llvm::errs() << "No value for the register " << name << ", defaulting to 0\n";
			return llvm::Constant::getIntegerValue(llvm::Type::getInt64Ty(llvmCtx),
												   llvm::APInt(64, 0));
		}

		return it->second;
	}

	void setReg(const std::string& name, llvm::Value* val) {
		_regs[name] = val;
	}

private:
	typedef std::map<std::string, llvm::Value*>::const_iterator ValRef;

	std::map<std::string, llvm::Value*> _locals;
	std::map<std::string, llvm::Value*> _regs;
};


// ----------------------------------------------------------------------------

class Operand {
public:
	enum Size {
		S8,
		S16,
		S32,
		S64
	};

	typedef llvm::MCOI::OperandType Storage;


	Operand() { _ctx = NULL; }

	Operand(Context* ctx) { 
		_ctx = ctx;
	}

	Operand(Context* ctx, Storage storage, Size size, const std::string& name) {
		_ctx = ctx;
		_size = size;
		_name = name;
		_storage = storage;
	}

	Operand(Context* ctx, llvm::Value* val) {
		_ctx = ctx;
		_val = val;

		llvm::Type* ty = val->getType();
		if (!ty->isIntegerTy()) {
			llvm::errs() << "Not an integer type!\n";
			abort();
		}

		switch (ty->getIntegerBitWidth()) {
		case 32:
			_size = S32;
			break;

		case 64:
			_size = S64;
			break;

		default:
			llvm::outs() << "Unsupported integer size!\n";
			abort();
		}
	}


	std::string adviceName() const {
		if (_storage == llvm::MCOI::OPERAND_REGISTER) {
			return _name;
		}

		return std::string();
	}


	llvm::Value* get(llvm::Type* ty = NULL) const {
		llvm::Value* res;

		switch (_storage) {
		case llvm::MCOI::OPERAND_MEMORY:
			res = llvmBuilder->CreateLoad(_ctx->getLocal(_name, NULL));
			break;

		case llvm::MCOI::OPERAND_REGISTER:
			res = _ctx->getReg(_name);
			if (_size != S64) {
				res = llvmBuilder->CreateIntCast(res, getIntType(_size), true);
			}
			break;

		default:
			res = _val;
		}

		return cast(res, ty);
	}

	void store(const Operand& op) {
		if (_ctx != op._ctx) {
			llvm::errs() << "Invalid context!\n";
			abort();
		}

		switch (_storage) {
		case llvm::MCOI::OPERAND_MEMORY:
			llvm::Type *ty;

			ty  = getIntType(_size);
			llvmBuilder->CreateStore(op.get(ty), _ctx->getLocal(_name, ty));
			break;

		case llvm::MCOI::OPERAND_REGISTER:
			llvm::Value* rhs;

			rhs = op.get();
			if (op._size != S64) {
				rhs = llvmBuilder->CreateIntCast(rhs, getIntType(S64), true);
			}

			_ctx->setReg(_name, rhs);
			break;

		default:
			llvm::outs() << "Don't know what to do; storage is " << _storage << "\n";
			abort();
		}
	}


	static llvm::Type* superType(Operand& op1, Operand& op2) {
		if (op1._size > op2._size) {
			return getIntType(op1._size);
		}

		return getIntType(op2._size);
	}


private:
	static llvm::Value* cast(llvm::Value* val, llvm::Type* ty) {
		if (ty && val->getType()->getIntegerBitWidth() != ty->getIntegerBitWidth()) {
			return llvmBuilder->CreateIntCast(val, ty, true);
		}

		return val;
	}


	static llvm::Type* getIntType(Size size) {
		switch (size) {
		case S32:
			return llvm::Type::getInt32Ty(llvmCtx);

		case S64:
			return llvm::Type::getInt64Ty(llvmCtx);

		default:
			abort();
		}
	}

private:
	Context*		_ctx;

	Storage			_storage;
	Size			_size;
	std::string		_name;
	llvm::Value*	_val;
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


class OperandParser {
public:
	OperandParser(Context* context, const llvm::MCInst& inst) {
		_ctx = context;
		const llvm::MCInstrDesc& id = MII->get(inst.getOpcode());

		for (unsigned i = 0; i < inst.getNumOperands(); ) {
			Operand op;
			const llvm::MCOperand& cop = inst.getOperand(i);
			Operand::Storage storage = (Operand::Storage)id.OpInfo[i].OperandType;

			switch (id.OpInfo[i].OperandType) {
			case llvm::MCOI::OPERAND_UNKNOWN:
				llvm::Value *base, *index, *scale, *disp;

				base  = getReg(inst.getOperand(i));
				scale = getImm(inst.getOperand(i + 1));
				index = getReg(inst.getOperand(i + 2));
				disp  = getImm(inst.getOperand(i + 3));

				op = Operand(
							 _ctx,
							 llvmBuilder->CreateAdd(base,
													llvmBuilder->CreateAdd(llvmBuilder->CreateMul(index, scale),
																		   disp))
							);
				i += 5;
				break;

			case llvm::MCOI::OPERAND_MEMORY:
				op = Operand(_ctx, storage, Operand::S32, getLocalName(inst, i));
				i += 5;
				break;

			case llvm::MCOI::OPERAND_REGISTER:
				op = Operand(_ctx, storage, getRegSize(cop), getReg64Name(cop));
				i++;
				break;

			case llvm::MCOI::OPERAND_IMMEDIATE:
				op = Operand(_ctx, getImm(cop));
				i++;
				break;

			default:
				llvm::errs() << "Storage is " << storage << "\n";
				printInst(inst);
				abort();
			}

			_operands.push_back(op);
		}
	}


	Operand& operator[](unsigned int i) {
		return _operands[i];
	}

private:
	llvm::Value* getImm(const llvm::MCOperand& op) {
		if (!op.isImm()) {
			llvm::errs() << "The operand isn't an immediate!\n";
			abort();
		}

		return llvm::Constant::getIntegerValue(llvm::Type::getInt64Ty(llvmCtx), 
											   llvm::APInt(64, op.getImm()));
	}

	llvm::Value* getReg(const llvm::MCOperand& op) {
		if (!op.isReg()) {
			llvm::errs() << "The operand isn't a register!\n";
			abort();
		}

		return _ctx->getReg(getReg64Name(op));
	}


	std::vector<Operand> _operands;
	Context*			 _ctx;
};


static void translateBlock(std::deque<llvm::MCInst>& block) {
	int cnt1 = 0;
	int cnt2 = 0;
	Context ctx;

	for (InstIter it = block.begin(); it != block.end(); ++it) {
		llvm::MCInst& inst = *it;
		const llvm::MCInstrDesc& id = MII->get(inst.getOpcode());
		llvm::StringRef iname = MII->getName(inst.getOpcode());
		OperandParser ops(&ctx, inst);

		//printInst(inst);

		if (iname.startswith("MOV")) {
			cnt1++;
			ops[0].store(ops[1]);
		} else if (iname.startswith("IMUL")) {
			cnt1++;

			llvm::Type* ty = Operand::superType(ops[1], ops[2]);
			ops[0].store(Operand(&ctx, llvmBuilder->CreateMul(ops[1].get(ty), ops[2].get(ty))));
		} else if (iname.startswith("LEA64")) {
			cnt1++;
			ops[0].store(ops[1]);
		} /*else {
			printInst(inst);
		}*/

		cnt2++;
	}

	llvm::outs() << "Coverage " << cnt2 << "/" << cnt1 << "\n";
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


	llvm::Module* module = new llvm::Module("test", llvmCtx);
	llvm::Function* mainFn = llvm::Function::Create(llvm::FunctionType::get(llvm::Type::getInt32Ty(llvmCtx), false),
													llvm::GlobalValue::ExternalLinkage,
													"main",
													module);


	llvm::BasicBlock* blk = llvm::BasicBlock::Create(llvmCtx, "", mainFn);
	llvmBuilder = new llvm::IRBuilder<>(blk, llvm::ConstantFolder());

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

	llvmBuilder->CreateRet(llvm::Constant::getIntegerValue(llvm::Type::getInt32Ty(llvmCtx),
														   llvm::APInt(32, 0)));

	llvm::outs() << *module;

	return 0;
}
