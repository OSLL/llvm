#include <llvm/Object/ObjectFile.h>

#include <llvm/Support/MemoryObject.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/system_error.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/Casting.h>
#include "llvm/Support/DataTypes.h"

#include <llvm/ADT/StringRef.h>
#include <llvm/ADT/OwningPtr.h>
#include <llvm/ADT/Triple.h>

#include <llvm/MC/MCDisassembler.h>
#include <llvm/MC/MCExpr.h>

#include "disasm.h"

// ----------------------------------------------------------------------------

static llvm::MCDisassembler*	Dis;

llvm::MCSubtargetInfo*	STI;
llvm::MCRegisterInfo*	MRI;
llvm::MCInstrInfo*		MII;

// ----------------------------------------------------------------------------

class Init {
public:
	Init()
	{
		llvm::InitializeAllTargetInfos();
		llvm::InitializeAllTargetMCs();
		llvm::InitializeAllAsmParsers();
		llvm::InitializeAllDisassemblers();
	}

private:
	llvm::llvm_shutdown_obj Y;
};

static Init init;

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

static void disassembleLinearBlock(const llvm::MemoryObject& data,
								   uint64_t start, uint64_t end,
								   InstList& result)
{
	uint64_t ptr = start;
	uint64_t instSize;	

	for (;;) {
		llvm::MCInst inst;

		if (ptr < start || ptr >= end) {
			break;
		}

		if (Dis->getInstruction(inst, instSize, data, ptr, llvm::nulls(), llvm::nulls()) != llvm::MCDisassembler::Success) {
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

static int disassembleSymbol(const llvm::object::SymbolRef& sym,
							 InstList& result)
{
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


int disassemble(const char* objname, SymbolList& result)
{
	llvm::error_code ec;
	std::string se;
	std::string file;

	file = objname;

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

	Dis = target->createMCDisassembler(*STI);
	if (!Dis) {
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


	for (auto i = obj->begin_sections(), e = obj->end_sections();
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


		for (auto isym = obj->begin_symbols();
				  isym != obj->end_symbols();
				  isym.increment(ec)) {
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

			result.push_back(symName.data());
			
			if (disassembleSymbol(*isym, result.back().insts))
				return 1;
		}
	}

	return 0;
}
