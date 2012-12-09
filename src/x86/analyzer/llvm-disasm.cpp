#include <elf.h>

#include <string>

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

	//llvm::outs() << bin->getType();

	if (!bin->isELF() /*!= llvm::object::Binary::isELF*/) {
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

	llvm::OwningPtr<llvm::MCSubtargetInfo> sti(target->createMCSubtargetInfo(targetName, "", ""));
	if (!sti) {
		llvm::errs() << file << ": " << ": to get the subtarget info!\n";
		return 1;
	}

	llvm::OwningPtr<llvm::MCDisassembler> disasm(target->createMCDisassembler(*sti));
	if (!disasm) {
		llvm::errs() << file << ": " << ": to get the disassembler!\n";
		return 1;
	}

	llvm::OwningPtr<llvm::MCInstrInfo> mmi(target->createMCInstrInfo());
    if (!mmi) {
		llvm::errs() << file << ": no instruction info for target\n";
		return 1;
    }

	llvm::OwningPtr<llvm::MCRegisterInfo> mri(target->createMCRegInfo(targetName));
    if (!mri) {
		llvm::errs() << file << ": no register info for target\n";
		return 1;
    }

	const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)bin->getData().data();

	for (llvm::object::section_iterator i = obj->begin_sections(), e = obj->end_sections();
		 i != e; 
		 i.increment(ec)) {

		if (ec) {
			break;
		}

		bool isText;
		llvm::StringRef contents;
		llvm::StringRef secName;
		uint64_t begin, size, end;

		if (i->getName(secName)) {
			llvm::errs() << file << ": failed to get the section name\n";
			break;
		}

		if (i->getAddress(begin)) {
			llvm::errs() << file << ": " << secName << ": failed to get the section virtual address\n";
			break;
		}

		if (i->getSize(size)) {
            llvm::errs() << file << ": " << secName << ": failed to get the section size\n";
            break;
        }

		end = begin + size;

		if (ehdr->e_entry < begin || ehdr->e_entry >= end) {
			continue;
		}

		if (i->isText(isText)) {
			llvm::errs() << file << ": " << secName << ": failed to determine the section type\n";
			break;
		}

		if (!isText) {
			llvm::errs() << file << ": " << secName << ": entry points here but it's not a text section\n";
            break;
		}

		if (i->getContents(contents)) {
			llvm::errs() << file << ": " << secName << ": failed to get the section contents\n";
			break;
		}

		StringRefMemoryObject moContents(contents);
		uint64_t instSize;
		uint64_t ptr = ehdr->e_entry - begin;

		while (ptr < end) {
			llvm::MCInst inst;

			if (disasm->getInstruction(inst, instSize, moContents, ptr, llvm::nulls(), llvm::nulls()) != llvm::MCDisassembler::Success) {
				llvm::errs() << file << ": " << secName << ": failed to disassemble at " << ptr << "\n";
				break;
			}

			ptr += instSize;

			const llvm::MCInstrDesc& id = mmi->get(inst.getOpcode());
			llvm::outs() << mmi->getName(inst.getOpcode());

			llvm::MCOperand op;

			if (id.isUnconditionalBranch()) {
				if (id.OpInfo[0].OperandType == llvm::MCOI::OPERAND_PCREL) {
					op = inst.getOperand(0);

					if (op.isImm()) {
						llvm::outs() << " " << op.getImm();
						ptr += op.getImm();
					} else if (op.isExpr()) {
						llvm::outs() << " " << op.getExpr()->getKind() << "\n";
						break;
					} else {
						llvm::outs() << " UNKNOWN!\n";
						break;
					}
				}
			} else if (id.isConditionalBranch()) {
				if (id.OpInfo[0].OperandType == llvm::MCOI::OPERAND_PCREL) {
					op = inst.getOperand(0);

					if (op.isImm()) {
						llvm::outs() << " " << op.getImm();
					} else if (op.isExpr()) {
						llvm::outs() << " " << op.getExpr()->getKind();
					} else if (op.isReg()) {
						llvm::outs() << " " << mri->get(op.getReg()).Name << "\n";
						break;
					} else {
						llvm::outs() << " UNKNOWN!\n";
						break;
					}
				}
			}

			llvm::outs() << "\n";
		}		
	}

	return 0;
}
