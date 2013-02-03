extern "C" {
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/fail.h>
}

#include <iostream>

#include "disasm.h"

// ============================================================================

static void printInst(const llvm::MCInst& inst) {
	const llvm::MCInstrDesc& id = MII->get(inst.getOpcode());
	std::cout << MII->getName(inst.getOpcode()) << " (" << inst.getNumOperands() << ") ";

	for (unsigned int iop = 0; iop < inst.getNumOperands(); ++iop) {
		const llvm::MCOperand& op = inst.getOperand(iop);

		if (op.isReg()) {
			unsigned reg = op.getReg();
			const char* rcName;
			char clsn[128];

			std::cout << MRI->getName(reg) << "(" << (uint64_t)id.OpInfo[iop].OperandType << ")";
		} else if (op.isImm()) {
			std::cout << op.getImm() << "(" << (uint64_t)id.OpInfo[iop].OperandType << ")";
		} else {
			std::cout << "<UNK>";
		}

		std::cout << ", ";
	}

	std::cout << "\n";
}


extern "C" CAMLprim value caml_disassemble(value objname)
{
	CAMLparam1(objname);
	CAMLlocal3(symArr, instArr, opArr);
	CAMLlocal3(mlsym, mlinst, mlop);
	CAMLlocal2(opArrWrap, opWrap);

	SymbolList syms;

	if (disassemble(String_val(objname), syms)) {
		caml_failwith("Failed to disassemble!");	
		return Val_emptylist;
	}

	std::cout << "Converting to OCaml representation...\n";
	symArr = caml_alloc(syms.size(), 0);

	unsigned int nsym = 0;
	for (auto isym = syms.begin(); isym != syms.end(); ++isym, ++nsym) {
		instArr = caml_alloc(isym->insts.size(), 0);

		unsigned int ninst = 0;
		for (auto iinst = isym->insts.begin(); iinst != isym->insts.end(); ++iinst, ++ninst) {
			if (iinst->getNumOperands()) {
				const llvm::MCInstrDesc& id = MII->get(iinst->getOpcode());
				unsigned physOps = 0;

				for (int iop = 0; iop < iinst->getNumOperands(); ++iop, ++physOps) {
					switch (id.OpInfo[iop].OperandType) {
					case llvm::MCOI::OPERAND_UNKNOWN:
					case llvm::MCOI::OPERAND_MEMORY:
						iop += 4;
					}
				}

				opArr = caml_alloc(physOps, 0);

				int phop = 0;
				int nop = 0;
				for (auto iop = iinst->begin(); phop < physOps; ++iop, ++phop, ++nop) {
					switch (id.OpInfo[nop].OperandType) {
					case llvm::MCOI::OPERAND_REGISTER:
						opWrap = caml_alloc(1, 0);
						mlop = caml_copy_string(MRI->getName(iop->getReg()));
						break;

					case llvm::MCOI::OPERAND_IMMEDIATE:
						opWrap = caml_alloc(1, 1);
						mlop = Val_int(iop->getImm());
						break;

					case llvm::MCOI::OPERAND_UNKNOWN:
					case llvm::MCOI::OPERAND_MEMORY:
						opWrap = caml_alloc(1, 2);
						mlop = caml_alloc(4, 0);
						Store_field(mlop, 0, caml_copy_string(MRI->getName(iop->getReg())));
						Store_field(mlop, 1, caml_copy_string(MRI->getName((iop + 2)->getReg())));
						Store_field(mlop, 2, Val_int((iop + 1)->getImm()));
						Store_field(mlop, 3, Val_int((iop + 3)->getImm()));

						iop += 4;
						nop += 4;
						break;

					default:
						std::cerr << "Unknown type of the operand " << id.OpInfo[nop].OperandType << "abz\n";
						abort();
					}


					Store_field(opWrap, 0, mlop);
					Store_field(opArr, phop, opWrap);
				}

				opArrWrap = caml_alloc(1, 0);
				Store_field(opArrWrap, 0, opArr);

			} else {
				opArrWrap = Val_int(0);
			}

			mlinst = caml_alloc(2, 0);
			Store_field(mlinst, 0, caml_copy_string(MII->getName(iinst->getOpcode())));
			Store_field(mlinst, 1, opArrWrap);

			Store_field(instArr, ninst, mlinst);
		}

		mlsym = caml_alloc(2, 0);
		Store_field(mlsym, 0, caml_copy_string(isym->name.c_str()));
		Store_field(mlsym, 1, instArr);

		Store_field(symArr, nsym, mlsym);
	}

	CAMLreturn(symArr);
}
