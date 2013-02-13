#include <elf.h>

#include <cstdio>
#include <cstring>
#include <cctype>

#include <string>
#include <deque>
#include <set>
#include <map>
#include <vector>
#include <algorithm>

#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/MemoryObject.h>
#include <llvm/Support/DataTypes.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/ADT/OwningPtr.h>
#include <llvm/ADT/Triple.h>
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

extern "C" {
#include <libvex.h>
}

// ----------------------------------------------------------------------------

typedef llvm::IRBuilder<> LLVMBuilder;

// ----------------------------------------------------------------------------

static llvm::MCSubtargetInfo*	STI;
static llvm::MCRegisterInfo*	MRI;
static llvm::MCInstrInfo*		MII;

static llvm::LLVMContext		llvmCtx;
static llvm::Module*			module;
 
// ----------------------------------------------------------------------------

static void vex_fail()
{
	llvm::errs() << "The VEX library exited abnormally";
	abort();
}

static void vex_log(HChar *msg, Int len)
{
	llvm::outs() << std::string((char*)msg, len);
}

static void vex_init()
{
	VexControl vc;

	LibVEX_default_VexControl(&vc);
	LibVEX_Init(vex_fail, vex_log, 0, 0, &vc);
}

static void vex_init_arg_common(VexTranslateArgs *pva)
{
	pva->arch_guest = VexArchAMD64;
	pva->archinfo_guest.hwcaps = 0;
	pva->archinfo_guest.hwcache_info.num_levels = 0;
	pva->archinfo_guest.hwcache_info.num_caches = 0;
	pva->archinfo_guest.hwcache_info.caches = NULL;
	pva->archinfo_guest.hwcache_info.icaches_maintain_coherence = 0;

	pva->arch_host = VexArchAMD64;
	pva->archinfo_host.hwcaps = 0;
	pva->archinfo_host.hwcache_info.num_levels = 0;
	pva->archinfo_host.hwcache_info.num_caches = 0;
	pva->archinfo_host.hwcache_info.caches = NULL;
	pva->archinfo_host.hwcache_info.icaches_maintain_coherence = 0;

	LibVEX_default_VexAbiInfo(&pva->abiinfo_both);
	pva->abiinfo_both.guest_stack_redzone_size = 128; /* XXX LibVEX aborts on AMD64 guest if it's not so */


	pva->host_bytes_used = NULL;

	pva->instrument1 = NULL;
	pva->instrument2 = NULL;
	pva->finaltidy = NULL;

	pva->preamble_function = NULL;
	pva->traceflags = 0;
	pva->sigill_diag = 0;
	pva->addProfInc = 0;

	pva->disp_cp_chain_me_to_slowEP = NULL;
	pva->disp_cp_chain_me_to_fastEP = NULL;
	pva->disp_cp_xindir = NULL;
	pva->disp_cp_xassisted = (void*)0xdeadbeef;
}

// ----------------------------------------------------------------------------

struct CodeBlock {
#define _ctx ctx()

public:
	CodeBlock(const llvm::object::SymbolRef &sym, llvm::Module *module)
	{
		auto isec = llvm::object::section_iterator(llvm::object::SectionRef());

		sym.getSection(isec);
		isec->getAddress(_secBase);
		sym.getAddress(_symAddr);
		sym.getSize(_symSize);
		sym.getName(_fname);
		isec->getContents(_contents);
		_symCode = _contents.data();
		_module = module;

		createBuilder();
	}


	static Bool vex_cb(void *_self, Addr64 addr)
	{
		CodeBlock *self = (CodeBlock*)_self;
		return addr >= self->_symAddr && addr < self->_symAddr + self->_symSize;
	}


	static
	IRSB *vex_instrument_cb(void *_self,
							IRSB *irsb,
							VexGuestLayout *guest_layouts,
							VexGuestExtents *guest_extents,
							VexArchInfo *archinfo,
							IRType gWordTy, IRType hWordTy)
	{
		CodeBlock *self = (CodeBlock*)_self;
		self->generateLLVM(irsb);

		return irsb;
	}


	void finalize()
	{
		_b->CreateRet(_b->CreateLoad(getRegPtr(16, intType(64))));
	}


private:
	void createBuilder()
	{
		int argNum = 3; /* FIXME use proper value when the argument analysis is done */

		std::vector<llvm::Type*> argTypes(argNum);
		std::fill(argTypes.begin(), argTypes.end(), llvm::Type::getInt64Ty(_ctx));

		llvm::Function* fn = llvm::Function::Create(
			llvm::FunctionType::get(llvm::Type::getInt64Ty(_ctx),
									llvm::ArrayRef<llvm::Type*>(&argTypes.front(), &argTypes.back() + 1),
									false),
			llvm::GlobalValue::ExternalLinkage,
			_fname,
			_module);

		llvm::BasicBlock *blk = llvm::BasicBlock::Create(_ctx, "", fn);
		_b = new llvm::IRBuilder<>(blk, llvm::ConstantFolder());

		_regs = _b->CreateAlloca(
			intType(8),
			constant(64, 216));

		_regsp = _b->CreatePtrToInt(_regs, intType(64));


		/* FIXME use proper initialization when the argument analysis is done */
		auto farg = fn->arg_begin();
		_b->CreateStore(&*(farg++), getRegPtr(72, intType(64)));
		_b->CreateStore(&*(farg++), getRegPtr(64, intType(64)));
		_b->CreateStore(&*(farg++), getRegPtr(32, intType(64)));
	}


	void generateLLVM(IRSB *irsb)
	{
		for (Int i = 0; i < irsb->stmts_used; ++i) {
			IRStmt *stmt = irsb->stmts[i];

			switch (stmt->tag) {
			case Ist_WrTmp:
				_tmps[stmt->Ist.WrTmp.tmp] = visit(stmt->Ist.WrTmp.data);
				break;

			case Ist_Put:
				llvm::Value *res;

				res = visit(stmt->Ist.Put.data);
				_b->CreateStore(
						res,
						getRegPtr(stmt->Ist.Put.offset, res->getType()));
				break;

			case Ist_Store:
				llvm::Value *data, *p;

				data = visit(stmt->Ist.Store.data);
				p = visit(stmt->Ist.Store.addr);
				_b->CreateStore(
							data,
							_b->CreateIntToPtr(p, ptr(data->getType())));
				break;

			case Ist_IMark:
			case Ist_NoOp:
			case Ist_AbiHint:	/* Not used for now */
				break;

			default:
				llvm::errs() << "Unknown VEX statement tag " << stmt->tag << "\n";
				abort();
			}
		}
	}


	llvm::Value *visit(IRExpr *expr)
	{
		switch (expr->tag) {
		case Iex_Binop:
			switch (expr->Iex.Binop.op) {
			case Iop_Add64:
			case Iop_Add32:
				return _b->CreateAdd(
							visit(expr->Iex.Binop.arg1),
							visit(expr->Iex.Binop.arg2));

			case Iop_Sub64:
				return _b->CreateSub(
							visit(expr->Iex.Binop.arg1),
							visit(expr->Iex.Binop.arg2));

			case Iop_Mul32:
				return _b->CreateMul(
							visit(expr->Iex.Binop.arg1),
							visit(expr->Iex.Binop.arg2));

			default:
				llvm::errs() << "Unknown type of a binop " << expr->Iex.Binop.op << "\n";
				abort();
			}

			break;

		case Iex_Unop:
			switch (expr->Iex.Unop.op) {
			case Iop_32Uto64:
				return _b->CreateIntCast(
							visit(expr->Iex.Unop.arg),
							intType(64), false);

			case Iop_64to32:
				return _b->CreateIntCast(
							visit(expr->Iex.Unop.arg),
							intType(32), false);

			default:
				llvm::errs() << "Unknown type of unop " << expr->Iex.Unop.op << "\n";
				abort();
			}
			break;

		case Iex_Get:
			return _b->CreateLoad(
						getRegPtr(
							expr->Iex.Get.offset,
							llvmType(expr->Iex.Get.ty)));

		case Iex_RdTmp:
			return _tmps[expr->Iex.RdTmp.tmp];

		case Iex_Load:
			return _b->CreateLoad(
							_b->CreateIntToPtr(
								visit(expr->Iex.Load.addr),
								ptr(llvmType(expr->Iex.Load.ty))));

		case Iex_Const:
			IRConst *con;

			con = expr->Iex.Const.con;
			switch (con->tag) {
			case Ico_U64:
				return constant(64, con->Ico.U64);

			default:
				llvm::errs() << "Unknown VEX IR constant type " << con->tag << "\n";
				abort();
			}
			break;

		default:
			llvm::errs() << "Unknown VEX IR expression tag " << expr->tag << "\n";
			abort();
		}
	}


	llvm::Type *intType(int size)
	{
		switch (size) {
		case 8:
			return llvm::Type::getInt8Ty(_ctx);

		case 16:
			return llvm::Type::getInt16Ty(_ctx);

		case 32:
			return llvm::Type::getInt32Ty(_ctx);

		case 64:
			return llvm::Type::getInt64Ty(_ctx);

		default:
			abort();
		}
	}


	llvm::Type *llvmType(IRType ty)
	{
		switch (ty) {
		case Ity_I8:
			return intType(8);

		case Ity_I16:
			return intType(16);

		case Ity_I32:
			return intType(32);

		case Ity_I64:
			return intType(64);

		default:
			llvm::errs() << "Unknown type " << ty << "\n";
			abort();
		}
	}


	llvm::Value *constant(int size, uint64_t val, bool isSigned = false)
	{
		return llvm::Constant::getIntegerValue(intType(size), llvm::APInt(size, val, isSigned));
	}


	llvm::Type *ptr(llvm::Type *pointed)
	{
		return llvm::PointerType::get(pointed, 0);
	}


	llvm::Value *getRegPtr(int offset, llvm::Type *destTy)
	{
		return _b->CreateIntToPtr(
			_b->CreateAdd(_regsp, constant(64, offset)),
			ptr(destTy));
	}


	llvm::LLVMContext &ctx() { return _module->getContext(); }


public:
	llvm::StringRef _contents;
	const char *_symCode;
	uint64_t _secBase, _symAddr, _symSize;

private:
	llvm::Module *_module;
	LLVMBuilder *_b;
	llvm::Value *_regs, *_regsp;
	llvm::StringRef _fname;

	std::map<IRTemp, llvm::Value*> _tmps;

#undef _ctx
};

static UInt need_selfcheck_cb_stub(void *opaque, VexGuestExtents *ext)
{
	return 0;
}


static int asmToVEX(const llvm::object::SymbolRef &sym, llvm::Module *module)
{
	VexTranslateArgs va;
	CodeBlock bc(sym, module);
	UChar *vexCode = new UChar[4096];
	Int vexCodeUsed;
	VexGuestExtents vge;
	VexTranslateResult res;

	vex_init_arg_common(&va);
	va.guest_bytes = (UChar*)bc._symCode;
	va.guest_bytes_addr = bc._symAddr;

	va.callback_opaque = &bc;
	va.chase_into_ok = CodeBlock::vex_cb;
	va.guest_extents = &vge;
	va.host_bytes = vexCode;
	va.host_bytes_size = 4096;
	va.host_bytes_used = &vexCodeUsed;
	va.needs_self_check = need_selfcheck_cb_stub;

	va.instrument1 = CodeBlock::vex_instrument_cb;

	while (va.guest_bytes_addr < bc._symAddr + bc._symSize) {
		memset(&vge, 0, sizeof(vge));
		res = LibVEX_Translate(&va);
		if (res.status != VexTranslateResult::VexTransOK) {
			llvm::errs() << "Failed to translate (error " << res.status << ")\n";
			abort();
		}

		if (vge.n_used != 1) {
			llvm::errs() << "Don't know what to do with the guest extents!\n";
			abort();
		}

		va.guest_bytes += vge.len[0];
		va.guest_bytes_addr += vge.len[0];
	}

	bc.finalize();

	delete vexCode;
}

static int analyzeSymbol(const llvm::object::SymbolRef &sym, llvm::Module *module)
{
	llvm::StringRef symName;
	sym.getName(symName);
	llvm::outs() << "Translating the symbol " << symName << "\n";


	asmToVEX(sym, module);

	return 0;
}

// ----------------------------------------------------------------------------

int main(int argc, char** argv)
{
	llvm::llvm_shutdown_obj Y;
	llvm::error_code ec;
	std::string se;
	std::string file;

	if (argc < 3) {
		llvm::errs() << "Usage vex-llvm <object> <output>\n";
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

	MII = target->createMCInstrInfo();
    if (!MII) {
		llvm::errs() << file << ": no instruction info for the target\n";
		return 1;
    }

	MRI = target->createMCRegInfo(targetName);
    if (!MRI) {
		llvm::errs() << file << ": no register info for the target\n";
		return 1;
    }

	vex_init();

	module = new llvm::Module("test", llvmCtx);

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
			if (analyzeSymbol(*isym, module)) {
				return 1;
			}
		}
	}

	std::string err;
	llvm::raw_fd_ostream out(argv[2], err, 0);
	module->print(out, NULL);

	return 0;
}
