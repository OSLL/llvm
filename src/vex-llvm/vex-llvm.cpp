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
//#define VGO_linux
//#define VGA_amd64

//#include <pub_tool_basics.h>
//#include <pub_tool_tooliface.h>
#include <libvex.h>
}

// ----------------------------------------------------------------------------

typedef llvm::IRBuilder<> LLVMBuilder;

// ----------------------------------------------------------------------------

static llvm::MCSubtargetInfo*	STI;
static llvm::MCRegisterInfo*	MRI;
static llvm::MCInstrInfo*		MII;

static llvm::LLVMContext		llvmCtx;
static LLVMBuilder*				llvmBuilder;
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
public:
	CodeBlock(const llvm::object::SymbolRef& sym)
	{
		auto isec = llvm::object::section_iterator(llvm::object::SectionRef());

		sym.getSection(isec);
		isec->getAddress(_secBase);
		sym.getAddress(_symAddr);
		sym.getSize(_symSize);
		isec->getContents(_contents);
		_symCode = _contents.data();
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
		return irsb;
	}



	llvm::StringRef _contents;
	const char *_symCode;
	uint64_t _secBase, _symAddr, _symSize;
};

static UInt need_selfcheck_cb_stub(void *opaque, VexGuestExtents *ext)
{
	return 0;
}


static int asmToVEX(const llvm::object::SymbolRef& sym)
{
	VexTranslateArgs va;
	CodeBlock bc(sym);
	UChar *vexCode = new UChar[4096];
	Int vexCodeUsed;
	VexGuestExtents vge[128];

	vex_init_arg_common(&va);
	va.guest_bytes = (UChar*)bc._symCode;
	va.guest_bytes_addr = bc._symAddr;

	va.callback_opaque = &bc;
	va.chase_into_ok = CodeBlock::vex_cb;
	va.guest_extents = vge;
	va.host_bytes = vexCode;
	va.host_bytes_size = 4096;
	va.host_bytes_used = &vexCodeUsed;
	va.needs_self_check = need_selfcheck_cb_stub;

	va.instrument1 = CodeBlock::vex_instrument_cb;

	LibVEX_Translate(&va);

	delete vexCode;
}

static int analyzeSymbol(const llvm::object::SymbolRef& sym)
{
	llvm::StringRef symName;

	sym.getName(symName);

	llvm::outs() << "Translating the symbol " << symName << "\n";


	asmToVEX(sym);

	return 0;
}

// ----------------------------------------------------------------------------

int main(int argc, char** argv)
{
	llvm::llvm_shutdown_obj Y;
	llvm::error_code ec;
	std::string se;
	std::string file;

	if (argc < 2) {
		llvm::errs() << "Usage vex-llvm <file>\n";
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
			if (analyzeSymbol(*isym)) {
				return 1;
			}
		}
	}

	llvm::outs() << *module;

	return 0;
}
