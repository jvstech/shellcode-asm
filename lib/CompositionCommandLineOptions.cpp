#include "shellcode-asm/CompositionOptions.h"

#include <cassert>

#include "llvm/Support/CommandLine.h"

namespace cl = llvm::cl;

namespace shellcode_asm
{

#define OPT(TY, NAME)                                                                 \
  static cl::opt<TY>* NAME##View;                                                     \
  TY get##NAME() noexcept                                                             \
  {                                                                                   \
    assert(NAME##View && "RegisterCompositionCommandLineOptions not created.");       \
    return *NAME##View;                                                               \
  }

OPT(std::string, TripleName)
OPT(std::string, ArchName)
OPT(std::string, CPU)
OPT(bool, ATTSyntax)
OPT(bool, MASMStyleHex)

} // namespace shellcode_asm

shellcode_asm::RegisterCompositionCommandLineOptions::RegisterCompositionCommandLineOptions() 
  noexcept
{
#define BINDOPT(NAME)                     \
  do                                      \
  {                                       \
    NAME##View = std::addressof(NAME);    \
  } while (0)

  static cl::opt<std::string> TripleName(
    "triple", cl::desc("Target triple"), cl::cat(GetCLCategory()));
  BINDOPT(TripleName);
  static cl::opt<std::string> ArchName(
    "march", cl::desc("Target architecture"), cl::cat(GetCLCategory()));
  BINDOPT(ArchName);
  static cl::opt<std::string> CPU("mcpu", 
    cl::desc("Target a specific CPU type (-mcpu=help for details)"),
    cl::value_desc("cpu-name"), cl::init(""), cl::cat(GetCLCategory()));
  BINDOPT(CPU);
  static cl::opt<bool> ATTSyntax(
    "x86-att", cl::desc("Use AT&T syntax for x86"), cl::cat(GetCLCategory()));
  BINDOPT(ATTSyntax);
  static cl::opt<bool> MASMStyleHex(
    "masm-hex", cl::desc("Use MASM-style hex values for x86"), cl::cat(GetCLCategory()));
  BINDOPT(MASMStyleHex);
}

std::string& shellcode_asm::GetCLCategoryName() noexcept
{
  static std::string* catName = new std::string("shellcode-asm");
  return *catName;
}

cl::OptionCategory& shellcode_asm::GetCLCategory() noexcept
{
  static cl::OptionCategory* cat = new cl::OptionCategory(GetCLCategoryName());
  return *cat;
}

shellcode_asm::CompositionOptions shellcode_asm::InitCompositionCommandLineOptions() noexcept
{
  CompositionOptions opts;
  opts.TargetTriple = getTripleName();
  opts.Arch = getArchName();
  opts.CPU = getCPU();
  opts.ATTSyntax = getATTSyntax();
  opts.MASMHex = getMASMStyleHex();
  return opts;
}
