#include "shellcode-asm/CompositionOptions.h"

llvm::Triple shellcode_asm::CompositionOptions::getTriple() const noexcept
{
  return llvm::Triple(TargetTriple);
}
