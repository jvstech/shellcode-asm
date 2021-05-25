#if !defined(SHELLCODE_ASM_ASSEMBLE_H_)
#define SHELLCODE_ASM_ASSEMBLE_H_

#include <cstdint>
#include <vector>

#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Error.h"

namespace shellcode_asm
{

class Composition;

/// @fn  assemble
///
/// @brief  Assembles the given input text to flat binary.
///
/// @param  composition The composition used for configuring the assembler.
/// @param  inputAsm    The input assembly text.
///
/// @returns  A flat binary as a vector of bytes.
llvm::Expected<std::vector<std::uint8_t>> assemble(
  const Composition& composition, llvm::StringRef inputAsm) noexcept;

} // namespace shellcode_asm


#endif // !SHELLCODE_ASM_ASSEMBLE_H_
