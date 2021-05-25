#if !defined(SHELLCODE_ASM_UTILITY_H_)
#define SHELLCODE_ASM_UTILITY_H_

#include <cstdint>

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Compiler.h"

namespace shellcode_asm
{

/// @fn ToArrayRef
///
/// @brief Creates an ArrayRef of uint8_t from a StringRef of raw bytes.
LLVM_ATTRIBUTE_ALWAYS_INLINE
static llvm::ArrayRef<std::uint8_t> ToArrayRef(llvm::StringRef bytes) noexcept
{
  return llvm::ArrayRef<std::uint8_t>(
    reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
}

/// @fn ToStringRef
///
/// @brief Creates a StringRef of raw bytes from an ArrayRef of uint8_t.
LLVM_ATTRIBUTE_ALWAYS_INLINE
static llvm::StringRef ToStringRef(llvm::ArrayRef<std::uint8_t> bytes) noexcept
{
  return llvm::StringRef(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

} // namespace shellcode_asm


#endif // !SHELLCODE_ASM_UTILITY_H_
