#if !defined(SHELLCODE_ASM_DISASSEMBLE_H_)
#define SHELLCODE_ASM_DISASSEMBLE_H_

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/raw_ostream.h"

#include "shellcode-asm/Utility.h"

namespace shellcode_asm
{

class Composition;

/// @class  DisassembledInst
///
/// @brief  Contains the address, opcode bytes, and instruction text of a disassembled machine code
///         instruction.
class DisassembledInst final
{
public:
  DisassembledInst(std::uint64_t address, std::uint8_t addressWidth, 
    llvm::ArrayRef<std::uint8_t> bytes, std::string&& text) noexcept;

  std::uint64_t address() const noexcept
  {
    return address_;
  }

  std::uint8_t address_width() const noexcept
  {
    return address_width_;
  }

  llvm::StringRef bytes() const noexcept
  {
    return ToStringRef(bytes_);
  }

  std::string_view text() const noexcept
  {
    return text_;
  }

private:
  std::uint64_t address_;
  std::uint8_t address_width_;
  llvm::SmallVector<std::uint8_t, 16> bytes_;
  std::string text_;
};

/// @struct Disassembled
///
/// @brief  Contains the results of a disassemble operation, including the list of successfully
///         disassembled instructions and a list of any errors that occurred during the disassembly
///         process.
struct Disassembled final
{
  std::vector<DisassembledInst> Insts;
  std::vector<std::string> Errors;
};

/// @fn disassemble
///
/// @brief  Disassembles the given input machine code to a list of instruction addresses, 
///         opcode bytes, and mnemonic text representations.
///
/// @param  composition     The composition used for configuring the disassembler.
/// @param  assembledBytes  The input machine code to be disassembled.
llvm::Expected<Disassembled> disassemble(
  const Composition& composition, llvm::ArrayRef<std::uint8_t> assembledBytes) noexcept;

/// @fn llvm::StringRef to_string(const DisassembledInst&, llvm::SmallVectorImpl<char>&) noexcept;
///
/// @brief  Converts the given disassembled instruction containiner to a string containing a
///         hexadecimal address, a string of hexadecimal digit pairs representing the instruction's
///         opcode bytes, and the mnemonic text representation of the instruction.
///
/// @param        disasmInst  The disassembled instruction.
/// @param [out]  outString   The output string.
///
/// @returns  A StringRef referencing outString.
llvm::StringRef to_string(
  const DisassembledInst& disasmInst, llvm::SmallVectorImpl<char>& outString) noexcept;

/// @fn std::string to_string(const DisassembledInst&) noexcept;
///
/// @brief  Converts the given disassembled instruction containiner to a string containing a
///         hexadecimal address, a string of hexadecimal digit pairs representing the instruction's
///         opcode bytes, and the mnemonic text representation of the instruction.
///
/// @param  disasmInst  The disassembled instruction.
std::string to_string(const DisassembledInst& disasmInst) noexcept;

/// @fn llvm::raw_ostream& to_string(const DisassembledInst&, llvm::raw_ostream&) noexcept;
///
/// @brief  Writes a text representation of the given disassembled instruction to the given output 
///         stream.
llvm::raw_ostream& to_string(const DisassembledInst& disasmInst, llvm::raw_ostream& os) noexcept;

} // namespace shellcode_asm


#endif // !SHELLCODE_ASM_DISASSEMBLE_H_
