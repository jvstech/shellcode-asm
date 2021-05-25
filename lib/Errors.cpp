#include "shellcode-asm/Errors.h"

char shellcode_asm::ShellcodeAsmError::ID = 0;

std::error_code shellcode_asm::ShellcodeAsmError::convertToErrorCode() const
{
  return std::make_error_code(std::errc::not_supported);
}

char shellcode_asm::TargetError::ID = 0;

shellcode_asm::TargetError::TargetError(const std::string& errMsg) noexcept
  : err_(errMsg)
{
}

void shellcode_asm::TargetError::log(llvm::raw_ostream& os) const noexcept
{
  os << err_;
}

char shellcode_asm::MachineCreationError::ID = 0;

shellcode_asm::MachineCreationError::MachineCreationError(const std::string& objectDesc) noexcept
  : object_desc_(objectDesc.empty() ? "machine code object" : objectDesc)
{
}

void shellcode_asm::MachineCreationError::log(llvm::raw_ostream& os) const noexcept
{
  os << "unable to create " << object_desc_;
}

char shellcode_asm::MCTargetAsmParserError::ID = 0;

void shellcode_asm::MCTargetAsmParserError::log(llvm::raw_ostream& os) const noexcept
{
  os << "this target does not support assembly parsing";
}


char shellcode_asm::AssembleError::ID = 0;

void shellcode_asm::AssembleError::log(llvm::raw_ostream& os) const noexcept
{
  os << "error(s) occurred while assembling";
}

char shellcode_asm::ObjectFileError::ID = 0;

void shellcode_asm::ObjectFileError::log(llvm::raw_ostream& os) const noexcept
{
  os << "unsupported or unrecognized object format";
}

char shellcode_asm::DisassemblerError::ID = 0;

shellcode_asm::DisassemblerError::DisassemblerError(const std::string& err) noexcept
  : err_(err),
  triple_()
{
}

shellcode_asm::DisassemblerError::DisassemblerError(const llvm::Triple& triple) noexcept
  : err_(),
  triple_(triple.getTriple())
{
}

void shellcode_asm::DisassemblerError::log(llvm::raw_ostream& os) const noexcept
{
  if (err_.empty())
  {
    os << "no disassembler for target " << triple_;
  }
  else
  {
    os << err_;
  }
}

char shellcode_asm::DisassembleError::ID = 0;

shellcode_asm::DisassembleError::DisassembleError(const std::string& errMsg) noexcept
  : err_(errMsg.empty() ? "error(s) occurred while disassembling" : errMsg)
{
}

void shellcode_asm::DisassembleError::log(llvm::raw_ostream& os) const noexcept
{
  os << err_;
}
