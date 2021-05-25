#if !defined(SHELLCODE_ASM_LIB_ERRORS_H_)
#define SHELLCODE_ASM_LIB_ERRORS_H_

#include <string>
#include <system_error>

#include "llvm/ADT/Triple.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/raw_ostream.h"

namespace shellcode_asm
{
/// @struct ShellcodeAsmError
///
/// @brief  Base type for all errors generated from assembly or disassembly operations.
struct ShellcodeAsmError : public llvm::ErrorInfo<ShellcodeAsmError>
{
  static char ID;
  
  virtual ~ShellcodeAsmError() = default;

  virtual std::error_code convertToErrorCode() const override;
};

template <typename T>
using SCAsmErrorInfo = llvm::ErrorInfo<T, ShellcodeAsmError>;

/// @class  TargetError
///
/// @brief  A target-specific assembly/disassembly error. This class cannot be inherited.
class TargetError final : public SCAsmErrorInfo<TargetError>
{
protected:
  using Base = SCAsmErrorInfo<TargetError>;

public:
  
  static char ID;

  TargetError(const std::string& errMsg) noexcept;

  void log(llvm::raw_ostream& os) const noexcept override;

private:
  std::string err_;
};

/// @class  MachineCreationError
///
/// @brief  Base class representing errors that occur when failing to construct 
///         machine-code-related objects.
class MachineCreationError : public SCAsmErrorInfo<MachineCreationError>
{
protected:
  template <typename T>
  using Base = llvm::ErrorInfo<T, MachineCreationError>;

public:
  
  static char ID;

  MachineCreationError(const std::string& objectDesc) noexcept;
  virtual ~MachineCreationError() = default;

  virtual void log(llvm::raw_ostream& os) const noexcept override;

  const std::string& object_desc() const noexcept
  {
    return object_desc_;
  }

private:
  std::string object_desc_;
};

struct MCTargetAsmParserError final : public SCAsmErrorInfo<MCTargetAsmParserError>
{
  static char ID;
  
  void log(llvm::raw_ostream& os) const noexcept override;
};

/// @struct AssembleError
///
/// @brief  Error generated during an assembly text lexical analysis or parsing operation. This
///         struct cannot be inherited.
struct AssembleError final : public SCAsmErrorInfo<AssembleError>
{
  static char ID;
  void log(llvm::raw_ostream& os) const noexcept override;
};

struct ObjectFileError final : public SCAsmErrorInfo<ObjectFileError>
{
  static char ID;
  void log(llvm::raw_ostream& os) const noexcept override;
};

class DisassemblerError final : public SCAsmErrorInfo<DisassemblerError>
{
public:
  static char ID;
  DisassemblerError(const std::string& err) noexcept;
  DisassemblerError(const llvm::Triple& triple) noexcept;
  void log(llvm::raw_ostream& os) const noexcept override;

private:
  std::string err_;
  std::string triple_;
};

/// @class  DisassembleError
///
/// @brief  Error generated from an instruction decoding operations during disassembly. This class 
///         cannot be inherited.
class DisassembleError final : public SCAsmErrorInfo<DisassembleError>
{
public:
  static char ID;
  DisassembleError() = default;
  DisassembleError(const std::string& errMsg) noexcept;
  void log(llvm::raw_ostream& os) const noexcept override;

private:
  std::string err_;
};

} // namespace shellcode_asm


#endif // !SHELLCODE_ASM_LIB_ERRORS_H_
