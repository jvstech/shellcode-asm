#if !defined(SHELLCODE_ASM_COMPOSITION_H_)
#define SHELLCODE_ASM_COMPOSITION_H_

#include <memory>
#include <string>
#include <string_view>

#include "llvm/ADT/Triple.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/TargetRegistry.h"

#include "shellcode-asm/CompositionOptions.h"

namespace shellcode_asm
{
/// @class  Composition
///
/// @brief  Provides basic construction logic for assembly- and disassembly-related objects using
///         simple configuration options. This class cannot be inherited.
class Composition final
{
  Composition(CompositionOptions&& options) noexcept;

public:

  const CompositionOptions& options() const noexcept
  {
    return options_;
  }

  const llvm::MCAsmInfo& mc_asm_info() const noexcept;
  const llvm::MCInstrInfo& mc_instr_info() const noexcept;
  const llvm::MCRegisterInfo& mc_register_info() const noexcept;
  const llvm::MCSubtargetInfo& mc_subtarget_info() const noexcept;
  const llvm::MCTargetOptions& mc_target_options() const noexcept;
  const llvm::Target& target() const noexcept;
  const llvm::Triple& triple() const noexcept;

  llvm::Expected<std::unique_ptr<llvm::MCStreamer>> CreateMCObjectStreamer(
    llvm::raw_pwrite_stream& os, llvm::MCContext& ctx) const noexcept;

  llvm::Expected<std::unique_ptr<llvm::MCDisassembler>> CreateMCDisassembler(
    llvm::MCContext& ctx) const noexcept;

  static llvm::Expected<Composition> Create(CompositionOptions&& options) noexcept;

private:
  CompositionOptions options_;
  const llvm::Target* target_{nullptr};
  llvm::Triple triple_{};
  
  std::unique_ptr<llvm::MCRegisterInfo> mc_register_info_{};
  std::unique_ptr<llvm::MCTargetOptions> mc_target_options_{};
  std::unique_ptr<llvm::MCAsmInfo> mc_asm_info_{};
  std::unique_ptr<llvm::MCInstrInfo> mc_instr_info_{};
  std::unique_ptr<llvm::MCSubtargetInfo> mc_subtarget_info_{};
};

} // namespace shellcode_asm


#endif // !SHELLCODE_ASM_COMPOSITION_H_
