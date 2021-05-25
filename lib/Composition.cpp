#include "shellcode-asm/Composition.h"

#include <memory>
#include <utility>

#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/TargetRegistry.h"

#include "shellcode-asm/Errors.h"

namespace
{

llvm::Expected<const llvm::Target*> getTarget(
  const std::string& arch, std::string& tripleName) noexcept
{
  // Figure out the target triple.
  if (tripleName.empty())
  {
    tripleName = llvm::sys::getDefaultTargetTriple();
  }
  
  llvm::Triple triple(llvm::Triple::normalize(tripleName));

  // Get the target specific parser.
  std::string err;
  const llvm::Target* target = llvm::TargetRegistry::lookupTarget(arch, triple, err);
  if (!target)
  {
    return llvm::make_error<shellcode_asm::TargetError>(err);
  }

  // Update the triple name and return the found target.
  tripleName = triple.getTriple();
  return target;
}

llvm::MCTargetOptions* createDefaultMCTargetOptions() noexcept
{
  llvm::MCTargetOptions* options = new llvm::MCTargetOptions();
  // TODO: Set default option values here:
  //   options->MCRelaxAll = getRelaxAll();
  //   options->MCIncrementalLinkerCompatible = getIncrementalLinkerCompatible();
  //   options->Dwarf64 = getDwarf64();
  //   options->DwarfVersion = getDwarfVersion();
  //   options->ShowMCInst = getShowMCInst();
  //   options->ABIName = getABIName();
  //   options->MCFatalWarnings = getFatalWarnings();
  //   options->MCNoWarn = getNoWarn();
  //   options->MCNoDeprecatedWarn = getNoDeprecatedWarn();
  return options;
}

} // namespace

shellcode_asm::Composition::Composition(CompositionOptions&& options) noexcept
  : options_(std::move(options))
{
}

const llvm::MCAsmInfo& shellcode_asm::Composition::mc_asm_info() const noexcept
{
  return *mc_asm_info_;
}

const llvm::MCInstrInfo& shellcode_asm::Composition::mc_instr_info() const noexcept
{
  return *mc_instr_info_;
}

const llvm::MCRegisterInfo& shellcode_asm::Composition::mc_register_info() const noexcept
{
  return *mc_register_info_;
}

const llvm::MCSubtargetInfo& shellcode_asm::Composition::mc_subtarget_info() const noexcept
{
  return *mc_subtarget_info_;
}

const llvm::MCTargetOptions& shellcode_asm::Composition::mc_target_options() const noexcept
{
  return *mc_target_options_;
}

const llvm::Target& shellcode_asm::Composition::target() const noexcept
{
  return *target_;
}

const llvm::Triple& shellcode_asm::Composition::triple() const noexcept
{
  return triple_;
}

auto shellcode_asm::Composition::CreateMCObjectStreamer(
  llvm::raw_pwrite_stream& os, llvm::MCContext& ctx) const noexcept
  -> llvm::Expected<std::unique_ptr<llvm::MCStreamer>>
{
  std::unique_ptr<llvm::MCAsmBackend> backend(target_->createMCAsmBackend(
    mc_subtarget_info(), mc_register_info(), mc_target_options()));
  if (!backend)
  {
    return llvm::make_error<MachineCreationError>("assembler backend");
  }

  std::unique_ptr<llvm::MCCodeEmitter> codeEmitter(target_->createMCCodeEmitter(mc_instr_info(), 
    mc_register_info(), ctx));
  if (!codeEmitter)
  {
    return llvm::make_error<MachineCreationError>("code emitter");
  }

  std::unique_ptr<llvm::MCObjectWriter> writer(backend->createObjectWriter(os));
  if (!writer)
  {
    return llvm::make_error<MachineCreationError>("object writer");
  }

  std::unique_ptr<llvm::MCStreamer> streamer(target_->createMCObjectStreamer(triple(), ctx,
    std::move(backend), std::move(writer), std::move(codeEmitter), mc_subtarget_info(),
    /*RelaxAll*/ mc_target_options().MCRelaxAll,
    /*IncrementalLinkerCompatible*/ mc_target_options().MCIncrementalLinkerCompatible,
    /*DWARFMustBeAtTheEnd*/ false));
  if (!streamer)
  {
    return llvm::make_error<MachineCreationError>("machine code stream");
  }

  return streamer;
}

auto shellcode_asm::Composition::CreateMCDisassembler(llvm::MCContext& ctx) const noexcept
  -> llvm::Expected<std::unique_ptr<llvm::MCDisassembler>>
{
  std::unique_ptr<llvm::MCDisassembler> disasm(
    target_->createMCDisassembler(mc_subtarget_info(), ctx));
  if (!disasm)
  {
    return llvm::make_error<DisassemblerError>(triple().getTriple());
  }

  return disasm;
}

llvm::Expected<shellcode_asm::Composition> shellcode_asm::Composition::Create(
  CompositionOptions&& options) noexcept
{
  Composition composition(std::move(options));
  auto target = getTarget(options.Arch, composition.options_.TargetTriple);
  if (!target)
  {
    return target.takeError();
  }

  composition.target_ = *target;
  composition.triple_ = composition.options_.getTriple();
  std::unique_ptr<llvm::MCRegisterInfo> mri(
    composition.target_->createMCRegInfo(composition.options_.TargetTriple));
  if (!mri)
  {
    return llvm::make_error<MachineCreationError>("register information");
  }

  composition.mc_register_info_ = std::move(mri);
  composition.mc_target_options_.reset(createDefaultMCTargetOptions());

  std::unique_ptr<llvm::MCAsmInfo> mai(composition.target_->createMCAsmInfo(
    *composition.mc_register_info_, composition.options_.TargetTriple, 
    composition.mc_target_options()));
  if (!mai)
  {
    return llvm::make_error<MachineCreationError>("assembler information");
  }

  composition.mc_asm_info_ = std::move(mai);

  std::unique_ptr<llvm::MCInstrInfo> mii(composition.target_->createMCInstrInfo());
  if (!mii)
  {
    return llvm::make_error<MachineCreationError>("assembler instruction information");
  }

  composition.mc_instr_info_ = std::move(mii);

  std::string featureStr;
  // TODO: Set the features string (if necessary).
  std::unique_ptr<llvm::MCSubtargetInfo> sti(composition.target_->createMCSubtargetInfo(
    composition.options_.TargetTriple, composition.options_.CPU, featureStr));
  if (!sti)
  {
    return llvm::make_error<MachineCreationError>("subtarget information");
  }

  composition.mc_subtarget_info_ = std::move(sti);

  return composition;
}
