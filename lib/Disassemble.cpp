#include "shellcode-asm/Disassemble.h"

#include <memory>

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/Triple.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCParser/MCAsmParser.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/Object/Binary.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/ErrorOr.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SMLoc.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetRegistry.h"

#include "shellcode-asm/Composition.h"
#include "shellcode-asm/Errors.h"


shellcode_asm::DisassembledInst::DisassembledInst(std::uint64_t address, std::uint8_t addressWidth, 
  llvm::ArrayRef<std::uint8_t> bytes, std::string&& text) noexcept
  : address_(address),
  address_width_(addressWidth),
  bytes_(bytes.begin(), bytes.end()),
  text_(std::move(text))
{
}

llvm::Expected<shellcode_asm::Disassembled> shellcode_asm::disassemble(
  const Composition& composition, llvm::ArrayRef<std::uint8_t> assembledBytes) noexcept
{
  auto& target = composition.target();
  auto& triple = composition.triple();
  std::uint8_t addressWidth = [&]
  {
    if (triple.isArch64Bit())
    {
      return static_cast<std::uint8_t>(8);
    }

    return static_cast<std::uint8_t>((triple.isArch32Bit() ? 4 : 2));
  }();
  llvm::HexStyle::Style hexStyle = (triple.isX86() && composition.options().MASMHex
    ? llvm::HexStyle::Asm
    : llvm::HexStyle::C);
  auto inputBuffer = llvm::MemoryBuffer::getMemBuffer(
    ToStringRef(assembledBytes), /*BufferName*/ "", /*RequiresNullTerminator*/ false);
  llvm::SourceMgr srcMgr;
  srcMgr.AddNewSourceBuffer(std::move(inputBuffer), llvm::SMLoc());

  llvm::MCObjectFileInfo mofi;
  llvm::MCContext ctx(&composition.mc_asm_info(), &composition.mc_register_info(), &mofi, &srcMgr,
    &composition.mc_target_options());
  // For almost all scenarios, shellcode is PIC-only using a tiny/small code model.
  mofi.InitMCObjectFileInfo(triple, /*PIC*/ true, ctx, /*LargeCodeModel*/ false);

  auto disasmOrErr = composition.CreateMCDisassembler(ctx);
  if (!disasmOrErr)
  {
    return disasmOrErr.takeError();
  }

  auto* disasm = disasmOrErr->get();
  llvm::SmallString<1024> bytes;
  llvm::raw_svector_ostream os(bytes);
  auto streamerOrErr = composition.CreateMCObjectStreamer(os, ctx);
  if (!streamerOrErr)
  {
    return streamerOrErr.takeError();
  }

  auto& streamer = *streamerOrErr;
  streamer->setUseAssemblerInfoForParsing(true);
  streamer->InitSections(/*NoExecStack*/ false);

  int asmPrinterVariant = composition.mc_asm_info().getAssemblerDialect();
  if (triple.isX86() && !composition.options().ATTSyntax)
  {
    // In the X86 backend, assembler dialect 0 is AT&T syntax while dialect 1
    // is Intel syntax.
    asmPrinterVariant = 1;
  }

  std::unique_ptr<llvm::MCInstPrinter> instPrinter(target.createMCInstPrinter(
    triple, asmPrinterVariant, composition.mc_asm_info(), composition.mc_instr_info(),
    composition.mc_register_info()));
  if (!instPrinter)
  {
    return llvm::make_error<MachineCreationError>("instruction printer");
  }

  instPrinter->setPrintImmHex(true);
  instPrinter->setPrintHexStyle(hexStyle);
  instPrinter->setPrintBranchImmAsAddress(true);

  shellcode_asm::Disassembled results;
  std::vector<shellcode_asm::DisassembledInst>& disasms = results.Insts;
  std::size_t size;
  // Instruction decoding loop.
  for (std::size_t idx = 0; idx < assembledBytes.size(); idx += size)
  {
    llvm::MCInst inst;
    llvm::MCDisassembler::DecodeStatus status;
    status = disasm->getInstruction(inst, size, assembledBytes.slice(idx), idx, llvm::nulls());
    switch (status)
    {
    case llvm::MCDisassembler::Fail:
      {
        std::string errText;
        llvm::raw_string_ostream s(errText);
        srcMgr.PrintMessage(s, llvm::SMLoc::getFromPointer(
          reinterpret_cast<const char*>(assembledBytes.data()) + idx), llvm::SourceMgr::DK_Warning,
          "invalid instruction encoding");
        s.flush();
        results.Errors.push_back(std::move(errText));
        if (size == 0)
        {
          // Skip illegible bytes.
          size = 1;
        }
      }

      break;

    case llvm::MCDisassembler::SoftFail:
      {
        std::string errText;
        llvm::raw_string_ostream s(errText);
        srcMgr.PrintMessage(s, llvm::SMLoc::getFromPointer(
          reinterpret_cast<const char*>(assembledBytes.data()) + idx), llvm::SourceMgr::DK_Warning,
          "potentially undefined instruction encoding");
        s.flush();
        results.Errors.push_back(std::move(errText));
      }

      LLVM_FALLTHROUGH;

    case llvm::MCDisassembler::Success:
      {
        streamer->emitInstruction(inst, composition.mc_subtarget_info());
        std::string instText;
        llvm::raw_string_ostream s(instText);
        // On x86 (and maybe other architectures -- I know not which others), the instruction 
        // pointer refers to the address immediately following the "currently executing" 
        // instruction. As such, we adjust the instruction address accordingly. Without doing so, 
        // branching instructions point to incorrect addresses.
        uint64_t addr = idx + (triple.isX86() ? size : 0);
        instPrinter->printInst(&inst, addr, "", composition.mc_subtarget_info(), s);
        s.flush();
        instText = llvm::StringRef(instText).trim().data();
        disasms.emplace_back(idx, addressWidth, assembledBytes.slice(idx).take_front(size),
          std::move(instText));
      }
      break;
    }
  }

  return results;
}

llvm::StringRef shellcode_asm::to_string(
  const DisassembledInst& disasmInst, llvm::SmallVectorImpl<char>& outString) noexcept
{
  llvm::raw_svector_ostream os(outString);
  to_string(disasmInst, os);
  return os.str();
}

std::string shellcode_asm::to_string(const DisassembledInst& disasmInst) noexcept
{
  std::string s;
  llvm::raw_string_ostream os(s);
  to_string(disasmInst, os);
  return os.str();
}

llvm::raw_ostream& shellcode_asm::to_string(
  const DisassembledInst& disasmInst, llvm::raw_ostream& os) noexcept
{
  os << llvm::format_hex_no_prefix(disasmInst.address(), disasmInst.address_width() << 1) << "  ";
  for (std::uint8_t b : disasmInst.bytes())
  {
    os << llvm::format_hex_no_prefix(b, 2);
  }

  if (disasmInst.bytes().size() >= 15)
  {
    os << "  ";
  }
  else
  {
    os << std::string(17 - (disasmInst.bytes().size() << 1), ' ');
  }

  os << disasmInst.text().data();
  return os;
}
