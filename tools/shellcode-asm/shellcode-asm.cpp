#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/Optional.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/Triple.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/ExecutionEngine/RuntimeDyld.h"
#include "llvm/LineEditor/LineEditor.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/MC/MCTargetOptionsCommandFlags.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/WithColor.h"

#include "shellcode-asm/Assemble.h"
#include "shellcode-asm/Composition.h"
#include "shellcode-asm/CompositionOptions.h"
#include "shellcode-asm/Disassemble.h"
#include "shellcode-asm/Errors.h"
#include "shellcode-asm/Utility.h"

namespace cl = llvm::cl;
namespace fs = llvm::sys::fs;

namespace
{

enum class OutputFormat
{
  Raw,
  Hex,
  HexRaw,
  C,
  CXX,
  Python,
  Decode
};

std::unique_ptr<llvm::ToolOutputFile> getOutputFile(llvm::StringRef path,
  fs::OpenFlags flags) noexcept
{
  std::error_code ec;
  auto outFile = std::make_unique<llvm::ToolOutputFile>(path, ec, flags);
  if (ec)
  {
    llvm::WithColor::error() << ec.message() << "\n";
    return nullptr;
  }

  return outFile;
}

void logError(llvm::Error&& err, llvm::raw_ostream& es) noexcept
{
  llvm::outs().flush();
  llvm::WithColor::error(es);
  llvm::logAllUnhandledErrors(std::move(err), es);
  es << "\n";
}

void logError(llvm::Error&& err) noexcept
{
  logError(std::move(err), llvm::errs());
}

void writeRaw(llvm::raw_ostream& os, llvm::StringRef bytes) noexcept
{
  os.write(bytes.data(), bytes.size());
  os.flush();
}

void writeHex(llvm::raw_ostream& os, llvm::StringRef bytes, bool raw) noexcept
{
  auto bytesRef = shellcode_asm::ToArrayRef(bytes);
  os << llvm::format_bytes(bytesRef,
    /*FirstByteOffset*/ llvm::None,
    /*NumPerLine*/ (raw ? static_cast<std::uint32_t>(-1) : 16),
    /*ByteGroupSize*/ 1)
    << "\n";
}

void writeCLang(llvm::raw_ostream& os, llvm::StringRef bytes, bool isCxx) noexcept
{
  if (bytes.empty())
  {
    return;
  }

  if (isCxx)
  {
    os << "constexpr char buf[" << bytes.size() << "]";
  }
  else
  {
    os << "const char buf[" << bytes.size() << "]";
  }

  os << " = {\n";
  for (std::size_t row = 0; row < bytes.size(); row += 8)
  {
    os << "  ";
    for (std::size_t col = 0; col < 8 && (col + row) < bytes.size(); ++col)
    {
      std::uint8_t b = static_cast<std::uint8_t>(bytes[row + col]);
      os << llvm::format_hex(b, 4);
      if (col + row < bytes.size() - 1)
      {
        os << ", ";
      }
    }
    
    os << "\n";
  }

  os << "};\n";
}

void writePython(llvm::raw_ostream& os, llvm::StringRef bytes) noexcept
{
  os << "buf = b\"\"\n";
  for (std::size_t row = 0; row < bytes.size(); row += 16)
  {
    os << "buf += b\"";
    for (std::size_t col = 0; col < 16 && (col + row) < bytes.size(); ++col)
    {
      std::uint8_t b = static_cast<std::uint8_t>(bytes[row + col]);
      os << "\\x" << llvm::format_hex_no_prefix(b, 2);
    }

    os << "\"\n";
  }
}

void writeDecoded(llvm::raw_ostream& os, llvm::StringRef bytes) noexcept
{
  auto compOpts = shellcode_asm::InitCompositionCommandLineOptions();
  auto c = shellcode_asm::Composition::Create(std::move(compOpts));
  if (!c)
  {
    logError(c.takeError());
    return;
  }

  auto disasm = shellcode_asm::disassemble(*c, shellcode_asm::ToArrayRef(bytes));
  if (!disasm)
  {
    logError(disasm.takeError());
    return;
  }

  for (const auto& e : disasm->Errors)
  {
    llvm::WithColor::error() << e << "\n";
  }

  for (const auto& d : disasm->Insts)
  {
    shellcode_asm::to_string(d, os) << "\n";
  }
}

void writeBytes(llvm::raw_ostream& os, OutputFormat mode, llvm::StringRef bytes) noexcept
{
  switch (mode)
  {
  case OutputFormat::Raw:
    writeRaw(os, bytes);
    break;
  case OutputFormat::Hex:
    writeHex(os, bytes, /*raw*/ false);
    break;
  case OutputFormat::HexRaw:
    writeHex(os, bytes, /*raw*/ true);
    break;
  case OutputFormat::C:
    writeCLang(os, bytes, /*isCxx*/ false);
    break;
  case OutputFormat::CXX:
    writeCLang(os, bytes, /*isCxx*/ true);
    break;
  case OutputFormat::Python:
    writePython(os, bytes);
    break;
  case OutputFormat::Decode:
    writeDecoded(os, bytes);
    break;
  }
}

int runShell(const shellcode_asm::Composition& composition, llvm::raw_ostream& ofs, 
  OutputFormat outputFmt) noexcept
{
  llvm::outs() << "Single-line shell mode; send EOF (Ctrl-"
#if defined(_WIN32)
    "Z"
#else
    "D"
#endif
    ") to quit.\n\n";
  llvm::LineEditor lineEditor("shellcode-asm ");
  while (auto inputLine = lineEditor.readLine())
  {
    std::unique_ptr<llvm::MemoryBuffer> bufferPtr = llvm::MemoryBuffer::getMemBuffer(*inputLine);
    auto codeBytes = shellcode_asm::assemble(composition, bufferPtr->getBuffer());
    if (!codeBytes)
    {
      auto err = codeBytes.takeError();
      if (!err.isA<shellcode_asm::AssembleError>())
      {
        logError(std::move(err));
        return 1;
      }
      else
      {
        llvm::consumeError(std::move(err));
      }
    }
    else
    {
      writeBytes(ofs, outputFmt, shellcode_asm::ToStringRef(*codeBytes));
    }
  }

  return 0;
}

} // namespace 


int main(int argc, char** argv)
{
  llvm::InitLLVM x(argc, argv);
  
  // Command-line options
  shellcode_asm::GetCLCategoryName() = "shellcode-asm options";
  shellcode_asm::RegisterCompositionCommandLineOptions scalo;
  static_cast<void>(scalo);
  auto& appCat = shellcode_asm::GetCLCategory();
  
  cl::opt<std::string> inputFilename(
    cl::Positional, cl::init("-"), cl::desc("<input file>"), cl::cat(appCat));
  cl::opt<std::string> outputFilename(
    "o", cl::desc("Output filename"), cl::value_desc("filename"), cl::init("-"), cl::cat(appCat));
  cl::opt<bool> shellMode(
    "shell", cl::desc("Shell mode (similar to msf-nasm_shell)"), cl::cat(appCat));
  cl::opt<bool> disasm("disasm", cl::desc("Disassemble raw bytes"), cl::cat(appCat));
  cl::opt<OutputFormat> outputFmt("format", cl::init(OutputFormat::Hex), cl::cat(appCat),
    cl::desc("Choose an output format (only when assembling):"),
    cl::values(
      clEnumValN(OutputFormat::Raw, "raw", "Emit raw bytes"),
      clEnumValN(OutputFormat::Hex, "hex", "Emit formatted pairs of hex digits"),
      clEnumValN(OutputFormat::HexRaw, "hexraw", "Emit unformatted pairs of hex digits"),
      clEnumValN(OutputFormat::C, "c", "Emit a C-style array"),
      clEnumValN(OutputFormat::CXX, "cxx", "Emit a C++-style array"),
      clEnumValN(OutputFormat::Python, "py", "Emit a Python byte array"),
      clEnumValN(OutputFormat::Decode, "decode", 
        "Emit decoded addresses, opcodes, and instructions")));
  
  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  cl::SetVersionPrinter([](llvm::raw_ostream& os)
    {
      os << "shellcode-asm - based on LLVM " LLVM_VERSION_STRING << "\n\n";
      llvm::TargetRegistry::printRegisteredTargetsForVersion(os);
    });
  
  // Parse command line options
  cl::HideUnrelatedOptions(appCat);
  cl::ParseCommandLineOptions(argc, argv, "shellcode assembler/disassembler");

  shellcode_asm::CompositionOptions opts = shellcode_asm::InitCompositionCommandLineOptions();
    llvm::Expected<shellcode_asm::Composition> c = 
    shellcode_asm::Composition::Create(std::move(opts));
  if (!c)
  {
    logError(c.takeError());
    return 1;
  }

  // Set the output stream.
  fs::OpenFlags outFlags = fs::OF_Text;
  if (outputFmt == OutputFormat::Raw)
  {
    outFlags = disasm ? fs::OF_Text : fs::OF_None;
  }
  
  if (shellMode)
  {
    outputFilename = "-";
    outFlags = fs::OF_Text;
  }

  std::unique_ptr<llvm::ToolOutputFile> outFile = getOutputFile(outputFilename, outFlags);
  if (!outFile)
  {
    return 1;
  }

  if (!shellMode)
  {
    std::unique_ptr<llvm::MemoryBuffer> bufferPtr;
    // Load the input file.
    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> bufferPtrOrErr =
      llvm::MemoryBuffer::getFileOrSTDIN(inputFilename);
    if (std::error_code ec = bufferPtrOrErr.getError())
    {
      llvm::WithColor::error(llvm::errs(), argv[0]) << inputFilename << ": " << ec.message() 
        << '\n';
      return 1;
    }

    bufferPtr = std::move(*bufferPtrOrErr);
    if (!disasm)
    {
      auto codeBytes = shellcode_asm::assemble(*c, bufferPtr->getBuffer());
      if (!codeBytes)
      {
        logError(codeBytes.takeError());
        return 1;
      }

      writeBytes(outFile->os(), outputFmt, shellcode_asm::ToStringRef(*codeBytes));
    }
    else
    {
      auto bytesRef = bufferPtr->getBuffer();
      llvm::ArrayRef<std::uint8_t> assembledBytes = shellcode_asm::ToArrayRef(bytesRef);
      auto disasm = shellcode_asm::disassemble(*c, assembledBytes);
      if (!disasm)
      {
        logError(disasm.takeError());
        return 1;
      }

      if (!disasm->Errors.empty())
      {
        for (const std::string& e : disasm->Errors)
        {
          llvm::WithColor::warning() << e << "\n";
        }
      }

      for (const auto& d : disasm->Insts)
      {
        shellcode_asm::to_string(d, outFile->os()) << "\n";
      }
    }

    outFile->keep();
    return 0;
  }
  else
  {
    return runShell(*c, outFile->os(), outputFmt);
  }
  
  return 0;
}
