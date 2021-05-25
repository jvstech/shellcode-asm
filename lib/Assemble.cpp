#include "shellcode-asm/Assemble.h"

#include <cassert>
#include <memory>
#include <set>

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/Triple.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCParser/MCAsmParser.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/Object/Binary.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/ErrorOr.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SMLoc.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetRegistry.h"

#include "shellcode-asm/Composition.h"
#include "shellcode-asm/Errors.h"

namespace obj = llvm::object;

namespace
{
///
/// Returns a list of all the code sections in an object file ordered by their address. For 
/// shellcode, the object file almost always contains a single code section, but this handles the 
/// unlikely/rare possibility of other code sections existing.
///
std::vector<obj::SectionRef> getOrderedCodeSections(const obj::ObjectFile& objectFile) noexcept
{
  struct SectionOrderer final
  {
    bool operator()(obj::SectionRef a, obj::SectionRef b) const noexcept
    {
      return a.getAddress() < b.getAddress();
    }
  };

  std::set<obj::SectionRef, SectionOrderer> codeSections;
  for (obj::SectionRef section : objectFile.sections())
  {
    if (section.isText())
    {
      codeSections.insert(section);
    }
  }
  
  return std::vector<obj::SectionRef>(codeSections.begin(), codeSections.end());
}

[[maybe_unused]]
bool isSectionReadOnly(obj::SectionRef section) noexcept
{
  assert(section.getObject() && "Section does not belong to an object file.");
  // TODO: Support ELF and Mach-O.
  // This is sort of a pain to implement so I'm not going to do it right now. COFF sections are 
  // easy. ELF sections are easy once you've cast the section to the proper 32-bit or 64-bit type.
  // Mach-O is a *huge* pain because individual sections don't have permissions -- you have to get
  // the permissions of their containing segment. And prior to final linkage, *every* segment is
  // RWX. Their *implied* default permissions are based on the segment name instead. The 
  // cctools-port source code lists what these sections are defaulted to being read-only (or RX), 
  // but I can't be bothered to look at it right now.
  // Since I'm building this tool and library mostly for OSED/OSEE -- which is Windows only -- I'm
  // sticking with just COFF support for the time being.
  if (!section.getObject()->isCOFF())
  {
    // Assume the section is read-only.
    return true;
  }

  const obj::COFFObjectFile* coffObj = llvm::cast<obj::COFFObjectFile>(section.getObject());
  const obj::coff_section* coffSection = coffObj->getCOFFSection(section);
  unsigned int flags = static_cast<unsigned int>(coffSection->Characteristics);
  return ((flags & llvm::COFF::IMAGE_SCN_MEM_WRITE) == 0);
}

} // namespace 


llvm::Expected<std::vector<std::uint8_t>> shellcode_asm::assemble(
  const Composition& composition, llvm::StringRef inputAsm) noexcept
{
  auto& target = composition.target();
  auto& triple = composition.triple();

  // Add the input assembly text to a source manager to be used by later assembly-related objects.
  auto inputBuffer = llvm::MemoryBuffer::getMemBufferCopy(inputAsm);
  llvm::SourceMgr srcMgr;
  srcMgr.AddNewSourceBuffer(std::move(inputBuffer), llvm::SMLoc());
  
  // Create the initial MC context with the given object file info instance.
  llvm::MCObjectFileInfo mofi;
  llvm::MCContext ctx(&composition.mc_asm_info(), &composition.mc_register_info(), &mofi, &srcMgr,
    &composition.mc_target_options());
  // For almost all scenarios, shellcode is PIC-only using a tiny/small code model.
  mofi.InitMCObjectFileInfo(triple, /*PIC*/ true, ctx, /*LargeCodeModel*/ false);

  llvm::SmallString<1024> bytes;
  llvm::raw_svector_ostream os(bytes);
  auto streamerOrErr = composition.CreateMCObjectStreamer(os, ctx);
  if (!streamerOrErr)
  {
    return streamerOrErr.takeError();
  }

  auto& streamer = *streamerOrErr;
  std::unique_ptr<llvm::MCAsmParser> parser(llvm::createMCAsmParser(srcMgr, ctx, *streamer,
    composition.mc_asm_info()));
  if (!parser)
  {
    return llvm::make_error<MachineCreationError>("assembly parser");
  }

  std::unique_ptr<llvm::MCTargetAsmParser> targetParser(target.createMCAsmParser(
    composition.mc_subtarget_info(), *parser, composition.mc_instr_info(), 
    composition.mc_target_options()));
  if (!targetParser)
  {
    return llvm::make_error<MCTargetAsmParserError>();
  }

  if (triple.isX86())
  {
    parser->getLexer().setLexMasmIntegers(composition.options().MASMHex);
    if (!composition.options().ATTSyntax)
    {
      // In the X86 backend, assembler dialect 0 is AT&T syntax while dialect 1
      // is Intel syntax.
      parser->setAssemblerDialect(1);
    }
  }

  parser->setTargetParser(*targetParser);
  bool hadErr = parser->Run(/*NoInitialTextSection*/ false);
  if (hadErr)
  {
    return llvm::make_error<AssembleError>();
  }

  // Now that we have the assembled object file, we have to extract the code from it.
  // 
  // FIXME: There is probably a MUCH better way of doing this. (Perhaps by wrapping MCCodeEmitter?
  // Maybe?) The goal is to not have to create an object file at all -- just emit a flat binary 
  // with only local relocations and immutable values (.rdata) appended.
  
  auto objMemBuffer =
    llvm::MemoryBuffer::getMemBuffer(bytes, /*BufferName*/ "", /*RequiresNullTerminator*/ false);
  auto binaryOrErr = obj::createBinary(*objMemBuffer);
  if (!binaryOrErr)
  {
    return binaryOrErr.takeError();
  }

  obj::Binary& binary = **binaryOrErr;
  obj::ObjectFile* o = llvm::dyn_cast<obj::ObjectFile>(&binary);
  if (!o)
  {
    return llvm::make_error<ObjectFileError>();
  }

  std::vector<std::uint8_t> codeBytes;
  auto codeSections = getOrderedCodeSections(*o);
  // TODO: Check to make sure there aren't any relocations to mutable sections or external symbols.
  for (auto section : codeSections)
  {
    auto contents = section.getContents();
    if (!contents)
    {
      return contents.takeError();
    }

    codeBytes.reserve(contents->size());
    codeBytes.insert(codeBytes.end(), contents->bytes_begin(), contents->bytes_end());
    // TODO: Possibly support more than one text section in the future. For now -- and in the most
    // likely scenarios -- there is only intended to be one section entirely. Multiple sections
    // should probably have a default/configurable alignment.
    break;
  }

  return codeBytes;
}
