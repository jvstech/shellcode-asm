#if !defined(SHELLCODE_ASM_COMPOSITIONOPTIONS_H_)
#define SHELLCODE_ASM_COMPOSITIONOPTIONS_H_

#include <string>

#include "llvm/ADT/Triple.h"

// Forward declarations
namespace llvm::cl
{

class OptionCategory;

} // namespace llvm::cl


namespace shellcode_asm
{
/// @struct CompositionOptions
///
/// @brief  Provides the most basic parameters used for constructing a Composition object. This 
///         struct cannot be inherited.
struct CompositionOptions final
{
  std::string Arch{};
  std::string CPU{};
  std::string TargetTriple{};
  bool ATTSyntax{false};
  bool MASMHex{false};

  llvm::Triple getTriple() const noexcept;
};

/// @struct RegisterCompositionCommandLineOptions
///
/// @brief  Similar to llvm::RegisterMCTargetOptionsFlags, create this object with static storage
///         to register shellcode-asm-related command-line options.
struct RegisterCompositionCommandLineOptions final
{
  RegisterCompositionCommandLineOptions() noexcept;
};

/// @fn GetCLCategoryName
///
/// @brief  Returns a reference to the string used for naming the command-line options category
///         related to internal Composition construction. Defaults to "shellcode-asm".
std::string& GetCLCategoryName() noexcept;

/// @fn GetCLCategory
///
/// @brief  Returns a reference to the command-line options category related to internal 
///         Composition construction.
llvm::cl::OptionCategory& GetCLCategory() noexcept;

/// @fn InitCompositionCommandLineOptions
///
/// @brief  Constructs a CompositionOptions instance using values specified by command-line 
///         arguments. This function may only be used after instantiating a 
///         RegisterCompositionCommandLineOptions object with static storage duration. 
CompositionOptions InitCompositionCommandLineOptions() noexcept;

} // namespace shellcode_asm


#endif // !SHELLCODE_ASM_COMPOSITIONOPTIONS_H_
