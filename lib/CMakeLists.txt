add_llvm_library(ShellcodeAsm
  Assemble.cpp
  Composition.cpp
  CompositionOptions.cpp
  CompositionCommandLineOptions.cpp
  Disassemble.cpp
  Errors.cpp
  )

target_include_directories(ShellcodeAsm
  PRIVATE 
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/../include
    )

set_target_properties(ShellcodeAsm
  PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON)
if (MSVC)
  set_target_properties(ShellcodeAsm
    PROPERTIES
      COMPILE_DEFINITIONS "_SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING=1")
endif()
