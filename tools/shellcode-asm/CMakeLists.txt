add_llvm_executable(shellcode-asm 
  shellcode-asm.cpp

  DEPENDS
  ShellcodeAsm
  )

install(TARGETS shellcode-asm DESTINATION bin)

target_include_directories(shellcode-asm
  PRIVATE 
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/../include
    )

target_link_libraries(shellcode-asm PUBLIC ShellcodeAsm)

set_target_properties(shellcode-asm
  PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    )
if (MSVC)
  set_target_properties(shellcode-asm
    PROPERTIES
      COMPILE_DEFINITIONS "_SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING=1")
endif()