# shellcode-asm
LLVM-based library and tool for assembling and disassembling shellcode

## Usage

### Install LLVM libraries and headers

```bash
sudo apt install llvm-dev
```

Alternatively, check out, build, and install [LLVM from source](https://github.com/llvm/llvm-project).

```bash
git clone https://github.com/llvm/llvm-project.git
cd llvm-project
cmake -S llvm -B build -G Ninja
cmake --build build
```

If you would prefer to use (or like to try) [llvm-toolchain](https://github.com/jvstech/llvm-toolchain) to check out, build, and install LLVM from source all at once:

```bash
git clone https://github.com/jvstech/llvm-toolchain.git
cmake -P llvm-toolchain/build-llvm-toolchain.cmake
```

### Building

You only need to ensure the CMake variable `PATH_TO_LLVM` points to the installation directory of LLVM.

```bash
git clone https://github.com/jvstech/shellcode-asm.git
cmake -S shellcode-asm -B build -G Ninja -DPATH_TO_LLVM=/usr/lib/llvm-11
cmake --build build
```
