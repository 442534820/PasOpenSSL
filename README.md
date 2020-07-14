# PasOpenSSL
OpenSSL lib support for Delphi

## How to build my 'libcrypto-3.dll' ?
1. Install Visual Studio 2015+
2. Install Strawberry Perl: http://straberryperl.com
3. Install NASM: https://www.nasm.us
4. Configure Windows enviroment variable '%PATH%', put the path of NASM into %PATH%
5. Download openssl source code: https://github.com/openssl/openssl
6. Run cmd line tool by VS:
    (64bit)...\Microsoft Visual Studio\20xx\Community\VC\Auxiliary\Build\vcvars64
    (32bit)...\Microsoft Visual Studio\20xx\Community\VC\Auxiliary\Build\vcvarsamd64_x86
7. Switch to openssl root dir
8. Configure build params:
    (64bit) perl Configure VC-WIN64A shared no-asm
    (32bit) perl Configure VC-WIN32 shared no-asm
9. Do make:
    nmake
10. Wait for build done and copy your target files and enjoy openssl
