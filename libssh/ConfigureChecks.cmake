include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckTypeSize)
include(CheckCXXSourceCompiles)
include(TestBigEndian)

set(PACKAGE ${APPLICATION_NAME})
set(VERSION ${APPLICATION_VERSION})
set(DATADIR ${DATA_INSTALL_DIR})
set(LIBDIR ${LIB_INSTALL_DIR})
set(PLUGINDIR "${PLUGIN_INSTALL_DIR}-${LIBRARY_SOVERSION}")
set(SYSCONFDIR ${SYSCONF_INSTALL_DIR})

set(BINARYDIR ${CMAKE_BINARY_DIR})
set(SOURCEDIR ${CMAKE_SOURCE_DIR})

function(COMPILER_DUMPVERSION _OUTPUT_VERSION)
    # Remove whitespaces from the argument.
    # This is needed for CC="ccache gcc" cmake ..
    string(REPLACE " " "" _C_COMPILER_ARG "${CMAKE_C_COMPILER_ARG1}")

    execute_process(
        COMMAND
            ${CMAKE_C_COMPILER} ${_C_COMPILER_ARG} -dumpversion
        OUTPUT_VARIABLE _COMPILER_VERSION
    )

    string(REGEX REPLACE "([0-9])\\.([0-9])(\\.[0-9])?" "\\1\\2"
           _COMPILER_VERSION "${_COMPILER_VERSION}")

    set(${_OUTPUT_VERSION} ${_COMPILER_VERSION} PARENT_SCOPE)
endfunction()

if(CMAKE_COMPILER_IS_GNUCC AND NOT MINGW AND NOT OS2)
    compiler_dumpversion(GNUCC_VERSION)
    if (NOT GNUCC_VERSION EQUAL 34)
        set(CMAKE_REQUIRED_FLAGS "-fvisibility=hidden")
        check_c_source_compiles(
"void __attribute__((visibility(\"default\"))) test() {}
int main(void){ return 0; }
" WITH_VISIBILITY_HIDDEN)
        set(CMAKE_REQUIRED_FLAGS "")
    endif (NOT GNUCC_VERSION EQUAL 34)
endif(CMAKE_COMPILER_IS_GNUCC AND NOT MINGW AND NOT OS2)

# HEADER FILES
set(CMAKE_REQUIRED_INCLUDES_SAVE ${CMAKE_REQUIRED_INCLUDES})
set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES} ${ARGP_INCLUDE_DIR})
check_include_file(argp.h HAVE_ARGP_H)
set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES_SAVE})

check_include_file(pty.h HAVE_PTY_H)
check_include_file(utmp.h HAVE_UTMP_H)
check_include_file(termios.h HAVE_TERMIOS_H)
check_include_file(unistd.h HAVE_UNISTD_H)
check_include_file(util.h HAVE_UTIL_H)
check_include_file(libutil.h HAVE_LIBUTIL_H)
check_include_file(sys/time.h HAVE_SYS_TIME_H)
check_include_file(sys/utime.h HAVE_SYS_UTIME_H)
check_include_file(sys/param.h HAVE_SYS_PARAM_H)
check_include_file(arpa/inet.h HAVE_ARPA_INET_H)
check_include_file(byteswap.h HAVE_BYTESWAP_H)
check_include_file(glob.h HAVE_GLOB_H)

if (WIN32)
  check_include_file(io.h HAVE_IO_H)

  check_include_files("winsock2.h;ws2tcpip.h;wspiapi.h" HAVE_WSPIAPI_H)
  if (NOT HAVE_WSPIAPI_H)
    message(STATUS "WARNING: Without wspiapi.h, this build will only work on Windows XP and newer versions")
  endif (NOT HAVE_WSPIAPI_H)
  check_include_files("winsock2.h;ws2tcpip.h" HAVE_WS2TCPIP_H)
endif (WIN32)

if (OPENSSL_FOUND)
    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    check_include_file(openssl/des.h HAVE_OPENSSL_DES_H)
    if (NOT HAVE_OPENSSL_DES_H)
        message(FATAL_ERROR "Could not detect openssl/des.h")
    endif()

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    check_include_file(openssl/aes.h HAVE_OPENSSL_AES_H)
    if (NOT HAVE_OPENSSL_AES_H)
        message(FATAL_ERROR "Could not detect openssl/aes.h")
    endif()

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    check_include_file(openssl/blowfish.h HAVE_OPENSSL_BLOWFISH_H)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    check_include_file(openssl/ecdh.h HAVE_OPENSSL_ECDH_H)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    check_include_file(openssl/ec.h HAVE_OPENSSL_EC_H)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    check_include_file(openssl/ecdsa.h HAVE_OPENSSL_ECDSA_H)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(EVP_aes_128_ctr HAVE_OPENSSL_EVP_AES_CTR)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(EVP_aes_128_cbc HAVE_OPENSSL_EVP_AES_CBC)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(CRYPTO_THREADID_set_callback HAVE_OPENSSL_CRYPTO_THREADID_SET_CALLBACK)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(CRYPTO_ctr128_encrypt HAVE_OPENSSL_CRYPTO_CTR128_ENCRYPT)

    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
    check_function_exists(EVP_CIPHER_CTX_new HAVE_OPENSSL_EVP_CIPHER_CTX_NEW)
endif()

if (CMAKE_HAVE_PTHREAD_H)
  set(HAVE_PTHREAD_H 1)
endif (CMAKE_HAVE_PTHREAD_H)

if (NOT WITH_GCRYPT AND NOT WITH_MBEDTLS)
    if (HAVE_OPENSSL_EC_H AND HAVE_OPENSSL_ECDSA_H)
        set(HAVE_OPENSSL_ECC 1)
    endif (HAVE_OPENSSL_EC_H AND HAVE_OPENSSL_ECDSA_H)

    if (HAVE_OPENSSL_ECC)
        set(HAVE_ECC 1)
    endif (HAVE_OPENSSL_ECC)
endif ()

if (NOT WITH_MBEDTLS)
    set(HAVE_DSA 1)
endif()

# FUNCTIONS

check_function_exists(isblank HAVE_ISBLANK)
check_function_exists(strncpy HAVE_STRNCPY)
check_function_exists(strtoull HAVE_STRTOULL)
check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
check_function_exists(memset_s HAVE_MEMSET_S)

if (HAVE_GLOB_H)
  check_function_exists(glob HAVE_GLOB)
endif (HAVE_GLOB_H)

if (NOT WIN32)
  check_function_exists(vsnprintf HAVE_VSNPRINTF)
  check_function_exists(snprintf HAVE_SNPRINTF)
endif (NOT WIN32)

if (WIN32)
    check_symbol_exists(vsnprintf "stdio.h" HAVE_VSNPRINTF)
    check_symbol_exists(snprintf "stdio.h" HAVE_SNPRINTF)

    check_symbol_exists(_vsnprintf_s "stdio.h" HAVE__VSNPRINTF_S)
    check_symbol_exists(_vsnprintf "stdio.h" HAVE__VSNPRINTF)
    check_symbol_exists(_snprintf "stdio.h" HAVE__SNPRINTF)
    check_symbol_exists(_snprintf_s "stdio.h" HAVE__SNPRINTF_S)

    if (HAVE_WSPIAPI_H OR HAVE_WS2TCPIP_H)
        check_symbol_exists(ntohll winsock2.h HAVE_NTOHLL)
        check_symbol_exists(htonll winsock2.h HAVE_HTONLL)

        set(CMAKE_REQUIRED_LIBRARIES ws2_32)
        check_symbol_exists(select "winsock2.h;ws2tcpip.h" HAVE_SELECT)
        check_symbol_exists(poll "winsock2.h;ws2tcpip.h" HAVE_SELECT)
        # The getaddrinfo function is defined to the WspiapiGetAddrInfo inline function
        check_symbol_exists(getaddrinfo "winsock2.h;ws2tcpip.h" HAVE_GETADDRINFO)
        set(CMAKE_REQUIRED_LIBRARIES)
    endif (HAVE_WSPIAPI_H OR HAVE_WS2TCPIP_H)

    check_function_exists(_strtoui64 HAVE__STRTOUI64)

    set(HAVE_SELECT TRUE)

    check_symbol_exists(SecureZeroMemory "windows.h" HAVE_SECURE_ZERO_MEMORY)
else (WIN32)
    check_function_exists(poll HAVE_POLL)
    check_function_exists(select HAVE_SELECT)
    check_function_exists(getaddrinfo HAVE_GETADDRINFO)

    check_symbol_exists(ntohll arpa/inet.h HAVE_NTOHLL)
    check_symbol_exists(htonll arpa/inet.h HAVE_HTONLL)
endif (WIN32)


if (UNIX)
    if (NOT LINUX)
        # libsocket (Solaris)
        check_library_exists(socket getaddrinfo "" HAVE_LIBSOCKET)
        if (HAVE_LIBSOCKET)
            set(HAVE_GETADDRINFO TRUE)
            set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} socket)
        endif (HAVE_LIBSOCKET)

        # libnsl/inet_pton (Solaris)
        check_library_exists(nsl inet_pton "" HAVE_LIBNSL)
        if (HAVE_LIBNSL)
            set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} nsl)
        endif (HAVE_LIBNSL)

        # librt
        check_library_exists(rt nanosleep "" HAVE_LIBRT)
    endif (NOT LINUX)

    check_library_exists(rt clock_gettime "" HAVE_CLOCK_GETTIME)
    if (HAVE_LIBRT OR HAVE_CLOCK_GETTIME)
        set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} rt)
    endif (HAVE_LIBRT OR HAVE_CLOCK_GETTIME)

    check_library_exists(util forkpty "" HAVE_LIBUTIL)
    check_function_exists(cfmakeraw HAVE_CFMAKERAW)
    check_function_exists(__strtoull HAVE___STRTOULL)
endif (UNIX)

set(LIBSSH_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} CACHE INTERNAL "libssh required system libraries")

# LIBRARIES
if (OPENSSL_FOUND)
  set(HAVE_LIBCRYPTO 1)
endif (OPENSSL_FOUND)

if (GCRYPT_FOUND)
    set(HAVE_LIBGCRYPT 1)
    if (GCRYPT_VERSION VERSION_GREATER "1.4.6")
        set(HAVE_GCRYPT_ECC 1)
        set(HAVE_ECC 1)
    endif (GCRYPT_VERSION VERSION_GREATER "1.4.6")
endif (GCRYPT_FOUND)

if (MBEDTLS_FOUND)
    set(HAVE_LIBMBEDCRYPTO 1)
    set(HAVE_ECC 1)
endif (MBEDTLS_FOUND)

if (CMAKE_USE_PTHREADS_INIT)
    set(HAVE_PTHREAD 1)
endif (CMAKE_USE_PTHREADS_INIT)

# OPTIONS
check_c_source_compiles("
__thread int tls;

int main(void) {
    return 0;
}" HAVE_GCC_THREAD_LOCAL_STORAGE)

check_c_source_compiles("
__declspec(thread) int tls;

int main(void) {
    return 0;
}" HAVE_MSC_THREAD_LOCAL_STORAGE)

check_c_source_compiles("
#define FALL_THROUGH __attribute__((fallthrough))

enum direction_e {
    UP = 0,
    DOWN,
};

int main(void) {
    enum direction_e key = UP;
    int i = 10;
    int j = 0;

    switch (key) {
    case UP:
        i = 5;
        FALL_THROUGH;
    case DOWN:
        j = i * 2;
        break;
    default:
        break;
    }

    return 0;
}" HAVE_FALLTHROUGH_ATTRIBUTE)

check_c_source_compiles("
#include <string.h>

int main(void)
{
    char buf[] = \"This is some content\";

    memset(buf, '\\\\0', sizeof(buf)); __asm__ volatile(\"\" : : \"g\"(&buf) : \"memory\");

    return 0;
}" HAVE_GCC_VOLATILE_MEMORY_PROTECTION)

check_c_source_compiles("
#include <stdio.h>
#define __VA_NARG__(...) (__VA_NARG_(_0, ## __VA_ARGS__, __RSEQ_N()) - 1)
#define __VA_NARG_(...) __VA_ARG_N(__VA_ARGS__)
#define __VA_ARG_N( _1, _2, _3, _4, _5, _6, _7, _8, _9,_10,N,...) N
#define __RSEQ_N() 10, 9,  8,  7,  6,  5,  4,  3,  2,  1,  0
#define myprintf(format, ...) printf((format), __VA_NARG__(__VA_ARGS__), __VA_ARGS__)
int main(void) {
    myprintf(\"%d %d %d %d\",1,2,3);
    return 0;
}" HAVE_GCC_NARG_MACRO)

check_c_source_compiles("
#include <stdio.h>
int main(void) {
    printf(\"%s\", __func__);
    return 0;
}" HAVE_COMPILER__FUNC__)

check_c_source_compiles("
#include <stdio.h>
int main(void) {
    printf(\"%s\", __FUNCTION__);
    return 0;
}" HAVE_COMPILER__FUNCTION__)


if (WITH_DEBUG_CRYPTO)
  set(DEBUG_CRYPTO 1)
endif (WITH_DEBUG_CRYPTO)

if (WITH_DEBUG_PACKET)
  set(DEBUG_PACKET 1)
endif (WITH_DEBUG_PACKET)

if (WITH_DEBUG_CALLTRACE)
  set(DEBUG_CALLTRACE 1)
endif (WITH_DEBUG_CALLTRACE)

if (WITH_GSSAPI AND NOT GSSAPI_FOUND)
    set(WITH_GSSAPI 0)
endif (WITH_GSSAPI AND NOT GSSAPI_FOUND)

# ENDIAN
if (NOT WIN32)
    test_big_endian(WORDS_BIGENDIAN)
endif (NOT WIN32)
