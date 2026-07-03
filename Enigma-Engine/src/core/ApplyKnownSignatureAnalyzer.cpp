#include <ghidra/ApplyKnownSignatureAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/SignatureSource.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/ParameterDefinitionImpl.h>
#include <ghidra/ParameterImpl.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/Undefined.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <iostream>

namespace ghidra {

namespace {

// -------- Known function signature database --------

struct RawSig {
    const char* name;
    const char* retType;
    const char* const* paramTypes;
    int paramCount;
    bool varargs;
    bool noreturn;
    const char* callingConvention;
};

// C standard library
static const char* _p_abort[] = {};
static const char* _p_free[] = {"void *"};
static const char* _p_malloc[] = {"size_t"};
static const char* _p_calloc[] = {"size_t", "size_t"};
static const char* _p_realloc[] = {"void *", "size_t"};
static const char* _p_memcpy[] = {"void *", "void *", "size_t"};
static const char* _p_memset[] = {"void *", "int", "size_t"};
static const char* _p_strlen[] = {"char *"};
static const char* _p_exit[] = {"int"};
static const char* _p_atexit[] = {"void *"};

// Windows CRT
static const char* _p_Sleep[] = {"DWORD"};
static const char* _p_GetLastError[] = {};
static const char* _p_VirtualProtect[] = {"LPVOID", "SIZE_T", "DWORD", "PDWORD"};
static const char* _p_VirtualQuery[] = {"LPCVOID", "void *", "SIZE_T"};
static const char* _p_VirtualAlloc[] = {"LPVOID", "SIZE_T", "DWORD", "DWORD"};
static const char* _p_VirtualFree[] = {"LPVOID", "SIZE_T", "DWORD"};
static const char* _p_HeapAlloc[] = {"HANDLE", "DWORD", "SIZE_T"};
static const char* _p_HeapFree[] = {"HANDLE", "DWORD", "LPVOID"};
static const char* _p_HeapReAlloc[] = {"HANDLE", "DWORD", "LPVOID", "SIZE_T"};
static const char* _p_HeapSize[] = {"HANDLE", "DWORD", "LPCVOID"};
static const char* _p_GetProcessHeap[] = {};
static const char* _p_InitializeCriticalSection[] = {"void *"};
static const char* _p_InitializeCriticalSectionAndSpinCount[] = {"void *", "DWORD"};
static const char* _p_EnterCriticalSection[] = {"void *"};
static const char* _p_TryEnterCriticalSection[] = {"void *"};
static const char* _p_LeaveCriticalSection[] = {"void *"};
static const char* _p_DeleteCriticalSection[] = {"void *"};
static const char* _p_CreateThread[] = {"void *", "SIZE_T", "void *", "LPVOID", "DWORD", "LPDWORD"};
static const char* _p_CreateRemoteThread[] = {"HANDLE", "void *", "SIZE_T", "void *", "LPVOID", "DWORD", "LPDWORD"};
static const char* _p_WaitForSingleObject[] = {"HANDLE", "DWORD"};
static const char* _p_WaitForMultipleObjects[] = {"DWORD", "HANDLE *", "BOOL", "DWORD"};
static const char* _p_CloseHandle[] = {"HANDLE"};
static const char* _p_LoadLibraryA[] = {"LPCSTR"};
static const char* _p_LoadLibraryW[] = {"LPCWSTR"};
static const char* _p_LoadLibraryExA[] = {"LPCSTR", "HANDLE", "DWORD"};
static const char* _p_GetProcAddress[] = {"HMODULE", "LPCSTR"};
static const char* _p_FreeLibrary[] = {"HMODULE"};
static const char* _p_GetStdHandle[] = {"DWORD"};
static const char* _p_WriteFile[] = {"HANDLE", "LPCVOID", "DWORD", "LPDWORD", "void *"};
static const char* _p_ReadFile[] = {"HANDLE", "LPVOID", "DWORD", "LPDWORD", "void *"};
static const char* _p_TerminateProcess[] = {"HANDLE", "UINT"};
static const char* _p_ExitProcess[] = {"UINT"};
static const char* _p_GetCommandLineA[] = {};
static const char* _p_GetModuleHandleA[] = {"LPCSTR"};
static const char* _p_RaiseException[] = {"DWORD", "DWORD", "DWORD", "void *"};
static const char* _p_SetUnhandledExceptionFilter[] = {"void *"};
static const char* _p_UnhandledExceptionFilter[] = {"void *"};
static const char* _p_GetSystemInfo[] = {"void *"};
static const char* _p_IsProcessorFeaturePresent[] = {"DWORD"};
static const char* _p_QueryPerformanceCounter[] = {"int64 *"};
static const char* _p_GetCurrentProcess[] = {};
static const char* _p_GetCurrentThread[] = {};
static const char* _p_GetCurrentProcessId[] = {};
static const char* _p_GetCurrentThreadId[] = {};
static const char* _p_SetLastError[] = {"DWORD"};
static const char* _p_CreateFileA[] = {"LPCSTR", "DWORD", "DWORD", "void *", "DWORD", "DWORD", "HANDLE"};
static const char* _p_DeleteFileA[] = {"LPCSTR"};
static const char* _p_FlushInstructionCache[] = {"HANDLE", "LPCVOID", "SIZE_T"};
static const char* _p_EncodePointer[] = {"PVOID"};
static const char* _p_DecodePointer[] = {"PVOID"};
static const char* _p_GetSystemTimeAsFileTime[] = {"void *"};
static const char* _p_SetStdHandle[] = {"BOOL", "HANDLE"};
static const char* _p_GetFileType[] = {"HANDLE"};
static const char* _p_SetHandleInformation[] = {"HANDLE", "DWORD", "DWORD"};
static const char* _p_GetEnvironmentStringsA[] = {};
static const char* _p_FreeEnvironmentStringsA[] = {"LPSTR"};
static const char* _p_GetEnvironmentVariableA[] = {"LPCSTR", "LPSTR", "DWORD"};
static const char* _p_SetEnvironmentVariableA[] = {"LPCSTR", "LPCSTR"};
static const char* _p_FlushProcessWriteBuffers[] = {};
static const char* _p_GetStartupInfoA[] = {"void *"};
static const char* _p_GetModuleHandleExA[] = {"DWORD", "LPCSTR", "HMODULE *"};

// Internal CRT (MSVC)
static const char* _p_amsg_exit[] = {"int"};
static const char* _p__exit[] = {"int"};
static const char* _p__initterm[] = {"void *", "void *"};
static const char* _p__set_app_type[] = {"int"};
static const char* _p_beginthreadex[] = {"void *", "unsigned", "void *", "void *", "unsigned", "unsigned *"};
static const char* _p_endthreadex[] = {"unsigned"};
static const char* _p__assert[] = {"void *", "void *", "unsigned"};

// Extended C standard library
static const char* _p_printf[] = {"char *"};
static const char* _p_fprintf[] = {"void *", "char *"};
static const char* _p_sprintf[] = {"char *", "char *"};
static const char* _p_snprintf[] = {"char *", "size_t", "char *"};
static const char* _p_puts[] = {"char *"};
static const char* _p_scanf[] = {"char *"};
static const char* _p_sscanf[] = {"char *", "char *"};
static const char* _p_fscanf[] = {"void *", "char *"};
static const char* _p_memmove[] = {"void *", "void *", "size_t"};
static const char* _p_memcmp[] = {"void *", "void *", "size_t"};
static const char* _p_memchr[] = {"void *", "void *", "int", "size_t"};
static const char* _p_strnlen[] = {"char *", "size_t"};
static const char* _p_strcpy[] = {"char *", "char *"};
static const char* _p_strncpy[] = {"char *", "char *", "size_t"};
static const char* _p_strcat[] = {"char *", "char *"};
static const char* _p_strncat[] = {"char *", "char *", "size_t"};
static const char* _p_strcmp[] = {"char *", "char *"};
static const char* _p_strncmp[] = {"char *", "char *", "size_t"};
static const char* _p_strchr[] = {"char *", "int"};
static const char* _p_strrchr[] = {"char *", "int"};
static const char* _p_strstr[] = {"char *", "char *"};
static const char* _p_strspn[] = {"char *", "char *"};
static const char* _p_strcspn[] = {"char *", "char *"};
static const char* _p_strtok[] = {"char *", "char *"};
static const char* _p_strerror[] = {"int"};
static const char* _p_wcslen[] = {"wchar_t *"};
static const char* _p_wcscpy[] = {"wchar_t *", "wchar_t *"};
static const char* _p_wcscmp[] = {"wchar_t *", "wchar_t *"};
static const char* _p_qsort[] = {"void *", "size_t", "size_t", "void *"};
static const char* _p_bsearch[] = {"void *", "void *", "size_t", "size_t", "void *"};
static const char* _p_abs[] = {"int"};
static const char* _p_labs[] = {"long"};
static const char* _p_rand[] = {};
static const char* _p_srand[] = {"unsigned"};
static const char* _p_atof[] = {"char *"};
static const char* _p_atoi[] = {"char *"};
static const char* _p_atol[] = {"char *"};
static const char* _p_strtol[] = {"char *", "char *", "int"};
static const char* _p_strtoul[] = {"char *", "char *", "int"};
static const char* _p_strtoll[] = {"char *", "char *", "int"};
static const char* _p_strtoull[] = {"char *", "char *", "int"};
static const char* _p_fopen[] = {"char *", "char *"};
static const char* _p_fclose[] = {"void *"};
static const char* _p_fread[] = {"void *", "size_t", "size_t", "void *"};
static const char* _p_fwrite[] = {"void *", "size_t", "size_t", "void *"};
static const char* _p_fflush[] = {"void *"};
static const char* _p_fseek[] = {"void *", "long", "int"};
static const char* _p_ftell[] = {"void *"};
static const char* _p_rewind[] = {"void *"};
static const char* _p_ferror[] = {"void *"};
static const char* _p_feof[] = {"void *"};
static const char* _p_remove[] = {"char *"};
static const char* _p_rename[] = {"char *", "char *"};
static const char* _p_tmpfile[] = {};
static const char* _p_setvbuf[] = {"void *", "char *", "int", "size_t"};
static const char* _p_perror[] = {"char *"};
static const char* _p_time[] = {"void *"};
static const char* _p_clock[] = {};
static const char* _p_difftime[] = {"size_t", "size_t"};
static const char* _p_gmtime[] = {"void *"};
static const char* _p_localtime[] = {"void *"};
static const char* _p_mktime[] = {"void *"};
static const char* _p_asctime[] = {"void *"};
static const char* _p_ctime[] = {"void *"};
static const char* _p_strftime[] = {"char *", "size_t", "char *", "void *"};
static const char* _p_isalnum[] = {"int"};
static const char* _p_isalpha[] = {"int"};
static const char* _p_iscntrl[] = {"int"};
static const char* _p_isdigit[] = {"int"};
static const char* _p_isgraph[] = {"int"};
static const char* _p_islower[] = {"int"};
static const char* _p_isprint[] = {"int"};
static const char* _p_ispunct[] = {"int"};
static const char* _p_isspace[] = {"int"};
static const char* _p_isupper[] = {"int"};
static const char* _p_isxdigit[] = {"int"};
static const char* _p_tolower[] = {"int"};
static const char* _p_toupper[] = {"int"};
static const char* _p_setlocale[] = {"int", "char *"};

// Math library
static const char* _p_math_d[] = {"double"};
static const char* _p_atan2[] = {"double", "double"};
static const char* _p_pow[] = {"double", "double"};
static const char* _p_modf[] = {"double", "double *"};
static const char* _p_frexp[] = {"double", "int *"};
static const char* _p_ldexp[] = {"double", "int"};

// Extended CRT internal
static const char* _p__initterm_e[] = {"void *", "void *"};
static const char* _p__crtTerminateProcess[] = {};
static const char* _p__seh_filter_exe[] = {"void *", "void *"};
static const char* _p__set_fmode[] = {"int"};
static const char* _p__set_new_mode[] = {"int"};
static const char* _p__set_error_mode[] = {"int"};
static const char* _p__wassert[] = {"wchar_t *", "wchar_t *", "unsigned"};
static const char* _p__beginthread[] = {"void *", "unsigned", "void *"};
static const char* _p__endthread[] = {};
static const char* _p_configure_narrow[] = {"int"};
static const char* _p_initialize_wide[] = {};
static const char* _p_configthreadlocale[] = {"int", "void *"};

// Additional Kernel32
static const char* _p_GetProcessHeaps[] = {"DWORD", "HANDLE *"};
static const char* _p_GetModuleHandleW[] = {"LPCWSTR"};
static const char* _p_GetModuleHandleExW[] = {"DWORD", "LPCWSTR", "HMODULE *"};
static const char* _p_EncodeSystemPointer[] = {"PVOID"};
static const char* _p_DecodeSystemPointer[] = {"PVOID"};
static const char* _p_QueryPerformanceFrequency[] = {"int64 *"};
static const char* _p_GetCommandLineW[] = {};
static const char* _p_FreeEnvironmentStringsW[] = {"LPWSTR"};
static const char* _p_GetEnvironmentVariableW[] = {"LPCWSTR", "LPWSTR", "DWORD"};
static const char* _p_SetEnvironmentVariableW[] = {"LPCWSTR", "LPCWSTR"};
static const char* _p_GetNativeSystemInfo[] = {"void *"};

// Memory management
static const char* _p_LocalAlloc[] = {"UINT", "SIZE_T"};
static const char* _p_LocalFree[] = {"HANDLE"};
static const char* _p_GlobalAlloc[] = {"UINT", "SIZE_T"};
static const char* _p_GlobalFree[] = {"HANDLE"};
static const char* _p_HeapCreate[] = {"DWORD", "SIZE_T", "SIZE_T"};
static const char* _p_HeapDestroy[] = {"HANDLE"};
static const char* _p_VirtualLock[] = {"LPVOID", "SIZE_T"};
static const char* _p_VirtualUnlock[] = {"LPVOID", "SIZE_T"};

static const RawSig kKnownSigs[] = {
    // C standard library
    {"malloc", "void *", _p_malloc, 1, false, false, nullptr},
    {"calloc", "void *", _p_calloc, 2, false, false, nullptr},
    {"realloc", "void *", _p_realloc, 2, false, false, nullptr},
    {"free", "void", _p_free, 1, false, false, nullptr},
    {"memcpy", "void *", _p_memcpy, 3, false, false, nullptr},
    {"memset", "void *", _p_memset, 3, false, false, nullptr},
    {"strlen", "size_t", _p_strlen, 1, false, false, nullptr},
    {"exit", "void", _p_exit, 1, false, true, nullptr},
    {"abort", "void", _p_abort, 0, false, true, nullptr},
    {"atexit", "void *", _p_atexit, 1, false, false, nullptr},

    // Kernel32 / Windows API
    {"Sleep", "void", _p_Sleep, 1, false, false, "__stdcall"},
    {"SleepEx", "DWORD", _p_Sleep, 1, false, false, "__stdcall"},
    {"GetLastError", "DWORD", _p_GetLastError, 0, false, false, "__stdcall"},
    {"SetLastError", "void", _p_SetLastError, 1, false, false, "__stdcall"},
    {"VirtualProtect", "BOOL", _p_VirtualProtect, 4, false, false, "__stdcall"},
    {"VirtualQuery", "SIZE_T", _p_VirtualQuery, 3, false, false, "__stdcall"},
    {"VirtualAlloc", "LPVOID", _p_VirtualAlloc, 4, false, false, "__stdcall"},
    {"VirtualFree", "BOOL", _p_VirtualFree, 3, false, false, "__stdcall"},
    {"HeapAlloc", "LPVOID", _p_HeapAlloc, 3, false, false, "__stdcall"},
    {"HeapFree", "BOOL", _p_HeapFree, 3, false, false, "__stdcall"},
    {"HeapReAlloc", "LPVOID", _p_HeapReAlloc, 4, false, false, "__stdcall"},
    {"HeapSize", "SIZE_T", _p_HeapSize, 3, false, false, "__stdcall"},
    {"GetProcessHeap", "HANDLE", _p_GetProcessHeap, 0, false, false, "__stdcall"},
    {"InitializeCriticalSection", "void", _p_InitializeCriticalSection, 1, false, false, "__stdcall"},
    {"InitializeCriticalSectionAndSpinCount", "BOOL", _p_InitializeCriticalSectionAndSpinCount, 2, false, false, "__stdcall"},
    {"EnterCriticalSection", "void", _p_EnterCriticalSection, 1, false, false, "__stdcall"},
    {"TryEnterCriticalSection", "BOOL", _p_TryEnterCriticalSection, 1, false, false, "__stdcall"},
    {"LeaveCriticalSection", "void", _p_LeaveCriticalSection, 1, false, false, "__stdcall"},
    {"DeleteCriticalSection", "void", _p_DeleteCriticalSection, 1, false, false, "__stdcall"},
    {"CreateThread", "HANDLE", _p_CreateThread, 6, false, false, "__stdcall"},
    {"CreateRemoteThread", "HANDLE", _p_CreateRemoteThread, 7, false, false, "__stdcall"},
    {"WaitForSingleObject", "DWORD", _p_WaitForSingleObject, 2, false, false, "__stdcall"},
    {"WaitForMultipleObjects", "DWORD", _p_WaitForMultipleObjects, 4, false, false, "__stdcall"},
    {"CloseHandle", "BOOL", _p_CloseHandle, 1, false, false, "__stdcall"},
    {"LoadLibraryA", "HMODULE", _p_LoadLibraryA, 1, false, false, "__stdcall"},
    {"LoadLibraryW", "HMODULE", _p_LoadLibraryW, 1, false, false, "__stdcall"},
    {"LoadLibraryExA", "HMODULE", _p_LoadLibraryExA, 3, false, false, "__stdcall"},
    {"FreeLibrary", "BOOL", _p_FreeLibrary, 1, false, false, "__stdcall"},
    {"GetProcAddress", "void *", _p_GetProcAddress, 2, false, false, "__stdcall"},
    {"GetStdHandle", "HANDLE", _p_GetStdHandle, 1, false, false, "__stdcall"},
    {"WriteFile", "BOOL", _p_WriteFile, 5, false, false, "__stdcall"},
    {"ReadFile", "BOOL", _p_ReadFile, 5, false, false, "__stdcall"},
    {"TerminateProcess", "BOOL", _p_TerminateProcess, 2, false, false, "__stdcall"},
    {"ExitProcess", "void", _p_ExitProcess, 1, false, true, "__stdcall"},
    {"GetCommandLineA", "LPSTR", _p_GetCommandLineA, 0, false, false, "__stdcall"},
    {"GetModuleHandleA", "HMODULE", _p_GetModuleHandleA, 1, false, false, "__stdcall"},
    {"RaiseException", "void", _p_RaiseException, 4, false, false, "__stdcall"},
    {"SetUnhandledExceptionFilter", "void *", _p_SetUnhandledExceptionFilter, 1, false, false, "__stdcall"},
    {"UnhandledExceptionFilter", "LONG", _p_UnhandledExceptionFilter, 1, false, false, "__stdcall"},
    {"GetSystemInfo", "void", _p_GetSystemInfo, 1, false, false, "__stdcall"},
    {"CreateFileA", "HANDLE", _p_CreateFileA, 7, false, false, "__stdcall"},
    {"DeleteFileA", "BOOL", _p_DeleteFileA, 1, false, false, "__stdcall"},
    {"IsProcessorFeaturePresent", "BOOL", _p_IsProcessorFeaturePresent, 1, false, false, "__stdcall"},
    {"QueryPerformanceCounter", "BOOL", _p_QueryPerformanceCounter, 1, false, false, "__stdcall"},
    {"GetCurrentProcess", "HANDLE", _p_GetCurrentProcess, 0, false, false, "__stdcall"},
    {"GetCurrentThread", "HANDLE", _p_GetCurrentThread, 0, false, false, "__stdcall"},
    {"GetCurrentProcessId", "DWORD", _p_GetCurrentProcessId, 0, false, false, "__stdcall"},
    {"GetCurrentThreadId", "DWORD", _p_GetCurrentThreadId, 0, false, false, "__stdcall"},
    {"FlushInstructionCache", "BOOL", _p_FlushInstructionCache, 3, false, false, "__stdcall"},
    {"EncodePointer", "PVOID", _p_EncodePointer, 1, false, false, "__stdcall"},
    {"DecodePointer", "PVOID", _p_DecodePointer, 1, false, false, "__stdcall"},
    {"GetSystemTimeAsFileTime", "void", _p_GetSystemTimeAsFileTime, 1, false, false, "__stdcall"},
    {"SetStdHandle", "BOOL", _p_SetStdHandle, 2, false, false, "__stdcall"},
    {"GetFileType", "DWORD", _p_GetFileType, 1, false, false, "__stdcall"},
    {"SetHandleInformation", "BOOL", _p_SetHandleInformation, 3, false, false, "__stdcall"},
    {"GetEnvironmentStringsA", "LPSTR", _p_GetEnvironmentStringsA, 0, false, false, "__stdcall"},
    {"GetEnvironmentStringsW", "LPWSTR", _p_GetEnvironmentStringsA, 0, false, false, "__stdcall"},
    {"FreeEnvironmentStringsA", "BOOL", _p_FreeEnvironmentStringsA, 1, false, false, "__stdcall"},
    {"GetEnvironmentVariableA", "DWORD", _p_GetEnvironmentVariableA, 3, false, false, "__stdcall"},
    {"SetEnvironmentVariableA", "BOOL", _p_SetEnvironmentVariableA, 2, false, false, "__stdcall"},
    {"FlushProcessWriteBuffers", "void", _p_FlushProcessWriteBuffers, 0, false, false, "__stdcall"},
    {"GetStartupInfoA", "void", _p_GetStartupInfoA, 1, false, false, "__stdcall"},
    {"GetModuleHandleExA", "BOOL", _p_GetModuleHandleExA, 3, false, false, "__stdcall"},

    // Internal CRT (MSVC)
    {"_amsg_exit", "void", _p_amsg_exit, 1, false, false, nullptr},
    {"_exit", "void", _p__exit, 1, false, false, nullptr},
    {"_initterm", "void", _p__initterm, 2, false, false, nullptr},
    {"_set_app_type", "void", _p__set_app_type, 1, false, false, nullptr},
    {"_beginthreadex", "int", _p_beginthreadex, 6, false, false, nullptr},
    {"_endthreadex", "void", _p_endthreadex, 1, false, false, nullptr},
    {"_assert", "void", _p__assert, 3, false, false, nullptr},

    // Extended C standard library
    {"printf", "int", _p_printf, 1, true, false, nullptr},
    {"fprintf", "int", _p_fprintf, 2, true, false, nullptr},
    {"sprintf", "int", _p_sprintf, 2, true, false, nullptr},
    {"snprintf", "int", _p_snprintf, 3, true, false, nullptr},
    {"puts", "int", _p_puts, 1, false, false, nullptr},
    {"scanf", "int", _p_scanf, 1, true, false, nullptr},
    {"sscanf", "int", _p_sscanf, 2, true, false, nullptr},
    {"fscanf", "int", _p_fscanf, 2, true, false, nullptr},
    {"memmove", "void *", _p_memmove, 3, false, false, nullptr},
    {"memcmp", "int", _p_memcmp, 3, false, false, nullptr},
    {"memchr", "void *", _p_memchr, 4, false, false, nullptr},
    {"strnlen", "size_t", _p_strnlen, 2, false, false, nullptr},
    {"strcpy", "char *", _p_strcpy, 2, false, false, nullptr},
    {"strncpy", "char *", _p_strncpy, 3, false, false, nullptr},
    {"strcat", "char *", _p_strcat, 2, false, false, nullptr},
    {"strncat", "char *", _p_strncat, 3, false, false, nullptr},
    {"strcmp", "int", _p_strcmp, 2, false, false, nullptr},
    {"strncmp", "int", _p_strncmp, 3, false, false, nullptr},
    {"strchr", "char *", _p_strchr, 2, false, false, nullptr},
    {"strrchr", "char *", _p_strrchr, 2, false, false, nullptr},
    {"strstr", "char *", _p_strstr, 2, false, false, nullptr},
    {"strspn", "size_t", _p_strspn, 2, false, false, nullptr},
    {"strcspn", "size_t", _p_strcspn, 2, false, false, nullptr},
    {"strtok", "char *", _p_strtok, 2, false, false, nullptr},
    {"strerror", "char *", _p_strerror, 1, false, false, nullptr},
    {"wcslen", "size_t", _p_wcslen, 1, false, false, nullptr},
    {"wcscpy", "wchar_t *", _p_wcscpy, 2, false, false, nullptr},
    {"wcscmp", "int", _p_wcscmp, 2, false, false, nullptr},
    {"qsort", "void", _p_qsort, 4, false, false, nullptr},
    {"bsearch", "void *", _p_bsearch, 5, false, false, nullptr},
    {"abs", "int", _p_abs, 1, false, false, nullptr},
    {"labs", "long", _p_labs, 1, false, false, nullptr},
    {"rand", "int", _p_rand, 0, false, false, nullptr},
    {"srand", "void", _p_srand, 1, false, false, nullptr},
    {"atof", "double", _p_atof, 1, false, false, nullptr},
    {"atoi", "int", _p_atoi, 1, false, false, nullptr},
    {"atol", "long", _p_atol, 1, false, false, nullptr},
    {"strtol", "long", _p_strtol, 3, false, false, nullptr},
    {"strtoul", "ULONG", _p_strtoul, 3, false, false, nullptr},
    {"strtoll", "int64", _p_strtoll, 3, false, false, nullptr},
    {"strtoull", "uint64", _p_strtoull, 3, false, false, nullptr},
    {"fopen", "void *", _p_fopen, 2, false, false, nullptr},
    {"fclose", "int", _p_fclose, 1, false, false, nullptr},
    {"fread", "size_t", _p_fread, 4, false, false, nullptr},
    {"fwrite", "size_t", _p_fwrite, 4, false, false, nullptr},
    {"fflush", "int", _p_fflush, 1, false, false, nullptr},
    {"fseek", "int", _p_fseek, 3, false, false, nullptr},
    {"ftell", "long", _p_ftell, 1, false, false, nullptr},
    {"rewind", "void", _p_rewind, 1, false, false, nullptr},
    {"ferror", "int", _p_ferror, 1, false, false, nullptr},
    {"feof", "int", _p_feof, 1, false, false, nullptr},
    {"remove", "int", _p_remove, 1, false, false, nullptr},
    {"rename", "int", _p_rename, 2, false, false, nullptr},
    {"tmpfile", "void *", _p_tmpfile, 0, false, false, nullptr},
    {"setvbuf", "int", _p_setvbuf, 4, false, false, nullptr},
    {"perror", "void", _p_perror, 1, false, false, nullptr},
    {"time", "size_t", _p_time, 1, false, false, nullptr},
    {"clock", "size_t", _p_clock, 0, false, false, nullptr},
    {"difftime", "double", _p_difftime, 2, false, false, nullptr},
    {"gmtime", "void *", _p_gmtime, 1, false, false, nullptr},
    {"localtime", "void *", _p_localtime, 1, false, false, nullptr},
    {"mktime", "size_t", _p_mktime, 1, false, false, nullptr},
    {"asctime", "char *", _p_asctime, 1, false, false, nullptr},
    {"ctime", "char *", _p_ctime, 1, false, false, nullptr},
    {"strftime", "size_t", _p_strftime, 4, false, false, nullptr},
    {"isalnum", "int", _p_isalnum, 1, false, false, nullptr},
    {"isalpha", "int", _p_isalpha, 1, false, false, nullptr},
    {"iscntrl", "int", _p_iscntrl, 1, false, false, nullptr},
    {"isdigit", "int", _p_isdigit, 1, false, false, nullptr},
    {"isgraph", "int", _p_isgraph, 1, false, false, nullptr},
    {"islower", "int", _p_islower, 1, false, false, nullptr},
    {"isprint", "int", _p_isprint, 1, false, false, nullptr},
    {"ispunct", "int", _p_ispunct, 1, false, false, nullptr},
    {"isspace", "int", _p_isspace, 1, false, false, nullptr},
    {"isupper", "int", _p_isupper, 1, false, false, nullptr},
    {"isxdigit", "int", _p_isxdigit, 1, false, false, nullptr},
    {"tolower", "int", _p_tolower, 1, false, false, nullptr},
    {"toupper", "int", _p_toupper, 1, false, false, nullptr},
    {"setlocale", "char *", _p_setlocale, 2, false, false, nullptr},

    // Math library
    {"sin", "double", _p_math_d, 1, false, false, nullptr},
    {"cos", "double", _p_math_d, 1, false, false, nullptr},
    {"tan", "double", _p_math_d, 1, false, false, nullptr},
    {"asin", "double", _p_math_d, 1, false, false, nullptr},
    {"acos", "double", _p_math_d, 1, false, false, nullptr},
    {"atan", "double", _p_math_d, 1, false, false, nullptr},
    {"atan2", "double", _p_atan2, 2, false, false, nullptr},
    {"sinh", "double", _p_math_d, 1, false, false, nullptr},
    {"cosh", "double", _p_math_d, 1, false, false, nullptr},
    {"tanh", "double", _p_math_d, 1, false, false, nullptr},
    {"exp", "double", _p_math_d, 1, false, false, nullptr},
    {"log", "double", _p_math_d, 1, false, false, nullptr},
    {"log10", "double", _p_math_d, 1, false, false, nullptr},
    {"pow", "double", _p_pow, 2, false, false, nullptr},
    {"sqrt", "double", _p_math_d, 1, false, false, nullptr},
    {"ceil", "double", _p_math_d, 1, false, false, nullptr},
    {"floor", "double", _p_math_d, 1, false, false, nullptr},
    {"fabs", "double", _p_math_d, 1, false, false, nullptr},
    {"modf", "double", _p_modf, 2, false, false, nullptr},
    {"frexp", "double", _p_frexp, 2, false, false, nullptr},
    {"ldexp", "double", _p_ldexp, 2, false, false, nullptr},

    // Extended CRT internal
    {"_initterm_e", "int", _p__initterm_e, 2, false, false, nullptr},
    {"_crtTerminateProcess", "void", _p__crtTerminateProcess, 0, false, false, nullptr},
    {"_seh_filter_exe", "int", _p__seh_filter_exe, 2, false, false, nullptr},
    {"_set_fmode", "int", _p__set_fmode, 1, false, false, nullptr},
    {"_set_new_mode", "int", _p__set_new_mode, 1, false, false, nullptr},
    {"_set_error_mode", "int", _p__set_error_mode, 1, false, false, nullptr},
    {"_wassert", "void", _p__wassert, 3, false, false, nullptr},
    {"_beginthread", "int", _p__beginthread, 3, false, false, nullptr},
    {"_endthread", "void", _p__endthread, 0, false, false, nullptr},
    {"_configure_narrow_argv", "void", _p_configure_narrow, 1, false, false, nullptr},
    {"_configure_wide_argv", "void", _p_configure_narrow, 1, false, false, nullptr},
    {"_initialize_onexit_table", "int", _p_configure_narrow, 1, false, false, nullptr},  // uses int param
    {"_register_onexit_function", "int", _p__initterm_e, 2, false, false, nullptr},
    {"_crt_atexit", "int", _p_configure_narrow, 1, false, false, nullptr},
    {"_get_initial_narrow_environment", "char *", _p_initialize_wide, 0, false, false, nullptr},
    {"_initialize_narrow_argv", "int", _p_initialize_wide, 0, false, false, nullptr},
    {"_initialize_wide_argv", "int", _p_initialize_wide, 0, false, false, nullptr},

    // Additional Kernel32
    {"GetProcessHeaps", "DWORD", _p_GetProcessHeaps, 2, false, false, "__stdcall"},
    {"GetModuleHandleW", "HMODULE", _p_GetModuleHandleW, 1, false, false, "__stdcall"},
    {"GetModuleHandleExW", "BOOL", _p_GetModuleHandleExW, 3, false, false, "__stdcall"},
    {"EncodeSystemPointer", "PVOID", _p_EncodeSystemPointer, 1, false, false, "__stdcall"},
    {"DecodeSystemPointer", "PVOID", _p_DecodeSystemPointer, 1, false, false, "__stdcall"},
    {"QueryPerformanceFrequency", "BOOL", _p_QueryPerformanceFrequency, 1, false, false, "__stdcall"},
    {"GetCommandLineW", "LPWSTR", _p_GetCommandLineW, 0, false, false, "__stdcall"},
    {"FreeEnvironmentStringsW", "BOOL", _p_FreeEnvironmentStringsW, 1, false, false, "__stdcall"},
    {"GetEnvironmentVariableW", "DWORD", _p_GetEnvironmentVariableW, 3, false, false, "__stdcall"},
    {"SetEnvironmentVariableW", "BOOL", _p_SetEnvironmentVariableW, 2, false, false, "__stdcall"},
    {"GetNativeSystemInfo", "void", _p_GetNativeSystemInfo, 1, false, false, "__stdcall"},

    // Memory management
    {"LocalAlloc", "HANDLE", _p_LocalAlloc, 2, false, false, "__stdcall"},
    {"LocalFree", "HANDLE", _p_LocalFree, 1, false, false, "__stdcall"},
    {"GlobalAlloc", "HANDLE", _p_GlobalAlloc, 2, false, false, "__stdcall"},
    {"GlobalFree", "HANDLE", _p_GlobalFree, 1, false, false, "__stdcall"},
    {"HeapCreate", "HANDLE", _p_HeapCreate, 3, false, false, "__stdcall"},
    {"HeapDestroy", "BOOL", _p_HeapDestroy, 1, false, false, "__stdcall"},
    {"VirtualLock", "BOOL", _p_VirtualLock, 2, false, false, "__stdcall"},
    {"VirtualUnlock", "BOOL", _p_VirtualUnlock, 2, false, false, "__stdcall"},

    // CRT file I/O
    {"_open", "int", _p_fopen, 2, false, false, nullptr},
    {"_close", "int", _p_fclose, 1, false, false, nullptr},
    {"_read", "int", _p_fread, 4, false, false, nullptr},
    {"_write", "int", _p_fwrite, 4, false, false, nullptr},
    {"_lseek", "long", _p_fseek, 3, false, false, nullptr},
    {"_tell", "long", _p_ftell, 1, false, false, nullptr},
    {"_commit", "int", _p_fclose, 1, false, false, nullptr},
    {"_chmod", "int", _p_fopen, 2, false, false, nullptr},
    {"_chsize_s", "int", _p__set_fmode, 1, false, false, nullptr},
    {"_filelength", "long", _p_fclose, 1, false, false, nullptr},
    {"_filelengthi64", "int64", _p_fclose, 1, false, false, nullptr},
    {"_mkdir", "int", _p_rename, 1, false, false, nullptr},
    {"_rmdir", "int", _p_rename, 1, false, false, nullptr},
    {"_unlink", "int", _p_rename, 1, false, false, nullptr},
    {"_access", "int", _p_fopen, 2, false, false, nullptr},
    {"_stat32", "int", _p_fopen, 2, false, false, nullptr},
    {"_stat64", "int", _p_fopen, 2, false, false, nullptr},
    {"_fstat32", "int", _p_fopen, 2, false, false, nullptr},
    {"_fstat64", "int", _p_fopen, 2, false, false, nullptr},
    {"_pipe", "int", _p__initterm_e, 2, false, false, nullptr},
    {"_dup", "int", _p_fclose, 1, false, false, nullptr},
    {"_dup2", "int", _p_fopen, 2, false, false, nullptr},
    {"_sopen_s", "int", _p__seh_filter_exe, 2, false, false, nullptr},
    {"_configthreadlocale", "int", _p_configthreadlocale, 2, false, false, nullptr},
    {"_getcwd", "char *", _p_rename, 1, false, false, nullptr},
    {"_chdir", "int", _p_rename, 1, false, false, nullptr},
    {"_tempnam", "char *", _p_fopen, 2, false, false, nullptr},
    {"_tempnam_s", "int", _p__seh_filter_exe, 2, false, false, nullptr},
    {"_strdup", "char *", _p_rename, 1, false, false, nullptr},
    {"_strdup_s", "int", _p__seh_filter_exe, 2, false, false, nullptr},
    {"_wcsdup", "wchar_t *", _p_rename, 1, false, false, nullptr},
    {"_wcsdup_s", "int", _p__seh_filter_exe, 2, false, false, nullptr},
    {"_itoa_s", "int", _p__seh_filter_exe, 2, false, false, nullptr},
    {"_itow_s", "int", _p__seh_filter_exe, 2, false, false, nullptr},
    {"_splitpath", "void", _p_rename, 1, false, false, nullptr},
    {"_splitpath_s", "int", _p__seh_filter_exe, 2, false, false, nullptr},
    {"_makepath", "void", _p_rename, 1, false, false, nullptr},
    {"_makepath_s", "int", _p__seh_filter_exe, 2, false, false, nullptr},
    {"_wsplitpath_s", "int", _p__seh_filter_exe, 2, false, false, nullptr},
    {"_wmakepath_s", "int", _p__seh_filter_exe, 2, false, false, nullptr},
    {"_dupenv_s", "int", _p__seh_filter_exe, 2, false, false, nullptr},
    {"_wdupenv_s", "int", _p__seh_filter_exe, 2, false, false, nullptr},

    // ntdll
    {"InitializeSListHead", "void", _p_DeleteCriticalSection, 1, false, false, "__stdcall"},
    {"InterlockedFlushSList", "void *", _p_DeleteCriticalSection, 1, false, false, "__stdcall"},
    {"QueryDepthSList", "word", _p_DeleteCriticalSection, 1, false, false, "__stdcall"},
};

} // anonymous namespace

std::unordered_map<std::string, FunctionSignatureImpl*> ApplyKnownSignatureAnalyzer::signatureTable_;

std::unordered_map<std::string, FunctionSignatureImpl*>& ApplyKnownSignatureAnalyzer::getSignatureTable() {
    return signatureTable_;
}

ApplyKnownSignatureAnalyzer::ApplyKnownSignatureAnalyzer()
    : AbstractAnalyzer("Known Function Signatures",
                       "Applies known return types, parameters, and calling conventions to matched functions.",
                       AnalyzerType::FUNCTION_ANALYZER) {
    setPriority(AnalysisPriority::CODE_ANALYSIS.after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool ApplyKnownSignatureAnalyzer::canAnalyze(Program* program) const {
    return program != nullptr;
}

DataType* ApplyKnownSignatureAnalyzer::resolveType(DataTypeManager* dtm, const std::string& name) {
    if (!dtm || name.empty()) return nullptr;

    if (name == "void") return dtm->getDataType(CategoryPath("/"), "void");
    if (name == "int") return dtm->getDataType(CategoryPath("/"), "int");
    if (name == "char" || name == "CHAR") return dtm->getDataType(CategoryPath("/"), "byte");
    if (name == "double" || name == "DOUBLE") return dtm->getDataType(CategoryPath("/"), "float");
    if (name == "long" || name == "LONG") return dtm->getDataType(CategoryPath("/"), "long");
    if (name == "unsigned") return dtm->getDataType(CategoryPath("/"), "bool"); // bool for unsigned int
    if (name == "DWORD" || name == "UINT" || name == "ULONG" || name == "DWORD64") return dtm->getDataType(CategoryPath("/"), "dword");
    if (name == "BOOL") return dtm->getDataType(CategoryPath("/"), "bool");
    if (name == "SIZE_T" || name == "size_t") return dtm->getDataType(CategoryPath("/"), "qword");
    if (name == "int64" || name == "INT64" || name == "LONGLONG") return dtm->getDataType(CategoryPath("/"), "qword");
    if (name == "uint64" || name == "UINT64" || name == "ULONGLONG") return dtm->getDataType(CategoryPath("/"), "qword");
    if (name == "wchar_t" || name == "WCHAR") return dtm->getDataType(CategoryPath("/"), "word");

    DataType* dt = dtm->getDataType(CategoryPath("/"), name);
    if (dt) return dt;

    for (auto* t : dtm->getDataTypes()) {
        if (t && t->getName() == name) return t;
    }
    return nullptr;
}

ParameterDefinition* ApplyKnownSignatureAnalyzer::makeParameter(DataTypeManager* dtm, const char* typeName,
                                                                   const std::string& paramName, int ordinal) {
    DataType* dt = resolveType(dtm, typeName);
    if (!dt) return nullptr;
    return new ParameterDefinitionImpl(paramName.empty() ? ("p" + std::to_string(ordinal)) : paramName, dt, "", ordinal);
}

static DataTypeManager* g_lastDtm = nullptr;

void ApplyKnownSignatureAnalyzer::ensureSignatureTable(DataTypeManager* dtm) {
    if (dtm != g_lastDtm) {
        for (auto& pair : signatureTable_) {
            delete pair.second;
        }
        signatureTable_.clear();
        g_lastDtm = dtm;
    }

    DataType* voidType = dtm ? dtm->getDataType(CategoryPath("/"), "void") : nullptr;
    DataType* defaultRetType = voidType;

    int numSigs = sizeof(kKnownSigs) / sizeof(kKnownSigs[0]);
    for (int i = 0; i < numSigs; ++i) {
        std::string name(kKnownSigs[i].name);
        if (signatureTable_.find(name) != signatureTable_.end()) continue;

        auto* sig = new FunctionSignatureImpl(name);

        DataType* retDt = resolveType(dtm, kKnownSigs[i].retType);
        if (!retDt) {
            if (strcmp(kKnownSigs[i].retType, "void") == 0 && voidType) retDt = voidType;
            else if (strcmp(kKnownSigs[i].retType, "BOOL") == 0) {
                retDt = dtm->getDataType(CategoryPath("/"), "bool");
                if (!retDt) retDt = dtm->getDataType(CategoryPath("/"), "byte");
            } else if (strcmp(kKnownSigs[i].retType, "DWORD") == 0 ||
                       strcmp(kKnownSigs[i].retType, "UINT") == 0 ||
                       strcmp(kKnownSigs[i].retType, "LONG") == 0 ||
                       strcmp(kKnownSigs[i].retType, "ULONG") == 0) {
                retDt = dtm->getDataType(CategoryPath("/"), "dword");
                if (!retDt) retDt = dtm->getDataType(CategoryPath("/"), "bool"); // fallback
            }
            if (!retDt) retDt = defaultRetType;
        }
        sig->setReturnType(retDt);

        for (int j = 0; j < kKnownSigs[i].paramCount; ++j) {
            ParameterDefinition* param = makeParameter(dtm, kKnownSigs[i].paramTypes[j], "", j);
            if (param) sig->addArgument(param);
        }

        sig->setHasVarArgs(kKnownSigs[i].varargs);
        sig->setHasNoReturn(kKnownSigs[i].noreturn);
        if (kKnownSigs[i].callingConvention)
            sig->setCallingConventionName(kKnownSigs[i].callingConvention);

        signatureTable_[name] = sig;
    }
}

bool ApplyKnownSignatureAnalyzer::added(Program* program, const AddressSetView& set,
                                         TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    FunctionManager* funcMgr = program->getFunctionManager();
    if (!funcMgr) return false;

    DataTypeManager* dtm = program->getDataTypeManager();

    ensureSignatureTable(dtm);

    if (monitor) monitor->setMessage("Applying known function signatures...");

    FunctionIterator funcIter = funcMgr->getFunctions(set, true);
    int applied = 0, skipped = 0;

    while (funcIter.hasNext()) {
        if (monitor && monitor->isCancelled()) break;

        Function* func = funcIter.next();
        if (!func) continue;

        if (func->getSignature()) {
            skipped++;
            continue;
        }

        std::string funcName = func->getName();
        if (funcName.empty()) continue;

        auto it = signatureTable_.find(funcName);
        if (it == signatureTable_.end()) continue;

        FunctionSignatureImpl* knownSig = it->second;
        if (!knownSig) continue;

        auto* cloned = knownSig->clone();
        func->setSignature(cloned, SignatureSource::KNOWN_LIBRARY);

        if (cloned->getReturnType())
            func->setReturnType(cloned->getReturnType(), SignatureSource::KNOWN_LIBRARY);

        for (auto* arg : cloned->getArguments()) {
            if (!arg) continue;
            DataType* paramDt = arg->getDataType();
            if (!paramDt) continue;
            auto* param = new ParameterImpl(arg->getName(), paramDt, program);
            func->addParameter(param, SignatureSource::KNOWN_LIBRARY);
        }

        if (cloned->hasNoReturn())
            func->setHasNoReturn(true, SignatureSource::KNOWN_LIBRARY);

        PrototypeModel* cc = nullptr;
        std::string ccName = cloned->getCallingConventionName();
        if (!ccName.empty() && dtm) {
            cc = dtm->getCallingConvention(ccName);
        }
        if (cc) func->setCallingConvention(cc, SignatureSource::KNOWN_LIBRARY);

        applied++;
    }

    if (std::getenv("ENIGMA_DEBUG")) {
        std::cerr << "[ApplyKnownSignature] " << applied << " applied, "
                  << skipped << " skipped\n";
    }

    return true;
}

} // namespace ghidra
