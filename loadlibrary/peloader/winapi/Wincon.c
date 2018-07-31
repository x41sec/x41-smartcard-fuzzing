#include <stdint.h> 
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "strings.h"

BOOL WINAPI WriteConsoleW(HANDLE hConsoleOutput, VOID *lpBuffer, DWORD nNumberOfCharsToWrite, PDWORD lpNumberOfCharsWritten, PVOID lpReserved) {
  DebugLog("");
  return 1;
}

DECLARE_CRT_EXPORT("WriteConsoleW", WriteConsoleW);
