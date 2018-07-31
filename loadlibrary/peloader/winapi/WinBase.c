#include <stdint.h> 
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <stdio.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "strings.h"

DWORD WINAPI FormatMessageA(DWORD flags, PVOID source, DWORD messageid, DWORD languageid, PCHAR buffer, DWORD size) {
  DebugLog("%p, %p, %p, %p, %p, %p", flags, source, messageid, languageid, buffer, size);
  return snprintf(buffer, size, "%x %x %x %x:", flags, source, messageid, languageid);
}

BOOL WINAPI AreFileApisANSI(void) {
  DebugLog("");
  return 1;
}

BOOL WINAPI IsDebuggerPresent(void) {
  return 0;
}

VOID WINAPI Sleep(DWORD ms) {
  // no sleep ;-)
  return;
}

LONGLONG WINAPI GetTickCount64(void) {
  DebugLog("");
  return 0;
}

VOID WINAPI ExitProcess(UINT uExitCode) {
  exit(uExitCode);
}


DECLARE_CRT_EXPORT("FormatMessageA", FormatMessageA);
DECLARE_CRT_EXPORT("AreFileApisANSI", AreFileApisANSI);
DECLARE_CRT_EXPORT("IsDebuggerPresent", IsDebuggerPresent);
DECLARE_CRT_EXPORT("Sleep", Sleep);
DECLARE_CRT_EXPORT("GetTickCount64", GetTickCount64);
DECLARE_CRT_EXPORT("ExitProcess", ExitProcess);
