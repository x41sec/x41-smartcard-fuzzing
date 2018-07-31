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

#ifndef FLS_OUT_OF_INDEXES 
#define FLS_OUT_OF_INDEXES ((DWORD)0xFFFFFFFF) 
#endif

PVOID flsVal = 0;

DWORD WINAPI FlsAlloc(PVOID ignore) {
  DebugLog("%p", ignore);	// TODO: handle callback
  return 'FLS0';
}

BOOL WINAPI FlsSetValue(DWORD index, PVOID data) {
//  DebugLog("%x", index);
  flsVal = data;
  return 1;
}

PVOID WINAPI FlsGetValue(DWORD index) {
//  DebugLog("%x", index);
  return flsVal;
}

BOOL WINAPI FlsFree(DWORD index) {
  DebugLog("%x", index);	// TODO: handle callback
  return 1;
}

#if 1

DECLARE_CRT_EXPORT("FlsAlloc", FlsAlloc);
DECLARE_CRT_EXPORT("FlsSetValue", FlsSetValue);
DECLARE_CRT_EXPORT("FlsGetValue", FlsGetValue);
DECLARE_CRT_EXPORT("FlsFree", FlsFree);

#endif
