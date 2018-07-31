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

BOOL WINAPI GetWindowInfo(HANDLE hWnd, PVOID pwi) {
  DebugLog("");
  return 0;
}

BOOL WINAPI PostMessageA(HANDLE hWnd, DWORD msg, DWORD param, DWORD lparam) {
  DebugLog("%x %x %x %x", hWnd, msg, param, lparam);
  return 1;
}

BOOL WINAPI DestroyWindow(HANDLE hWnd) {
  DebugLog("");
  return 1;
}

UINT WINAPI RegisterWindowMessageA(PCHAR string) {
  DebugLog("%s", string);
  return 0xC123;
}

int WINAPI MessageBoxW(HANDLE hWnd, PVOID lpText, PVOID lpCaption, UINT uType) {
  DebugLog("");
  return 1;
}

DECLARE_CRT_EXPORT("GetWindowInfo", GetWindowInfo);
DECLARE_CRT_EXPORT("PostMessageA", PostMessageA);
DECLARE_CRT_EXPORT("DestroyWindow", DestroyWindow);
DECLARE_CRT_EXPORT("RegisterWindowMessageA", RegisterWindowMessageA);
DECLARE_CRT_EXPORT("MessageBoxW", MessageBoxW);
