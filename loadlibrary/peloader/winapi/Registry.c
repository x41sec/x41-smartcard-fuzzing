#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include "winnt_types.h"
#include "winerror.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"


typedef struct _KEY_VALUE_BASIC_INFORMATION {
  ULONG TitleIndex;
  ULONG Type;
  ULONG NameLength;
  WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
  ULONG TitleIndex;
  ULONG Type;
  ULONG DataLength;
  UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

STATIC LONG WINAPI RegOpenKeyExA(HANDLE hKey, PVOID lpSubKey, DWORD ulOptions, DWORD samDesired, PHANDLE phkResult)
{
    LONG Result = -1;
    char *ansikey = lpSubKey;

    DebugLog("%p, %p [%s], %#x, %#x, %p", hKey, lpSubKey, ansikey, ulOptions, samDesired, phkResult);

    if (strstr(ansikey, "Explorer\\Shell Folders")) {
        *phkResult = (HANDLE) 'REG0';
        Result = 0;
    } else if (strstr(ansikey, "Explorer\\User Shell Folders")) {
        *phkResult = (HANDLE) 'REG1';
        Result = 0;
    } else if (strstr(ansikey, "ProfileList")) {
        *phkResult = (HANDLE) 'REG2';
        Result = 0;
    } else if (strstr(ansikey, "Yubico\\ykmd")) {
        *phkResult = (HANDLE) 'REG3';
        Result = 0;
    } else if (strstr(ansikey, "Software\\Microsoft\\Windows NT\\CurrentVersion")) {
        *phkResult = (HANDLE) 'REG4';
        Result = 0;
    } else if (strstr(ansikey, "SOFTWARE\\T-Systems\\CardMiniDriverTCOS3")) {
        *phkResult = (HANDLE) 'REG5';
        Result = 0;
    } else if (strstr(ansikey, "MSCP")) {
        *phkResult = (HANDLE) 'REG6';
        Result = 0;
    } else if (strstr(ansikey, "Applications")) {
        *phkResult = (HANDLE) 'REG6';
        Result = 0;
    }
    return Result;
}

STATIC LONG WINAPI RegOpenKeyExW(HANDLE hKey, PVOID lpSubKey, DWORD ulOptions, DWORD samDesired, PHANDLE phkResult) {
  char *ansikey = CreateAnsiFromWide(lpSubKey);
  DebugLog("%p, %p [%s], %#x, %#x, %p", hKey, lpSubKey, ansikey, ulOptions, samDesired, phkResult);
  RegOpenKeyExA(hKey, ansikey, ulOptions, samDesired, phkResult);
  free(ansikey);
}


STATIC LONG WINAPI RegCloseKey(HANDLE hKey)
{
    DebugLog("%p");
    return 0;
}

STATIC LONG WINAPI RegQueryInfoKeyW(
  HANDLE   hKey,
  PWCHAR   lpClass,
  PDWORD   lpcClass,
  PDWORD   lpReserved,
  PDWORD   lpcSubKeys,
  PDWORD   lpcMaxSubKeyLen,
  PDWORD   lpcMaxClassLen,
  PDWORD   lpcValues,
  PDWORD   lpcMaxValueNameLen,
  PDWORD   lpcMaxValueLen,
  PDWORD   lpcbSecurityDescriptor,
  PVOID    lpftLastWriteTime)
{
    DebugLog("");

    if (lpClass || lpcClass || lpReserved || lpcSubKeys || lpcMaxSubKeyLen || lpcMaxClassLen || lpcMaxValueLen || lpcbSecurityDescriptor || lpftLastWriteTime) {
        DebugLog("NOT SUPPORTED");
        return -1;
    }

    switch ((DWORD) hKey) {
        case 'REG0':
        case 'REG1':
        case 'REG2':
            *lpcValues = 1;
            *lpcMaxValueNameLen = 1024;
            break;
        default:
            DebugLog("NOT SUPPROTED KEY");
            return -1;
    }

    return 0;
}

STATIC NTSTATUS WINAPI NtEnumerateValueKey(
  HANDLE                      KeyHandle,
  ULONG                       Index,
  DWORD                       KeyValueInformationClass,
  PKEY_VALUE_BASIC_INFORMATION KeyValueInformation,
  ULONG                       Length,
  PULONG                      ResultLength
) {
    DebugLog("%p, %u, %u, %p, %u, %p", KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

    if (KeyValueInformationClass != 0) {
        DebugLog("NOT SUPPORTED");
        return -1;
    }

    switch ((DWORD) KeyHandle) {
        case 'REG1':
            KeyValueInformation->Type       = REG_SZ;
            KeyValueInformation->NameLength = sizeof(L"Common AppDatz") - 2;
            memcpy(&KeyValueInformation->Name[0], L"Common AppData", KeyValueInformation->NameLength);
            *ResultLength = sizeof(KEY_VALUE_BASIC_INFORMATION) + KeyValueInformation->NameLength;
            break;
        case 'REG0':
            KeyValueInformation->Type       = REG_SZ;
            KeyValueInformation->NameLength = sizeof(L"Common AppDatz") - 2;
            memcpy(&KeyValueInformation->Name[0], L"Common AppData", KeyValueInformation->NameLength);
            *ResultLength = sizeof(KEY_VALUE_BASIC_INFORMATION) + KeyValueInformation->NameLength;
            break;
        case 'REG2':
            KeyValueInformation->Type       = REG_SZ;
            KeyValueInformation->NameLength = sizeof(L"Common AppDatz") - 2;
            memcpy(&KeyValueInformation->Name[0], L"Common AppData", KeyValueInformation->NameLength);
            *ResultLength = sizeof(KEY_VALUE_BASIC_INFORMATION) + KeyValueInformation->NameLength;
            break;
        default:
            DebugLog("NOT SUPPROTED KEY");
            return -1;
    }

    return 0;
}

STATIC NTSTATUS WINAPI NtQueryValueKey(
 HANDLE                      KeyHandle,
 PVOID                       ValueName,
 DWORD                       KeyValueInformationClass,
 PKEY_VALUE_PARTIAL_INFORMATION KeyValueInformation,
 ULONG                       Length,
 PULONG                      ResultLength
)
{
    DebugLog("%p, %p, %u, %u, %u, %p", KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

    if (KeyValueInformationClass != 2) {
        DebugLog("NOT SUPPROTED");
        return -1;
    }

    switch ((DWORD) KeyHandle) {
        case 'REG1':
            KeyValueInformation->Type = REG_SZ;
            KeyValueInformation->DataLength = sizeof(L"Common AppData") - 2;
            memcpy(&KeyValueInformation->Data[0], L"Common AppData", KeyValueInformation->DataLength);
            *ResultLength = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + KeyValueInformation->DataLength;
            break;
        case 'REG0':
            KeyValueInformation->Type = REG_SZ;
            KeyValueInformation->DataLength = sizeof(L"Common AppData") - 2;
            memcpy(&KeyValueInformation->Data[0], L"Common AppData", KeyValueInformation->DataLength);
            *ResultLength = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + KeyValueInformation->DataLength;
            break;
        case 'REG2':
            KeyValueInformation->Type = REG_SZ;
            KeyValueInformation->DataLength = sizeof(L"Common AppData") - 2;
            memcpy(&KeyValueInformation->Data[0], L"Common AppData", KeyValueInformation->DataLength);
            *ResultLength = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + KeyValueInformation->DataLength;
            break;
        default:
            DebugLog("NOT SUPPORTED KEY");
            return -1;
    }

    return 0;
}

STATIC LONG WINAPI RegCreateKeyExW(HANDLE hKey, PVOID lpSubKey, DWORD Reserved, PVOID lpClass, DWORD dwOptions, PVOID samDesired, PVOID lpSecurityAttributes, PVOID phkResult, PDWORD lpdwDisposition)
{
    DebugLog("%p, %p, %#x, %p, %#x, %p, %p, %p, %p",
             hKey,
             lpSubKey,
             Reserved,
             lpClass,
             dwOptions,
             samDesired,
             lpSecurityAttributes,
             phkResult,
             lpdwDisposition);
    return 0;
}

STATIC LONG WINAPI RegQueryValueExA(HANDLE hKey, PVOID ValueName, PDWORD reserved, PDWORD type, PCHAR data, PDWORD cbData) {
  DebugLog("%p, %p [%s], %#x, %p, %p, %p", hKey, ValueName, (char *) ValueName, reserved, type, data, cbData);
  char *val;
  size_t valsize = 0;

  switch ((DWORD) hKey) {
    case 'REG5':
      if (!strcmp(ValueName, "Version")) {
        valsize = sizeof("1");
        val = "1";

        if (type)
          *type = REG_SZ;

        if (data && cbData && *cbData > valsize)
          memcpy(data, val, valsize);

        if (cbData)
          *cbData = valsize;

      } else if (!strcmp(ValueName, "CSPVersion")) {
        valsize = sizeof("1");
        val = "1";

        if (type)
          *type = REG_SZ;

        if (data && cbData && *cbData > valsize)
          memcpy(data, val, valsize);

        if (cbData)
          *cbData = valsize;



      } else if (!strcmp(ValueName, "cacheMode")) {
        return -1;
      }

      break;


    default:
      DebugLog("NOT SUPPORTED YET");
      return -1;
  }

  return 0;
}

STATIC LONG WINAPI RegQueryValueExW(HANDLE hKey, PVOID ValueName, PDWORD reserved, PDWORD type, PCHAR data, PDWORD cbData) {
  char *ansikey = CreateAnsiFromWide(ValueName);
  const uint16_t *val;
  size_t valsize = 0;
  DebugLog("%p, %p [%s], %#x, %p, %p, %p", hKey, ValueName, ansikey, reserved, type, data, cbData);

  switch ((DWORD) hKey) {
    case 'REG4':
      if (!strcmp(ansikey, "ProductName")) {
        valsize = sizeof(L"Windows 10 Pro");
        val = L"Windows 10 Pro";
      } else if (!strcmp(ansikey, "ReleaseId")) {
        valsize = sizeof(L"1709");
        val = L"1709";
      } else if (!strcmp(ansikey, "InstallationType")) {
        valsize = sizeof(L"Client");
        val = L"Client";
      } else {
        break;
      }

      if (type)
        *type = REG_SZ;

      if (data && cbData && *cbData > valsize)
        memcpy(data, val, valsize);

      if (cbData)
        *cbData = valsize;

      break;

    case 'REG3':
      if (type)
        *type = REG_DWORD;
      if (data && *cbData >= 4)
        *data = (DWORD) (1);
      if (cbData)
        *cbData = 4;
      break;

    default:
      free(ansikey);
      DebugLog("NOT SUPPORTED YET");
      return -1;
  }

  free(ansikey);
  return 0;
}

LONG WINAPI RegConnectRegistryA(PCHAR *lpName, HANDLE hKey, HANDLE *res) {
  // We never care about the handle so just return something
  DebugLog("%s", lpName);
  *res = (HANDLE) 'RREG';
  return 0;
}

LONG WINAPI RegEnumKeyExA(HANDLE hKey, DWORD dwIndex, PCHAR lpName, PDWORD lpcName, PDWORD lpReserved, PCHAR lpClass, PDWORD lpcClass, PVOID lpftLastWriteTime) {
  DebugLog("");
  return ERROR_NO_MORE_ITEMS;
}

DECLARE_CRT_EXPORT("RegOpenKeyExW", RegOpenKeyExW);
DECLARE_CRT_EXPORT("RegOpenKeyExA", RegOpenKeyExA);
DECLARE_CRT_EXPORT("RegCloseKey", RegCloseKey);
DECLARE_CRT_EXPORT("RegQueryInfoKeyW", RegQueryInfoKeyW);
DECLARE_CRT_EXPORT("NtEnumerateValueKey", NtEnumerateValueKey);
DECLARE_CRT_EXPORT("NtQueryValueKey", NtQueryValueKey);
DECLARE_CRT_EXPORT("RegCreateKeyExW", RegCreateKeyExW);
DECLARE_CRT_EXPORT("RegQueryValueExA", RegQueryValueExA);
DECLARE_CRT_EXPORT("RegQueryValueExW", RegQueryValueExW);
DECLARE_CRT_EXPORT("RegConnectRegistryA", RegConnectRegistryA);
DECLARE_CRT_EXPORT("RegEnumKeyExA", RegEnumKeyExA);
