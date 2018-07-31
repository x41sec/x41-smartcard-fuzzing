//
// Copyright (C) 2017 Tavis Ormandy
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/unistd.h>
#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <mcheck.h>
#include <err.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"
#include "hook.h"
#include "log.h"
#include "rsignal.h"
#include "cardmod.h"

static char *atr = ATR;                                                                
static size_t atrlen = sizeof(ATR) - 1;
#define CARDNAME L"Yubico"


// Any usage limits to prevent bugs disrupting system.
const struct rlimit kUsageLimits[] = {
    [RLIMIT_FSIZE]  = { .rlim_cur = 0x20000000, .rlim_max = 0x20000000 },
    [RLIMIT_CPU]    = { .rlim_cur = 3600,       .rlim_max = RLIM_INFINITY },
    [RLIMIT_CORE]   = { .rlim_cur = 0,          .rlim_max = 0 },
    [RLIMIT_NOFILE] = { .rlim_cur = 32,         .rlim_max = 32 },
};

DWORD (*__cardacquirecontext)(PCARD_DATA, DWORD);

// These are available for pintool.
BOOL __noinline InstrumentationCallback(PVOID ImageStart, SIZE_T ImageSize)
{
    // Prevent the call from being optimized away.
    asm volatile ("");
    return TRUE;
}

void print_error(LONG rv, char *function) {
  char *error = "<unknown>";
    switch(rv) {
      case 0x80100002: error = "The action was cancelled by an SCardCancel request."; break;
      case 0x80100003: error = "The supplied handle was invalid."; break;
      case 0x80100004: error = "One or more of the supplied parameters could not be properly interpreted."; break;
      case 0x80100005: error = "Registry startup information is missing or invalid."; break;
      case 0x80100006: error = "Not enough memory available to complete this command."; break;
      case 0x80100008: error = "The data buffer to receive returned data is too small for the returned data."; break;
      case 0x80100009: error = "The specified reader name is not recognized."; break;
      case 0x8010000A: error = "The user-specified timeout value has expired."; break;
      case 0x8010000B: error = "The smart card cannot be accessed because of other connections outstanding."; break;
      case 0x8010000C: error = "The operation requires a Smart Card, but no Smart Card is currently in the device."; break;
      case 0x8010000D: error = "The specified smart card name is not recognized."; break;
      case 0x8010000E: error = "The system could not dispose of the media in the requested manner."; break;
      case 0x8010000F: error = "The requested protocols are incompatible with the protocol currently in use with the smart card."; break;
      case 0x80100010: error = "The reader or smart card is not ready to accept commands."; break;
      case 0x80100011: error = "One or more of the supplied parameters values could not be properly interpreted."; break;
      case 0x80100012: error = "The action was cancelled by the system, presumably to log off or shut down."; break;
      case 0x80100015: error = "An ATR obtained from the registry is not a valid ATR string."; break;
      case 0x80100016: error = "An attempt was made to end a non-existent transaction."; break;
      case 0x80100017: error = "The specified reader is not currently available for use."; break;
      case 0x80100019: error = "The PCI Receive buffer was too small."; break;
      case 0x8010001A: error = "The reader driver does not meet minimal requirements for support."; break;
      case 0x8010001B: error = "The reader driver did not produce a unique reader name."; break;
      case 0x8010001C: error = "The smart card does not meet minimal requirements for support."; break;
      case 0x8010001D: error = "The Smart card resource manager is not running."; break;
      case 0x8010001E: error = "The Smart card resource manager has shut down."; break;
      case 0x8010001F: error = "This smart card does not support the requested feature."; break;
      case 0x80100020: error = "No primary provider can be found for the smart card."; break;
      case 0x80100021: error = "The requested order of object creation is not supported."; break;
      case 0x80100022: error = "This smart card does not support the requested feature."; break;
      case 0x80100023: error = "The identified directory does not exist in the smart card."; break;
      case 0x80100024: error = "The identified file does not exist in the smart card."; break;
      case 0x80100025: error = "The supplied path does not represent a smart card directory."; break;
      case 0x80100026: error = "The supplied path does not represent a smart card file."; break;
      case 0x80100027: error = "Access is denied to this file."; break;
      case 0x80100028: error = "The smart card does not have enough memory to store the information."; break;
      case 0x80100029: error = "There was an error trying to set the smart card file object pointer."; break;
      case 0x8010002A: error = "The supplied PIN is incorrect."; break;
      case 0x8010002B: error = "An unrecognized error code was returned from a layered component."; break;
      case 0x8010002C: error = "The requested certificate does not exist."; break;
      case 0x8010002D: error = "The requested certificate could not be obtained."; break;
      case 0x8010002E: error = "Cannot find a smart card reader."; break;
      case 0x8010002F: error = "A communications error with the smart card has been detected. Retry the operation."; break;
      case 0x80100030: error = "The requested key container does not exist on the smart card."; break;
      case 0x80100031: error = "The Smart Card Resource Manager is too busy to complete this operation."; break;
    }
  LogMessage("%s() failed: %x -> %s", function, rv, error);
}

int main(int argc, char **argv, char **envp)
{
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS PeHeader;
    HANDLE KernelHandle;
    CARD_DATA pcarddata;
    LONG rv;

    struct pe_image image = {
        .entry  = NULL,
        //.name   = "engine/myeiddrv.dll",
        .name   = "engine/tcos3cmd.dll",
    

        //.name   = "engine/ykmd.dll", // -> eip winds up bad...
        //.name   = "engine/SmaOSMiniCSP.dll", // -> crash in GOT

        //.name   = "engine/esteidcm.dll", // -> exception handler plays to much with fs: ... :/
        //.name   = "engine/DNIeCMx86.dll", // managed code, dont care further
	//.name   = "engine/eps2003csp11.dll", // some kind of re protection?
    };

    // Load the module.
    if (pe_load_library(image.name, &image.image, &image.size) == false) {
        LogMessage("You must add the dll and vdm files to the engine directory");
        return 1;
    }

    // Handle relocations, imports, etc.
    link_pe_images(&image, 1);

    // Fetch the headers to get base offsets.
    DosHeader   = (PIMAGE_DOS_HEADER) image.image;
    PeHeader    = (PIMAGE_NT_HEADERS)(image.image + DosHeader->e_lfanew);

    // Load any additional exports.
    if (!process_extra_exports(image.image, PeHeader->OptionalHeader.BaseOfCode, "engine/mpengine.map")) {
#ifndef NDEBUG
        LogMessage("The map file wasn't found, symbols wont be available");
#endif
    } else {
        // Calculate the commands needed to get export and map symbols visible in gdb.
        if (xIsDebuggerPresent()) {
            LogMessage("GDB: add-symbol-file %s %#x+%#x",
                       image.name,
                       image.image,
                       PeHeader->OptionalHeader.BaseOfCode);
            LogMessage("GDB: shell bash genmapsym.sh %#x+%#x symbols_%d.o < %s",
                       image.image,
                       PeHeader->OptionalHeader.BaseOfCode,
                       getpid(),
                       "engine/mpengine.map");
            LogMessage("GDB: add-symbol-file symbols_%d.o 0", getpid());
            __debugbreak();
        }
    }

    if (get_export("CardAcquireContext", &__cardacquirecontext) == -1) {
        errx(EXIT_FAILURE, "Failed to resolve CardAcquireContext");
    }

    EXCEPTION_DISPOSITION ExceptionHandler(struct _EXCEPTION_RECORD *ExceptionRecord,
            struct _EXCEPTION_FRAME *EstablisherFrame,
            struct _CONTEXT *ContextRecord,
            struct _EXCEPTION_FRAME **DispatcherContext)
    {
        LogMessage("Toplevel Exception Handler Caught Exception");
        abort();
    }

    VOID ResourceExhaustedHandler(int Signal)
    {
        errx(EXIT_FAILURE, "Resource Limits Exhausted, Signal %s", strsignal(Signal));
    }

    setup_nt_threadinfo(ExceptionHandler);

    // Call DllMain()
    // dont call for engine/DNIeCMx86.dll which is managed code, so we dont care
    image.entry((PVOID) 'MPEN', DLL_PROCESS_ATTACH, NULL);

    // Install usage limits to prevent system crash.
    setrlimit(RLIMIT_CORE, &kUsageLimits[RLIMIT_CORE]);
    setrlimit(RLIMIT_CPU, &kUsageLimits[RLIMIT_CPU]);
    setrlimit(RLIMIT_FSIZE, &kUsageLimits[RLIMIT_FSIZE]);
    setrlimit(RLIMIT_NOFILE, &kUsageLimits[RLIMIT_NOFILE]);

    signal(SIGXCPU, ResourceExhaustedHandler);
    signal(SIGXFSZ, ResourceExhaustedHandler);

# ifndef NDEBUG
    // Enable Maximum heap checking.
    mcheck_pedantic(NULL);
# endif

    LogMessage("Calling into library...\n");
    ZeroMemory(&pcarddata, sizeof pcarddata);
    pcarddata.dwVersion = CARD_DATA_VERSION_SEVEN;
    pcarddata.pbAtr = atr;
    pcarddata.cbAtr = atrlen;
    pcarddata.pwszCardName = CARDNAME;
    pcarddata.pfnCspAlloc = (PFN_CSP_ALLOC) malloc;
    pcarddata.pfnCspReAlloc = (PFN_CSP_REALLOC) realloc;
    pcarddata.pfnCspFree = (PFN_CSP_FREE) free;
    pcarddata.pfnCspPadData = (PFN_CSP_PAD_DATA) 0x99887766;
    pcarddata.hSCardCtx = 0x654321;
    pcarddata.hScard = 0x654321;


    // Enable Instrumentation.
    InstrumentationCallback(image.image, image.size);

    rv = __cardacquirecontext(&pcarddata, 0);
    if (rv != 0) {
      print_error(rv, "CardAcquireContext");
      return 1;
    }


    return 0;
}
