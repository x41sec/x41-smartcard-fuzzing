#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>
#include <assert.h>
#include <malloc.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "cardmod.h"
#include "util.h"

#define FUZZBUFSIZE 8120
static char fuzzbuffer[FUZZBUFSIZE];
static size_t fuzzlen;
static size_t fuzzoffset;

static char *atr = ATR;                                                                
static size_t atrlen = sizeof(ATR) - 1;

// from OpenSC sc.c
int sc_hex_to_bin(const char *in, unsigned char *out, size_t *outlen)
{
	int err = 0;
	size_t left, count = 0, in_len;

	if (in == NULL || out == NULL || outlen == NULL) {
		return -1;
	}
	left = *outlen;
	in_len = strlen(in);

	while (*in != '\0') {
		int byte = 0, nybbles = 2;

		while (nybbles-- && *in && *in != ':' && *in != ' ') {
			char c;
			byte <<= 4;
			c = *in++;
			if ('0' <= c && c <= '9')
				c -= '0';
			else
			if ('a' <= c && c <= 'f')
				c = c - 'a' + 10;
			else
			if ('A' <= c && c <= 'F')
				c = c - 'A' + 10;
			else {
				err = -1;
				goto out;
			}
			byte |= c;
		}

		/* Detect premature end of string before byte is complete */
		if (in_len > 1 && *in == '\0' && nybbles >= 0) {
			err = -1;
			break;
		}

		if (*in == ':' || *in == ' ')
			in++;
		if (left <= 0) {
			err = -1;
			break;
		}
		out[count++] = (unsigned char) byte;
		left--;
	}

out:
	*outlen = count;
	return err;
}

LONG init() {
	char *filename;
	FILE *f;
	char buf[30];
	size_t buflen = sizeof(buf);
	char *atr2;

	if (fuzzlen == 0) {
		/* setup input from afl or other fuzzer */
		filename = getenv("FUZZ_FILE");
		if (!filename)
			filename = "input.apdu";

		f = fopen(filename, "rb");
		if (!f)
			return SCARD_E_NO_MEMORY;

		fuzzlen = fread(fuzzbuffer, 1, sizeof(fuzzbuffer), f);
		fclose(f);
		fuzzoffset = 0;
	}

	return SCARD_S_SUCCESS;
}

LONG get_fuzz_bytes(char *rbuf, size_t *rsize) {
	if (init() != SCARD_S_SUCCESS)
		return SCARD_E_NO_MEMORY;

	if (*rsize > 0x50)
	        *rsize = 0x50;	// arbitrary limit

	if (fuzzoffset >= fuzzlen)
		return SCARD_E_NO_MEMORY;

	if (fuzzoffset + *rsize > fuzzlen)
		*rsize = fuzzlen - fuzzoffset;
		
	memcpy(rbuf, fuzzbuffer + fuzzoffset, *rsize);

	fuzzoffset += *rsize;

	return SCARD_S_SUCCESS;
}



//SCardEstablishContext
STATIC LONG WINAPI SCardEstablishContext(DWORD dwScope,
		/*@null@*/ PVOID pvReserved1, /*@null@*/ PVOID pvReserved2,
		/*@out@*/ LPSCARDCONTEXT phContext) {

	DebugLog("");
	if (phContext)
		*phContext = 0x654321;
	return SCARD_S_SUCCESS;
}

//SCardReleaseContext
STATIC LONG WINAPI SCardReleaseContext(SCARDCONTEXT hContext) {
	DebugLog("");
	return SCARD_S_SUCCESS;
}

//SCardIsValidContext
STATIC LONG WINAPI SCardIsValidContext(SCARDCONTEXT hContext) {
	DebugLog("");
	return SCARD_S_SUCCESS;
}

//SCardConnect
STATIC LONG WINAPI SCardConnectA(SCARDCONTEXT hContext,
		PCHAR szReader,
		DWORD dwShareMode,
		DWORD dwPreferredProtocols,
		/*@out@*/ LPSCARDHANDLE phCard, /*@out@*/ PDWORD pdwActiveProtocol) {

	DebugLog("");
	if (init() != SCARD_S_SUCCESS)
		return SCARD_E_NO_MEMORY;
	
	if (phCard)
		*phCard = 0x123456;	// arbitrary handle

	if (pdwActiveProtocol)
		*pdwActiveProtocol = 2;	// arbitrary protocol

	return SCARD_S_SUCCESS;
}

//SCardReconnect
STATIC LONG WINAPI SCardReconnect(SCARDHANDLE hCard,
		DWORD dwShareMode,
		DWORD dwPreferredProtocols,
		DWORD dwInitialization, /*@out@*/ PDWORD pdwActiveProtocol) {

	DebugLog("");
	if (pdwActiveProtocol)
		*pdwActiveProtocol = 2;	// arbitrary protocol

	return SCARD_S_SUCCESS;
}

//SCardDisconnect
STATIC LONG WINAPI SCardDisconnect(SCARDHANDLE hCard, DWORD dwDisposition) {
	DebugLog("");
	return SCARD_S_SUCCESS;
}

//SCardBeginTransaction
STATIC LONG WINAPI SCardBeginTransaction(SCARDHANDLE hCard) {
	DebugLog("");
	return SCARD_S_SUCCESS; 
}

//SCardEndTransaction
STATIC LONG WINAPI SCardEndTransaction(SCARDHANDLE hCard, DWORD dwDisposition) {
	DebugLog("");
	return SCARD_S_SUCCESS;
}

//SCardStatusA
STATIC LONG WINAPI SCardStatusA(SCARDHANDLE hCard,
		/*@null@*/ /*@out@*/ PCHAR mszReaderName,
		/*@null@*/ /*@out@*/ PDWORD pcchReaderLen,
		/*@null@*/ /*@out@*/ PDWORD pdwState,
		/*@null@*/ /*@out@*/ PDWORD pdwProtocol,
		/*@null@*/ /*@out@*/ LPBYTE pbAtr,
		/*@null@*/ /*@out@*/ PDWORD pcbAtrLen) {

	DebugLog("%x %x", *pcchReaderLen, *pcbAtrLen);
	if (init() != SCARD_S_SUCCESS)
		return SCARD_E_NO_MEMORY;

	if (mszReaderName && pcchReaderLen && *pcchReaderLen > strlen(READER)) {
			memset(mszReaderName, 0, *pcchReaderLen);
			strcpy(mszReaderName, READER);
	}
	if (pcchReaderLen)
		*pcchReaderLen = strlen(READER) + 1;

	if (pdwState)
		*pdwState = SCARD_PRESENT;

	if (pdwProtocol)
		*pdwProtocol = 2;

	if (pbAtr && pcbAtrLen && *pcbAtrLen >= atrlen) {
		memset(pbAtr, 0, *pcbAtrLen);
		memcpy(pbAtr, atr, atrlen);
	}

	if (pcbAtrLen)
		*pcbAtrLen = atrlen;

	return SCARD_S_SUCCESS;
}

//SCardStatusW
STATIC LONG WINAPI SCardStatusW(SCARDHANDLE hCard,
		/*@null@*/ /*@out@*/ PCHAR mszReaderName,
		/*@null@*/ /*@out@*/ PDWORD pcchReaderLen,
		/*@null@*/ /*@out@*/ PDWORD pdwState,
		/*@null@*/ /*@out@*/ PDWORD pdwProtocol,
		/*@null@*/ /*@out@*/ LPBYTE pbAtr,
		/*@null@*/ /*@out@*/ PDWORD pcbAtrLen) {

	DebugLog("%x %x", *pcchReaderLen, *pcbAtrLen);
	if (init() != SCARD_S_SUCCESS)
		return SCARD_E_NO_MEMORY;

	if (mszReaderName && pcchReaderLen && *pcchReaderLen > sizeof(READERW) - 2) {
			memset(mszReaderName, 0, *pcchReaderLen);
			memcpy(mszReaderName, READERW, sizeof(READERW));
	}
	if (pcchReaderLen)
		*pcchReaderLen = sizeof(READERW) - 2;

	if (pdwState)
		*pdwState = SCARD_PRESENT;

	if (pdwProtocol)
		*pdwProtocol = 2;

	if (pbAtr && pcbAtrLen && *pcbAtrLen >= atrlen) {
		memset(pbAtr, 0, *pcbAtrLen);
		memcpy(pbAtr, atr, atrlen);
	}

	if (pcbAtrLen)
		*pcbAtrLen = atrlen;

	return SCARD_S_SUCCESS;
}
// SCardGetStatusChange
STATIC LONG WINAPI SCardGetStatusChange(SCARDCONTEXT hContext,
	DWORD dwTimeout,
	SCARD_READERSTATE *rgReaderStates, DWORD cReaders) {

	DebugLog("");
	if (init() != SCARD_S_SUCCESS)
		return SCARD_E_NO_MEMORY;

	if (cReaders < 1)
		return SCARD_E_NO_MEMORY;
#if 0
	for (int i = 0; i < cReaders; i++) {
		printf(">%x %s %x %x\n", cReaders, rgReaderStates[i].szReader, rgReaderStates[i].dwCurrentState, rgReaderStates[i].dwEventState);
	}
#endif
	
	rgReaderStates[0].cbAtr = atrlen;
	memset(rgReaderStates[0].rgbAtr, 0, sizeof(rgReaderStates[0].rgbAtr));
	memcpy(rgReaderStates[0].rgbAtr, atr, atrlen);

	if (rgReaderStates[0].dwCurrentState & SCARD_STATE_PRESENT) {
		rgReaderStates[0].dwEventState = rgReaderStates[0].dwCurrentState | SCARD_STATE_PRESENT;
	} else {
		rgReaderStates[0].dwEventState = rgReaderStates[0].dwCurrentState | SCARD_STATE_PRESENT | SCARD_STATE_CHANGED;
	}
	
	return SCARD_S_SUCCESS;
}

// SCardControl
STATIC LONG WINAPI SCardControl(SCARDHANDLE hCard, DWORD dwControlCode,
	PVOID pbSendBuffer, DWORD cbSendLength,                       
	/*@out@*/ PVOID pbRecvBuffer, DWORD cbRecvLength,              
	/*@out@*/ PDWORD lpBytesReturned) {
	size_t rsize = cbRecvLength;
	char *rbuf = pbRecvBuffer;
	LONG rc;

	DebugLog("");
	memset(rbuf, 0, rsize);
	*lpBytesReturned = 0;
	//printf("%x %x %x\n", dwControlCode, cbSendLength, cbRecvLength);
	// This handles Terminal_PCSC::Pace()
	if (dwControlCode == 0x42000d48) {
		rbuf[0] = 0x12;	// Tag
		rbuf[1] = 0x00; // Len
		rbuf[2] = 0x00; // Value
		rbuf[3] = 0x00;
		rbuf[4] = 0x00;
		rbuf[5] = 0x00;

		rbuf[6] = ' ';
		rbuf[7] = 0;
		rbuf[8] = 0x12;	// specifies next control code... 
		rbuf[9] = 0x13;
		rbuf[10] = 0x14;
		rbuf[11] = 0x15;
		*lpBytesReturned = 12;
	} else if (dwControlCode == 0x12131415) {
		if (cbSendLength == 3) {
			rbuf[0] = 0x00;	// Tag
			rbuf[1] = 0x00; // Len
			rbuf[2] = 0x00; // Value
			rbuf[3] = 0x00;
			rbuf[4] = 0x00;
			rbuf[5] = 0x00;
			*lpBytesReturned = 7;
		} else if (cbSendLength == 0xc) {
			memset(rbuf, 0x33, rsize);
			*lpBytesReturned = rsize;
		}
	}


	return SCARD_S_SUCCESS;
#if 0
	rc = get_fuzz_bytes(rbuf, rsize);

	if (rc == SCARD_S_SUCCESS)
		*lpBytesReturned = cbRecvLength;

	return rc;
#endif
}

//SCardTransmit
STATIC LONG WINAPI SCardTransmit(SCARDHANDLE hCard,
		const SCARD_IO_REQUEST *pioSendPci,
		LPBYTE pbSendBuffer, DWORD cbSendLength,
		/*@out@*/ SCARD_IO_REQUEST *pioRecvPci,
		/*@out@*/ LPBYTE pbRecvBuffer, PDWORD pcbRecvLength) {
	char *rbuf = pbRecvBuffer;
	LONG rc;

	DebugLog("");
	printf("|| %x %x\n", cbSendLength, *pcbRecvLength);
	printf("> ");
	for (int i=0; i < cbSendLength; i++) { printf("%02x ", ((char *)pbSendBuffer)[i] & 0xff); }
	printf("\n");

#if 0
	if (cbSendLength == 5) {
		return get_fuzz_bytes(rbuf, rsize);

	} else {
		*pcbRecvLength = 2;
		rbuf[0] = 0x00;
		rbuf[1] = 0x90;
	}
#endif	
	rc = get_fuzz_bytes(rbuf, pcbRecvLength);
        if (rc != SCARD_S_SUCCESS)
		return rc;

	// force select and read binary to succeed
        if (pbSendBuffer[1] == 0xa4 || pbSendBuffer[1] == 0xb0) {
          rbuf[(*pcbRecvLength)-1] = 0x00;
          rbuf[(*pcbRecvLength)-2] = 0x90;
        }

	printf("< ");
	for (int i=0; i < *pcbRecvLength; i++) { printf("%02x ", ((char *)rbuf)[i] & 0xff); }
	printf("\n");
	
	return rc;
}

STATIC LONG WINAPI SCardListReaderGroups(SCARDCONTEXT hContext,
	/*@out@*/ PCHAR mszGroups, PDWORD pcchGroups) {

	DebugLog("");
	// TODO: update mszGroups
	return SCARD_S_SUCCESS;
}

//SCardListReaders
STATIC LONG WINAPI SCardListReaders(SCARDCONTEXT hContext,
		/*@null@*/ /*@in@*/ PCHAR mszGroups,
		/*@null@*/ /*@out@*/ PCHAR mszReaders,
		/*@out@*/ PDWORD pcchReaders) {

	DebugLog("");
	if (mszReaders) {
		if (pcchReaders && *pcchReaders > strlen(READER) + 1) {
			memset(mszReaders, 0, *pcchReaders);
			strcpy(mszReaders, READER);
		}
	}

	if (pcchReaders)
		*pcchReaders = strlen(READER) + 2;

	return SCARD_S_SUCCESS;
}


//SCardFreeMemory
STATIC LONG WINAPI SCardFreeMemory(SCARDCONTEXT hContext, PVOID pvMem) {
	DebugLog("");
	return SCARD_S_SUCCESS;
}

//SCardCancel
STATIC LONG WINAPI SCardCancel(SCARDCONTEXT hContext) {
	DebugLog("");
	return SCARD_S_SUCCESS;
}

STATIC LONG WINAPI SCardGetAttrib(SCARDHANDLE hCard, DWORD dwAttrId,
	/*@out@*/ LPBYTE pbAttr, PDWORD pcbAttrLen) {
	DebugLog("");

	//TODO: implement
	abort();
	return SCARD_S_SUCCESS;
}

STATIC LONG WINAPI SCardSetAttrib(SCARDHANDLE hCard, DWORD dwAttrId,
	LPBYTE pbAttr, DWORD cbAttrLen) {

	DebugLog("");
	return SCARD_S_SUCCESS;
}

DECLARE_CRT_EXPORT("SCardEstablishContext", SCardEstablishContext);
DECLARE_CRT_EXPORT("SCardReleaseContext", SCardReleaseContext);
DECLARE_CRT_EXPORT("SCardIsValidContext", SCardIsValidContext);
DECLARE_CRT_EXPORT("SCardConnectA", SCardConnectA);
DECLARE_CRT_EXPORT("SCardReconnect", SCardReconnect);
DECLARE_CRT_EXPORT("SCardDisconnect", SCardDisconnect);
DECLARE_CRT_EXPORT("SCardBeginTransaction", SCardBeginTransaction);
DECLARE_CRT_EXPORT("SCardEndTransaction", SCardEndTransaction);
DECLARE_CRT_EXPORT("SCardStatusA", SCardStatusA);
DECLARE_CRT_EXPORT("SCardStatusW", SCardStatusW);
DECLARE_CRT_EXPORT("SCardGetStatusChange", SCardGetStatusChange);
DECLARE_CRT_EXPORT("SCardControl", SCardControl);
DECLARE_CRT_EXPORT("SCardTransmit", SCardTransmit);
DECLARE_CRT_EXPORT("SCardListReaderGroups", SCardListReaderGroups);
DECLARE_CRT_EXPORT("SCardListReaders", SCardListReaders);
DECLARE_CRT_EXPORT("SCardFreeMemory", SCardFreeMemory);
DECLARE_CRT_EXPORT("SCardCancel", SCardCancel);
DECLARE_CRT_EXPORT("SCardGetAttrib", SCardGetAttrib);
DECLARE_CRT_EXPORT("SCardSetAttrib", SCardSetAttrib);
