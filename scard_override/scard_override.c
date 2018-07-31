/*
 * Library to fuzz APDU responses by intercepting calls to SCCard*
 *
 * written by Eric Sesterhenn <eric.sesterhenn@x41-dsec.de>
 * Released under GPLv3
 * 
 * Compile:
 *     gcc -shared -fPIC -o libscard_override.so scard_override.c -ldl -I/usr/include/PCSC/
 *
 * Test: 
 *   LD_PRELOAD=./libscard_override.so ./test
 * 
 * Fuzz:
 *   FUZZ_FILE="input.apdu" AFL_PRELOAD="./libscard_override.so" afl-fuzz -i in -o out -f input.apdu
 *
 * Use FUZZ_ATR environment variable to change ATR on the fly, for some drivers
 * you might want to change the reader as well.
 *
 */

#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <wintypes.h>
#include <winscard.h>


#define FUZZBUFSIZE 8120
static char fuzzbuffer[FUZZBUFSIZE];
static size_t fuzzlen;
static size_t fuzzoffset;

//char *atr = "\x3B\xBF\xB6\x00\x81\x31\xFE\x5D\x00\x64\x04\x28\x03\x02\x31\xC0\x73\xF7\x01\xD0\x00\x90\x00\x67\x00\x00";
// #define ATR "\x3b\x88\x80\x01\x30\x4c\x47\x12\x77\x83\xd5\x00\x01\x00\x00\x00" // NetKey
// #define ATR "\x3B\xF2\x18\x00\x02\xC1\x0A\x31\xFE\x58\xC8\x09\x75" // Etoken PRO 64k
// #define ATR "\x3B\xD5\x18\x00\x81\x31\x3A\x7D\x80\x73\xC8\x21\x10\x30" // Etoken PRO v4.29
#define ATR "\x3b\xfc\x13\x00\x00\x8\x3b\xfc\x13\x00\x00\x81\x31\xfe\x15\x59\x75\x62\x69\x6b\x65\x79\x4e\x45\x4f\x72\x33\xe1" // YKPIV_ATR_NEO_R3
char *atr = ATR;
size_t atrlen = sizeof(ATR);

#define READER "Yubico"


#ifdef DEBUG
#define LOGFUNC() printf("Enter: %s\n", __FUNCTION__)
#else 
#define LOGFUNC()
#endif

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

		atr2 = getenv("FUZZ_ATR");
		if (atr2) {
			if (sc_hex_to_bin(atr2, (unsigned char *) buf, &buflen) == 0) {
				atr = buf;
				atrlen = buflen;
			}
		}
	}

	return SCARD_S_SUCCESS;
}

LONG get_fuzz_bytes(char *rbuf, size_t rsize) {
	if (init() != SCARD_S_SUCCESS)
		return SCARD_E_NO_MEMORY;

	if (fuzzoffset >= fuzzlen)
		return SCARD_E_NO_MEMORY;

	if (fuzzoffset + rsize >= fuzzlen) 
		return SCARD_E_NO_MEMORY;
		
	memcpy(rbuf, fuzzbuffer + fuzzoffset, rsize);

	fuzzoffset += rsize;

	return SCARD_S_SUCCESS;
}



//SCardEstablishContext
PCSC_API LONG SCardEstablishContext(DWORD dwScope,
		/*@null@*/ LPCVOID pvReserved1, /*@null@*/ LPCVOID pvReserved2,
		/*@out@*/ LPSCARDCONTEXT phContext) {

//	LOGFUNC();
	if (phContext)
		*phContext = 0x654321;
	return SCARD_S_SUCCESS;
}

//SCardReleaseContext
LONG SCardReleaseContext(SCARDCONTEXT hContext) {
//	LOGFUNC();
	return SCARD_S_SUCCESS;
}

//SCardIsValidContext
LONG SCardIsValidContext(SCARDCONTEXT hContext) {
	LOGFUNC();
	return SCARD_S_SUCCESS;
}

//SCardConnect
LONG SCardConnect(SCARDCONTEXT hContext,
		LPCSTR szReader,
		DWORD dwShareMode,
		DWORD dwPreferredProtocols,
		/*@out@*/ LPSCARDHANDLE phCard, /*@out@*/ LPDWORD pdwActiveProtocol) {

	LOGFUNC();
	if (init() != SCARD_S_SUCCESS)
		return SCARD_E_NO_MEMORY;
	
	if (phCard)
		*phCard = 0x123456;	// arbitrary handle

	if (pdwActiveProtocol)
		*pdwActiveProtocol = 2;	// arbitrary protocol

	return SCARD_S_SUCCESS;
}

//SCardReconnect
LONG SCardReconnect(SCARDHANDLE hCard,
		DWORD dwShareMode,
		DWORD dwPreferredProtocols,
		DWORD dwInitialization, /*@out@*/ LPDWORD pdwActiveProtocol) {

	LOGFUNC();
	if (pdwActiveProtocol)
		*pdwActiveProtocol = 2;	// arbitrary protocol

	return SCARD_S_SUCCESS;
}

//SCardDisconnect
LONG SCardDisconnect(SCARDHANDLE hCard, DWORD dwDisposition) {
	LOGFUNC();
	return SCARD_S_SUCCESS;
}

//SCardBeginTransaction
LONG SCardBeginTransaction(SCARDHANDLE hCard) {
	LOGFUNC();
	return SCARD_S_SUCCESS; 
}

//SCardEndTransaction
LONG SCardEndTransaction(SCARDHANDLE hCard, DWORD dwDisposition) {
	LOGFUNC();
	return SCARD_S_SUCCESS;
}

//SCardStatus
LONG SCardStatus(SCARDHANDLE hCard,
		/*@null@*/ /*@out@*/ LPSTR mszReaderName,
		/*@null@*/ /*@out@*/ LPDWORD pcchReaderLen,
		/*@null@*/ /*@out@*/ LPDWORD pdwState,
		/*@null@*/ /*@out@*/ LPDWORD pdwProtocol,
		/*@null@*/ /*@out@*/ LPBYTE pbAtr,
		/*@null@*/ /*@out@*/ LPDWORD pcbAtrLen) {

	LOGFUNC();

	if (init() != SCARD_S_SUCCESS)
		return SCARD_E_NO_MEMORY;

	if (mszReaderName && pcchReaderLen && *pcchReaderLen > strlen(READER)) {
			memset(mszReaderName, 0, *pcchReaderLen);
			strcpy(mszReaderName, READER);
	}
	if (pcchReaderLen)
		*pcchReaderLen = strlen(READER) + 2;

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
LONG SCardGetStatusChange(SCARDCONTEXT hContext,
	DWORD dwTimeout,
	SCARD_READERSTATE *rgReaderStates, DWORD cReaders) {

	LOGFUNC();
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
LONG SCardControl(SCARDHANDLE hCard, DWORD dwControlCode,
	LPCVOID pbSendBuffer, DWORD cbSendLength,                       
	/*@out@*/ LPVOID pbRecvBuffer, DWORD cbRecvLength,              
	/*@out@*/ LPDWORD lpBytesReturned) {
	size_t rsize = cbRecvLength;
	char *rbuf = pbRecvBuffer;
	LONG rc;

	LOGFUNC();
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
LONG SCardTransmit(SCARDHANDLE hCard,
		const SCARD_IO_REQUEST *pioSendPci,
		LPCBYTE pbSendBuffer, DWORD cbSendLength,
		/*@out@*/ SCARD_IO_REQUEST *pioRecvPci,
		/*@out@*/ LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength) {
	size_t rsize = *pcbRecvLength;
	char *rbuf = pbRecvBuffer;
	LONG rc;

	LOGFUNC();

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
	rc = get_fuzz_bytes(rbuf, rsize);

	printf("< ");
	for (int i=0; i < *pcbRecvLength; i++) { printf("%02x ", ((char *)rbuf)[i] & 0xff); }
	printf("\n");
	
	return rc;
}

LONG SCardListReaderGroups(SCARDCONTEXT hContext,
	/*@out@*/ LPSTR mszGroups, LPDWORD pcchGroups) {

	LOGFUNC();
	// TODO: update mszGroups
	abort();
	return SCARD_S_SUCCESS;
}

//SCardListReaders
LONG SCardListReaders(SCARDCONTEXT hContext,
		/*@null@*/ /*@in@*/ LPCSTR mszGroups,
		/*@null@*/ /*@out@*/ LPSTR mszReaders,
		/*@out@*/ LPDWORD pcchReaders) {

	LOGFUNC();
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
LONG SCardFreeMemory(SCARDCONTEXT hContext, LPCVOID pvMem) {
	LOGFUNC();
	return SCARD_S_SUCCESS;
}

//SCardCancel
LONG SCardCancel(SCARDCONTEXT hContext) {
	LOGFUNC();
	return SCARD_S_SUCCESS;
}

LONG SCardGetAttrib(SCARDHANDLE hCard, DWORD dwAttrId,
	/*@out@*/ LPBYTE pbAttr, LPDWORD pcbAttrLen) {

	LOGFUNC();
	//TODO: implement
	abort();
	return SCARD_S_SUCCESS;
}

LONG SCardSetAttrib(SCARDHANDLE hCard, DWORD dwAttrId,
	LPCBYTE pbAttr, DWORD cbAttrLen) {

	LOGFUNC();
	return SCARD_S_SUCCESS;
}







