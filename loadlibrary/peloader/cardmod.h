//==============================================================;
//
//  CARDMOD.H
//
//  Abstract:
//      This is the header file commonly used for card modules.
//
//  This source code is only intended as a supplement to existing Microsoft
//  documentation.
//
//  THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
//  KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
//  IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
//  PURPOSE.
//
//  Copyright (C) Microsoft Corporation.  All Rights Reserved.
//
//==============================================================;
#ifndef __CARDMOD__H__
#define __CARDMOD__H__


// The next few do not belong here...! >----------

// Defines for fuzzer
// #define ATR "\x3b\x88\x80\x01\x30\x4c\x47\x12\x77\x83\xd5\x00\x01\x00\x00\x00" // NetKey
// #define ATR "\x3B\xF2\x18\x00\x02\xC1\x0A\x31\xFE\x58\xC8\x09\x75" // Etoken PRO 64k
// #define ATR "\x3B\xD5\x18\x00\x81\x31\x3A\x7D\x80\x73\xC8\x21\x10\x30" // Etoken PRO v4.29
// #define ATR "\x3b\xfc\x13\x00\x00\x81\x31\xfe\x15\x59\x75\x62\x69\x6b\x65\x79\x4e\x45\x4f\x72\x33\xe1" // YubicoNeo3
// #define ATR "\x3b\xba\x96\x00\x81\x31\x86\x5d\x00\x64\x00\x00\x02\x03\x31\x80\x90\x00\x00" // TCOS3 from inf file
#define ATR "\x3B\xFE\x18\x00\x00\x80\x31\xFE\x45\x80\x31\x80\x66\x40\x90\xA4\x16\x2A\x00\x83\x0F\x90\x00\xEF" // EstEID
//#define ATR "\x3b\x00\x00\x00\x00\x00\x00\x00\x00\x4D\x79\x45\x49\x44\x00" // MyEID
#define READER "Yubico"   
#define READERW L"Yubico"   



// Data from PCSC

#define SCARD_S_SUCCESS                 ((LONG)0x00000000) /**< No error was encountered. */
#define SCARD_E_NO_MEMORY               ((LONG)0x80100006) /**< Not enough memory available to complete this command. */

#define MAX_ATR_SIZE                    33      /**< Maximum ATR size */

#define SCARD_PRESENT                   0x0004  /**< Card is present */

#define SCARD_STATE_CHANGED             0x0002  /**< State has changed */      
#define SCARD_STATE_PRESENT             0x0020  /**< Card inserted */

typedef struct
{
        unsigned long dwProtocol;       /**< Protocol identifier */
        unsigned long cbPciLength;      /**< Protocol Control Inf Length */    
}
SCARD_IO_REQUEST, *PSCARD_IO_REQUEST, *LPSCARD_IO_REQUEST;

typedef struct
{
        const char *szReader;
        void *pvUserData;
        DWORD dwCurrentState;
        DWORD dwEventState;
        DWORD cbAtr;
        unsigned char rgbAtr[MAX_ATR_SIZE];
} SCARD_READERSTATE, *LPSCARD_READERSTATE;

typedef LONG SCARDCONTEXT;
typedef SCARDCONTEXT *LPSCARDCONTEXT;
typedef LONG SCARDHANDLE;
typedef SCARDHANDLE *LPSCARDHANDLE;

// Data from Wincrypt.h

typedef unsigned int ALG_ID;


// the rest is original stuff --------------------<



// This value should be passed to
//
//  SCardSetCardTypeProviderName
//  SCardGetCardTypeProviderName
//
// in order to query and set the Card Specific Module to be used
// for a given card.
#define SCARD_PROVIDER_CARD_MODULE 0x80000001

typedef struct _CARD_DATA CARD_DATA, *PCARD_DATA;

typedef ULONG_PTR CARD_KEY_HANDLE, *PCARD_KEY_HANDLE;

//
// This define can be used as a return value for queries involving
// card data that may be impossible to determine on a given card
// OS, such as the number of available card storage bytes.
//
#define CARD_DATA_VALUE_UNKNOWN                     ((DWORD) -1)

//
// Well Known Logical Names
//

//
// Logical Directory Names
//

// Second-level logical directories

#define szBASE_CSP_DIR                             "mscp"

#define szINTERMEDIATE_CERTS_DIR                   "mscerts"

//
// Logical File Names
//
// When requesting (or otherwise referring to) any logical file, the full path
// must be used, including when referring to well known files.  For example,
// to request the wszCONTAINER_MAP_FILE, the provided name will be
// "/mscp/cmapfile".
//

// Well known logical files under Microsoft
#define szCACHE_FILE                               "cardcf"

#define szCARD_IDENTIFIER_FILE                     "cardid"

// Well known logical files under CSP
#define szCONTAINER_MAP_FILE                       "cmapfile"
#define szROOT_STORE_FILE                          "msroots"

//
// Well known logical files under User Certs
//
// The following prefixes are appended with the container index of the
// associated key.  For example, the certificate associated with the
// Key Exchange key in container index 2 will have the name:
//  "/mscp/kxc2"
//
#define szUSER_SIGNATURE_CERT_PREFIX               "ksc"
#define szUSER_KEYEXCHANGE_CERT_PREFIX             "kxc"
#define szUSER_SIGNATURE_PRIVATE_KEY_PREFIX        "kss"
#define szUSER_SIGNATURE_PUBLIC_KEY_PREFIX         "ksp"
#define szUSER_KEYEXCHANGE_PRIVATE_KEY_PREFIX      "kxs"
#define szUSER_KEYEXCHANGE_PUBLIC_KEY_PREFIX       "kxp"

//
// Logical Card User Names
//
#define wszCARD_USER_EVERYONE                       L"anonymous"
#define wszCARD_USER_USER                           L"user"
#define wszCARD_USER_ADMIN                          L"admin"

// new ecc key specs

#define AT_ECDSA_P256      3
#define AT_ECDSA_P384      4
#define AT_ECDSA_P521      5
#define AT_ECDHE_P256      6
#define AT_ECDHE_P384      7
#define AT_ECDHE_P521      8
        
//
// Type: CARD_CACHE_FILE_FORMAT
//
// This struct is used as the file format of the cache file,
// as stored on the card.
//

#define CARD_CACHE_FILE_CURRENT_VERSION         1

typedef struct _CARD_CACHE_FILE_FORMAT
{
    BYTE bVersion;
    BYTE bPinsFreshness;

    WORD wContainersFreshness;
    WORD wFilesFreshness;
} CARD_CACHE_FILE_FORMAT, *PCARD_CACHE_FILE_FORMAT;

//
// Type: CONTAINER_MAP_RECORD
//
// This structure describes the format of the Base CSP's container map file,
// stored on the card.  This is well-known logical file wszCONTAINER_MAP_FILE.
// The file consists of zero or more of these records.
//
#define MAX_CONTAINER_NAME_LEN                  39

// This flag is set in the CONTAINER_MAP_RECORD bFlags member if the
// corresponding container is valid and currently exists on the card.
// If the container is deleted, its bFlags field must be cleared.
#define CONTAINER_MAP_VALID_CONTAINER           1

// This flag is set in the CONTAINER_MAP_RECORD bFlags
// member if the corresponding container is the default container on the card.
#define CONTAINER_MAP_DEFAULT_CONTAINER         2

typedef struct _CONTAINER_MAP_RECORD
{
    WCHAR wszGuid [MAX_CONTAINER_NAME_LEN + 1];
    BYTE bFlags;
    BYTE bReserved;
    WORD wSigKeySizeBits;
    WORD wKeyExchangeKeySizeBits;
} CONTAINER_MAP_RECORD, *PCONTAINER_MAP_RECORD;

//
// Converts a card filename string from unicode to ansi
//
DWORD 
WINAPI 
I_CardConvertFileNameToAnsi(
        PCARD_DATA pCardData,
        PWCHAR wszUnicodeName,
            PCHAR *ppszAnsiName);

// Logical Directory Access Conditions
typedef enum
{
    InvalidDirAc = 0,

    // User Read, Write
    UserCreateDeleteDirAc,

    // Admin Write
    AdminCreateDeleteDirAc

} CARD_DIRECTORY_ACCESS_CONDITION;

// Logical File Access Conditions
typedef enum
{
    // Invalid value, chosed to cooincide with common initialization
    // of memory
    InvalidAc = 0,

    // Everyone     Read
    // User         Read, Write
    //
    // Example:  A user certificate file.
    EveryoneReadUserWriteAc,

    // Everyone     None
    // User         Write, Execute
    //
    // Example:  A private key file.
    UserWriteExecuteAc,

    // Everyone     Read
    // Admin        Read, Write
    //
    // Example:  The Card Identifier file.
    EveryoneReadAdminWriteAc,

    // Explicit value to set when it is desired to say that
    // it is unknown
    UnknownAc,

    // Everyone No Access 
    // User Read Write 
    // 
    // Example:  A password wallet file. 

    UserReadWriteAc,
    // Everyone/User No Access 
    // Admin Read Write 
    // 
    // Example:  Administration data. 

    AdminReadWriteAc
} CARD_FILE_ACCESS_CONDITION;

//
// Function: CardAcquireContext
//
// Purpose: Initialize the CARD_DATA structure which will be used by
//          the CSP to interact with a specific card.
//
typedef DWORD (WINAPI *PFN_CARD_ACQUIRE_CONTEXT)(
            PCARD_DATA  pCardData,
            DWORD       dwFlags);

DWORD
WINAPI
CardAcquireContext(
            PCARD_DATA  pCardData,
            DWORD       dwFlags);

//
// Function: CardDeleteContext
//
// Purpose: Free resources consumed by the CARD_DATA structure.
//
typedef DWORD (WINAPI *PFN_CARD_DELETE_CONTEXT)(
            PCARD_DATA  pCardData);

DWORD
WINAPI
CardDeleteContext(
            PCARD_DATA  pCardData);

//
// Function: CardQueryCapabilities
//
// Purpose: Query the card module for specific functionality
//          provided by this card.
//
#define CARD_CAPABILITIES_CURRENT_VERSION 1

typedef struct _CARD_CAPABILITIES
{
    DWORD   dwVersion;
    BOOL    fCertificateCompression;
    BOOL    fKeyGen;
} CARD_CAPABILITIES, *PCARD_CAPABILITIES;

typedef DWORD (WINAPI *PFN_CARD_QUERY_CAPABILITIES)(
          PCARD_DATA          pCardData,
          PCARD_CAPABILITIES  pCardCapabilities);

DWORD
WINAPI
CardQueryCapabilities(
          PCARD_DATA          pCardData,
          PCARD_CAPABILITIES  pCardCapabilities);

// ****************
// PIN SUPPORT
// ****************

//
// There are 8 PINs currently defined in version 6. PIN values 0, 1 and 2 are 
// reserved for backwards compatibility, whereas PIN values 3-7 can be used 
// as additional PINs to protect key containers.
//

typedef     DWORD                       PIN_ID, *PPIN_ID;
typedef     DWORD                       PIN_SET, *PPIN_SET;

#define     MAX_PINS                    8

#define     ROLE_EVERYONE               0
#define     ROLE_USER                   1
#define     ROLE_ADMIN                  2

#define     PIN_SET_NONE                0x00
#define     PIN_SET_ALL_ROLES           0xFF
#define     CREATE_PIN_SET(PinId)       (1 << PinId)
#define     SET_PIN(PinSet, PinId)      PinSet |= CREATE_PIN_SET(PinId)
#define     IS_PIN_SET(PinSet, PinId)   (0 != (PinSet & CREATE_PIN_SET(PinId)))
#define     CLEAR_PIN(PinSet, PinId)    PinSet &= ~CREATE_PIN_SET(PinId)

#define     PIN_CHANGE_FLAG_UNBLOCK     0x01
#define     PIN_CHANGE_FLAG_CHANGEPIN   0x02

#define     CP_CACHE_MODE_GLOBAL_CACHE  1
#define     CP_CACHE_MODE_SESSION_ONLY  2
#define     CP_CACHE_MODE_NO_CACHE      3

#define     CARD_AUTHENTICATE_GENERATE_SESSION_PIN      0x10000000
#define     CARD_AUTHENTICATE_SESSION_PIN               0x20000000

#define     CARD_PIN_STRENGTH_PLAINTEXT                 0x1
#define     CARD_PIN_STRENGTH_SESSION_PIN               0x2 

#define     CARD_PIN_SILENT_CONTEXT                     0x00000040

typedef enum
{
    AlphaNumericPinType = 0,            // Regular PIN
    ExternalPinType,                    // Biometric PIN
    ChallengeResponsePinType,           // Challenge/Response PIN
    EmptyPinType                        // No PIN
} SECRET_TYPE;

typedef enum
{
    AuthenticationPin,                  // Authentication PIN
    DigitalSignaturePin,                // Digital Signature PIN
    EncryptionPin,                      // Encryption PIN
    NonRepudiationPin,                  // Non Repudiation PIN
    AdministratorPin,                   // Administrator PIN
    PrimaryCardPin,                     // Primary Card PIN
    UnblockOnlyPin,                     // Unblock only PIN (PUK)
} SECRET_PURPOSE;

typedef enum
{
    PinCacheNormal = 0,
    PinCacheTimed,
    PinCacheNone,
    PinCacheAlwaysPrompt
} PIN_CACHE_POLICY_TYPE;

#define      PIN_CACHE_POLICY_CURRENT_VERSION     6

typedef struct _PIN_CACHE_POLICY
{
    DWORD                                 dwVersion;
    PIN_CACHE_POLICY_TYPE                 PinCachePolicyType;
    DWORD                                 dwPinCachePolicyInfo;
} PIN_CACHE_POLICY, *PPIN_CACHE_POLICY;

#define      PIN_INFO_CURRENT_VERSION             6

#define      PIN_INFO_REQUIRE_SECURE_ENTRY        1

typedef struct _PIN_INFO
{
    DWORD                                 dwVersion;
    SECRET_TYPE                           PinType;
    SECRET_PURPOSE                        PinPurpose;
    PIN_SET                               dwChangePermission;
    PIN_SET                               dwUnblockPermission;
    PIN_CACHE_POLICY                      PinCachePolicy;
    DWORD                                 dwFlags;
} PIN_INFO, *PPIN_INFO;

typedef DWORD (WINAPI *PFN_CARD_GET_CHALLENGE_EX)(
                                    PCARD_DATA  pCardData,
                                    PIN_ID      PinId,
                                     PBYTE       *ppbChallengeData,
                                    PDWORD      pcbChallengeData,
                                    DWORD       dwFlags);

DWORD
WINAPI
CardGetChallengeEx(
                                        PCARD_DATA  pCardData,
                                        PIN_ID      PinId,
                                         PBYTE       *ppbChallengeData,
                                        PDWORD      pcbChallengeData,
                                        DWORD       dwFlags);

typedef DWORD (WINAPI *PFN_CARD_AUTHENTICATE_EX)(
                                        PCARD_DATA  pCardData,
                                        PIN_ID      PinId,
                                        DWORD       dwFlags,
                                        PBYTE       pbPinData,
                                        DWORD       cbPinData,
                                         PBYTE       *ppbSessionPin,
                                        PDWORD      pcbSessionPin,
                                        PDWORD      pcAttemptsRemaining);

DWORD 
WINAPI 
CardAuthenticateEx(
                                        PCARD_DATA  pCardData,
                                        PIN_ID      PinId,
                                        DWORD       dwFlags,
                                        PBYTE       pbPinData,
                                        DWORD       cbPinData,
                                        PBYTE       *ppbSessionPin,
                                   PDWORD      pcbSessionPin,
                                   PDWORD      pcAttemptsRemaining);

typedef DWORD (WINAPI *PFN_CARD_CHANGE_AUTHENTICATOR_EX)(
                                        PCARD_DATA  pCardData,
                                        DWORD       dwFlags,
                                        PIN_ID      dwAuthenticatingPinId,
                                        PBYTE       pbAuthenticatingPinData,
                                        DWORD       cbAuthenticatingPinData,
                                        PIN_ID      dwTargetPinId,
                                        PBYTE       pbTargetData,
                                        DWORD       cbTargetData,
                                        DWORD       cRetryCount,
                                        PDWORD      pcAttemptsRemaining);

DWORD 
WINAPI 
CardChangeAuthenticatorEx(
                                        PCARD_DATA  pCardData,
                                        DWORD       dwFlags,
                                        PIN_ID      dwAuthenticatingPinId,
                                            PBYTE       pbAuthenticatingPinData,
                                        DWORD       cbAuthenticatingPinData,
                                        PIN_ID      dwTargetPinId,
                                            PBYTE       pbTargetData,
                                        DWORD       cbTargetData,
                                        DWORD       cRetryCount,
                                        PDWORD      pcAttemptsRemaining);

typedef DWORD (WINAPI *PFN_CARD_DEAUTHENTICATE_EX)(
        PCARD_DATA   pCardData,
        PIN_SET      PinId,
        DWORD        dwFlags);

DWORD 
WINAPI 
CardDeauthenticateEx(
        PCARD_DATA   pCardData,
        PIN_SET      PinId,
        DWORD        dwFlags);

//
// Function: CardDeleteContainer
//
// Purpose: Delete the specified key container.
//
typedef DWORD (WINAPI *PFN_CARD_DELETE_CONTAINER)(
        PCARD_DATA  pCardData,
        BYTE        bContainerIndex,
        DWORD       dwReserved);

DWORD
WINAPI
CardDeleteContainer(
        PCARD_DATA  pCardData,
        BYTE        bContainerIndex,
        DWORD       dwReserved);

//
// Function: CardCreateContainer
//

#define CARD_CREATE_CONTAINER_KEY_GEN           1
#define CARD_CREATE_CONTAINER_KEY_IMPORT        2

typedef DWORD (WINAPI *PFN_CARD_CREATE_CONTAINER)(
        PCARD_DATA  pCardData,
        BYTE        bContainerIndex,
        DWORD       dwFlags,
        DWORD       dwKeySpec,
        DWORD       dwKeySize,
        PBYTE       pbKeyData);

DWORD
WINAPI
CardCreateContainer(
        PCARD_DATA  pCardData,
        BYTE        bContainerIndex,
        DWORD       dwFlags,
        DWORD       dwKeySpec,
        DWORD       dwKeySize,
        PBYTE       pbKeyData);

//
// Function: CardCreateContainerEx
//

typedef DWORD (WINAPI *PFN_CARD_CREATE_CONTAINER_EX)(
        PCARD_DATA  pCardData,
        BYTE        bContainerIndex,
        DWORD       dwFlags,
        DWORD       dwKeySpec,
        DWORD       dwKeySize,
        PBYTE       pbKeyData,
        PIN_ID      PinId);

DWORD
WINAPI
CardCreateContainerEx(
        PCARD_DATA  pCardData,
        BYTE        bContainerIndex,
        DWORD       dwFlags,
        DWORD       dwKeySpec,
        DWORD       dwKeySize,
        PBYTE       pbKeyData,
        PIN_ID      PinId);

//
// Function: CardGetContainerInfo
//
// Purpose: Query for all public information available about
//          the named key container.  This includes the Signature
//          and Key Exchange type public keys, if they exist.
//
//          The pbSigPublicKey and pbKeyExPublicKey buffers contain the
//          Signature and Key Exchange public keys, respectively, if they
//          exist.  The format of these buffers is a Crypto
//          API PUBLICKEYBLOB -
//
//              BLOBHEADER
//              RSAPUBKEY
//              modulus
//          
//          In the case of ECC public keys, the pbSigPublicKey will contain
//          the ECDSA key and pbKeyExPublicKey will contain the ECDH key if
//          they exist. ECC key structure -
//
//              BCRYPT_ECCKEY_BLOB
//              X coord (big endian)
//              Y coord (big endian)
//
#define CONTAINER_INFO_CURRENT_VERSION 1

typedef struct _CONTAINER_INFO
{
    DWORD dwVersion;
    DWORD dwReserved;

    DWORD cbSigPublicKey;
    PBYTE pbSigPublicKey;

    DWORD cbKeyExPublicKey;
    PBYTE pbKeyExPublicKey;
} CONTAINER_INFO, *PCONTAINER_INFO;

typedef DWORD (WINAPI *PFN_CARD_GET_CONTAINER_INFO)(
        PCARD_DATA      pCardData,
        BYTE            bContainerIndex,
        DWORD           dwFlags,
        PCONTAINER_INFO pContainerInfo);

DWORD
WINAPI
CardGetContainerInfo(
        PCARD_DATA      pCardData,
        BYTE            bContainerIndex,
        DWORD           dwFlags,
        PCONTAINER_INFO pContainerInfo);

//
// Function: CardAuthenticatePin
//
typedef DWORD (WINAPI *PFN_CARD_AUTHENTICATE_PIN)(
                       PCARD_DATA   pCardData,
                       PWCHAR       pwszUserId,
                       PBYTE        pbPin,
                       DWORD        cbPin,
                       PDWORD       pcAttemptsRemaining);


DWORD
WINAPI
CardAuthenticatePin(
                       PCARD_DATA   pCardData,
                       PWCHAR       pwszUserId,
                       PBYTE        pbPin,
                       DWORD        cbPin,
                       PDWORD       pcAttemptsRemaining);

//
// Function: CardGetChallenge
//
typedef DWORD (WINAPI *PFN_CARD_GET_CHALLENGE)(
                                        PCARD_DATA  pCardData,
                                        PBYTE       *ppbChallengeData,
                                        PDWORD      pcbChallengeData);

DWORD
WINAPI
CardGetChallenge(
                                        PCARD_DATA  pCardData,
                                        PBYTE       *ppbChallengeData,
                                        PDWORD      pcbChallengeData);

//
// Function: CardAuthenticateChallenge
//
typedef DWORD (WINAPI *PFN_CARD_AUTHENTICATE_CHALLENGE)(
                                 PCARD_DATA pCardData,
                                 PBYTE      pbResponseData,
                                 DWORD      cbResponseData,
                                 PDWORD     pcAttemptsRemaining);

DWORD
WINAPI
CardAuthenticateChallenge(
                                 PCARD_DATA pCardData,
                                 PBYTE      pbResponseData,
                                 DWORD      cbResponseData,
                                 PDWORD     pcAttemptsRemaining);

//
// Function: CardUnblockPin
//
#define CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE                 1
#define CARD_AUTHENTICATE_PIN_PIN                                2

typedef DWORD (WINAPI *PFN_CARD_UNBLOCK_PIN)(
                                   PCARD_DATA  pCardData,
                                   PWCHAR      pwszUserId,
                                   PBYTE       pbAuthenticationData,
                                   DWORD       cbAuthenticationData,
                                   PBYTE       pbNewPinData,
                                   DWORD       cbNewPinData,
                                   DWORD       cRetryCount,
                                   DWORD       dwFlags);

DWORD
WINAPI
CardUnblockPin(
                                   PCARD_DATA  pCardData,
                                   PWCHAR      pwszUserId,
                                   PBYTE       pbAuthenticationData,
                                   DWORD       cbAuthenticationData,
                                   PBYTE       pbNewPinData,
                                   DWORD       cbNewPinData,
                                   DWORD       cRetryCount,
                                   DWORD       dwFlags);

//
// Function: CardChangeAuthenticator
//
typedef DWORD (WINAPI *PFN_CARD_CHANGE_AUTHENTICATOR)(
                                     PCARD_DATA  pCardData,
                                     PWCHAR      pwszUserId,
                                     PBYTE       pbCurrentAuthenticator,
                                     DWORD       cbCurrentAuthenticator,
                                     PBYTE       pbNewAuthenticator,
                                     DWORD       cbNewAuthenticator,
                                     DWORD       cRetryCount,
                                     DWORD       dwFlags,
                                     PDWORD      pcAttemptsRemaining);

DWORD
WINAPI
CardChangeAuthenticator(
                                     PCARD_DATA  pCardData,
                                     PWCHAR      pwszUserId,
                                     PBYTE       pbCurrentAuthenticator,
                                     DWORD       cbCurrentAuthenticator,
                                     PBYTE       pbNewAuthenticator,
                                     DWORD       cbNewAuthenticator,
                                     DWORD       cRetryCount,
                                     DWORD       dwFlags,
                                PDWORD      pcAttemptsRemaining);

//
// Function: CardDeauthenticate
//
// Purpose: De-authenticate the specified logical user name on the card.
//
// This is an optional API.  If implemented, this API is used instead
// of SCARD_RESET_CARD by the Base CSP.  An example scenario is leaving
// a transaction in which the card has been authenticated (a Pin has been
// successfully presented).
//
// The pwszUserId parameter will point to a valid well-known User Name (see
// above).
//
// The dwFlags parameter is currently unused and will always be zero.
//
// Card modules that choose to not implement this API must set the CARD_DATA
// pfnCardDeauthenticate pointer to NULL.
//
typedef DWORD (WINAPI *PFN_CARD_DEAUTHENTICATE)(
          PCARD_DATA  pCardData,
          PWCHAR      pwszUserId,
          DWORD       dwFlags);

DWORD
WINAPI
CardDeauthenticate(
        PCARD_DATA  pCardData,
        PWCHAR      pwszUserId,
        DWORD       dwFlags);

// Directory Control Group

//
// Function: CardCreateDirectory
//
// Purpose: Register the specified application name on the card, and apply the
//          provided access condition.
//
// Return Value:
//          ERROR_FILE_EXISTS - directory already exists
//
typedef DWORD (WINAPI *PFN_CARD_CREATE_DIRECTORY)(
        PCARD_DATA                      pCardData,
        PCHAR                           pszDirectoryName,
        CARD_DIRECTORY_ACCESS_CONDITION AccessCondition);

DWORD
WINAPI
CardCreateDirectory(
        PCARD_DATA                      pCardData,
        PCHAR                           pszDirectoryName,
        CARD_DIRECTORY_ACCESS_CONDITION AccessCondition);

//
// Function: CardDeleteDirectory
//
// Purpose: Unregister the specified application from the card.
//
// Return Value:
//          SCARD_E_DIR_NOT_FOUND - directory does not exist
//          ERROR_DIR_NOT_EMPTY - the directory is not empty
//
typedef DWORD (WINAPI *PFN_CARD_DELETE_DIRECTORY)(
        PCARD_DATA  pCardData,
        PCHAR       pszDirectoryName);

DWORD
WINAPI
CardDeleteDirectory(
        PCARD_DATA  pCardData,
        PCHAR       pszDirectoryName);

// File Control Group

//
// Function: CardCreateFile
//
typedef DWORD (WINAPI *PFN_CARD_CREATE_FILE)(
            PCARD_DATA                  pCardData,
        PCHAR                       pszDirectoryName,
            PCHAR                       pszFileName,
            DWORD                       cbInitialCreationSize,
            CARD_FILE_ACCESS_CONDITION  AccessCondition);

DWORD
WINAPI
CardCreateFile(
            PCARD_DATA                  pCardData,
        PCHAR                       pszDirectoryName,
            PCHAR                       pszFileName,
            DWORD                       cbInitialCreationSize,
            CARD_FILE_ACCESS_CONDITION  AccessCondition);

//
// Function: CardReadFile
//
// Purpose: Read the specified file from the card.
//
//          The pbData parameter should be allocated
//          by the card module and freed by the CSP.  The card module
//          must set the cbData parameter to the size of the returned buffer.
//
typedef DWORD (WINAPI *PFN_CARD_READ_FILE)(
                                        PCARD_DATA  pCardData,
                                            PCHAR       pszDirectoryName,
                                         PCHAR       pszFileName,
                                        DWORD       dwFlags,
                                        PBYTE       *ppbData,
                                              PDWORD      pcbData);

DWORD
WINAPI
CardReadFile(
                                        PCARD_DATA  pCardData,
                                                    PCHAR       pszDirectoryName,
                                        PCHAR       pszFileName,
                                        DWORD       dwFlags,
                                            PBYTE       *ppbData,
                                              PDWORD      pcbData);

//
// Function: CardWriteFile
//
typedef DWORD (WINAPI *PFN_CARD_WRITE_FILE)(
                         PCARD_DATA  pCardData,
                             PCHAR       pszDirectoryName,
                         PCHAR       pszFileName,
                         DWORD       dwFlags,
                         PBYTE       pbData,
                         DWORD       cbData);

DWORD
WINAPI
CardWriteFile(
                         PCARD_DATA  pCardData,
                         PCHAR       pszDirectoryName,
                         PCHAR       pszFileName,
                         DWORD       dwFlags,
                         PBYTE       pbData,
                         DWORD       cbData);

//
// Function: CardDeleteFile
//
typedef DWORD (WINAPI *PFN_CARD_DELETE_FILE)(
            PCARD_DATA  pCardData,
            PCHAR       pszDirectoryName,
            PCHAR       pszFileName,
            DWORD       dwFlags);

DWORD
WINAPI
CardDeleteFile(
            PCARD_DATA  pCardData,
            PCHAR       pszDirectoryName,
            PCHAR       pszFileName,
            DWORD       dwFlags);

//
// Function: CardEnumFiles
//
// Purpose: Return a multi-string list of the general files
//          present on this card.  The multi-string is allocated
//          by the card module and must be freed by the CSP.
//
//  The caller must provide a logical file directory name in the
//  pmwszFileNames parameter (see Logical Directory Names, above).
//  The logical directory name indicates which group of files will be
//  enumerated.
//
//  The logical directory name is expected to be a static string, so the
//  the card module will not free it.  The card module
//  will allocate a new buffer in *pmwszFileNames to store the multi-string
//  list of enumerated files using pCardData->pfnCspAlloc.
//
//  If the function fails for any reason, *pmwszFileNames is set to NULL.
//
typedef DWORD (WINAPI *PFN_CARD_ENUM_FILES)(
                                    PCARD_DATA  pCardData,
                                PCHAR       pszDirectoryName,
                                        PCHAR       *pmszFileNames,
                                        PDWORD     pdwcbFileName,
                                        DWORD       dwFlags);

DWORD
WINAPI
CardEnumFiles(
                                    PCARD_DATA  pCardData,
                                    PCHAR       pszDirectoryName,
                                    PCHAR      *pmszFileNames,
                                    PDWORD     pdwcbFileName,
                                    DWORD       dwFlags);

//
// Function: CardGetFileInfo
//
#define CARD_FILE_INFO_CURRENT_VERSION 1

typedef struct _CARD_FILE_INFO
{
    DWORD                       dwVersion;
    DWORD                       cbFileSize;
    CARD_FILE_ACCESS_CONDITION  AccessCondition;
} CARD_FILE_INFO, *PCARD_FILE_INFO;

typedef DWORD (WINAPI *PFN_CARD_GET_FILE_INFO)(
            PCARD_DATA      pCardData,
            PCHAR           pszDirectoryName,
            PCHAR           pszFileName,
            PCARD_FILE_INFO pCardFileInfo);

DWORD
WINAPI
CardGetFileInfo(
            PCARD_DATA      pCardData,
            PCHAR           pszDirectoryName,
            PCHAR           pszFileName,
            PCARD_FILE_INFO pCardFileInfo);

//
// Function: CardQueryFreeSpace
//
#define CARD_FREE_SPACE_INFO_CURRENT_VERSION 1

typedef struct _CARD_FREE_SPACE_INFO
{
    DWORD dwVersion;
    DWORD dwBytesAvailable;
    DWORD dwKeyContainersAvailable;
    DWORD dwMaxKeyContainers;

} CARD_FREE_SPACE_INFO, *PCARD_FREE_SPACE_INFO;

typedef DWORD (WINAPI *PFN_CARD_QUERY_FREE_SPACE)(
        PCARD_DATA              pCardData,
        DWORD                   dwFlags,
        PCARD_FREE_SPACE_INFO   pCardFreeSpaceInfo);

DWORD
WINAPI
CardQueryFreeSpace(
        PCARD_DATA              pCardData,
        DWORD                   dwFlags,
        PCARD_FREE_SPACE_INFO   pCardFreeSpaceInfo);

//
// Function: CardQueryKeySizes
//
#define CARD_KEY_SIZES_CURRENT_VERSION 1

typedef struct _CARD_KEY_SIZES
{
    DWORD dwVersion;
    DWORD dwMinimumBitlen;
    DWORD dwDefaultBitlen;
    DWORD dwMaximumBitlen;
    DWORD dwIncrementalBitlen;

} CARD_KEY_SIZES, *PCARD_KEY_SIZES;

typedef DWORD (WINAPI *PFN_CARD_QUERY_KEY_SIZES)(
        PCARD_DATA      pCardData,
        DWORD           dwKeySpec,
        DWORD           dwFlags,
        PCARD_KEY_SIZES pKeySizes);

DWORD
WINAPI
CardQueryKeySizes(
        PCARD_DATA      pCardData,
        DWORD           dwKeySpec,
        DWORD           dwFlags,
        PCARD_KEY_SIZES pKeySizes);

// CARD_RSA_DECRYPT_INFO_VERSION_ONE is provided for pre-v7 certified
// mini-drivers that do not have logic for on-card padding removal.
#define CARD_RSA_KEY_DECRYPT_INFO_VERSION_ONE   1

#define CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO   2

//
// Function: CardRSADecrypt
//
// Purpose: Perform a private key decryption on the supplied data.  The
//          card module should assume that pbData is the length of the
//          key modulus.
//
#define CARD_RSA_KEY_DECRYPT_INFO_CURRENT_VERSION CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO

typedef struct _CARD_RSA_DECRYPT_INFO
{
    DWORD dwVersion; 
    BYTE bContainerIndex; 

    // For RSA operations, this should be AT_SIGNATURE or AT_KEYEXCHANGE.
    DWORD dwKeySpec;

    // This is the buffer and length that the caller expects to be decrypted.
    // For RSA operations, cbData is redundant since the length of the buffer
    // should always be equal to the length of the key modulus.
    PBYTE pbData; 
    DWORD cbData;

    // The following parameters are new in version 2 of the
    // CARD_RSA_DECRYPT_INFO structure.
    // Currently supported values for dwPaddingType are
    // CARD_PADDING_PKCS1, CARD_PADDING_OAEP, and CARD_PADDING_NONE.
    // If dwPaddingType is set to CARD_PADDING_OAEP, then pPaddingInfo
    // will point to a BCRYPT_OAEP_PADDING_INFO structure.
    PVOID  pPaddingInfo;
    DWORD   dwPaddingType;
} CARD_RSA_DECRYPT_INFO, *PCARD_RSA_DECRYPT_INFO;

typedef DWORD (WINAPI *PFN_CARD_RSA_DECRYPT)(
        PCARD_DATA              pCardData,
        PCARD_RSA_DECRYPT_INFO  pInfo);

DWORD
WINAPI
CardRSADecrypt(
        PCARD_DATA              pCardData,
        PCARD_RSA_DECRYPT_INFO  pInfo);

#define CARD_PADDING_INFO_PRESENT 0x40000000
#define CARD_BUFFER_SIZE_ONLY     0x20000000
#define CARD_PADDING_NONE         0x00000001
#define CARD_PADDING_PKCS1        0x00000002
#define CARD_PADDING_PSS          0x00000004
#define CARD_PADDING_OAEP         0x00000008

// CARD_SIGNING_INFO_BASIC_VERSION is provided for thos applications
// do not intend to support passing in the pPaddingInfo structure
#define CARD_SIGNING_INFO_BASIC_VERSION 1

//
// Function: CardSignData
//
// Purpose: Sign inupt data using a specified key
//
#define CARD_SIGNING_INFO_CURRENT_VERSION 2
typedef struct _CARD_SIGNING_INFO
{
    DWORD  dwVersion;

    BYTE   bContainerIndex;

    // See dwKeySpec constants
    DWORD  dwKeySpec;

    // If CARD_BUFFER_SIZE_ONLY flag is present then the card 
    // module should return only the size of the resulting 
    // key in cbSignedData
    DWORD  dwSigningFlags;

    // If the aiHashAlg is non zero, then it specifies the algorithm
    // to use when padding the data using PKCS
    ALG_ID aiHashAlg;

    // This is the buffer and length that the caller expects to be signed.
    // Signed version is allocated a buffer and put in cb/pbSignedData.  That should
    // be freed using PFN_CSP_FREE callback.
    PBYTE  pbData;
    DWORD  cbData;

    PBYTE  pbSignedData;
    DWORD  cbSignedData;

    // The following parameters are new in version 2 of the 
    // CARD_SIGNING_INFO structure.
    // If CARD_PADDING_INFO_PRESENT is set in dwSigningFlags then
    // pPaddingInfo will point to the BCRYPT_PADDING_INFO structure
    // defined by dwPaddingType.  Currently supported values are
    // CARD_PADDING_PKCS1, CARD_PADDING_PSS and CARD_PADDING_NONE
    PVOID pPaddingInfo;
    DWORD  dwPaddingType;
} CARD_SIGNING_INFO, *PCARD_SIGNING_INFO;

typedef DWORD (WINAPI *PFN_CARD_SIGN_DATA)(
        PCARD_DATA          pCardData,
        PCARD_SIGNING_INFO  pInfo);

DWORD
WINAPI
CardSignData(
        PCARD_DATA          pCardData,
        PCARD_SIGNING_INFO  pInfo);

//
// Type: CARD_DH_AGREEMENT_INFO
//
// CARD_DH_AGREEMENT_INFO version 1 is no longer supported and should
// not be implemented
//

#define CARD_DH_AGREEMENT_INFO_VERSION 2

typedef struct _CARD_DH_AGREEMENT_INFO
{
    DWORD dwVersion;
    BYTE  bContainerIndex;
    DWORD dwFlags;
    DWORD dwPublicKey;
    PBYTE pbPublicKey;
    PBYTE pbReserved;
    DWORD cbReserved;

    BYTE bSecretAgreementIndex;
} CARD_DH_AGREEMENT_INFO, *PCARD_DH_AGREEMENT_INFO;

//
// Function:  CardConstructDHAgreement
//
// Purpose: compute a DH secret agreement from a ECDH key on the card
// and the public portion of another ECDH key
//

typedef DWORD (WINAPI *PFN_CARD_CONSTRUCT_DH_AGREEMENT)(
        PCARD_DATA pCardData,
        PCARD_DH_AGREEMENT_INFO pAgreementInfo);

DWORD 
WINAPI 
CardConstructDHAgreement(
        PCARD_DATA pCardData,
        PCARD_DH_AGREEMENT_INFO pAgreementInfo);

//
// Type: CARD_DERIVE_KEY_INFO
//
#define CARD_DERIVE_KEY_VERSION 1
#define CARD_DERIVE_KEY_VERSION_TWO     2
#define CARD_DERIVE_KEY_CURRENT_VERSION CARD_DERIVE_KEY_VERSION_TWO

// If CARD_RETURN_KEY_HANDLE is passed then the card module should return a
// key handle instead of the key derivation data
#define CARD_RETURN_KEY_HANDLE          0x1000000

typedef struct _CARD_DERIVE_KEY
{
    DWORD             dwVersion;
   
    // If CARD_BUFFER_SIZE_ONLY is passed then the card module
    // should return only the size of the resulting key in
    // cbDerivedKey 
    DWORD             dwFlags;
    PWCHAR            pwszKDF;
    BYTE              bSecretAgreementIndex;     

    PVOID             pParameterList;

    PBYTE             pbDerivedKey;
    DWORD             cbDerivedKey;

    // The following parameter can be used by the card to determine 
    // key derivation material and to pass back a symmetric key handle
    // as a result of the key derivation algorithm
    PWCHAR            pwszAlgId;
    DWORD             dwKeyLen;
    CARD_KEY_HANDLE   hKey;
} CARD_DERIVE_KEY, *PCARD_DERIVE_KEY;

//
// Function:  CardDeriveKey
//
// Purpose: Generate a dervived session key using a generated agreed 
// secret and various other parameters.
//

typedef DWORD (WINAPI *PFN_CARD_DERIVE_KEY)(
        PCARD_DATA pCardData,
        PCARD_DERIVE_KEY pAgreementInfo);

DWORD 
WINAPI 
CardDeriveKey(
        PCARD_DATA pCardData,
        PCARD_DERIVE_KEY pAgreementInfo);

//
// Function:  CardDestroyAgreement
//
// Purpose: Force a deletion of the DH agreed secret.
//

typedef DWORD (WINAPI *PFN_CARD_DESTROY_DH_AGREEMENT)(
     PCARD_DATA pCardData,
     BYTE       bSecretAgreementIndex,
     DWORD      dwFlags);

DWORD 
WINAPI 
CardDestroyDHAgreement(
     PCARD_DATA pCardData,
     BYTE       bSecretAgreementIndex,
     DWORD      dwFlags);

//
// Function:  CspGetDHAgreement
//
// Purpose: The CARD_DERIVE_KEY structure contains a list of parameters
// (pParameterList) which might contain a reference to one or more addition
// agreed secrets (KDF_NCRYPT_SECRET_HANDLE).  This callback is provided by
// the caller of CardDeriveKey and will translate the parameter into the
// on card agreed secret handle.
//

typedef DWORD (WINAPI *PFN_CSP_GET_DH_AGREEMENT)(
        PCARD_DATA  pCardData,
        PVOID       hSecretAgreement,
            BYTE*       pbSecretAgreementIndex,
        DWORD       dwFlags);

DWORD 
WINAPI 
CspGetDHAgreement(
        PCARD_DATA  pCardData,
        PVOID       hSecretAgreement,
            BYTE*       pbSecretAgreementIndex,
        DWORD       dwFlags);

//
// Memory Management Routines
//
// These routines are supplied to the card module
// by the calling CSP.
//

//
// Function: PFN_CSP_ALLOC
//
typedef PVOID (WINAPI *PFN_CSP_ALLOC)(
          SIZE_T      Size);

//
// Function: PFN_CSP_REALLOC
//
typedef PVOID (WINAPI *PFN_CSP_REALLOC)(
          PVOID      Address,
          SIZE_T      Size);

//
// Function: PFN_CSP_FREE
//
// Note: Data allocated for the CSP by the card module must
//       be freed by the CSP.
//
typedef void (WINAPI *PFN_CSP_FREE)(
          PVOID      Address);

//
// Function: PFN_CSP_CACHE_ADD_FILE
//
// A copy of the pbData parameter is added to the cache.
//
typedef DWORD (WINAPI *PFN_CSP_CACHE_ADD_FILE)(
                    PVOID       pvCacheContext,
                    PWCHAR      wszTag,
                    DWORD       dwFlags,
                    PBYTE       pbData,
                    DWORD       cbData);

//
// Function: PFN_CSP_CACHE_LOOKUP_FILE
//
// If the cache lookup is successful,
// the caller must free the *ppbData pointer with pfnCspFree.
//
typedef DWORD (WINAPI *PFN_CSP_CACHE_LOOKUP_FILE)(
                                PVOID       pvCacheContext,
                                PWCHAR      wszTag,
                                DWORD       dwFlags,
                                PBYTE      *ppbData,
                                PDWORD      pcbData);

//
// Function: PFN_CSP_CACHE_DELETE_FILE
//
// Deletes the specified item from the cache.
//
typedef DWORD (WINAPI *PFN_CSP_CACHE_DELETE_FILE)(
          PVOID       pvCacheContext,
          PWCHAR      wszTag,
          DWORD       dwFlags);

//
// Function: PFN_CSP_PAD_DATA
//
// Callback to pad buffer for crypto operation.  Used when
// the card does not provide this.
//
typedef DWORD (WINAPI *PFN_CSP_PAD_DATA)(
                                        PCARD_SIGNING_INFO  pSigningInfo,
                                        DWORD               cbMaxWidth,
                                        DWORD*              pcbPaddedBuffer,
                                        PBYTE*              ppbPaddedBuffer);

//
// Function: PFN_CSP_UNPAD_DATA
//
// Callback to unpad buffer for crypto operation. Used when
// the card does not provide this.
//
typedef DWORD (WINAPI *PFN_CSP_UNPAD_DATA)(
                                        PCARD_RSA_DECRYPT_INFO  pRSADecryptInfo,
                                        DWORD*                  pcbUnpaddedData,
                                        PBYTE*                  ppbUnpaddedData);

// *******************
// Container Porperties
// *******************

#define CCP_CONTAINER_INFO             L"Container Info" // Read only
#define CCP_PIN_IDENTIFIER             L"PIN Identifier"
#define CCP_ASSOCIATED_ECDH_KEY        L"Associated ECDH Key"

typedef DWORD (WINAPI *PFN_CARD_GET_CONTAINER_PROPERTY)(
                                            PCARD_DATA  pCardData,
                                            BYTE        bContainerIndex,
                                            PWCHAR     wszProperty,
                                            PBYTE       pbData,
                                            DWORD       cbData,
                                            PDWORD      pdwDataLen,
                                            DWORD       dwFlags);

DWORD 
WINAPI 
CardGetContainerProperty(
                                            PCARD_DATA  pCardData,
                                            BYTE        bContainerIndex,
                                            PWCHAR     wszProperty,
                                            PBYTE       pbData,
                                            DWORD       cbData,
                                            PDWORD      pdwDataLen,
                                            DWORD       dwFlags);

typedef DWORD (WINAPI *PFN_CARD_SET_CONTAINER_PROPERTY)(
                        PCARD_DATA  pCardData,
                        BYTE        bContainerIndex,
                        PWCHAR     wszProperty,
                        PBYTE       pbData,
                        DWORD       cbDataLen,
                        DWORD       dwFlags);

DWORD 
WINAPI 
CardSetContainerProperty(
                        PCARD_DATA  pCardData,
                        BYTE        bContainerIndex,
                        PWCHAR     wszProperty,
                        PBYTE       pbData,
                        DWORD       cbDataLen,
                        DWORD       dwFlags);

// *******************
// Card Properties
// *******************

#define CP_CARD_FREE_SPACE              L"Free Space"              // Read only
#define CP_CARD_CAPABILITIES            L"Capabilities"            // Read only
#define CP_CARD_KEYSIZES                L"Key Sizes"               // Read only

#define CP_CARD_READ_ONLY               L"Read Only Mode"
#define CP_CARD_CACHE_MODE              L"Cache Mode"
#define CP_SUPPORTS_WIN_X509_ENROLLMENT L"Supports Windows x.509 Enrollment"

#define CP_CARD_GUID                    L"Card Identifier"
#define CP_CARD_SERIAL_NO               L"Card Serial Number"

#define CP_CARD_PIN_INFO                L"PIN Information"
#define CP_CARD_LIST_PINS               L"PIN List"                // Read only
#define CP_CARD_AUTHENTICATED_STATE     L"Authenticated State"     // Read only

#define CP_CARD_PIN_STRENGTH_VERIFY     L"PIN Strength Verify"     // Read only
#define CP_CARD_PIN_STRENGTH_CHANGE     L"PIN Strength Change"     // Read only
#define CP_CARD_PIN_STRENGTH_UNBLOCK    L"PIN Strength Unblock"    // Read only

#define CP_PARENT_WINDOW                L"Parent Window"           // Write only
#define CP_PIN_CONTEXT_STRING           L"PIN Context String"      // Write only


typedef DWORD (WINAPI *PFN_CARD_GET_PROPERTY)(
                                            PCARD_DATA  pCardData,
                                            PWCHAR     wszProperty,
                                            PBYTE       pbData,
                                            DWORD       cbData,
                                            PDWORD      pdwDataLen,
                                            DWORD       dwFlags);

DWORD 
WINAPI 
CardGetProperty(
                                            PCARD_DATA  pCardData,
                                            PWCHAR     wszProperty,
                                            PBYTE       pbData,
                                            DWORD       cbData,
                                            PDWORD      pdwDataLen,
                                            DWORD       dwFlags);

typedef DWORD (WINAPI *PFN_CARD_SET_PROPERTY)(
                        PCARD_DATA  pCardData,
                        PWCHAR     wszProperty,
                        PBYTE       pbData,
                        DWORD       cbDataLen,
                        DWORD       dwFlags);

DWORD 
WINAPI 
CardSetProperty(
                        PCARD_DATA  pCardData,
                        PWCHAR     wszProperty,
                        PBYTE       pbData,
                        DWORD       cbDataLen,
                        DWORD       dwFlags);

// **************************
// Secure key injection flags
// **************************

#define    CARD_SECURE_KEY_INJECTION_NO_CARD_MODE 0x1 // No card operations

#define    CARD_KEY_IMPORT_PLAIN_TEXT             0x1
#define    CARD_KEY_IMPORT_RSA_KEYEST             0x2
#define    CARD_KEY_IMPORT_ECC_KEYEST             0x4
#define    CARD_KEY_IMPORT_SHARED_SYMMETRIC       0x8

#define    CARD_CIPHER_OPERATION       0x1 // Symmetric operations
#define    CARD_ASYMMETRIC_OPERATION   0x2 // Asymmetric operations

#define    CARD_3DES_112_ALGORITHM     BCRYPT_3DES_112_ALGORITHM  // 3DES 2 key
#define    CARD_3DES_ALGORITHM         BCRYPT_3DES_ALGORITHM      // 3DES 3 key
#define    CARD_AES_ALGORITHM          BCRYPT_AES_ALGORITHM

#define    CARD_BLOCK_PADDING          BCRYPT_BLOCK_PADDING

#define    CARD_CHAIN_MODE_CBC         BCRYPT_CHAIN_MODE_CBC

// *******************************
// Secure key injection structures
// *******************************

#pragma warning(push)
#pragma warning(disable:4200) //nonstandard extension used : zero-sized array in struct/union

typedef struct _CARD_ENCRYPTED_DATA {
    PBYTE   pbEncryptedData;
    DWORD   cbEncryptedData;
} CARD_ENCRYPTED_DATA, *PCARD_ENCRYPTED_DATA;

#define     CARD_IMPORT_KEYPAIR_VERSION_SEVEN   7
#define     CARD_IMPORT_KEYPAIR_CURRENT_VERSION CARD_IMPORT_KEYPAIR_VERSION_SEVEN

typedef struct _CARD_IMPORT_KEYPAIR
{
    DWORD   dwVersion;
    BYTE    bContainerIndex;
    PIN_ID  PinId;
    DWORD   dwKeySpec;
    DWORD   dwKeySize;
    DWORD   cbInput;
    BYTE    pbInput[0];
} CARD_IMPORT_KEYPAIR, *PCARD_IMPORT_KEYPAIR;

#define     CARD_CHANGE_AUTHENTICATOR_VERSION_SEVEN   7
#define     CARD_CHANGE_AUTHENTICATOR_CURRENT_VERSION CARD_CHANGE_AUTHENTICATOR_VERSION_SEVEN

typedef struct _CARD_CHANGE_AUTHENTICATOR
{
    DWORD   dwVersion;
    DWORD   dwFlags;
    PIN_ID  dwAuthenticatingPinId;
    DWORD   cbAuthenticatingPinData;
    PIN_ID  dwTargetPinId;
    DWORD   cbTargetData;
    DWORD   cRetryCount;
    BYTE    pbData[0];
    /* pbAuthenticatingPinData = pbData */
    /* pbTargetData = pbData + cbAuthenticatingPinData */
} CARD_CHANGE_AUTHENTICATOR, *PCARD_CHANGE_AUTHENTICATOR;

#define     CARD_CHANGE_AUTHENTICATOR_RESPONSE_VERSION_SEVEN   7
#define     CARD_CHANGE_AUTHENTICATOR_RESPONSE_CURRENT_VERSION CARD_CHANGE_AUTHENTICATOR_RESPONSE_VERSION_SEVEN

typedef struct _CARD_CHANGE_AUTHENTICATOR_RESPONSE
{
    DWORD   dwVersion;
    DWORD   cAttemptsRemaining;
} CARD_CHANGE_AUTHENTICATOR_RESPONSE, *PCARD_CHANGE_AUTHENTICATOR_RESPONSE;

#define     CARD_AUTHENTICATE_VERSION_SEVEN   7
#define     CARD_AUTHENTICATE_CURRENT_VERSION CARD_AUTHENTICATE_VERSION_SEVEN

typedef struct _CARD_AUTHENTICATE
{
    DWORD   dwVersion;
    DWORD   dwFlags;
    PIN_ID  PinId;
    DWORD   cbPinData;
    BYTE    pbPinData[0];
} CARD_AUTHENTICATE, *PCARD_AUTHENTICATE;

#define     CARD_AUTHENTICATE_RESPONSE_VERSION_SEVEN   7
#define     CARD_AUTHENTICATE_RESPONSE_CURRENT_VERSION CARD_AUTHENTICATE_RESPONSE_VERSION_SEVEN

typedef struct _CARD_AUTHENTICATE_RESPONSE
{
    DWORD   dwVersion;
    DWORD   cbSessionPin;
    DWORD   cAttemptsRemaining;
    BYTE    pbSessionPin[0];
} CARD_AUTHENTICATE_RESPONSE, *PCARD_AUTHENTICATE_RESPONSE;

#pragma warning(pop)

// *******************************************************
// Secure key injection properties / secure function names
// *******************************************************

#define CP_KEY_IMPORT_SUPPORT           L"Key Import Support"    // Read only
#define CP_ENUM_ALGORITHMS              L"Algorithms"            // Read only
#define CP_PADDING_SCHEMES              L"Padding Schemes"       // Read only
#define CP_CHAINING_MODES               L"Chaining Modes"        // Read only

#define CSF_IMPORT_KEYPAIR              L"Import Key Pair"
#define CSF_CHANGE_AUTHENTICATOR        L"Change Authenticator"
#define CSF_AUTHENTICATE                L"Authenticate"

#define CKP_CHAINING_MODE               L"ChainingMode"
#define CKP_INITIALIZATION_VECTOR       L"IV"
#define CKP_BLOCK_LENGTH                L"BlockLength"

// ******************************
// Secure key injection functions
// ******************************

typedef DWORD (WINAPI *PFN_MD_IMPORT_SESSION_KEY)(
                        PCARD_DATA          pCardData,
                        PWCHAR             pwszBlobType,
                        PWCHAR             pwszAlgId,
                        PCARD_KEY_HANDLE    phKey,
                        PBYTE               pbInput,
                        DWORD               cbInput);

DWORD 
WINAPI 
MDImportSessionKey(
                        PCARD_DATA          pCardData,
                        PWCHAR             pwszBlobType,
                        PWCHAR             pwszAlgId,
                        PCARD_KEY_HANDLE    phKey,
                        PBYTE               pbInput,
                        DWORD               cbInput);

typedef DWORD (WINAPI *PFN_MD_ENCRYPT_DATA)(
                                        PCARD_DATA              pCardData,
                                        CARD_KEY_HANDLE         hKey,
                                        PWCHAR                 pwszSecureFunction,
                                        PBYTE                   pbInput,
                                        DWORD                   cbInput,
                                        DWORD                   dwFlags,
                                        PCARD_ENCRYPTED_DATA    *ppEncryptedData,
                                        PDWORD                  pcEncryptedData);

DWORD 
WINAPI 
MDEncryptData(
                                        PCARD_DATA              pCardData,
                                        CARD_KEY_HANDLE         hKey,
                                        PWCHAR                 pwszSecureFunction,
                                        PBYTE                   pbInput,
                                        DWORD                   cbInput,
                                        DWORD                   dwFlags,
                                        PCARD_ENCRYPTED_DATA    *ppEncryptedData,
                                        PDWORD                  pcEncryptedData);

typedef DWORD (WINAPI *PFN_CARD_GET_SHARED_KEY_HANDLE)(
                                    PCARD_DATA          pCardData,
                                    PBYTE               pbInput,
                                    DWORD               cbInput,
                                    PBYTE               *ppbOutput,
                                    PDWORD              pcbOutput,
                                    PCARD_KEY_HANDLE    phKey);

DWORD 
WINAPI 
CardGetSharedKeyHandle(
                                    PCARD_DATA          pCardData,
                                    PBYTE               pbInput,
                                    DWORD               cbInput,
                                    PBYTE               *ppbOutput,
                                    PDWORD              pcbOutput,
                                    PCARD_KEY_HANDLE    phKey);

typedef DWORD (WINAPI *PFN_CARD_DESTROY_KEY)(
        PCARD_DATA      pCardData,
        CARD_KEY_HANDLE hKey);

DWORD 
WINAPI 
CardDestroyKey(
        PCARD_DATA      pCardData,
        CARD_KEY_HANDLE hKey);

typedef DWORD (WINAPI *PFN_CARD_GET_ALGORITHM_PROPERTY)(
                                            PCARD_DATA  pCardData,
                                            PWCHAR     pwszAlgId,
                                            PWCHAR     pwszProperty,
                                            PBYTE       pbData,
                                            DWORD       cbData,
                                            PDWORD      pdwDataLen, 
                                            DWORD       dwFlags);

DWORD 
WINAPI 
CardGetAlgorithmProperty(
                                            PCARD_DATA  pCardData,
                                            PWCHAR     pwszAlgId,
                                            PWCHAR     pwszProperty,
                                            PBYTE       pbData,
                                            DWORD       cbData,
                                            PDWORD      pdwDataLen, 
                                            DWORD       dwFlags);

typedef DWORD (WINAPI *PFN_CARD_GET_KEY_PROPERTY)(
                                            PCARD_DATA      pCardData,
                                            CARD_KEY_HANDLE hKey,
                                            PWCHAR         pwszProperty,
                                            PBYTE           pbData,
                                            DWORD           cbData,
                                            PDWORD          pdwDataLen,
                                            DWORD           dwFlags);

DWORD 
WINAPI 
CardGetKeyProperty(
                                            PCARD_DATA      pCardData,
                                            CARD_KEY_HANDLE hKey,
                                            PWCHAR         pwszProperty,
                                            PBYTE           pbData,
                                            DWORD           cbData,
                                            PDWORD          pdwDataLen,
                                            DWORD           dwFlags);

typedef DWORD (WINAPI *PFN_CARD_SET_KEY_PROPERTY)(
                        PCARD_DATA      pCardData,
                        CARD_KEY_HANDLE hKey,
                        PWCHAR         pwszProperty,
                        PBYTE           pbInput,
                        DWORD           cbInput,
                        DWORD           dwFlags);

DWORD 
WINAPI 
CardSetKeyProperty(
                        PCARD_DATA      pCardData,
                        CARD_KEY_HANDLE hKey,
                        PWCHAR         pwszProperty,
                        PBYTE           pbInput,
                        DWORD           cbInput,
                        DWORD           dwFlags);

typedef DWORD (WINAPI *PFN_CARD_IMPORT_SESSION_KEY)(
                        PCARD_DATA          pCardData,
                        BYTE                bContainerIndex,
                        PVOID              pPaddingInfo,
                        PWCHAR             pwszBlobType,
                        PWCHAR             pwszAlgId,
                        PCARD_KEY_HANDLE    phKey,
                        PBYTE               pbInput,
                        DWORD               cbInput,
                        DWORD               dwFlags);

DWORD 
WINAPI 
CardImportSessionKey(
                        PCARD_DATA          pCardData,
                        BYTE                bContainerIndex,
                        PVOID              pPaddingInfo,
                        PWCHAR             pwszBlobType,
                        PWCHAR             pwszAlgId,
                        PCARD_KEY_HANDLE    phKey,
                        PBYTE               pbInput,
                        DWORD               cbInput,
                        DWORD               dwFlags);

typedef DWORD (WINAPI *PFN_CARD_PROCESS_ENCRYPTED_DATA)(
                                                PCARD_DATA              pCardData,
                                                CARD_KEY_HANDLE         hKey,
                                                PWCHAR                 pwszSecureFunction,
                                                PCARD_ENCRYPTED_DATA    pEncryptedData,
                                                DWORD                   cEncryptedData,
                                                PBYTE                   pbOutput,
                                                DWORD                   cbOutput,
                                                PDWORD                  pdwOutputLen,
                                                DWORD                   dwFlags);

DWORD 
WINAPI 
CardProcessEncryptedData(
                                                PCARD_DATA              pCardData,
                                                CARD_KEY_HANDLE         hKey,
                                                PWCHAR                 pwszSecureFunction,
                                                PCARD_ENCRYPTED_DATA    pEncryptedData,
                                                DWORD                   cEncryptedData,
                                                PBYTE                   pbOutput,
                                                DWORD                   cbOutput,
                                                PDWORD                  pdwOutputLen,
                                                DWORD                   dwFlags);

//
// Type: CARD_DATA
//

#define CARD_DATA_VERSION_SEVEN 7

// This verison supports new features suched as enhanced support
// for PINs, support for read-only cards, a secure PIN channel
// and external PIN support.
#define CARD_DATA_VERSION_SIX   6

// This version supports new features such as a designed
// CardSecretAgreement and key derivation functions.  Also
// added is the PKCS#1 2.1 (PSS) padding format.
#define CARD_DATA_VERSION_FIVE  5

// This is the minimum version currently supported.  Those
// applications that require basic RSA crypto functionality
// and file operations should use this version
#define CARD_DATA_VERSION_FOUR  4

// For those apps, that want the maximum version available, use
// CARD_DATA_CURRENT_VERSION.  Otherwise applications should
// target a specific version that includes the functionality
// that they require.
#define CARD_DATA_CURRENT_VERSION CARD_DATA_VERSION_SEVEN

typedef struct _CARD_DATA
{
    // These members must be initialized by the CSP/KSP before
    // calling CardAcquireContext.

    DWORD                               dwVersion;

    PBYTE                               pbAtr;
    DWORD                               cbAtr;
    PWCHAR                              pwszCardName;

    PFN_CSP_ALLOC                       pfnCspAlloc;
    PFN_CSP_REALLOC                     pfnCspReAlloc;
    PFN_CSP_FREE                        pfnCspFree;

    PFN_CSP_CACHE_ADD_FILE              pfnCspCacheAddFile;
    PFN_CSP_CACHE_LOOKUP_FILE           pfnCspCacheLookupFile;
    PFN_CSP_CACHE_DELETE_FILE           pfnCspCacheDeleteFile;
    PVOID                               pvCacheContext;

    PFN_CSP_PAD_DATA                    pfnCspPadData;

    SCARDCONTEXT                        hSCardCtx;
    SCARDHANDLE                         hScard;

    // pointer to vendor specific information

    PVOID                               pvVendorSpecific;

    // These members are initialized by the card module

    PFN_CARD_DELETE_CONTEXT             pfnCardDeleteContext;
    PFN_CARD_QUERY_CAPABILITIES         pfnCardQueryCapabilities;
    PFN_CARD_DELETE_CONTAINER           pfnCardDeleteContainer;
    PFN_CARD_CREATE_CONTAINER           pfnCardCreateContainer;
    PFN_CARD_GET_CONTAINER_INFO         pfnCardGetContainerInfo;
    PFN_CARD_AUTHENTICATE_PIN           pfnCardAuthenticatePin;
    PFN_CARD_GET_CHALLENGE              pfnCardGetChallenge;
    PFN_CARD_AUTHENTICATE_CHALLENGE     pfnCardAuthenticateChallenge;
    PFN_CARD_UNBLOCK_PIN                pfnCardUnblockPin;
    PFN_CARD_CHANGE_AUTHENTICATOR       pfnCardChangeAuthenticator;
    PFN_CARD_DEAUTHENTICATE             pfnCardDeauthenticate;
    PFN_CARD_CREATE_DIRECTORY           pfnCardCreateDirectory;
    PFN_CARD_DELETE_DIRECTORY           pfnCardDeleteDirectory;
    PVOID                              pvUnused3;
    PVOID                              pvUnused4;
    PFN_CARD_CREATE_FILE                pfnCardCreateFile;
    PFN_CARD_READ_FILE                  pfnCardReadFile;
    PFN_CARD_WRITE_FILE                 pfnCardWriteFile;
    PFN_CARD_DELETE_FILE                pfnCardDeleteFile;
    PFN_CARD_ENUM_FILES                 pfnCardEnumFiles;
    PFN_CARD_GET_FILE_INFO              pfnCardGetFileInfo;
    PFN_CARD_QUERY_FREE_SPACE           pfnCardQueryFreeSpace;
    PFN_CARD_QUERY_KEY_SIZES            pfnCardQueryKeySizes;

    PFN_CARD_SIGN_DATA                  pfnCardSignData;
    PFN_CARD_RSA_DECRYPT                pfnCardRSADecrypt;
    PFN_CARD_CONSTRUCT_DH_AGREEMENT     pfnCardConstructDHAgreement;

    // New functions in version five.
    PFN_CARD_DERIVE_KEY                 pfnCardDeriveKey;
    PFN_CARD_DESTROY_DH_AGREEMENT       pfnCardDestroyDHAgreement;
    PFN_CSP_GET_DH_AGREEMENT            pfnCspGetDHAgreement;

    // version 6 additions below here
    PFN_CARD_GET_CHALLENGE_EX           pfnCardGetChallengeEx;
    PFN_CARD_AUTHENTICATE_EX            pfnCardAuthenticateEx;
    PFN_CARD_CHANGE_AUTHENTICATOR_EX    pfnCardChangeAuthenticatorEx;
    PFN_CARD_DEAUTHENTICATE_EX          pfnCardDeauthenticateEx;
    PFN_CARD_GET_CONTAINER_PROPERTY     pfnCardGetContainerProperty;
    PFN_CARD_SET_CONTAINER_PROPERTY     pfnCardSetContainerProperty;
    PFN_CARD_GET_PROPERTY               pfnCardGetProperty;
    PFN_CARD_SET_PROPERTY               pfnCardSetProperty;

    // version 7 additions below here
    PFN_CSP_UNPAD_DATA                  pfnCspUnpadData;
    PFN_MD_IMPORT_SESSION_KEY           pfnMDImportSessionKey;
    PFN_MD_ENCRYPT_DATA                 pfnMDEncryptData;
    PFN_CARD_IMPORT_SESSION_KEY         pfnCardImportSessionKey;
    PFN_CARD_GET_SHARED_KEY_HANDLE      pfnCardGetSharedKeyHandle;
    PFN_CARD_GET_ALGORITHM_PROPERTY     pfnCardGetAlgorithmProperty;
    PFN_CARD_GET_KEY_PROPERTY           pfnCardGetKeyProperty;
    PFN_CARD_SET_KEY_PROPERTY           pfnCardSetKeyProperty;
    PFN_CARD_DESTROY_KEY                pfnCardDestroyKey;
    PFN_CARD_PROCESS_ENCRYPTED_DATA     pfnCardProcessEncryptedData;
    PFN_CARD_CREATE_CONTAINER_EX        pfnCardCreateContainerEx;

} CARD_DATA, *PCARD_DATA;

#endif

