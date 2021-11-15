#include "integrity_level.h"
#include "..\allinclude.h"
#pragma warning(disable:4996)
#pragma comment(lib, "advapi32.lib")


std::string GetCurrentProcessIntegrityLevel(HANDLE process) {
    DWORD level;

    bool ret = false;
    HANDLE token;
    if (OpenProcessToken(process, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &token)) {
        DWORD size;
        if (!GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &size) &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER) {

            char* buf[100];
            TOKEN_MANDATORY_LABEL* til =
                reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf);
            if (GetTokenInformation(token, TokenIntegrityLevel, til, size, &size)) {

                DWORD count = *GetSidSubAuthorityCount(til->Label.Sid);
                level = *GetSidSubAuthority(til->Label.Sid, count - 1);
                ret = true;

                if (level == SECURITY_MANDATORY_LOW_RID)
                {
                    //Low Integrity
                    return "Low Process";
                }
                else if (level >= SECURITY_MANDATORY_MEDIUM_RID &&
                    level < SECURITY_MANDATORY_HIGH_RID)
                {
                    //Medium Integrity
                    return  "Medium Process";
                }
                else if (level >= SECURITY_MANDATORY_HIGH_RID)
                {
                    //High Integrity
                    return "High Integrity Process";
                }
                else if (level >= SECURITY_MANDATORY_SYSTEM_RID)
                {
                    //System Integrity
                    return "System Integrity Process";
                }
            }
        }
    }
    return "integrity_level_error";
}


bool setLevel(WCHAR* path, int lvl)//
{
    LPCWSTR INTEGRITY_SDDL_SACL_W = nullptr;
    if (lvl == 0)
        INTEGRITY_SDDL_SACL_W = L"";
    else if (lvl == 1)
        INTEGRITY_SDDL_SACL_W = L"S:(ML;;NW;;;LW)";
    else if (lvl == 2)
        INTEGRITY_SDDL_SACL_W = L"S:(ML;;NW;;;ME)";
    else if (lvl == 3)
        INTEGRITY_SDDL_SACL_W = L"S:(ML;;NW;;;HI)";

    DWORD dwErr = ERROR_SUCCESS;
    PSECURITY_DESCRIPTOR pSD = nullptr;
    PACL pSacl = nullptr;
    BOOL fSaclPresent = FALSE;
    BOOL fSaclDefaulted = FALSE;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(INTEGRITY_SDDL_SACL_W, SDDL_REVISION_1, &pSD, nullptr))
    {
        if (GetSecurityDescriptorSacl(pSD, &fSaclPresent, &pSacl, &fSaclDefaulted))
        {
            dwErr = SetNamedSecurityInfoW(path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, pSacl);
            if (dwErr == ERROR_SUCCESS)
            {
                LocalFree(pSD);
                return true;
            }
            else
            {
                cout << "Error: SetNamedSecurityInfoW, error = " << endl;
            }
        }
        LocalFree(pSD);
    }
    else
    {
        cout << "Error: ConvertStringSecurityDescriptorToSecurityDescriptorW, error = " << endl;
    }

    return false;
}