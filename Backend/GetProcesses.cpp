#include "GetProcesses.h"
#include "..\allinclude.h"
#include "fileFunc.h"
#include <stdio.h>
#pragma warning(disable:4996)
#pragma comment(lib, "advapi32.lib")

std::vector<Process> processes;
#define MAX_NAME 256

size_t GetProcessesSize(void)
{
    return processes.size();
}

std::string GetProcessDescription(size_t index)
{
    std::string str=utf8_encode( processes[index].Description);
 
    return str;
}

std::string GetProcessNameString(size_t index)
{
    //std::string str = utf8_encode(processes[index].name);
    return processes[index].name;
}


std::string GetProcessIlString(size_t index)
{
    return processes[index].integrity_level;
}

std::string GetProcessPidString(size_t index)
{
    return std::to_string(processes[index].pid);
}

std::string GetProcessPathString(size_t index)
{
    return utf8_encode(processes[index].path);
}

std::string GetProcessAslrString(size_t index)
{
    if (processes[index].aslr == true)
        return std::string("true");
    else
        return std::string("false");
}

std::string GetProcessDepString(size_t index)
{
    if (processes[index].dep == true)
        return std::string("true");
    else
        return std::string("false");
}

std::string GetProcessParentPidString(size_t index)
{
    return std::to_string(processes[index].pPid);
}

std::string GetProcessSidString(size_t index)
{
    return utf8_encode(processes[index].sid);
}


std::string GetProcessArchString(size_t index)
{
    if (processes[index].arch64 == true)
        return std::string("64 bit");
    else
        return std::string("32 bit");
}

String^ GetProcessName(size_t index)
{
    String^ name = gcnew String(processes[index].name.c_str());
    return name;
}

String^ GetProcessPid(size_t index)
{
    String^ pid = gcnew String(std::to_string(processes[index].pid).c_str());
    return pid;
}

String^ GetProcessPath(size_t index)
{
    String^ path = gcnew String(processes[index].path.c_str());
    return path;
}

String^ GetProcessAslr(size_t index)
{
    if (processes[index].aslr == true)
        return "true";
    else
        return "false";
}

String^ GetProcessDep(size_t index)
{
    if (processes[index].dep == true)
        return "true";
    else
        return "false";
}

String^ GetProcessParentPid(size_t index)
{
    String^ pid = gcnew String(std::to_string(processes[index].pPid).c_str());
    return pid;
}

String^ GetProcessArch(size_t index)
{
    if (processes[index].arch64 == true)
        return "64 bit";
    else
        return "32 bit";
}

size_t GetProcessModulesSize(size_t index)
{
    return processes[index].modules.size();
}

String^ GetProcessModule(size_t indexProc, size_t indexModule)
{
    String^ module = gcnew String(processes[indexProc].modules[indexModule].c_str());
    return module;
}

String^ GetProcessSid(size_t indexProc)
{
    String^ sid = gcnew String(processes[indexProc].sid.c_str());
    return sid;
}

void ClearProcesses(void)
{
    processes.clear();
}

void GetProcessInfo(Process& ret, DWORD processID, bool& flag);
BOOL GetLogonFromToken(HANDLE hToken, wchar_t* lpName, wchar_t* lpDomain);
BOOL IsWow64(HANDLE process);
DWORD GetParentPid(DWORD processID);


//wchar_t to std::string
std::string wchar_tToString(const wchar_t* s)
{
	const std::locale& loc = std::locale();
	char dfault = '?';
	std::ostringstream stm;

	while (*s != L'\0') {
		stm << std::use_facet< std::ctype<wchar_t> >(loc).narrow(*s++, dfault);
	}
	return stm.str();
}

void GetProcesses(void)
{
	DWORD aProcesses[2048], cbNeeded, cProcesses;
	EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded);
	cProcesses = cbNeeded / sizeof(DWORD);

    for (size_t i = 0; i < cProcesses; i++)
        if (aProcesses[i] != 0)
        {
            bool notEmptyProc = true;
            Process procInfo = { 0 };
            GetProcessInfo(procInfo, aProcesses[i], notEmptyProc);
            if (notEmptyProc)
                processes.push_back(procInfo);
        }
}

void GetProcessInfo(Process& ret, DWORD processID, bool& flag)
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);
    if (NULL == hProcess)
    {
        flag = false;
        return;
    }

    if (!EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
    {
        flag = false;
        return;
    }

    PROCESS_MITIGATION_ASLR_POLICY aslrPolicy;
    ret.aslr = GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, (PVOID)&aslrPolicy, sizeof(_PROCESS_MITIGATION_ASLR_POLICY));
    
    PROCESS_MITIGATION_DEP_POLICY depPolicy;
    ret.dep = GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, (PVOID)&depPolicy, sizeof(_PROCESS_MITIGATION_DEP_POLICY));

    ret.pPid = GetParentPid(processID);
    ret.arch64 = IsWow64(hProcess);

    wchar_t filePath[MAX_PATH];
    GetModuleFileNameExW(hProcess, NULL, filePath, sizeof(filePath) / sizeof(TCHAR));
    ret.path = filePath;

    TCHAR szProcessName[MAX_PATH] ;
    wchar_t szProcessNameW[MAX_PATH]= TEXT(L"<unknown>");

    GetModuleBaseName(hProcess, hMods[0], szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
    GetModuleBaseNameW(hProcess, hMods[0], szProcessNameW, sizeof(szProcessNameW) / sizeof(wchar_t));
    ret.name = utf8_encode(szProcessNameW); ;

    wchar_t lpName[MAX_PATH];
    wchar_t lpDomain[MAX_PATH];

    if (GetLogonFromToken(hProcess, lpName, lpDomain) == TRUE)
    {

        ret.sid = lpDomain;
        ret.sid += L"\\";
        ret.sid += lpName;
    }
    else
        ret.sid = lpName;

    
    for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
    {
        TCHAR szModName[MAX_PATH];

        if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
            sizeof(szModName) / sizeof(TCHAR)))
            ret.modules.push_back(szModName);
    }

    ret.pid = processID;

    GetProcessDescription(szProcessName,ret);


    //integrityLevel
    ret.integrity_level= GetCurrentProcessIntegrityLevel(hProcess);
    /////

    CloseHandle(hProcess);
}

DWORD GetParentPid(DWORD processID)
{
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD ppid = 0, pid = processID;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    __try {
        if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

        ZeroMemory(&pe32, sizeof(pe32));
        pe32.dwSize = sizeof(pe32);
        if (!Process32First(hSnapshot, &pe32)) __leave;

        do {
            if (pe32.th32ProcessID == pid) {
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));

    }
    __finally {
        if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
    }
    return ppid;
}

BOOL IsWow64(HANDLE process)
{
    BOOL bIsWow64 = FALSE;

    typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process;
    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

    if (NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(process, &bIsWow64))
        {
            //handle error
        }
    }
    return !bIsWow64;
}


BOOL GetLogonFromToken(HANDLE hToken, wchar_t* lpName, wchar_t* lpDomain)
{
    DWORD dwSize = MAX_PATH;
    BOOL bSuccess = FALSE;
    DWORD dwLength = 0;
    PTOKEN_USER ptu = NULL;
    //Verify the parameter passed in is not NULL.
    if (NULL == hToken)
        goto Cleanup;

    if (!OpenProcessToken(hToken, TOKEN_QUERY, &hToken))
    {
        return E_FAIL;
    }

    if (!GetTokenInformation(
        hToken,         // handle to the access token
        TokenUser,    // get information about the token's groups 
        (LPVOID)ptu,   // pointer to PTOKEN_USER buffer
        0,              // size of buffer
        &dwLength       // receives required buffer size
    ))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            goto Cleanup;

        ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(),
            HEAP_ZERO_MEMORY, dwLength);

        if (ptu == NULL)
            goto Cleanup;
    }

    if (!GetTokenInformation(
        hToken,         // handle to the access token
        TokenUser,    // get information about the token's groups 
        (LPVOID)ptu,   // pointer to PTOKEN_USER buffer
        dwLength,       // size of buffer
        &dwLength       // receives required buffer size
    ))
    {
        goto Cleanup;
    }
    SID_NAME_USE SidType;

    if (!LookupAccountSidW(NULL, ptu->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType))
    {
        DWORD dwResult = GetLastError();
        if (dwResult == ERROR_NONE_MAPPED)
            wcscpy(lpName, L"NONE_MAPPED");
        else
        {
            printf("LookupAccountSid Error %u\n", GetLastError());
        }
    }
    else
    {
        bSuccess = TRUE;
    }

Cleanup:

    if (ptu != NULL)
        HeapFree(GetProcessHeap(), 0, (LPVOID)ptu);
    return bSuccess;
}

int GetProcessDescription(const char* filename, Process& ret)
{
    ret.Description = L"null";
    int versionInfoSize = GetFileVersionInfoSize(filename, NULL);
    if (!versionInfoSize) {
        return 0;
    }

    auto versionInfo = new BYTE[versionInfoSize];
    std::unique_ptr<BYTE[]> versionInfo_automatic_cleanup(versionInfo);
    if (!GetFileVersionInfo(filename, NULL, versionInfoSize, versionInfo)) {
        return 0;
    }

    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *translationArray;

    UINT translationArrayByteLength = 0;
    if (!VerQueryValueW(versionInfo, L"\\VarFileInfo\\Translation", (LPVOID*)&translationArray, &translationArrayByteLength)) {
        return 0;
    }

    // You may check GetSystemDefaultUILanguage() == translationArray[i].wLanguage 
    // if only the system language required
    for (unsigned int i = 0; i < (translationArrayByteLength / sizeof(LANGANDCODEPAGE)); i++) {
        wchar_t fileDescriptionKey[256];
        wsprintfW(
            fileDescriptionKey,
            L"\\StringFileInfo\\%04x%04x\\FileDescription",
            translationArray[i].wLanguage,
            translationArray[i].wCodePage
        );

        wchar_t* fileDescription;
       // wmemset(fileDescription, '\0', 50);
        UINT fileDescriptionSize;
        if (VerQueryValueW(versionInfo, fileDescriptionKey, (LPVOID*)&fileDescription, &fileDescriptionSize)) {
            //fileDescription;
            ret.Description= fileDescription;
           //wcout << endl << fileDescription << endl;
        }
    }
}