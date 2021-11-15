#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>
#include <comdef.h>
#include <tlhelp32.h>
#include <vcclr.h>
#include "integrity_level.h"
#include "fileFunc.h"

using namespace System;

struct Process
{
	DWORD pid;
	std::string name, decription;
	std::wstring path;
	std::wstring Description;
	DWORD pPid;
	std::string pName;
	std::wstring sid;
	std::vector<std::string> modules;
	bool arch64;
	bool aslr, dep;
	std::string integrity_level;
};

void ClearProcesses(void);
void GetProcesses(void);

size_t GetProcessesSize(void);

String^ GetProcessName(size_t index);
String^ GetProcessPid(size_t index);
String^ GetProcessPath(size_t index);
String^ GetProcessDep(size_t index);
String^ GetProcessAslr(size_t index);
String^ GetProcessParentPid(size_t index);
String^ GetProcessArch(size_t index);
String^ GetProcessModule(size_t indexProc, size_t indexModule);
String^ GetProcessSid(size_t indexProc);
size_t GetProcessModulesSize(size_t index);

std::string GetProcessDescription(size_t index);
std::string GetProcessNameString(size_t index);
std::string GetProcessPidString(size_t index);
std::string GetProcessPathString(size_t index);
std::string GetProcessAslrString(size_t index);
std::string GetProcessDepString(size_t index);
std::string GetProcessParentPidString(size_t index);
std::string GetProcessArchString(size_t index);
std::string GetProcessSidString(size_t index);
std::string GetProcessIlString(size_t index);

std::string wchar_tToString(const wchar_t* s);

int GetProcessDescription(const char* filename, Process& ret);
BOOL SearchTokenGroupsForSID(HANDLE hToken);