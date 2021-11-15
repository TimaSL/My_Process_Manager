#pragma once
#include "integrity_level.h"
#include "GetProcesses.h"


void fileFunc(wchar_t FileName[200]);
std::string utf8_encode(const std::wstring& wstr);
bool setIntegrityLevelF(WCHAR* path, int lvl);