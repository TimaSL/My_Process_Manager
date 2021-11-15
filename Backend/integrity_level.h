#pragma once
#include "..\allinclude.h"
#include "..\Backend/GetProcesses.h"
#include <iostream>

using namespace System;

std::string GetCurrentProcessIntegrityLevel(HANDLE process);
bool setLevel(WCHAR* path, int lvl);