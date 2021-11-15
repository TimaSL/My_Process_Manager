//программа работает в трёх режимах - 1) сохраняет всю информацию о процессах в json (файл result.json), в аргументе передаётся 1
// 2)изменение integrity level процесса (первый аргумент - 2, второй - желаемый integrity level 1-3, третий аргумент - путь до процесса) 
// 3) работает с файлами (первый аргумент - 3, второй - путь до файла, третий - integrity level (либо "-", либо желаемый integrity level 1-3)
// чтобы изменение вступило в силу - процесс необходимо перезапустить

#include "allinclude.h"
#include "Backend/integrity_level.h"
#include "Backend/GetProcesses.h"
#include "Backend/fileFunc.h"
#include <iostream>

using namespace System;

#include <locale>
#include <sstream>
#include <string>

//проверяет аргументы на корректность. EXIT_FAILURE - некорректно; 1 - режим с процессами; 2 - режим с уровнем целостности; 3 - информация о файле
int argCheck(int argc,wchar_t* argv[],int* mode,wchar_t* procName, int* integrityLevel) {
	wchar_t check2[] = L"2";
	if ((argc == 2)&&(!wcsncmp(argv[1],L"1",1))) {
		*mode = 1;
		return 1;
	}
	if ((argc == 4))
	{
		if (!wcsncmp(argv[1], L"2", 2)) {
			*mode = 2;
			int pathSize = 249;
			if (wcslen(argv[3]) < pathSize)
				pathSize = wcslen(argv[3]);
			wcsncpy(procName, argv[3], pathSize);

			if (!wcsncmp(argv[2], L"1", 2)) {
				*integrityLevel = 1;
				return 2;
			}
			if (!wcsncmp(argv[2], L"2", 2)) {
				*integrityLevel = 2;
				return 2;
			}
			if (!wcsncmp(argv[2], L"3", 2)) {
				*integrityLevel = 3;
				return 2;
			}
		}
		else if (!wcsncmp(argv[1], L"3", 2)) {

		}
	}
	return EXIT_FAILURE;
}

int wmain(int argc, wchar_t* argv[])
{
	setlocale(LC_ALL, "Russian");

	if(!wcsncmp(argv[1],L"3",2))
	fileFunc(argv[3]);
	//mode - режим работы(1 или 2)
	int mode;
	//путь до процесса
	wchar_t procPath[250]=L"";
	int integrityLevel;
	argCheck(argc, argv,&mode,procPath,&integrityLevel);

	if (mode == 2){
		if (setLevel(procPath, integrityLevel))
			return 1;
			else
		return 0;
	}
	
	if (mode != 1) {
		return 0;
	}

	GetProcesses();

	nlohmann::json jsonData;
	size_t amountProcesses = GetProcessesSize();

	for (size_t i = 0; i < amountProcesses; i++)
	{
		nlohmann::json jsonProcess;
		jsonProcess["PID"] = GetProcessPidString(i);
		jsonProcess["Name"] = GetProcessNameString(i);
		jsonProcess["Path"] = GetProcessPathString(i);
		jsonProcess["Description"] = GetProcessDescription(i);
		jsonProcess["Arch"] = GetProcessArchString(i);
		jsonProcess["Parent PID"] = GetProcessParentPidString(i);
		jsonProcess["SID"] = GetProcessSidString(i);
		jsonProcess["DEP"] = GetProcessDepString(i);
		jsonProcess["ASLR"] = GetProcessAslrString(i);
		jsonProcess["Integrity_level"] = GetProcessIlString(i);
		jsonData.push_back(jsonProcess);
	}

	
	std::ofstream jsonFile("result.json");

	if (!jsonFile.is_open())
	{
		printf("Incorrect file name\n");
		getchar();
		return EXIT_FAILURE;
	}

	jsonFile << jsonData;

	return EXIT_SUCCESS;
}