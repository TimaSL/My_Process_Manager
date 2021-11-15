#define _CRT_SECURE_NO_WARNINGS

#include<stdio.h>
#include<windows.h>
#include<aclapi.h>
#include<locale.h>
#include "..\allinclude.h"

#define STRLEN(x) (sizeof(x)/sizeof(TCHAR) - 1)

using namespace System;
const char* msgMainMenu = "\nИНСТРУКЦИЯ ACE : \n\n<1>: Добавить атрибут\n<2>: Перезаписать атрибут\n<3>: Удалить атрибут\n<4>: Читать атрибуты\n<5>: Узнать уровень целостности\n<6> изменить уровень целостности\n <0>: Завершить работу\n";
const char* msgFinish = "Завершение работы...\n";
const char* msgFinishF = "Завершение работы с файлом...\n";
const char* msgWrongCmd = "Неверная команда\n";

char* msgWhichAce = "\nКакой ACE добавить?\n0 - Запрещающий \n1 - Разрешающий \n";

char* msgFullAccess = "Полный доступ";
char* msgPermChg = "Изменение разрешений";
char* msgOwnerChg = "Смена владельца";
char* msgFileDel = "Удаление файла";
char* msgFileWr = "Запись в файл";
char* msgFileRd = "Чтение файла";
char* msgFileExec = "Выполнение файла";

char* msgX[7];
const ACCESS_MASK maskX[7] = { FILE_EXECUTE, FILE_ALL_ACCESS, FILE_WRITE_DATA, FILE_READ_DATA, DELETE, WRITE_DAC, WRITE_OWNER };

const char* msgAccessMaskMenu = "\nВыбор прав :\n1 - Полный доступ \n2 - Запись в файл \n3 - Чтение из файла \n4 - Удаление файла \n";

const char* msgChooseUserGrp = "\nВыберите нужного пользователя или группу: ";
const char* msgGetAceFailed = "GetAce failed\n";
const char* msgSetNamedSecurityInfoError = "SetNamedSecurityInfo Error %u\n";
const char* msgSetEntriesInACLError = "SetEntriesInAcl Error %u\n";
const char* msgLookUpAccountSIDFailed = "LookupAccountSid failed";


void PrintAccesses(ACCESS_ALLOWED_ACE* PrACE) // печать атрибутов файла
{
	int i;
	for (i = 0; i < 7; i++) {
		if ((PrACE->Mask & maskX[i] == maskX[i])) {
			printf("%s\n", msgX[i]);
		}
	}
	printf("\n");
}

std::string utf8_encode(const std::wstring& wstr) {

	if (wstr.empty()) return std::string();

	int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);

	std::string strTo(size_needed, 0);

	WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);

	return strTo;

}

BOOL FileSystemObjectInfo(WCHAR* path, int& integrLvl)//write info about file into &integrLvl
{
	PACL pAcl;
	PSECURITY_DESCRIPTOR sd;

	GetNamedSecurityInfoW(path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, &pAcl, &sd);
	if (pAcl == NULL)
	{
		integrLvl = 4;
		cout<< "Untrusted" << endl;
		return 1;
	}
	DWORD count;
	MANDATORY_LEVEL integrityLevel = MandatoryLevelMedium;//
	PCSTR integrityString = NULL;
	if (pAcl)
	{
		ACL_SIZE_INFORMATION saclSize;
		if (!GetAclInformation(pAcl, &saclSize, sizeof(saclSize), AclSizeInformation))
		{
			return FALSE;
		}
		count = saclSize.AceCount;
		for (int i = 0; i < count; i++)// check all ACEs subAutority Securitylevel
		{
			SYSTEM_MANDATORY_LABEL_ACE* pAce;
			if (!GetAce(pAcl, i, (LPVOID*)&pAce))
			{
				return FALSE;
			}
			if (pAce->Header.AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE)
			{
				continue;
			}
			ULONG subAuthority;
			subAuthority = *GetSidSubAuthority((PSID)&pAce->SidStart, 0);
			switch (subAuthority)
			{
			case SECURITY_MANDATORY_LOW_RID:
				integrLvl = 0;
				cout << "Low" << endl;
				break;

			case SECURITY_MANDATORY_MEDIUM_RID:
				integrLvl = 1;
				cout << "Medium" << endl;
				break;

			case SECURITY_MANDATORY_HIGH_RID:
				integrLvl = 2;
				cout << "High" << endl;
				break;

			case SECURITY_MANDATORY_SYSTEM_RID:
				integrLvl = 3;
				cout << "System" << endl;
				break;

			default:
				return FALSE;
			}
			break;
		}
	}
}

bool setIntegrityLevelF(WCHAR* path, int lvl)//
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
				cout << "Error: SetNamedSecurityInfoW, error = " << dwErr;
			}
		}
		LocalFree(pSD);
	}
	else
	{
		cout << "Error: ConvertStringSecurityDescriptorToSecurityDescriptorW, error = " << GetLastError();
	}

	return false;
}

void PrintName(ACCESS_ALLOWED_ACE* PrACE)
{
	PSID PointerSID = &PrACE->SidStart;
	SID_NAME_USE SIDType;
	DWORD UserNameSize = 0;
	DWORD DomainNameSize = 0;
	DWORD Res = LookupAccountSid(NULL, PointerSID, NULL, &UserNameSize, NULL, &DomainNameSize, &SIDType);

	LPSTR UserName = (LPSTR)malloc(UserNameSize);

	if ((Res = LookupAccountSid(NULL, PointerSID, UserName, &UserNameSize, NULL, &DomainNameSize, &SIDType)) == 0)
	{
		free(UserName);
		printf(msgLookUpAccountSIDFailed);
		return;
	}
	printf("%s: %sающий", UserName, (PrACE->Header.AceType == ACCESS_ALLOWED_ACE_TYPE ? "Разреш" : (PrACE->Header.AceType == ACCESS_DENIED_ACE_TYPE ? "Запрещ" : "Ужас")));
	free(UserName);
}

void AccessMask(DWORD* AccessMask)
{
	printf(msgAccessMaskMenu);
	char c = getchar();
	do
	{
		scanf("%c", &c);
		c -= 0x30;
		if (((c - 1) * (4 - c)) >= 0) {
			*AccessMask |= maskX[c];
		}
		else c = 0;
	} while (c != 0);
}

void CleanUpHLocal(HLOCAL h) {
	if (h != NULL) {
		LocalFree(h);
	}
}

DWORD ExtendObjects(wchar_t* OName, ACCESS_ALLOWED_ACE* PrACE, PACL PrOldDACL, PSECURITY_DESCRIPTOR PointerSecurityDescriptor)
{
	DWORD Res;
	printf(msgChooseUserGrp);
	int flag;
	scanf("%d", &flag);
	PrACE = NULL;
	if ((Res = GetAce(PrOldDACL, flag, (void**)&PrACE)) == 0)
	{
		printf(msgGetAceFailed);
		return 0;
	}
	printf(msgWhichAce);
	scanf("%d", &flag);
	ACCESS_MODE AccessMode;
	//ACCESS_MODE AccessMode = (flag == 0 ? DENY_ACCESS : (flag == 1 ? GRANT_ACCESS : 0));
	if (flag == 0) {
		AccessMode = DENY_ACCESS;
	}
	else if (flag == 1) {
		AccessMode == GRANT_ACCESS;
	}

	DWORD AccessRights = 0;
	AccessMask(&AccessRights);
	PSID PointerSID = &PrACE->SidStart;

	EXPLICIT_ACCESS ea;
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = AccessRights;
	ea.grfAccessMode = AccessMode;
	ea.grfInheritance = NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.ptstrName = (LPCH)PointerSID;

	PACL PrNewDACL = NULL;
	if (ERROR_SUCCESS != (Res = SetEntriesInAcl(1, &ea, PrOldDACL, &PrNewDACL)))
	{
		printf(msgSetEntriesInACLError, Res);
	}
	else {
		Res = SetNamedSecurityInfoW(OName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, PrNewDACL, NULL);
		if (ERROR_SUCCESS != Res)
		{
			printf(msgSetNamedSecurityInfoError, Res);
		}
	}
	CleanUpHLocal((HLOCAL)PointerSecurityDescriptor);
	CleanUpHLocal((HLOCAL)PrNewDACL);
	return Res;
}


DWORD ChangeObjects(wchar_t* OName, ACCESS_ALLOWED_ACE* PrACE, PACL PrOldDACL, PSECURITY_DESCRIPTOR PointerSecurityDescriptor)
{
	DWORD Res;
	printf(msgChooseUserGrp);
	int flag;
	scanf("%d", &flag);
	PrACE = NULL;
	if ((Res = GetAce(PrOldDACL, flag, (void**)&PrACE)) == 0)
	{
		printf(msgGetAceFailed);
		return 0;
	}
	DWORD AccessRights = 0;
	AccessMask(&AccessRights);
	PrACE->Mask = AccessRights;
	Res = SetNamedSecurityInfoW(OName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, PrOldDACL, NULL);
	if (ERROR_SUCCESS != Res)
	{
		printf(msgSetNamedSecurityInfoError, Res);
	}
	CleanUpHLocal((HLOCAL)PointerSecurityDescriptor);
	return Res;
}


DWORD DeleteObjects(wchar_t* OName, PACL PrOldDACL, PSECURITY_DESCRIPTOR PointerSecurityDescriptor)
{
	DWORD Res;
	printf(msgChooseUserGrp);
	int flag;
	scanf("%d", &flag);
	if ((Res = DeleteAce(PrOldDACL, flag)) == 0)
	{
		printf(msgGetAceFailed);
		return 0;
	}
	Res = SetNamedSecurityInfoW(OName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, PrOldDACL, NULL);
	if (ERROR_SUCCESS != Res)
	{
		printf(msgSetNamedSecurityInfoError, Res);
	}
	CleanUpHLocal((HLOCAL)PointerSecurityDescriptor);
	return Res;
}


DWORD OpenDACL(wchar_t* OName, int Action) // открываем список избирательного управления доступом 
{
	DWORD Res = 0;
	PACL PrOldDACL = NULL;
	PSECURITY_DESCRIPTOR PointerSecurityDescriptor = NULL;
	if (ERROR_SUCCESS != (Res = GetNamedSecurityInfoW(OName, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &PrOldDACL, NULL, &PointerSecurityDescriptor)))
	{
		printf(msgSetNamedSecurityInfoError, Res);
		return Res;
	}
	ACCESS_ALLOWED_ACE* PrACE = NULL; // указатель на пролистываемый ACE
	for (int i = 0; i < PrOldDACL->AceCount; i++) // цикл, выводящий все ACE из файла (все атрибуты)
	{
		if ((Res = GetAce(PrOldDACL, i,(void**) &PrACE)) == 0) // получение указателя на выбранный ace 
		{
			printf(msgGetAceFailed);
			return Res;
		}
		printf("%d - ", i);
		PrintName(PrACE);
		if (Action == 4)
			PrintAccesses(PrACE); // функция печати атрибутов файла
	}
	switch (Action) {
	case 4:
		CleanUpHLocal((HLOCAL)PointerSecurityDescriptor);
		return Res;
		break;
	case 3:
		return DeleteObjects(OName, PrOldDACL, PointerSecurityDescriptor);
		break;
	case 2:
		return ChangeObjects(OName, PrACE, PrOldDACL, PointerSecurityDescriptor);
		break;
	case 1:
		return ExtendObjects(OName, PrACE, PrOldDACL, PointerSecurityDescriptor);
		break;
	}
}

void initMsgPtrs() {
	msgX[0] = msgFileExec;
	msgX[1] = msgFullAccess;
	msgX[2] = msgFileWr;
	msgX[3] = msgFileRd;
	msgX[4] = msgFileDel;
	msgX[5] = msgPermChg;
	msgX[6] = msgOwnerChg;
}


void fileFunc(wchar_t FileName[200]) // главная функция - прием пути до файла и вывод меню
{
	initMsgPtrs();

	while (1)
	{
		if (wcsncmp(FileName, L"0",200) == 0)
		{
			printf(msgFinish);
			free(FileName);
			break;
		}
		int flag = 0;
		do
		{
			printf(msgMainMenu);
			scanf("%d", &flag);
			DWORD Res;
			switch (flag) {
			case 0:
				printf(msgFinishF);
				break;
			case 1:
			case 2:
			case 3:
			case 4:
				Res = OpenDACL(FileName, flag);
				break;
			case 5:
			{
				int integrity_level;
				FileSystemObjectInfo(FileName,integrity_level);
				break;
			}
			case 6:
			{int integrity_level;
			printf("какой integrity level установить?(1-3):");
			scanf("%d", &integrity_level);
			if (setIntegrityLevelF(FileName, integrity_level))
			{
				printf("успешно\n");
			}
			else {
				printf("error\n");
			}

			}
			default:
				printf(msgWrongCmd);
				break;
			}

		} while (flag != 0);
		getchar();
	}
	system("pause");
}
