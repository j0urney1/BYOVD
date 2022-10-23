#include "struct.h"

UCHAR PTRN_W10_Image[] = { 0x45, 0x33, 0xc0, 0x48, 0x8d, 0x0c, 0xd9, 0x48, 0x8b, 0xd7, 0xe8 };
void InitLoadImage(PINFORMATION pInfor)
{
	switch (pInfor->Build)
	{
	case 22000:
		pInfor->Notify.Pattern = PTRN_W10_Image;
		pInfor->Notify.dwPattern = sizeof(PTRN_W10_Image);
		pInfor->Notify.startFunc = "PsSetLoadImageNotifyRoutineEx";
		pInfor->Notify.endFunc = "PoRegisterCoalescingCallback";
		pInfor->Notify.ModuleName = "ntoskrnl.exe";
		pInfor->Notify.offset = -4;
		break;
	default:
		break;
	}
}