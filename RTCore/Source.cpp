#include "Native.h"
#include "RTCore.h"
#include <iostream>
#include <map>


std::map<ULONG, ULONG> KernelDirectoryTableBase =
{
    { 7601, 0x187000 },
    { 9200, 0x187000 },
    { 9600, 0x1A7000 },
    { 10240, 0x1AB000 },
    { 10586, 0x1AB000 },
    { 14393, 0x1AB000 },
    { 15063, 0x1AB000 },
    { 16299, 0x1AB000 },
    { 17134, 0x1AD000 },
    { 17763, 0x1AD000 },
    { 18362, 0x1AD000 },
    { 18363, 0x1AD000 },
    { 19041, 0x1AD000 },
    { 19042, 0x1AD000 },
    { 19043, 0x1AD000 },
    { 19044, 0x1AD000 },
    { 19045, 0x1AD000 },
    { 22621, 0x1AE000 },
    { 22449, 0x1AE000 },
    { 22000, 0x1AE000 }
};

int main_test(CRTCore* rtcore)
{
    if (rtcore->Load())
    {
        ULONG_PTR DirectoryTableBase = KernelDirectoryTableBase[PebBuildNumber];

        if (HMODULE ntoskrnl = LoadLibraryExW(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES))
        {
            if (PVOID SystemModuleBase = GetSystemModuleBase("ntoskrnl.exe"))
            {
                PUCHAR PtrNtBuildNumber = (PUCHAR)GetProcAddress(ntoskrnl, "NtBuildNumber") + ((PUCHAR)SystemModuleBase - (PUCHAR)ntoskrnl);

                USHORT NtBuildNumber = 0;
                if (rtcore->ReadVirtual(DirectoryTableBase, PtrNtBuildNumber, &NtBuildNumber, sizeof(PtrNtBuildNumber)))
                {
                    printf("NtBuildNumber: %d\n", NtBuildNumber);
                }
                else printf("Failed ReadVirtual\n");
            }
            else printf("Failed GetSystemModuleBase\n");
            FreeLibrary(ntoskrnl);
        }
        else printf("Failed LoadLibraryExW\n");

        rtcore->Unload();
    }
    else printf("Failed DriverLoad\n");

    system("pause");
    return 0;
}
int main()
{
	SetConsoleTitleW(L"RTCore Test");

    CRTCore rtcore;
	return main_test(&rtcore);
}