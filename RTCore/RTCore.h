#pragma once

class CRTCore
{
public:
	CRTCore();
	virtual ~CRTCore();

	virtual BOOLEAN Load();
	virtual VOID Unload();

	virtual BOOLEAN MapPhysical(PVOID BaseAddress, ULONG_PTR RegionSize, PVOID* SectionAddress);
	virtual BOOLEAN UnmapPhysical(PVOID SectionAddress);

	virtual BOOLEAN ReadPhysical(PVOID PhysicalAddress, PVOID Buffer, ULONG_PTR Length);
	virtual BOOLEAN WritePhysical(PVOID PhysicalAddress, PVOID Buffer, ULONG_PTR Length);

	virtual BOOLEAN ReadVirtual(ULONG_PTR DirectoryTableBase, PVOID VirtualAddress, PVOID Buffer, ULONG_PTR Length);
	virtual BOOLEAN WriteVirtual(ULONG_PTR DirectoryTableBase, PVOID VirtualAddress, PVOID Buffer, ULONG_PTR Length);

	virtual PVOID GetPhysicalAddress(ULONG_PTR DirectoryTableBase, PVOID VirtualAddress);
private:
	HANDLE Handle;
};