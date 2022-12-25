#include "Native.h"

NTSTATUS OpenFile(PHANDLE FileHandle, PCWSTR filename, ULONG DesiredAccess, ULONG ShareAccess, ULONG OpenOptions)
{
	UNICODE_STRING UnicodeObjectName;
	RtlInitUnicodeString(&UnicodeObjectName, filename);

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, &UnicodeObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	IO_STATUS_BLOCK IoStatusBlock;
	return NtOpenFile(FileHandle, DesiredAccess, &ObjectAttributes, &IoStatusBlock, ShareAccess, OpenOptions);
}

NTSTATUS NTAPI MySetPrivilege(IN ULONG Privilege, IN ULONG Attributes)
{
	TOKEN_PRIVILEGES Privileges;
	Privileges.PrivilegeCount = 1;
	Privileges.Privileges[0].Attributes = Attributes;
	Privileges.Privileges[0].Luid.LowPart = Privilege;
	Privileges.Privileges[0].Luid.HighPart = 0;

	HANDLE Token;
	NTSTATUS status = NtOpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, FALSE, &Token);
	if (status == STATUS_NO_TOKEN)
	{
		status = NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &Token);
	}
	if (status == STATUS_SUCCESS)
	{
		status = NtAdjustPrivilegesToken(Token, FALSE, &Privileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
		NtClose(Token);
	}
	return status;
}


NTSTATUS NTAPI MyCreateFile(PHANDLE FileHandle, PCWSTR filename, ULONG DesiredAccess, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	UNICODE_STRING UnicodeObjectName;
	RtlInitUnicodeString(&UnicodeObjectName, filename);

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, &UnicodeObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	IO_STATUS_BLOCK IoStatusBlock;
	return NtCreateFile(FileHandle, DesiredAccess, &ObjectAttributes, &IoStatusBlock, NULL, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}
NTSTATUS NTAPI MyOpenFile(PHANDLE FileHandle, PCWSTR filename, ULONG DesiredAccess, ULONG ShareAccess, ULONG OpenOptions)
{
	UNICODE_STRING UnicodeObjectName;
	RtlInitUnicodeString(&UnicodeObjectName, filename);

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, &UnicodeObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	IO_STATUS_BLOCK IoStatusBlock;
	return NtOpenFile(FileHandle, DesiredAccess, &ObjectAttributes, &IoStatusBlock, ShareAccess, OpenOptions);
}
NTSTATUS NTAPI MyGetFileSize(IN HANDLE FileHandle, OUT PULONGLONG PtrFileSize)
{
	IO_STATUS_BLOCK IoStatusBlock;
	FILE_STANDARD_INFORMATION FileInformation;

	FileInformation.EndOfFile.QuadPart = 0;
	NTSTATUS status = NtQueryInformationFile(FileHandle, &IoStatusBlock, &FileInformation, sizeof(FileInformation), FileStandardInformation);

	if (PtrFileSize)
		PtrFileSize[0] = FileInformation.EndOfFile.QuadPart;

	return status;
}
NTSTATUS NTAPI MyReadFile(HANDLE FileHandle, PVOID Buffer, ULONG_PTR Offset, ULONG_PTR Length, PULONG_PTR Bytes)
{
	LARGE_INTEGER BytesOffset;
	BytesOffset.QuadPart = Offset;

	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS status = NtReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Buffer, Length, &BytesOffset, NULL);
	if (status == STATUS_PENDING)
	{
		status = NtWaitForSingleObject(FileHandle, FALSE, NULL);
		if (NT_SUCCESS(status)) status = IoStatusBlock.Status;
	}
	if (NT_SUCCESS(status))
	{
		if (Bytes)
			*Bytes = IoStatusBlock.Information;
	}
	return status;
}
NTSTATUS NTAPI MyWriteFile(HANDLE FileHandle, PVOID Buffer, ULONG_PTR Offset, ULONG_PTR Length, PULONG_PTR pWritted)
{
	LARGE_INTEGER BytesOffset;
	BytesOffset.QuadPart = Offset;

	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS status = NtWriteFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Buffer, Length, &BytesOffset, NULL);

	if (status == STATUS_PENDING)
	{
		status = NtWaitForSingleObject(FileHandle, FALSE, NULL);
		if (NT_SUCCESS(status)) status = IoStatusBlock.Status;
	}
	if (NT_SUCCESS(status))
	{
		if (pWritted)
			*pWritted = IoStatusBlock.Information;
	}
	return status;
}
NTSTATUS NTAPI MyDeleteFile(IN HANDLE FileHandle)
{
	BOOLEAN DeleteFile = TRUE;

	IO_STATUS_BLOCK IoStatusBlock;
	return NtSetInformationFile(FileHandle, &IoStatusBlock, &DeleteFile, sizeof(DeleteFile), FileDispositionInformation);
}
NTSTATUS NTAPI MyDeleteFile(PCWSTR FilePath)
{
	HANDLE FileHandle = NULL;
	NTSTATUS status = MyOpenFile(&FileHandle, FilePath, GENERIC_ALL, FILE_SHARE_READ, NULL);
	if (NT_SUCCESS(status))
	{
		status = MyDeleteFile(FileHandle);
		NtClose(FileHandle);
	}
	if (status == STATUS_OBJECT_NAME_NOT_FOUND)
		status = STATUS_SUCCESS;

	return status;
}

NTSTATUS NTAPI RegistryOpen(OUT PHANDLE KeyHandle, HANDLE RootKeyHandle, IN ACCESS_MASK DesiredAccess, IN PCWSTR Key, IN ULONG OpenOptions)
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING UnicodeKey;

	RtlInitUnicodeString(&UnicodeKey, Key);
	InitializeObjectAttributes(&ObjectAttributes, &UnicodeKey, OBJ_CASE_INSENSITIVE, RootKeyHandle, NULL);

	return NtOpenKeyEx(KeyHandle, MAXIMUM_ALLOWED, &ObjectAttributes, NULL);
}
NTSTATUS NTAPI RegistryCreate(OUT PHANDLE KeyHandle, IN HANDLE RootKeyHandle, IN ULONG Desired, IN PCWSTR SubKey, IN PCWSTR Class, IN ULONG Options, OUT OPTIONAL PULONG Disposition)
{
	UNICODE_STRING UnicodeObjectName;
	RtlInitUnicodeString(&UnicodeObjectName, SubKey);

	UNICODE_STRING UnicodeClass;
	RtlInitUnicodeString(&UnicodeClass, Class);

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, &UnicodeObjectName, OBJ_CASE_INSENSITIVE, RootKeyHandle, NULL);

	return NtCreateKey(KeyHandle, MAXIMUM_ALLOWED, &ObjectAttributes, NULL, &UnicodeClass, NULL, Disposition);
}
NTSTATUS NTAPI RegistrySetValue(IN HANDLE KeyHandle, IN PCWSTR ValueName, IN OPTIONAL ULONG TitleIndex, IN ULONG Type, IN OPTIONAL PVOID Data, IN ULONG DataSize)
{
	UNICODE_STRING UnicodeValueName;
	RtlInitUnicodeString(&UnicodeValueName, ValueName);

	return NtSetValueKey(KeyHandle, &UnicodeValueName, TitleIndex, Type, Data, DataSize);
}
NTSTATUS NTAPI RegistryQuery(OUT HANDLE KeyHandle, IN PCWSTR ValueName, IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, IN PVOID KeyValueInformation, IN ULONG Length, OUT PULONG ResultLength)
{
	UNICODE_STRING UnicodeString;
	RtlInitUnicodeString(&UnicodeString, ValueName);
	return NtQueryValueKey(KeyHandle, &UnicodeString, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
}

NTSTATUS NTAPI MyLoadDriver(IN PCWSTR DriverServiceName)
{
	UNICODE_STRING UnicodeString;
	RtlInitUnicodeString(&UnicodeString, DriverServiceName);
	return NtLoadDriver(&UnicodeString);
}
NTSTATUS NTAPI MyUnloadDriver(IN PCWSTR DriverServiceName)
{
	UNICODE_STRING UnicodeString;
	RtlInitUnicodeString(&UnicodeString, DriverServiceName);
	return NtUnloadDriver(&UnicodeString);
}

NTSTATUS NTAPI MyDeviceIoControl(IN HANDLE DeviceHandle, IN ULONG IoControlCode, IN OPTIONAL PVOID InBuffer, IN ULONG InBufferSize, OUT OPTIONAL PVOID OutBuffer, IN ULONG OutBufferSize, OUT OPTIONAL PULONG BytesReturned)
{
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS status = NtDeviceIoControlFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock, IoControlCode, InBuffer, InBufferSize, OutBuffer, OutBufferSize);
	if (status == STATUS_PENDING)
	{
		status = NtWaitForSingleObject(DeviceHandle, FALSE, NULL);
		if (NT_SUCCESS(status)) status = IoStatusBlock.Status;
	}
	if (NT_SUCCESS(status))
	{
		if (BytesReturned)
			*BytesReturned = (ULONG)IoStatusBlock.Information;
	}
	return status;
}

NTSTATUS NTAPI MySaveFileFromMemory(IN PCWSTR FilePath, IN PVOID Buffer, IN ULONG_PTR Length, IN ULONG FileAttributes)
{
	HANDLE FileHandle;
	NTSTATUS status = MyCreateFile(&FileHandle, FilePath, GENERIC_ALL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, FILE_CREATE, NULL, NULL);
	if (NT_SUCCESS(status))
	{
		status = MyWriteFile(FileHandle, Buffer, NULL, Length, NULL);
		NtClose(FileHandle);
	}
	return status;
}

NTSTATUS NTAPI MyLoadUnloadDriver(IN PCWSTR DriverServiceName, IN OPTIONAL PCWSTR ImageFilePath, IN ULONG Type, IN ULONG Start)
{
	HANDLE Key;
	NTSTATUS status;
	if (ImageFilePath)
	{
		status = RegistryCreate(&Key, NULL, MAXIMUM_ALLOWED, DriverServiceName, NULL, NULL, NULL);
		if (NT_SUCCESS(status))
		{
			RegistrySetValue(Key, L"ImagePath", NULL, REG_SZ, (PVOID)ImageFilePath, (lstrlenW(ImageFilePath) + 1) * sizeof(WCHAR));
			RegistrySetValue(Key, L"Type", NULL, REG_DWORD, &Type, sizeof(Type));

			if (Start != 0xFFFFFFFF)
				RegistrySetValue(Key, L"Start", NULL, REG_DWORD, &Start, sizeof(Start));

			status = MyLoadDriver(DriverServiceName);
			if (NT_FAILED(status)) NtDeleteKey(Key);
			NtClose(Key);
		}
	}
	else
	{
		status = RegistryOpen(&Key, NULL, MAXIMUM_ALLOWED, DriverServiceName, NULL);
		if (NT_SUCCESS(status))
		{
			status = MyUnloadDriver(DriverServiceName);
			if (NT_SUCCESS(status)) NtDeleteKey(Key);
			NtClose(Key);
		}
	}

	return status;
}

PVOID GetSystemModuleBase(IN PCSTR ModuleName)
{
	PVOID SystemModuleBase = NULL;
	ULONG ReturnLength = NULL;
	if (NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, NULL, NULL, &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH)
	{
		PRTL_PROCESS_MODULES ModuleInfo = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, ReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (ModuleInfo != NULL)
		{
			if (NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, ModuleInfo, ReturnLength, &ReturnLength) == STATUS_SUCCESS)
			{
				for (ULONG i = 0; i < ModuleInfo->NumberOfModules; i++)
				{
					if (_stricmp((PCHAR)ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName, ModuleName) == 0)
					{
						SystemModuleBase = ModuleInfo->Modules[i].ImageBase;
						break;
					}
				}
			}
			VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		}
	}
	return SystemModuleBase;
}