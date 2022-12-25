#pragma once
#define WIN32_LEAN_AND_MEAN
#define UMDF_USING_NTSTATUS
#include <Windows.h>
#include <ntstatus.h>

#ifdef DeleteFile
#undef DeleteFile
#endif
#ifdef CreateFile
#undef CreateFile
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) ((LONG)(status) >= 0)
#endif
#ifndef NT_FAILED
#define NT_FAILED(status) ((LONG)(status) < 0)
#endif
#ifndef DECLSPEC_DLLIMPORT
#define DECLSPEC_DLLIMPORT __declspec(dllimport)
#endif
#ifndef DLLIMPORT
#define DLLIMPORT EXTERN_C DECLSPEC_DLLIMPORT
#endif

#ifndef FILE_SUPERSEDE
#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005
#endif

#ifndef SE_MIN_WELL_KNOWN_PRIVILEGE
#define SE_MIN_WELL_KNOWN_PRIVILEGE         (2L)
#define SE_CREATE_TOKEN_PRIVILEGE           (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE     (3L)
#define SE_LOCK_MEMORY_PRIVILEGE            (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE         (5L)
#define SE_MACHINE_ACCOUNT_PRIVILEGE        (6L)
#define SE_TCB_PRIVILEGE                    (7L)
#define SE_SECURITY_PRIVILEGE               (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE         (9L)
#define SE_LOAD_DRIVER_PRIVILEGE            (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE         (11L)
#define SE_SYSTEMTIME_PRIVILEGE             (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE    (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE      (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE        (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE       (16L)
#define SE_BACKUP_PRIVILEGE                 (17L)
#define SE_RESTORE_PRIVILEGE                (18L)
#define SE_SHUTDOWN_PRIVILEGE               (19L)
#define SE_DEBUG_PRIVILEGE                  (20L)
#define SE_AUDIT_PRIVILEGE                  (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE     (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE          (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE        (24L)
#define SE_UNDOCK_PRIVILEGE                 (25L)
#define SE_SYNC_AGENT_PRIVILEGE             (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE      (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE          (28L)
#define SE_IMPERSONATE_PRIVILEGE            (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE          (30L)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE (31L)
#define SE_RELABEL_PRIVILEGE                (32L)
#define SE_INC_WORKING_SET_PRIVILEGE        (33L)
#define SE_TIME_ZONE_PRIVILEGE              (34L)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE   (35L)
#endif

#ifndef OBJ_INHERIT
#define OBJ_INHERIT                         0x2L
#define OBJ_PERMANENT                       0x10L
#define OBJ_EXCLUSIVE                       0x20L
#define OBJ_CASE_INSENSITIVE                0x40L
#define OBJ_OPENIF                          0x80L
#define OBJ_OPENLINK                        0x100L
#define OBJ_KERNEL_HANDLE                   0x200L
#define OBJ_FORCE_ACCESS_CHECK              0x400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP   0x800L
#define OBJ_DONT_REPARSE                    0x1000L
#define OBJ_VALID_ATTRIBUTES                0x1FF2L
#endif


typedef LONG NTSTATUS, * PNTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _ANSI_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} ANSI_STRING, * PANSI_STRING;



typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    struct _ACTIVATION_CONTEXT* ActivationContext;
    ULONG Flags;
}RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
    RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
}ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH {
    ULONG Offset : 31;
    ULONG HasRenderingCommand : 1;
    ULONG_PTR HDC;
    ULONG Buffer[310];
}GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG Flags;
    PSTR FrameName;
}TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    TEB_ACTIVE_FRAME_CONTEXT* Context;
}TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _RTL_BITMAP {
    ULONG SizeOfBitMap;                     // Number of bits in bit map
    PULONG Buffer;                          // Pointer to the bit map itself
} RTL_BITMAP, * PRTL_BITMAP;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, * PCURDIR;

typedef struct RTL_DRIVE_LETTER_CURDIR
{
    USHORT              Flags;
    USHORT              Length;
    ULONG               TimeStamp;
    ANSI_STRING         DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _PEB_LDR_DATA
{
    ULONG               Length;
    BOOLEAN             Initialized;
    PVOID               SsHandle;
    LIST_ENTRY          InLoadOrderModuleList;
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList;
    PVOID               EntryInProgress;
    BOOLEAN             ShutdownInProgress;
    HANDLE              ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS                                 /* win32/win64 */
{
    ULONG                   MaximumLength;                                  /* 00000/00000 */
    ULONG                   Length;                                         /* 00004/00004 */
    ULONG                   Flags;                                          /* 00008/00008 */
    ULONG                   DebugFlags;                                     /* 0000C/0000C */
    HANDLE                  ConsoleHandle;                                  /* 00010/00010 */
    ULONG                   ConsoleFlags;                                   /* 00014/00018 */
    HANDLE                  StandardInput;                                  /* 00018/00020 */
    HANDLE                  StandardOutput;                                 /* 0001C/00028 */
    HANDLE                  StandardError;                                  /* 00020/00030 */
    CURDIR                  CurrentDirectory;                               /* 00024/00038 */
    UNICODE_STRING          DllPath;                                        /* 00000/00050 */
    UNICODE_STRING          ImagePathName;                                  /* 00000/00060 */
    UNICODE_STRING          CommandLine;                                    /* 00000/00070 */
    PVOID                   Environment;                                    /* 00000/00080 */
    ULONG                   StartingX;                                      /* 00000/00088 */
    ULONG                   StartingY;                                      /* 00000/0008C */
    ULONG                   CountX;                                         /* 00000/00090 */
    ULONG                   CountY;                                         /* 00000/00094 */
    ULONG                   CountCharsX;                                    /* 00000/00098 */
    ULONG                   CountCharsY;                                    /* 00000/0009C */
    ULONG                   FillAttribute;                                  /* 00000/000A0 */
    ULONG                   WindowFlags;                                    /* 00000/000A4 */
    ULONG                   ShowWindowFlags;                                /* 00000/000A8 */
    UNICODE_STRING          WindowTitle;                                    /* 00000/000B0 */
    UNICODE_STRING          DesktopInfo;                                    /* 00000/000C0 */
    UNICODE_STRING          ShellInfo;                                      /* 00000/000D0 */
    UNICODE_STRING          RuntimeInfo;                                    /* 00000/000E0 */
    RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[32];                         /* 00000/000F0 */
    ULONG_PTR               EnvironmentSize;                                /* 00000/003F0 */
    ULONG_PTR               EnvironmentVersion;                             /* 00000/003F8 */
    PVOID                   PackageDependencyData;                          /* 00000/00400 */
    ULONG                   ProcessGroupId;                                 /* 00000/00408 */
    ULONG                   LoaderThreads;                                  /* 00000/0040C */
    UNICODE_STRING          RedirectionDllName;                             /* 00000/00410 */
    UNICODE_STRING          HeapPartitionName;                              /* 00000/00420 */
    PULONG_PTR              DefaultThreadpoolCpuSetMasks;                   /* 00000/00430 */
    ULONG                   DefaultThreadpoolCpuSetMaskCount;               /* 00000/00438 */
    ULONG                   DefaultThreadpoolThreadMaximum;                 /* 00000/0043C */
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB
{                                                                           /* win32/win64 */
    BOOLEAN                         InheritedAddressSpace;                  /* 00000/00000 */
    BOOLEAN                         ReadImageFileExecOptions;               /* 00001/00001 */
    BOOLEAN                         BeingDebugged;                          /* 00002/00002 */
    union
    {
        BOOLEAN                     BitField;                               /* 00003/00003 */
        struct
        {
            BOOLEAN                 ImageUsesLargePages : 1;
            BOOLEAN                 IsProtectedProcess : 1;
            BOOLEAN                 IsImageDynamicallyRelocated : 1;
            BOOLEAN                 SkipPatchingUser32Forwarders : 1;
            BOOLEAN                 IsPackagedProcess : 1;
            BOOLEAN                 IsAppContainer : 1;
            BOOLEAN                 IsProtectedProcessLight : 1;
            BOOLEAN                 IsLongPathAwareProcess : 1;
        };
    };
    HANDLE                          Mutant;                                 /* 00004/00008 */
    PVOID                           ImageBaseAddress;                       /* 00008/00010 */
    PPEB_LDR_DATA                   Ldr;                                    /* 0000C/00018 */
    PRTL_USER_PROCESS_PARAMETERS    ProcessParameters;                      /* 00010/00020 */
    PVOID                           SubSystemData;                          /* 00014/00028 */
    PVOID                           ProcessHeap;                            /* 00018/00030 */
    PVOID /*PRTL_CRITICAL_SECTION*/ FastPebLock;                            /* 0001c/00038 */
    PVOID /*PPEBLOCKROUTINE*/       FastPebLockRoutine;                     /* 00020/00040 */
    PVOID /*PPEBLOCKROUTINE*/       FastPebUnlockRoutine;                   /* 00024/00048 */
    ULONG                           EnvironmentUpdateCount;                 /* 00028/00050 */
    PVOID                           KernelCallbackTable;                    /* 0002C/00058 */
    ULONG                           Reserved[2];                            /* 00030/00060 */
    PVOID /*PPEB_FREE_BLOCK*/       FreeList;                               /* 00038/00068 */
    ULONG                           TlsExpansionCounter;                    /* 0003C/00070 */
    PRTL_BITMAP                     TlsBitmap;                              /* 00040/00078 */
    ULONG                           TlsBitmapBits[2];                       /* 00044/00080 */
    PVOID                           ReadOnlySharedMemoryBase;               /* 0004C/00088 */
    PVOID                           ReadOnlySharedMemoryHeap;               /* 00050/00090 */
    PVOID* ReadOnlyStaticServerData;               /* 00054/00098 */
    PVOID                           AnsiCodePageData;                       /* 00058/000A0 */
    PVOID                           OemCodePageData;                        /* 0005C/000A8 */
    PVOID                           UnicodeCaseTableData;                   /* 00060/000B0 */
    ULONG                           NumberOfProcessors;                     /* 00064/000B8 */
    ULONG                           NtGlobalFlag;                           /* 00068/000BC */
    LARGE_INTEGER                   CriticalSectionTimeout;                 /* 00070/000C0 */
    ULONG_PTR                       HeapSegmentReserve;                     /* 00078/000C8 */
    ULONG_PTR                       HeapSegmentCommit;                      /* 0007C/000D0 */
    ULONG_PTR                       HeapDeCommitTotalFreeThreshold;         /* 00080/000D8 */
    ULONG_PTR                       HeapDeCommitFreeBlockThreshold;         /* 00084/000E0 */
    ULONG                           NumberOfHeaps;                          /* 00088/000E8 */
    ULONG                           MaximumNumberOfHeaps;                   /* 0008C/000EC */
    PVOID* ProcessHeaps;                           /* 00090/000F0 */
    PVOID                           GdiSharedHandleTable;                   /* 00094/000F8 */
    PVOID                           ProcessStarterHelper;                   /* 00098/00100 */
    PVOID                           GdiDCAttributeList;                     /* 0009C/00108 */
    PVOID                           LoaderLock;                             /* 000A0/00110 */
    ULONG                           OSMajorVersion;                         /* 000A4/00118 */
    ULONG                           OSMinorVersion;                         /* 000A8/0011C */
    SHORT                           OSBuildNumber;                          /* 000AC/00120 */
    ULONG                           OSPlatformId;                           /* 000B0/00124 */
    ULONG                           ImageSubSystem;                         /* 000B4/00128 */
    ULONG                           ImageSubSystemMajorVersion;             /* 000B8/0012C */
    ULONG                           ImageSubSystemMinorVersion;             /* 000BC/00130 */
    ULONG                           ImageProcessAffinityMask;               /* 000C0/00134 */
    HANDLE                          GdiHandleBuffer[28];                    /* 000C4/00138 */
    ULONG                           unknown[6];                             /* 00134/00218 */
    PVOID                           PostProcessInitRoutine;                 /* 0014C/00230 */
    PRTL_BITMAP                     TlsExpansionBitmap;                     /* 00150/00238 */
    ULONG                           TlsExpansionBitmapBits[32];             /* 00154/00240 */
    ULONG                           SessionId;                              /* 001D4/002C0 */
}PEB, * PPEB;

typedef struct _TEB
{                                                                           /* win32/win64 */
    NT_TIB                          Tib;                                    /* 00000/00000 */
    PVOID                           EnvironmentPointer;                     /* 0001C/00038 */
    CLIENT_ID                       ClientId;                               /* 00020/00040 */
    PVOID                           ActiveRpcHandle;                        /* 00028/00050 */
    PVOID* ThreadLocalStoragePointer;              /* 0002C/00058 */
    PPEB                            Peb;                                    /* 00030/00060 */
    union
    {
        ULONG                       LastErrorValue;                         /* 00034/00068 */
        ULONG                       SystemCallNumber;                       /* 00034/00068 */
    };
    ULONG                           CountOfOwnedCriticalSections;           /* 00038/0006C */
    PVOID                           CsrClientThread;                        /* 0003C/00070 */
    PVOID                           Win32ThreadInfo;                        /* 00040/00078 */
    ULONG                           Win32ClientInfo[31];                    /* 00044/00080 used for user32 private data in Wine */
    PVOID                           WOW32Reserved;                          /* 000C0/00100 */
    ULONG                           CurrentLocale;                          /* 000C4/00108 */
    ULONG                           FpSoftwareStatusRegister;               /* 000C8/0010C */
    PVOID                           SystemReserved1[54];                    /* 000CC/00110 used for kernel32 private data in Wine */
    LONG                            ExceptionCode;                          /* 001A4/002C0 */
    ACTIVATION_CONTEXT_STACK        ActivationContextStack;                 /* 001A8/002C8 */
    UCHAR                           SpareBytes1[24];                        /* 001BC/002E8 */
    PVOID                           SystemReserved2[10];                    /* 001D4/00300 used for ntdll platform-specific private data in Wine */
    GDI_TEB_BATCH                   GdiTebBatch;                            /* 001FC/00350 used for ntdll private data in Wine */
    HANDLE                          gdiRgn;                                 /* 006DC/00838 */
    HANDLE                          gdiPen;                                 /* 006E0/00840 */
    HANDLE                          gdiBrush;                               /* 006E4/00848 */
    CLIENT_ID                       RealClientId;                           /* 006E8/00850 */
    HANDLE                          GdiCachedProcessHandle;                 /* 006F0/00860 */
    ULONG                           GdiClientPID;                           /* 006F4/00868 */
    ULONG                           GdiClientTID;                           /* 006F8/0086C */
    PVOID                           GdiThreadLocaleInfo;                    /* 006FC/00870 */
    ULONG                           UserReserved[5];                        /* 00700/00878 */
    PVOID                           glDispatchTable[280];                   /* 00714/00890 */
    PVOID                           glReserved1[26];                        /* 00B74/01150 */
    PVOID                           glReserved2;                            /* 00BDC/01220 */
    PVOID                           glSectionInfo;                          /* 00BE0/01228 */
    PVOID                           glSection;                              /* 00BE4/01230 */
    PVOID                           glTable;                                /* 00BE8/01238 */
    PVOID                           glCurrentRC;                            /* 00BEC/01240 */
    PVOID                           glContext;                              /* 00BF0/01248 */
    ULONG                           LastStatusValue;                        /* 00BF4/01250 */
    UNICODE_STRING                  StaticUnicodeString;                    /* 00BF8/01258 used by advapi32 */
    WCHAR                           StaticUnicodeBuffer[261];               /* 00C00/01268 used by advapi32 */
    PVOID                           DeallocationStack;                      /* 00E0C/01478 */
    PVOID                           TlsSlots[64];                           /* 00E10/01480 */
    LIST_ENTRY                      TlsLinks;                               /* 00F10/01680 */
    PVOID                           Vdm;                                    /* 00F18/01690 */
    PVOID                           ReservedForNtRpc;                       /* 00F1C/01698 */
    PVOID                           DbgSsReserved[2];                       /* 00F20/016A0 */
    ULONG                           HardErrorDisabled;                      /* 00F28/016B0 */
    PVOID                           Instrumentation[16];                    /* 00F2C/016B8 */
    PVOID                           WinSockData;                            /* 00F6C/01738 */
    ULONG                           GdiBatchCount;                          /* 00F70/01740 */
    ULONG                           Spare2;                                 /* 00F74/01744 */
    ULONG                           GuaranteedStackBytes;                   /* 00F78/01748 */
    PVOID                           ReservedForPerf;                        /* 00F7C/01750 */
    PVOID                           ReservedForOle;                         /* 00F80/01758 */
    ULONG                           WaitingOnLoaderLock;                    /* 00F84/01760 */
    PVOID                           Reserved5[3];                           /* 00F88/01768 */
    PVOID* TlsExpansionSlots;                      /* 00F94/01780 */
#ifdef _WIN64
    PVOID                           DeallocationBStore;                     /* 00000/01788 */
    PVOID                           BStoreLimit;                            /* 00000/01790 */
#endif
    ULONG                           ImpersonationLocale;                    /* 00F98/01798 */
    ULONG                           IsImpersonating;                        /* 00F9C/0179C */
    PVOID                           NlsCache;                               /* 00FA0/017A0 */
    PVOID                           ShimData;                               /* 00FA4/017A8 */
    ULONG                           HeapVirtualAffinity;                    /* 00FA8/017B0 */
    PVOID                           CurrentTransactionHandle;               /* 00FAc/017B8 */
    TEB_ACTIVE_FRAME* ActiveFrame;                            /* 00FB0/017C0 */
} TEB, * PTEB;

#ifndef NtSetLastError
#define NtSetLastError(error) __writegsdword(UFIELD_OFFSET(TEB, LastErrorValue), (ULONG)(error))
#define NtGetLastError() __readgsdword(UFIELD_OFFSET(TEB, LastErrorValue))
#endif
#ifndef NtSetCurrentLocale
#define NtSetCurrentLocale(locale) __writegsdword(UFIELD_OFFSET(TEB, CurrentLocale), locale)
#define NtGetCurrentLocale() __readgsdword(UFIELD_OFFSET(TEB, CurrentLocale))
#endif
#ifndef NtSetExceptionCode
#define NtSetExceptionCode(code) __writegsdword(UFIELD_OFFSET(TEB, ExceptionCode), code)
#define NtGetExceptionCode() __readgsdword(UFIELD_OFFSET(TEB, ExceptionCode))
#endif
#ifndef NtCurrentTeb
#define NtCurrentTeb() ((PTEB)__readgsqword(UFIELD_OFFSET(NT_TIB, Self)))
#define NtCurrentPeb() ((PPEB)__readgsqword(UFIELD_OFFSET(TEB, Peb)))
#endif

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#endif
#ifndef GetCurrentProcess
#define GetCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#endif
#ifndef GetCurrentThread
#define GetCurrentThread() ((HANDLE)(LONG_PTR)-2)
#endif
#ifndef GetCurrentProcessId
#define GetCurrentProcessId() NtCurrentTeb()->ClientId.UniqueProcess
#endif
#ifndef GetCurrentThreadId
#define GetCurrentThreadId() NtCurrentTeb()->ClientId.UniqueThread
#endif
#ifndef PebBuildNumber
#define PebBuildNumber NtCurrentPeb()->OSBuildNumber
#endif

#ifndef __ROL1__
#define __ROL1__ _rotl8
#define __ROR1__ _rotr8
#define __ROL2__ _rotl16
#define __ROR2__ _rotr16
#define __ROL4__ _rotl
#define __ROR4__ _rotr
#define __ROL8__ _rotl64
#define __ROR8__ _rotr64
#endif

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
#endif

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;
typedef VOID(NTAPI* PIO_APC_ROUTINE) (IN PVOID ApcContext, IN PIO_STATUS_BLOCK IoStatusBlock, IN ULONG Reserved);


#pragma region Registry
typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    KeyHandleTagsInformation,
    KeyTrustInformation,
    KeyLayerInformation,
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;
typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG         TitleIndex;
    ULONG         NameLength;
    WCHAR         Name[1];
} KEY_BASIC_INFORMATION, * PKEY_BASIC_INFORMATION;
typedef struct _KEY_NODE_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG         TitleIndex;
    ULONG         ClassOffset;
    ULONG         ClassLength;
    ULONG         NameLength;
    WCHAR         Name[1];
} KEY_NODE_INFORMATION, * PKEY_NODE_INFORMATION;
typedef struct _KEY_FULL_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG         TitleIndex;
    ULONG         ClassOffset;
    ULONG         ClassLength;
    ULONG         SubKeys;
    ULONG         MaxNameLen;
    ULONG         MaxClassLen;
    ULONG         Values;
    ULONG         MaxValueNameLen;
    ULONG         MaxValueDataLen;
    WCHAR         Class[1];
} KEY_FULL_INFORMATION, * PKEY_FULL_INFORMATION;
typedef struct _KEY_NAME_INFORMATION {
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NAME_INFORMATION, * PKEY_NAME_INFORMATION;
typedef struct _KEY_CACHED_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG         TitleIndex;
    ULONG         SubKeys;
    ULONG         MaxNameLen;
    ULONG         Values;
    ULONG         MaxValueNameLen;
    ULONG         MaxValueDataLen;
    ULONG         NameLength;
} KEY_CACHED_INFORMATION, * PKEY_CACHED_INFORMATION;
typedef struct _KEY_FLAGS_INFORMATION {
    ULONG   UserFlags;
} KEY_FLAGS_INFORMATION, * PKEY_FLAGS_INFORMATION;
typedef struct _KEY_VIRTUALIZATION_INFORMATION {
    ULONG VirtualizationCandidate : 1;
    ULONG VirtualizationEnabled : 1;
    ULONG VirtualTarget : 1;
    ULONG VirtualStore : 1;
    ULONG VirtualSource : 1;
    ULONG Reserved : 27;
} KEY_VIRTUALIZATION_INFORMATION, * PKEY_VIRTUALIZATION_INFORMATION;
EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtQueryKey(IN HANDLE KeyHandle, IN KEY_INFORMATION_CLASS KeyInformationClass, IN OPTIONAL PVOID KeyInformation, IN ULONG Length, OUT PULONG ResultLength);

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    KeyValueLayerInformation,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;
typedef struct _KEY_VALUE_BASIC_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, * PKEY_VALUE_BASIC_INFORMATION;
typedef struct _KEY_VALUE_FULL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION, * PKEY_VALUE_FULL_INFORMATION;
typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    WCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, * PKEY_VALUE_PARTIAL_INFORMATION;
EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtQueryValueKey(IN HANDLE KeyHandle, IN PUNICODE_STRING ValueName, IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, OUT OPTIONAL PVOID KeyValueInformation, IN ULONG Length, OUT PULONG ResultLength);


EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtOpenKeyEx(OUT PHANDLE KeyHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN ULONG OpenOptions);
EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtCreateKey(OUT PHANDLE KeyHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, IN OPTIONAL PUNICODE_STRING Class, IN ULONG CreateOptions, OUT OPTIONAL PULONG Disposition);
EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtSetValueKey(IN HANDLE KeyHandle, IN PUNICODE_STRING ValueName, IN OPTIONAL ULONG TitleIndex, IN ULONG Type, IN OPTIONAL PVOID Data, IN ULONG DataSize);
EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtDeleteKey(IN HANDLE KeyHandle);
#pragma endregion

#pragma region File
typedef enum _FILE_INFORMATION_CLASS
{
    FileDirectoryInformation = 1, // FILE_DIRECTORY_INFORMATION
    FileFullDirectoryInformation, // FILE_FULL_DIR_INFORMATION
    FileBothDirectoryInformation, // FILE_BOTH_DIR_INFORMATION
    FileBasicInformation, // FILE_BASIC_INFORMATION
    FileStandardInformation, // FILE_STANDARD_INFORMATION
    FileInternalInformation, // FILE_INTERNAL_INFORMATION
    FileEaInformation, // FILE_EA_INFORMATION
    FileAccessInformation, // FILE_ACCESS_INFORMATION
    FileNameInformation, // FILE_NAME_INFORMATION
    FileRenameInformation, // FILE_RENAME_INFORMATION // 10
    FileLinkInformation, // FILE_LINK_INFORMATION
    FileNamesInformation, // FILE_NAMES_INFORMATION
    FileDispositionInformation, // FILE_DISPOSITION_INFORMATION
    FilePositionInformation, // FILE_POSITION_INFORMATION
    FileFullEaInformation, // FILE_FULL_EA_INFORMATION
    FileModeInformation, // FILE_MODE_INFORMATION
    FileAlignmentInformation, // FILE_ALIGNMENT_INFORMATION
    FileAllInformation, // FILE_ALL_INFORMATION
    FileAllocationInformation, // FILE_ALLOCATION_INFORMATION
    FileEndOfFileInformation, // FILE_END_OF_FILE_INFORMATION // 20
    FileAlternateNameInformation, // FILE_NAME_INFORMATION
    FileStreamInformation, // FILE_STREAM_INFORMATION
    FilePipeInformation, // FILE_PIPE_INFORMATION
    FilePipeLocalInformation, // FILE_PIPE_LOCAL_INFORMATION
    FilePipeRemoteInformation, // FILE_PIPE_REMOTE_INFORMATION
    FileMailslotQueryInformation, // FILE_MAILSLOT_QUERY_INFORMATION
    FileMailslotSetInformation, // FILE_MAILSLOT_SET_INFORMATION
    FileCompressionInformation, // FILE_COMPRESSION_INFORMATION
    FileObjectIdInformation, // FILE_OBJECTID_INFORMATION
    FileCompletionInformation, // FILE_COMPLETION_INFORMATION // 30
    FileMoveClusterInformation, // FILE_MOVE_CLUSTER_INFORMATION
    FileQuotaInformation, // FILE_QUOTA_INFORMATION
    FileReparsePointInformation, // FILE_REPARSE_POINT_INFORMATION
    FileNetworkOpenInformation, // FILE_NETWORK_OPEN_INFORMATION
    FileAttributeTagInformation, // FILE_ATTRIBUTE_TAG_INFORMATION
    FileTrackingInformation, // FILE_TRACKING_INFORMATION
    FileIdBothDirectoryInformation, // FILE_ID_BOTH_DIR_INFORMATION
    FileIdFullDirectoryInformation, // FILE_ID_FULL_DIR_INFORMATION
    FileValidDataLengthInformation, // FILE_VALID_DATA_LENGTH_INFORMATION
    FileShortNameInformation, // FILE_NAME_INFORMATION // 40
    FileIoCompletionNotificationInformation, // FILE_IO_COMPLETION_NOTIFICATION_INFORMATION // since VISTA
    FileIoStatusBlockRangeInformation, // FILE_IOSTATUSBLOCK_RANGE_INFORMATION
    FileIoPriorityHintInformation, // FILE_IO_PRIORITY_HINT_INFORMATION, FILE_IO_PRIORITY_HINT_INFORMATION_EX
    FileSfioReserveInformation, // FILE_SFIO_RESERVE_INFORMATION
    FileSfioVolumeInformation, // FILE_SFIO_VOLUME_INFORMATION
    FileHardLinkInformation, // FILE_LINKS_INFORMATION
    FileProcessIdsUsingFileInformation, // FILE_PROCESS_IDS_USING_FILE_INFORMATION
    FileNormalizedNameInformation, // FILE_NAME_INFORMATION
    FileNetworkPhysicalNameInformation, // FILE_NETWORK_PHYSICAL_NAME_INFORMATION
    FileIdGlobalTxDirectoryInformation, // FILE_ID_GLOBAL_TX_DIR_INFORMATION // since WIN7 // 50
    FileIsRemoteDeviceInformation, // FILE_IS_REMOTE_DEVICE_INFORMATION
    FileUnusedInformation,
    FileNumaNodeInformation, // FILE_NUMA_NODE_INFORMATION
    FileStandardLinkInformation, // FILE_STANDARD_LINK_INFORMATION
    FileRemoteProtocolInformation, // FILE_REMOTE_PROTOCOL_INFORMATION
    FileRenameInformationBypassAccessCheck, // (kernel-mode only); FILE_RENAME_INFORMATION // since WIN8
    FileLinkInformationBypassAccessCheck, // (kernel-mode only); FILE_LINK_INFORMATION
    FileVolumeNameInformation, // FILE_VOLUME_NAME_INFORMATION
    FileIdInformation, // FILE_ID_INFORMATION
    FileIdExtdDirectoryInformation, // FILE_ID_EXTD_DIR_INFORMATION // 60
    FileReplaceCompletionInformation, // FILE_COMPLETION_INFORMATION // since WINBLUE
    FileHardLinkFullIdInformation, // FILE_LINK_ENTRY_FULL_ID_INFORMATION // FILE_LINKS_FULL_ID_INFORMATION
    FileIdExtdBothDirectoryInformation, // FILE_ID_EXTD_BOTH_DIR_INFORMATION // since THRESHOLD
    FileDispositionInformationEx, // FILE_DISPOSITION_INFO_EX // since REDSTONE
    FileRenameInformationEx, // FILE_RENAME_INFORMATION_EX
    FileRenameInformationExBypassAccessCheck, // (kernel-mode only); FILE_RENAME_INFORMATION_EX
    FileDesiredStorageClassInformation, // FILE_DESIRED_STORAGE_CLASS_INFORMATION // since REDSTONE2
    FileStatInformation, // FILE_STAT_INFORMATION
    FileMemoryPartitionInformation, // FILE_MEMORY_PARTITION_INFORMATION // since REDSTONE3
    FileStatLxInformation, // FILE_STAT_LX_INFORMATION // since REDSTONE4 // 70
    FileCaseSensitiveInformation, // FILE_CASE_SENSITIVE_INFORMATION
    FileLinkInformationEx, // FILE_LINK_INFORMATION_EX // since REDSTONE5
    FileLinkInformationExBypassAccessCheck, // (kernel-mode only); FILE_LINK_INFORMATION_EX
    FileStorageReserveIdInformation, // FILE_SET_STORAGE_RESERVE_ID_INFORMATION
    FileCaseSensitiveInformationForceAccessCheck, // FILE_CASE_SENSITIVE_INFORMATION
    FileKnownFolderInformation, // FILE_KNOWN_FOLDER_INFORMATION // since WIN11
    FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;
typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    WCHAR         FileName[1];
} FILE_DIRECTORY_INFORMATION, * PFILE_DIRECTORY_INFORMATION;
typedef struct _FILE_FULL_DIR_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    WCHAR         FileName[1];
} FILE_FULL_DIR_INFORMATION, * PFILE_FULL_DIR_INFORMATION;
typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    CCHAR         ShortNameLength;
    WCHAR         ShortName[12];
    WCHAR         FileName[1];
} FILE_BOTH_DIR_INFORMATION, * PFILE_BOTH_DIR_INFORMATION;
typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;
typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;
typedef struct _FILE_INTERNAL_INFORMATION {
    LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, * PFILE_INTERNAL_INFORMATION;
typedef struct _FILE_EA_INFORMATION {
    ULONG EaSize;
} FILE_EA_INFORMATION, * PFILE_EA_INFORMATION;
typedef struct _FILE_ACCESS_INFORMATION {
    ULONG AccessFlags;
} FILE_ACCESS_INFORMATION, * PFILE_ACCESS_INFORMATION;
typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, * PFILE_NAME_INFORMATION;
typedef struct _FILE_RENAME_INFORMATION {
    union {
        BOOLEAN ReplaceIfExists;  // FileRenameInformation
        ULONG Flags;              // FileRenameInformationEx
    };
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION, * PFILE_RENAME_INFORMATION;
typedef struct _FILE_LINK_INFORMATION {
    union {
        BOOLEAN ReplaceIfExists;  // FileLinkInformation
        ULONG Flags;              // FileLinkInformationEx
    };
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_INFORMATION, * PFILE_LINK_INFORMATION;
typedef struct _FILE_NAMES_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFORMATION, * PFILE_NAMES_INFORMATION;
typedef struct _FILE_DISPOSITION_INFORMATION {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, * PFILE_DISPOSITION_INFORMATION;
typedef struct _FILE_POSITION_INFORMATION {
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, * PFILE_POSITION_INFORMATION;
typedef struct _FILE_FULL_EA_INFORMATION {
    ULONG  NextEntryOffset;
    UCHAR  Flags;
    UCHAR  EaNameLength;
    USHORT EaValueLength;
    CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, * PFILE_FULL_EA_INFORMATION;
typedef struct _FILE_MODE_INFORMATION {
    ULONG Mode;
} FILE_MODE_INFORMATION, * PFILE_MODE_INFORMATION;
EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);

EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtCreateFile(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock, IN OPTIONAL PLARGE_INTEGER AllocationSize, IN ULONG FileAttributes, IN ULONG ShareAccess, IN ULONG CreateDisposition, IN ULONG CreateOptions, IN OPTIONAL PVOID EaBuffer, IN ULONG EaLength);
EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtOpenFile(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG ShareAccess, IN ULONG OpenOptions);
EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtReadFile(IN HANDLE FileHandle, IN OPTIONAL HANDLE Event, IN OPTIONAL PIO_APC_ROUTINE ApcRoutine, IN OPTIONAL PVOID ApcContext, OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID Buffer, IN ULONG_PTR Length, IN OPTIONAL PLARGE_INTEGER ByteOffset, IN OPTIONAL PULONG Key);
EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtSetInformationFile(IN HANDLE FileHandle, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PVOID FileInformation, IN ULONG Length, IN FILE_INFORMATION_CLASS FileInformationClass);
EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtWriteFile(IN HANDLE FileHandle, IN OPTIONAL HANDLE Event, IN OPTIONAL PIO_APC_ROUTINE ApcRoutine, IN OPTIONAL PVOID ApcContext, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PVOID Buffer, IN ULONG_PTR Length, IN OPTIONAL PLARGE_INTEGER ByteOffset, IN OPTIONAL PULONG Key);
#pragma endregion

#pragma region System

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation, // not implemented
    SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
    SystemModuleInformation, // q: RTL_PROCESS_MODULES
    SystemLocksInformation, // q: RTL_PROCESS_LOCKS
    SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
    SystemPagedPoolInformation, // not implemented
    SystemNonPagedPoolInformation, // not implemented
    SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
    SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
    SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
    SystemVdmInstemulInformation, // q: SYSTEM_VDM_INSTEMUL_INFO
    SystemVdmBopInformation, // not implemented // 20
    SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
    SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
    SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
    SystemFullMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemLoadGdiDriverInformation, // s (kernel-mode only)
    SystemUnloadGdiDriverInformation, // s (kernel-mode only)
    SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
    SystemSummaryMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
    SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
    SystemObsolete0, // not implemented
    SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
    SystemCrashDumpStateInformation, // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
    SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
    SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
    SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
    SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
    SystemPrioritySeperation, // s (requires SeTcbPrivilege)
    SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
    SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
    SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
    SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
    SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
    SystemTimeSlipNotification, // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
    SystemSessionCreate, // not implemented
    SystemSessionDetach, // not implemented
    SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
    SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
    SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
    SystemVerifierThunkExtend, // s (kernel-mode only)
    SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
    SystemLoadGdiDriverInSystemSpace, // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
    SystemNumaProcessorMap, // q: SYSTEM_NUMA_INFORMATION
    SystemPrefetcherInformation, // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
    SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
    SystemRecommendedSharedDataAlignment, // q: ULONG // KeGetRecommendedSharedDataAlignment
    SystemComPlusPackage, // q; s: ULONG
    SystemNumaAvailableMemory, // q: SYSTEM_NUMA_INFORMATION // 60
    SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemEmulationBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemEmulationProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
    SystemLostDelayedWriteInformation, // q: ULONG
    SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
    SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
    SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
    SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
    SystemObjectSecurityMode, // q: ULONG // 70
    SystemWatchdogTimerHandler, // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
    SystemWatchdogTimerInformation, // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // (kernel-mode only)
    SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemWow64SharedInformationObsolete, // not implemented
    SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
    SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION

    SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
    SystemVerifierTriageInformation, // not implemented
    SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
    SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
    SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
    SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
    SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
    SystemVerifierCancellationInformation, // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
    SystemProcessorPowerInformationEx, // not implemented
    SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
    SystemSpecialPoolInformation, // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
    SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
    SystemErrorPortInformation, // s (requires SeTcbPrivilege)
    SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
    SystemHypervisorInformation, // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
    SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
    SystemTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
    SystemCoverageInformation, // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
    SystemPrefetchPatchInformation, // SYSTEM_PREFETCH_PATCH_INFORMATION
    SystemVerifierFaultsInformation, // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
    SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
    SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
    SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // 100
    SystemNumaProximityNodeInformation, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
    SystemDynamicTimeZoneInformation, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
    SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
    SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
    SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
    SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // KeQueryLogicalProcessorRelationship
    SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
    SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
    SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
    SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
    SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
    SystemCpuQuotaInformation, // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
    SystemNativeBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemErrorPortTimeouts, // SYSTEM_ERROR_PORT_TIMEOUTS
    SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
    SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
    SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
    SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
    SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
    SystemNodeDistanceInformation, // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber)
    SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
    SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
    SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
    SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
    SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
    SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
    SystemBadPageInformation,
    SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
    SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
    SystemEntropyInterruptTimingInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemConsoleInformation, // q: SYSTEM_CONSOLE_INFORMATION
    SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
    SystemPolicyInformation, // q: SYSTEM_POLICY_INFORMATION
    SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
    SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemDeviceDataEnumerationInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
    SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
    SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
    SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // since WINBLUE
    SystemCriticalProcessErrorLogInformation,
    SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
    SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
    SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
    SystemEntropyInterruptTimingRawInformation,
    SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
    SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
    SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
    SystemBootMetadataInformation, // 150
    SystemSoftRebootInformation, // q: ULONG
    SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
    SystemOfflineDumpConfigInformation, // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
    SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
    SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
    SystemEdidInformation, // q: SYSTEM_EDID_INFORMATION
    SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
    SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
    SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
    SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // 160
    SystemVmGenerationCountInformation,
    SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
    SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
    SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
    SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
    SystemHardwareSecurityTestInterfaceResultsInformation,
    SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
    SystemAllowedCpuSetsInformation,
    SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
    SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
    SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
    SystemCodeIntegrityPolicyFullInformation,
    SystemAffinitizedInterruptProcessorInformation, // (requires SeIncreaseBasePriorityPrivilege)
    SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
    SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
    SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
    SystemWin32WerStartCallout,
    SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
    SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
    SystemInterruptSteeringInformation, // SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT // 180
    SystemSupportedProcessorArchitectures, // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
    SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
    SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
    SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
    SystemControlFlowTransition,
    SystemKernelDebuggingAllowed, // s: ULONG
    SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
    SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
    SystemCodeIntegrityPoliciesFullInformation,
    SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
    SystemIntegrityQuotaInformation,
    SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
    SystemProcessorIdleMaskInformation, // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
    SystemSecureDumpEncryptionInformation,
    SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
    SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
    SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
    SystemFirmwareBootPerformanceInformation,
    SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
    SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
    SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
    SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
    SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
    SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
    SystemCodeIntegrityUnlockModeInformation,
    SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
    SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
    SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
    SystemCodeIntegritySyntheticCacheInformation,
    SystemFeatureConfigurationInformation, // SYSTEM_FEATURE_CONFIGURATION_INFORMATION // since 20H1 // 210
    SystemFeatureConfigurationSectionInformation, // SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
    SystemFeatureUsageSubscriptionInformation, // SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
    SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
    SystemSpacesBootInformation, // since 20H2
    SystemFwRamdiskInformation, // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
    SystemWheaIpmiHardwareInformation,
    SystemDifSetRuleClassInformation,
    SystemDifClearRuleClassInformation,
    SystemDifApplyPluginVerificationOnDriver,
    SystemDifRemovePluginVerificationOnDriver, // 220
    SystemShadowStackInformation, // SYSTEM_SHADOW_STACK_INFORMATION
    SystemBuildVersionInformation, // SYSTEM_BUILD_VERSION_INFORMATION
    SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION
    SystemCodeIntegrityAddDynamicStore,
    SystemCodeIntegrityClearDynamicStores,
    SystemDifPoolTrackingInformation,
    SystemPoolZeroingInformation, // SYSTEM_POOL_ZEROING_INFORMATION
    SystemDpcWatchdogInformation,
    SystemDpcWatchdogInformation2,
    SystemSupportedProcessorArchitectures2, // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx  // 230
    SystemSingleProcessorRelationshipInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor)
    SystemXfgCheckFailureInformation,
    SystemIommuStateInformation, // SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
    SystemHypervisorMinrootInformation, // SYSTEM_HYPERVISOR_MINROOT_INFORMATION
    SystemHypervisorBootPagesInformation, // SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
    SystemPointerAuthInformation, // SYSTEM_POINTER_AUTH_INFORMATION
    SystemSecureKernelDebuggerInformation,
    SystemOriginalImageFeatureInformation,
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;
#pragma endregion

EXTERN_C VOID DECLSPEC_DLLIMPORT RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN OPTIONAL PCWSTR SourceString);
EXTERN_C VOID DECLSPEC_DLLIMPORT RtlInitAnsiString(IN OUT PANSI_STRING DestinationString, IN OPTIONAL PCSTR SourceString);

EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtOpenThreadToken(IN HANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN OpenAsSelf, OUT PHANDLE TokenHandle);
EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtOpenProcessToken(IN HANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, OUT PHANDLE TokenHandle);
EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtAdjustPrivilegesToken(IN HANDLE TokenHandle, IN BOOLEAN DisableAllPrivileges, IN PTOKEN_PRIVILEGES TokenPrivileges, IN ULONG PreviousPrivilegesLength, OUT OPTIONAL PTOKEN_PRIVILEGES PreviousPrivileges, OUT OPTIONAL PULONG RequiredLength);

EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtLoadDriver(IN PUNICODE_STRING DriverServiceName);
EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtUnloadDriver(IN PUNICODE_STRING DriverServiceName);

EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtDeviceIoControlFile(IN HANDLE FileHandle, IN OPTIONAL HANDLE Event, IN OPTIONAL PIO_APC_ROUTINE ApcRoutine, IN OPTIONAL PVOID ApcContext, OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG IoControlCode, IN OPTIONAL PVOID InputBuffer, IN ULONG InputBufferLength, OUT OPTIONAL PVOID OutputBuffer, IN ULONG OutputBufferLength);
EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtWaitForSingleObject(IN HANDLE Handle, IN BOOLEAN Alertable, IN PLARGE_INTEGER Timeout);

EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtClose(IN HANDLE FileHandle);

EXTERN_C NTSTATUS DECLSPEC_DLLIMPORT NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT OPTIONAL PULONG ReturnLength);

NTSTATUS NTAPI MySetPrivilege(IN ULONG Privilege, IN ULONG Attributes);

NTSTATUS NTAPI MyCreateFile(PHANDLE FileHandle, PCWSTR filename, ULONG DesiredAccess, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
NTSTATUS NTAPI MyOpenFile(PHANDLE FileHandle, PCWSTR filename, ULONG DesiredAccess, ULONG ShareAccess, ULONG OpenOptions);
NTSTATUS NTAPI MyGetFileSize(IN HANDLE FileHandle, OUT PULONGLONG PtrFileSize);
NTSTATUS NTAPI MyReadFile(HANDLE FileHandle, PVOID Buffer, ULONG_PTR Offset, ULONG_PTR Length, PULONG_PTR Bytes);
NTSTATUS NTAPI MyWriteFile(HANDLE FileHandle, PVOID Buffer, ULONG_PTR Offset, ULONG_PTR Length, PULONG_PTR pWritted);
NTSTATUS NTAPI MyDeleteFile(IN HANDLE FileHandle);
NTSTATUS NTAPI MyDeleteFile(PCWSTR FilePath);

NTSTATUS NTAPI RegistryOpen(OUT PHANDLE KeyHandle, HANDLE RootKeyHandle, IN ACCESS_MASK DesiredAccess, IN PCWSTR Key, IN ULONG OpenOptions);
NTSTATUS NTAPI RegistryCreate(OUT PHANDLE KeyHandle, IN HANDLE RootKeyHandle, IN ULONG Desired, IN PCWSTR SubKey, IN PCWSTR Class, IN ULONG Options, OUT OPTIONAL PULONG Disposition);
NTSTATUS NTAPI RegistrySetValue(IN HANDLE KeyHandle, IN PCWSTR ValueName, IN OPTIONAL ULONG TitleIndex, IN ULONG Type, IN OPTIONAL PVOID Data, IN ULONG DataSize);
NTSTATUS NTAPI RegistryQuery(OUT HANDLE KeyHandle, IN PCWSTR ValueName, IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, IN PVOID KeyValueInformation, IN ULONG Length, OUT PULONG ResultLength);

NTSTATUS NTAPI MyLoadDriver(IN PCWSTR DriverServiceName);
NTSTATUS NTAPI MyUnloadDriver(IN PCWSTR DriverServiceName);

NTSTATUS NTAPI MyDeviceIoControl(IN HANDLE DeviceHandle, IN ULONG IoControlCode, IN OPTIONAL PVOID InBuffer, IN ULONG InBufferSize, OUT OPTIONAL PVOID OutBuffer, IN ULONG OutBufferSize, OUT OPTIONAL PULONG BytesReturned);
NTSTATUS NTAPI MySaveFileFromMemory(IN PCWSTR FilePath, IN PVOID Buffer, IN ULONG_PTR Length, IN ULONG FileAttributes);
NTSTATUS NTAPI MyLoadUnloadDriver(IN PCWSTR DriverServiceName, IN OPTIONAL PCWSTR ImageFilePath, IN ULONG Type = 1, IN ULONG Start = 0xFFFFFFFF);

PVOID GetSystemModuleBase(IN PCSTR ModuleName);