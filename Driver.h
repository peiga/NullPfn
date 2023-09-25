
#ifndef NATIVE_DECLARE_STRUCTURE
#define NATIVE_DECLARE_STRUCTURE(x) \
    typedef struct _##x x, *P##x;   \
    struct _##x
#endif

#ifndef _WIN64
#define KDDEBUGGER_DATA_OFFSET 0x1068
#else
#define KDDEBUGGER_DATA_OFFSET 0x2080
#endif

#ifndef _WIN64
#define DUMP_BLOCK_SIZE 0x20000
#else
#define DUMP_BLOCK_SIZE 0x40000
#endif

//0x8 bytes (sizeof)
struct _MMPTE_PROTOTYPE
{
    ULONGLONG Valid:1;                                                      //0x0
    ULONGLONG DemandFillProto:1;                                            //0x0
    ULONGLONG HiberVerifyConverted:1;                                       //0x0
    ULONGLONG ReadOnly:1;                                                   //0x0
    ULONGLONG SwizzleBit:1;                                                 //0x0
    ULONGLONG Protection:5;                                                 //0x0
    ULONGLONG Prototype:1;                                                  //0x0
    ULONGLONG Combined:1;                                                   //0x0
    ULONGLONG Unused1:4;                                                    //0x0
    LONGLONG ProtoAddress:48;                                               //0x0
}; 

//0x8 bytes (sizeof)
struct _MMPTE_TIMESTAMP
{
    ULONGLONG MustBeZero:1;                                                 //0x0
    ULONGLONG Unused:3;                                                     //0x0
    ULONGLONG SwizzleBit:1;                                                 //0x0
    ULONGLONG Protection:5;                                                 //0x0
    ULONGLONG Prototype:1;                                                  //0x0
    ULONGLONG Transition:1;                                                 //0x0
    ULONGLONG PageFileLow:4;                                                //0x0
    ULONGLONG Reserved:16;                                                  //0x0
    ULONGLONG GlobalTimeStamp:32;                                           //0x0
}; 

//0x8 bytes (sizeof)
struct _MMPTE_LIST
{
    ULONGLONG Valid:1;                                                      //0x0
    ULONGLONG OneEntry:1;                                                   //0x0
    ULONGLONG filler0:2;                                                    //0x0
    ULONGLONG SwizzleBit:1;                                                 //0x0
    ULONGLONG Protection:5;                                                 //0x0
    ULONGLONG Prototype:1;                                                  //0x0
    ULONGLONG Transition:1;                                                 //0x0
    ULONGLONG filler1:16;                                                   //0x0
    ULONGLONG NextEntry:36;                                                 //0x0
}; 

//0x8 bytes (sizeof)
struct _MMPTE_HARDWARE
{
    ULONGLONG Valid:1;                                                      //0x0
    ULONGLONG Dirty1:1;                                                     //0x0
    ULONGLONG Owner:1;                                                      //0x0
    ULONGLONG WriteThrough:1;                                               //0x0
    ULONGLONG CacheDisable:1;                                               //0x0
    ULONGLONG Accessed:1;                                                   //0x0
    ULONGLONG Dirty:1;                                                      //0x0
    ULONGLONG LargePage:1;                                                  //0x0
    ULONGLONG Global:1;                                                     //0x0
    ULONGLONG CopyOnWrite:1;                                                //0x0
    ULONGLONG Unused:1;                                                     //0x0
    ULONGLONG Write:1;                                                      //0x0
    ULONGLONG PageFrameNumber:40;                                           //0x0
    ULONGLONG ReservedForSoftware:4;                                        //0x0
    ULONGLONG WsleAge:4;                                                    //0x0
    ULONGLONG WsleProtection:3;                                             //0x0
    ULONGLONG NoExecute:1;                                                  //0x0
}; 

//0x8 bytes (sizeof)
struct _MMPTE_SUBSECTION
{
    ULONGLONG Valid:1;                                                      //0x0
    ULONGLONG Unused0:2;                                                    //0x0
    ULONGLONG OnStandbyLookaside:1;                                         //0x0
    ULONGLONG SwizzleBit:1;                                                 //0x0
    ULONGLONG Protection:5;                                                 //0x0
    ULONGLONG Prototype:1;                                                  //0x0
    ULONGLONG ColdPage:1;                                                   //0x0
    ULONGLONG Unused2:3;                                                    //0x0
    ULONGLONG ExecutePrivilege:1;                                           //0x0
    LONGLONG SubsectionAddress:48;                                          //0x0
}; 

//0x8 bytes (sizeof)
struct _MMPTE_TRANSITION
{
    ULONGLONG Valid:1;                                                      //0x0
    ULONGLONG Write:1;                                                      //0x0
    ULONGLONG OnStandbyLookaside:1;                                         //0x0
    ULONGLONG IoTracker:1;                                                  //0x0
    ULONGLONG SwizzleBit:1;                                                 //0x0
    ULONGLONG Protection:5;                                                 //0x0
    ULONGLONG Prototype:1;                                                  //0x0
    ULONGLONG Transition:1;                                                 //0x0
    ULONGLONG PageFrameNumber:40;                                           //0x0
    ULONGLONG Unused:12;                                                    //0x0
}; 

//0x8 bytes (sizeof)
struct _MMPTE_SOFTWARE
{
    ULONGLONG Valid:1;                                                      //0x0
    ULONGLONG PageFileReserved:1;                                           //0x0
    ULONGLONG PageFileAllocated:1;                                          //0x0
    ULONGLONG ColdPage:1;                                                   //0x0
    ULONGLONG SwizzleBit:1;                                                 //0x0
    ULONGLONG Protection:5;                                                 //0x0
    ULONGLONG Prototype:1;                                                  //0x0
    ULONGLONG Transition:1;                                                 //0x0
    ULONGLONG PageFileLow:4;                                                //0x0
    ULONGLONG UsedPageTableEntries:10;                                      //0x0
    ULONGLONG ShadowStack:1;                                                //0x0
    ULONGLONG OnStandbyLookaside:1;                                         //0x0
    ULONGLONG Unused:4;                                                     //0x0
    ULONGLONG PageFileHigh:32;                                              //0x0
}; 

//0x8 bytes (sizeof)
typedef struct _MMPTE
{
    union
    {
        ULONGLONG Long;                                                     //0x0
        volatile ULONGLONG VolatileLong;                                    //0x0
        struct _MMPTE_HARDWARE Hard;                                        //0x0
        struct _MMPTE_PROTOTYPE Proto;                                      //0x0
        struct _MMPTE_SOFTWARE Soft;                                        //0x0
        struct _MMPTE_TIMESTAMP TimeStamp;                                  //0x0
        struct _MMPTE_TRANSITION Trans;                                     //0x0
        struct _MMPTE_SUBSECTION Subsect;                                   //0x0
        struct _MMPTE_LIST List;                                            //0x0
    } u;                                                                    //0x0
}MMPTE,*PMMPTE;


NATIVE_DECLARE_STRUCTURE(DBGKD_DEBUG_DATA_HEADER)
{ //
    // Link to other blocks
    //

    LIST_ENTRY64 List;

    //
    // This is a unique tag to identify the owner of the block.
    // If your component only uses one pool tag, use it for this, too.
    //

    ULONG OwnerTag;

    //
    // This must be initialized to the size of the data block,
    // including this structure.
    //

    ULONG Size;
};

NATIVE_DECLARE_STRUCTURE(KDDEBUGGER_DATA)
{
    DBGKD_DEBUG_DATA_HEADER Header;

    //
    // Base address of kernel image
    //

    ULONGLONG KernBase;

    //
    // DbgBreakPointWithStatus is a function which takes an argument
    // and hits a breakpoint.  This field contains the address of the
    // breakpoint instruction.  When the debugger sees a breakpoint
    // at this address, it may retrieve the argument from the first
    // argument register, or on x86 the eax register.
    //

    ULONGLONG BreakpointWithStatus; // address of breakpoint

    //
    // Address of the saved context record during a bugcheck
    //
    // N.B. This is an automatic in KeBugcheckEx's frame, and
    // is only valid after a bugcheck.
    //

    ULONGLONG SavedContext;

    //
    // help for walking stacks with user callbacks:
    //

    //
    // The address of the thread structure is provided in the
    // WAIT_STATE_CHANGE packet.  This is the offset from the base of
    // the thread structure to the pointer to the kernel stack frame
    // for the currently active usermode callback.
    //

    USHORT ThCallbackStack; // offset in thread data

    //
    // these values are offsets into that frame:
    //

    USHORT NextCallback; // saved pointer to next callback frame
    USHORT FramePointer; // saved frame pointer

    //
    // pad to a quad boundary
    //
    USHORT PaeEnabled;

    //
    // Address of the kernel callout routine.
    //

    ULONGLONG KiCallUserMode; // kernel routine

    //
    // Address of the usermode entry point for callbacks.
    //

    ULONGLONG KeUserCallbackDispatcher; // address in ntdll

    //
    // Addresses of various kernel data structures and lists
    // that are of interest to the kernel debugger.
    //

    ULONGLONG PsLoadedModuleList;
    ULONGLONG PsActiveProcessHead;
    ULONGLONG PspCidTable;

    ULONGLONG ExpSystemResourcesList;
    ULONGLONG ExpPagedPoolDescriptor;
    ULONGLONG ExpNumberOfPagedPools;

    ULONGLONG KeTimeIncrement;
    ULONGLONG KeBugCheckCallbackListHead;
    ULONGLONG KiBugcheckData;

    ULONGLONG IopErrorLogListHead;

    ULONGLONG ObpRootDirectoryObject;
    ULONGLONG ObpTypeObjectType;

    ULONGLONG MmSystemCacheStart;
    ULONGLONG MmSystemCacheEnd;
    ULONGLONG MmSystemCacheWs;

    ULONGLONG MmPfnDatabase;
    ULONGLONG MmSystemPtesStart;
    ULONGLONG MmSystemPtesEnd;
    ULONGLONG MmSubsectionBase;
    ULONGLONG MmNumberOfPagingFiles;

    ULONGLONG MmLowestPhysicalPage;
    ULONGLONG MmHighestPhysicalPage;
    ULONGLONG MmNumberOfPhysicalPages;

    ULONGLONG MmMaximumNonPagedPoolInBytes;
    ULONGLONG MmNonPagedSystemStart;
    ULONGLONG MmNonPagedPoolStart;
    ULONGLONG MmNonPagedPoolEnd;

    ULONGLONG MmPagedPoolStart;
    ULONGLONG MmPagedPoolEnd;
    ULONGLONG MmPagedPoolInformation;
    ULONGLONG MmPageSize;

    ULONGLONG MmSizeOfPagedPoolInBytes;

    ULONGLONG MmTotalCommitLimit;
    ULONGLONG MmTotalCommittedPages;
    ULONGLONG MmSharedCommit;
    ULONGLONG MmDriverCommit;
    ULONGLONG MmProcessCommit;
    ULONGLONG MmPagedPoolCommit;
    ULONGLONG MmExtendedCommit;

    ULONGLONG MmZeroedPageListHead;
    ULONGLONG MmFreePageListHead;
    ULONGLONG MmStandbyPageListHead;
    ULONGLONG MmModifiedPageListHead;
    ULONGLONG MmModifiedNoWritePageListHead;
    ULONGLONG MmAvailablePages;
    ULONGLONG MmResidentAvailablePages;

    ULONGLONG PoolTrackTable;
    ULONGLONG NonPagedPoolDescriptor;

    ULONGLONG MmHighestUserAddress;
    ULONGLONG MmSystemRangeStart;
    ULONGLONG MmUserProbeAddress;

    ULONGLONG KdPrintCircularBuffer;
    ULONGLONG KdPrintCircularBufferEnd;
    ULONGLONG KdPrintWritePointer;
    ULONGLONG KdPrintRolloverCount;

    ULONGLONG MmLoadedUserImageList;

    // NT 5.1 Addition

    ULONGLONG NtBuildLab;
    ULONGLONG KiNormalSystemCall;

    // NT 5.0 hotfix addition

    ULONGLONG KiProcessorBlock;
    ULONGLONG MmUnloadedDrivers;
    ULONGLONG MmLastUnloadedDriver;
    ULONGLONG MmTriageActionTaken;
    ULONGLONG MmSpecialPoolTag;
    ULONGLONG KernelVerifier;
    ULONGLONG MmVerifierData;
    ULONGLONG MmAllocatedNonPagedPool;
    ULONGLONG MmPeakCommitment;
    ULONGLONG MmTotalCommitLimitMaximum;
    ULONGLONG CmNtCSDVersion;

    // NT 5.1 Addition

    ULONGLONG MmPhysicalMemoryBlock;
    ULONGLONG MmSessionBase;
    ULONGLONG MmSessionSize;
    ULONGLONG MmSystemParentTablePage;

    // Server 2003 addition

    ULONGLONG MmVirtualTranslationBase;

    USHORT OffsetKThreadNextProcessor;
    USHORT OffsetKThreadTeb;
    USHORT OffsetKThreadKernelStack;
    USHORT OffsetKThreadInitialStack;

    USHORT OffsetKThreadApcProcess;
    USHORT OffsetKThreadState;
    USHORT OffsetKThreadBStore;
    USHORT OffsetKThreadBStoreLimit;

    USHORT SizeEProcess;
    USHORT OffsetEprocessPeb;
    USHORT OffsetEprocessParentCID;
    USHORT OffsetEprocessDirectoryTableBase;

    USHORT SizePrcb;
    USHORT OffsetPrcbDpcRoutine;
    USHORT OffsetPrcbCurrentThread;
    USHORT OffsetPrcbMhz;

    USHORT OffsetPrcbCpuType;
    USHORT OffsetPrcbVendorString;
    USHORT OffsetPrcbProcStateContext;
    USHORT OffsetPrcbNumber;

    USHORT SizeEThread;

    ULONGLONG KdPrintCircularBufferPtr;
    ULONGLONG KdPrintBufferSize;

    ULONGLONG KeLoaderBlock;

    USHORT SizePcr;
    USHORT OffsetPcrSelfPcr;
    USHORT OffsetPcrCurrentPrcb;
    USHORT OffsetPcrContainedPrcb;

    USHORT OffsetPcrInitialBStore;
    USHORT OffsetPcrBStoreLimit;
    USHORT OffsetPcrInitialStack;
    USHORT OffsetPcrStackLimit;

    USHORT OffsetPrcbPcrPage;
    USHORT OffsetPrcbProcStateSpecialReg;
    USHORT GdtR0Code;
    USHORT GdtR0Data;

    USHORT GdtR0Pcr;
    USHORT GdtR3Code;
    USHORT GdtR3Data;
    USHORT GdtR3Teb;

    USHORT GdtLdt;
    USHORT GdtTss;
    USHORT Gdt64R3CmCode;
    USHORT Gdt64R3CmTeb;

    ULONGLONG IopNumTriageDumpDataBlocks;
    ULONGLONG IopTriageDumpDataBlocks;

    // Longhorn addition

    ULONGLONG VfCrashDataBlock;
    ULONGLONG MmBadPagesDetected;
    ULONGLONG MmZeroedPageSingleBitErrorsDetected;

    // Windows 7 addition

    ULONGLONG EtwpDebuggerData;
    USHORT OffsetPrcbContext;

    // Windows 8 addition

    USHORT OffsetPrcbMaxBreakpoints;
    USHORT OffsetPrcbMaxWatchpoints;

    ULONG OffsetKThreadStackLimit;
    ULONG OffsetKThreadStackBase;
    ULONG OffsetKThreadQueueListEntry;
    ULONG OffsetEThreadIrpList;

    USHORT OffsetPrcbIdleThread;
    USHORT OffsetPrcbNormalDpcState;
    USHORT OffsetPrcbDpcStack;
    USHORT OffsetPrcbIsrStack;

    USHORT SizeKDPC_STACK_FRAME;

    // Windows 8.1 Addition

    USHORT OffsetKPriQueueThreadListHead;
    USHORT OffsetKThreadWaitReason;

    // Windows 10 RS1 Addition

    USHORT Padding;
    ULONGLONG PteBase;

    // Windows 10 RS5 Addition

    ULONGLONG RetpolineStubFunctionTable;
    ULONG RetpolineStubFunctionTableSize;
    ULONG RetpolineStubOffset;
    ULONG RetpolineStubSize;
};

NATIVE_DECLARE_STRUCTURE(DUMP_HEADER)
{
    ULONG Signature;
    ULONG ValidDump;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONGLONG DirectoryTableBase;
    ULONGLONG PfnDataBase;
    PLIST_ENTRY PsLoadedModuleList;
    PLIST_ENTRY PsActiveProcessHead;
    ULONG MachineImageType;
    ULONG NumberProcessors;
    ULONG BugCheckCode;
    ULONGLONG BugCheckParameter1;
    ULONGLONG BugCheckParameter2;
    ULONGLONG BugCheckParameter3;
    ULONGLONG BugCheckParameter4;
    CHAR VersionUser[32];
    PKDDEBUGGER_DATA KdDebuggerDataBlock;
};


NTKERNELAPI ULONG KeCapturePersistentThreadState(
    PCONTEXT Context,
    PKTHREAD Thread,
    ULONG BugCheckCode,
    ULONG BugCheckParameter1,
    ULONG BugCheckParameter2,
    ULONG BugCheckParameter3,
    ULONG BugCheckParameter4,
    PVOID VirtualAddress);
























