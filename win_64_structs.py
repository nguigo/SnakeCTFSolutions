from miasm.core.types import MemStruct, Num, Ptr, Str, \
    Array, RawStruct, Union, \
    BitField, Self, Void, Bits, \
    set_allocator, MemUnion, Struct


class UnicodeString(MemStruct):
    fields = [
        ("length", Num("H")),
        ("maxlength", Num("H")),
        ("data", Ptr("<Q", Str("utf16"))),
    ]


class ListEntry(MemStruct):
    fields = [
        ("flink", Ptr("<Q", Void())),
        ("blink", Ptr("<Q", Void())),
    ]


class LdrDataEntry(MemStruct):

    """
    +0x000 InLoadOrderLinks : _LIST_ENTRY
    +0x010 InMemoryOrderLinks : _LIST_ENTRY
    +0x020 InInitializationOrderLinks : _LIST_ENTRY
    +0x030 DllBase          : Ptr64 Void
    +0x038 EntryPoint       : Ptr64 Void
    +0x040 SizeOfImage      : Uint4B
    +0x048 FullDllName      : _UNICODE_STRING
    +0x058 BaseDllName      : _UNICODE_STRING
    +0x068 FlagGroup        : [4] UChar
    +0x068 Flags            : Uint4B
    +0x068 PackagedBinary   : Pos 0, 1 Bit
    +0x068 MarkedForRemoval : Pos 1, 1 Bit
    +0x068 ImageDll         : Pos 2, 1 Bit
    +0x068 LoadNotificationsSent : Pos 3, 1 Bit
    +0x068 TelemetryEntryProcessed : Pos 4, 1 Bit
    +0x068 ProcessStaticImport : Pos 5, 1 Bit
    +0x068 InLegacyLists    : Pos 6, 1 Bit
    +0x068 InIndexes        : Pos 7, 1 Bit
    +0x068 ShimDll          : Pos 8, 1 Bit
    +0x068 InExceptionTable : Pos 9, 1 Bit
    +0x068 ReservedFlags1   : Pos 10, 2 Bits
    +0x068 LoadInProgress   : Pos 12, 1 Bit
    +0x068 LoadConfigProcessed : Pos 13, 1 Bit
    +0x068 EntryProcessed   : Pos 14, 1 Bit
    +0x068 ProtectDelayLoad : Pos 15, 1 Bit
    +0x068 ReservedFlags3   : Pos 16, 2 Bits
    +0x068 DontCallForThreads : Pos 18, 1 Bit
    +0x068 ProcessAttachCalled : Pos 19, 1 Bit
    +0x068 ProcessAttachFailed : Pos 20, 1 Bit
    +0x068 CorDeferredValidate : Pos 21, 1 Bit
    +0x068 CorImage         : Pos 22, 1 Bit
    +0x068 DontRelocate     : Pos 23, 1 Bit
    +0x068 CorILOnly        : Pos 24, 1 Bit
    +0x068 ChpeImage        : Pos 25, 1 Bit
    +0x068 ReservedFlags5   : Pos 26, 2 Bits
    +0x068 Redirected       : Pos 28, 1 Bit
    +0x068 ReservedFlags6   : Pos 29, 2 Bits
    +0x068 CompatDatabaseProcessed : Pos 31, 1 Bit
    +0x06c ObsoleteLoadCount : Uint2B
    +0x06e TlsIndex         : Uint2B
    +0x070 HashLinks        : _LIST_ENTRY
    +0x080 TimeDateStamp    : Uint4B
    +0x088 EntryPointActivationContext : Ptr64 _ACTIVATION_CONTEXT
    +0x090 Lock             : Ptr64 Void
    +0x098 DdagNode         : Ptr64 _LDR_DDAG_NODE
    +0x0a0 NodeModuleLink   : _LIST_ENTRY
    +0x0b0 LoadContext      : Ptr64 _LDRP_LOAD_CONTEXT
    +0x0b8 ParentDllBase    : Ptr64 Void
    +0x0c0 SwitchBackContext : Ptr64 Void
    +0x0c8 BaseAddressIndexNode : _RTL_BALANCED_NODE
    +0x0e0 MappingInfoIndexNode : _RTL_BALANCED_NODE
    +0x0f8 OriginalBase     : Uint8B
    +0x100 LoadTime         : _LARGE_INTEGER
    +0x108 BaseNameHashValue : Uint4B
    +0x10c LoadReason       : _LDR_DLL_LOAD_REASON
    +0x110 ImplicitPathOptions : Uint4B
    +0x114 ReferenceCount   : Uint4B
    +0x118 DependentLoadFlags : Uint4B
    +0x11c SigningLevel     : UChar
    """

    fields = [
        ("InLoadOrderLinks", ListEntry),
        ("InMemoryOrderLinks", ListEntry),
        ("InInitializationOrderLinks", ListEntry),
        ("DllBase", Ptr("<Q", Void())),
        ("EntryPoint", Ptr("<Q", Void())),
        ("SizeOfImage", Num("<I")),
        ("FullDllName", UnicodeString),
        ("BaseDllName", UnicodeString),
        ("Flags", Array(Num("B"), 4)),
        ("ObsoleteLoadCount", Num("H")),
        ("TlsIndex", Num("H")),
        ("HashLinks", ListEntry),
        ("TimeDateStamp", Num("<I")),
        ("EntryPointActivationContext", Ptr("<Q", Void())),
    ]


class PEB_LDR_DATA(MemStruct):

    """
    +0x000 Length           : Uint4B
    +0x004 Initialized      : UChar
    +0x008 SsHandle         : Ptr64 Void
    +0x010 InLoadOrderModuleList : _LIST_ENTRY
    +0x020 InMemoryOrderModuleList : _LIST_ENTRY
    +0x030 InInitializationOrderModuleList : _LIST_ENTRY
    """

    fields = [
        ("Length", Num("<I")),
        ("Initialized", Num("<I")),
        ("SsHandle", Ptr("<Q", Void())),
        ("InLoadOrderModuleList", ListEntry),
        ("InMemoryOrderModuleList", ListEntry),
        ("InInitializationOrderModuleList", ListEntry)
    ]


class PEB(MemStruct):

    """
    +0x000 InheritedAddressSpace : UChar
    +0x001 ReadImageFileExecOptions : UChar
    +0x002 BeingDebugged    : UChar
    +0x003 BitField         : UChar
      +0x003 ImageUsesLargePages : Pos 0, 1 Bit
      +0x003 IsProtectedProcess : Pos 1, 1 Bit
      +0x003 IsLegacyProcess  : Pos 2, 1 Bit
      +0x003 IsImageDynamicallyRelocated : Pos 3, 1 Bit
      +0x003 SkipPatchingUser32Forwarders : Pos 4, 1 Bit
      +0x003 SpareBits        : Pos 5, 3 Bits
    +0x008 Mutant           : Ptr64 Void
    +0x010 ImageBaseAddress : Ptr64 Void
    +0x018 Ldr              : Ptr64 _PEB_LDR_DATA
    """

    fields = [
        ("InheritedAddressSpace", Num("B")),
        ("ReadImageFileExecOptions", Num("B")),
        ("BeingDebugged", Num("B")),
        ("BitField", Num("B")),
        ("Mutant", Ptr("<Q", Void())),
        ("ImageBaseAddress", Num("<Q")),
        ("Ldr", Ptr("<Q", PEB_LDR_DATA)),
    ]

class NT_TIB(MemStruct):

    """
    +0x000 ExceptionList    : Ptr64 _EXCEPTION_REGISTRATION_RECORD
    +0x008 StackBase        : Ptr64 Void
    +0x010 StackLimit       : Ptr64 Void
    +0x018 SubSystemTib     : Ptr64 Void
    +0x020 FiberData        : Ptr64 Void
    +0x020 Version          : Uint4B
    +0x028 ArbitraryUserPointer : Ptr64 Void
    +0x030 Self             : Ptr64 _NT_TIB
    """

    fields = [
        ("ExceptionList", Ptr("<Q", Void())),
        ("StackBase", Ptr("<Q", Void())),
        ("StackLimit", Ptr("<Q", Void())),
        ("SubSystemTib", Ptr("<Q", Void())),
        (None, Union([
            ("FiberData", Ptr("<Q", Void())),
            ("Version", Num("<I"))
        ])),
        ("ArbitraryUserPointer", Ptr("<Q", Void())),
        ("Self", Ptr("<Q", Self())),
    ]


class TEB(MemStruct):

    """
    +0x000 NtTib            : _NT_TIB
    +0x038 EnvironmentPointer : Ptr64 Void
    +0x040 ClientId         : _CLIENT_ID
    +0x050 ActiveRpcHandle  : Ptr64 Void
    +0x058 ThreadLocalStoragePointer : Ptr64 Void
    +0x060 ProcessEnvironmentBlock : Ptr64 _PEB
    +0x068 LastErrorValue   : Uint4B
    ...
    """

    fields = [
        ("NtTib", NT_TIB),
        ("EnvironmentPointer", Ptr("<Q", Void())),
        ("ClientId", Array(Num("B"), 0x8)),
        ("ActiveRpcHandle", Ptr("<Q", Void())),
        ("ThreadLocalStoragePointer", Ptr("<Q", Void())),
        ("ProcessEnvironmentBlock", Ptr("<Q", PEB)),
        ("LastErrorValue", Num("<Q")),
    ]


class ContextException(MemStruct):
    """
    +0x000 P1Home           : Uint8B
    +0x008 P2Home           : Uint8B
    +0x010 P3Home           : Uint8B
    +0x018 P4Home           : Uint8B
    +0x020 P5Home           : Uint8B
    +0x028 P6Home           : Uint8B
    +0x030 ContextFlags     : Uint4B
    +0x034 MxCsr            : Uint4B
    +0x038 SegCs            : Uint2B
    +0x03a SegDs            : Uint2B
    +0x03c SegEs            : Uint2B
    +0x03e SegFs            : Uint2B
    +0x040 SegGs            : Uint2B
    +0x042 SegSs            : Uint2B
    +0x044 EFlags           : Uint4B
    +0x048 Dr0              : Uint8B
    +0x050 Dr1              : Uint8B
    +0x058 Dr2              : Uint8B
    +0x060 Dr3              : Uint8B
    +0x068 Dr6              : Uint8B
    +0x070 Dr7              : Uint8B
    +0x078 Rax              : Uint8B
    +0x080 Rcx              : Uint8B
    +0x088 Rdx              : Uint8B
    +0x090 Rbx              : Uint8B
    +0x098 Rsp              : Uint8B
    +0x0a0 Rbp              : Uint8B
    +0x0a8 Rsi              : Uint8B
    +0x0b0 Rdi              : Uint8B
    +0x0b8 R8               : Uint8B
    +0x0c0 R9               : Uint8B
    +0x0c8 R10              : Uint8B
    +0x0d0 R11              : Uint8B
    +0x0d8 R12              : Uint8B
    +0x0e0 R13              : Uint8B
    +0x0e8 R14              : Uint8B
    +0x0f0 R15              : Uint8B
    +0x0f8 Rip              : Uint8B
    +0x100 FltSave          : _XSAVE_FORMAT
    +0x100 Header           : [2] _M128A
    +0x120 Legacy           : [8] _M128A
    +0x1a0 Xmm0             : _M128A
    +0x1b0 Xmm1             : _M128A
    +0x1c0 Xmm2             : _M128A
    +0x1d0 Xmm3             : _M128A
    +0x1e0 Xmm4             : _M128A
    +0x1f0 Xmm5             : _M128A
    +0x200 Xmm6             : _M128A
    +0x210 Xmm7             : _M128A
    +0x220 Xmm8             : _M128A
    +0x230 Xmm9             : _M128A
    +0x240 Xmm10            : _M128A
    +0x250 Xmm11            : _M128A
    +0x260 Xmm12            : _M128A
    +0x270 Xmm13            : _M128A
    +0x280 Xmm14            : _M128A
    +0x290 Xmm15            : _M128A
    +0x300 VectorRegister   : [26] _M128A
    +0x4a0 VectorControl    : Uint8B
    +0x4a8 DebugControl     : Uint8B
    +0x4b0 LastBranchToRip  : Uint8B
    +0x4b8 LastBranchFromRip : Uint8B
    +0x4c0 LastExceptionToRip : Uint8B
    +0x4c8 LastExceptionFromRip : Uint8B
    """

    fields = [
    ("P1Home", Num("<Q")),
    ("P2Home", Num("<Q")),
    ("P3Home", Num("<Q")),
    ("P4Home", Num("<Q")),
    ("P5Home", Num("<Q")),
    ("P6Home", Num("<Q")),
    ("ContextFlags", Num("<I")),
    ("MxCsr", Num("<I")),
    ("SegCs", Num("<H")),
    ("SegDs", Num("<H")),
    ("SegEs", Num("<H")),
    ("SegFs", Num("<H")),
    ("SegGs", Num("<H")),
    ("SegSs", Num("<H")),
    ("EFlags", Num("<I")),
    ("Dr0", Num("<Q")),
    ("Dr1", Num("<Q")),
    ("Dr2", Num("<Q")),
    ("Dr3", Num("<Q")),
    ("Dr6", Num("<Q")),
    ("Dr7", Num("<Q")),
    ("Rax", Num("<Q")),
    ("Rcx", Num("<Q")),
    ("Rdx", Num("<Q")),
    ("Rbx", Num("<Q")),
    ("Rsp", Num("<Q")),
    ("Rbp", Num("<Q")),
    ("Rsi", Num("<Q")),
    ("Rdi", Num("<Q")),
    ("R8", Num("<Q")),
    ("R9", Num("<Q")),
    ("R10", Num("<Q")),
    ("R11", Num("<Q")),
    ("R12", Num("<Q")),
    ("R13", Num("<Q")),
    ("R14", Num("<Q")),
    ("R15", Num("<Q")),
    ("Rip", Num("<Q")),
    ("FltSave", Num("<"+"B"*200)),
    ("Header", Num("<"+"Q"*2)),
    ("Legacy", Num("<"+"Q"*8)),
    ("Xmm0", Num("<QQ")),
    ("Xmm1", Num("<QQ")),
    ("Xmm2", Num("<QQ")),
    ("Xmm3", Num("<QQ")),
    ("Xmm4", Num("<QQ")),
    ("Xmm5", Num("<QQ")),
    ("Xmm6", Num("<QQ")),
    ("Xmm7", Num("<QQ")),
    ("Xmm8", Num("<QQ")),
    ("Xmm9", Num("<QQ")),
    ("Xmm10", Num("<QQ")),
    ("Xmm11", Num("<QQ")),
    ("Xmm12", Num("<QQ")),
    ("Xmm13", Num("<QQ")),
    ("Xmm14", Num("<QQ")),
    ("Xmm15", Num("<QQ")),
    ("VectorRegister", Num("<"+"Q"*26)),
    ("VectorControl", Num("<Q")),
    ("DebugControl", Num("<Q")),
    ("LastBranchToRip", Num("<Q")),
    ("LastBranchFromRip", Num("<Q")),
    ("LastExceptionToRip", Num("<Q")),
    ("wastExceptionFromRip", Num("<Q"))
    ]
