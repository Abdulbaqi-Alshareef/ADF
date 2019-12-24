unit TitanEngine;

interface
uses Windows,jwapsapi,SysUtils;

{Types}
type
  PE32Structure = ^PE_32_STRUCT;
  PE_32_STRUCT = packed record
	PE32Offset : LongInt;
	ImageBase : LongInt;
	OriginalEntryPoint : LongInt;
	NtSizeOfImage : LongInt;
	NtSizeOfHeaders : LongInt;
	SizeOfOptionalHeaders : SmallInt;
	FileAlignment : LongInt;
	SectionAligment : LongInt;
	ImportTableAddress : LongInt;
	ImportTableSize : LongInt;
	ResourceTableAddress : LongInt;
	ResourceTableSize : LongInt;
	ExportTableAddress : LongInt;
	ExportTableSize : LongInt;
	TLSTableAddress : LongInt;
	TLSTableSize : LongInt;
	RelocationTableAddress : LongInt;
	RelocationTableSize : LongInt;
	TimeDateStamp : LongInt;
	SectionNumber : SmallInt;
	CheckSum : LongInt;
	SubSystem : SmallInt;
	Characteristics : SmallInt;
	NumberOfRvaAndSizes : LongInt;
  end;

  FileStatusInfo = ^FILE_STATUS_INFO;
  FILE_STATUS_INFO = packed record
	OveralEvaluation : BYTE;
	EvaluationTerminatedByException : boolean;
	FileIs64Bit : boolean;
	FileIsDLL : boolean;
	FileIsConsole : boolean;
	MissingDependencies : boolean;
	MissingDeclaredAPIs : boolean;
	SignatureMZ : BYTE;
	SignaturePE : BYTE;
	EntryPoint : BYTE;
	ImageBase : BYTE;
	SizeOfImage : BYTE;
	FileAlignment : BYTE;
	SectionAlignment : BYTE;
	ExportTable : BYTE;
	RelocationTable : BYTE;
	ImportTable : BYTE;
	ImportTableSection : BYTE;
	ImportTableData : BYTE;
	IATTable : BYTE;
	TLSTable : BYTE;
	LoadConfigTable : BYTE;
	BoundImportTable : BYTE;
	COMHeaderTable : BYTE;
	ResourceTable : BYTE;
	ResourceData : BYTE;
	SectionTable : BYTE;
  end;

  FileFixInfo = ^FILE_FIX_INFO;
  FILE_FIX_INFO = packed record
	OveralEvaluation : BYTE;
	FixingTerminatedByException : boolean;
	FileFixPerformed : boolean;
	StrippedRelocation : boolean;
	DontFixRelocations : boolean;
	OriginalRelocationTableAddress : LongInt;
	OriginalRelocationTableSize : LongInt;
	StrippedExports : boolean;
	DontFixExports : boolean;
	OriginalExportTableAddress : LongInt;
	OriginalExportTableSize : LongInt;
	StrippedResources : boolean;
	DontFixResources : boolean;
	OriginalResourceTableAddress : LongInt;
	OriginalResourceTableSize : LongInt;
	StrippedTLS : boolean;
	DontFixTLS : boolean;
	OriginalTLSTableAddress : LongInt;
	OriginalTLSTableSize : LongInt;
	StrippedLoadConfig : boolean;
	DontFixLoadConfig : boolean;
	OriginalLoadConfigTableAddress : LongInt;
	OriginalLoadConfigTableSize : LongInt;
	StrippedBoundImports : boolean;
	DontFixBoundImports : boolean;
	OriginalBoundImportTableAddress : LongInt;
	OriginalBoundImportTableSize : LongInt;
	StrippedIAT : boolean;
	DontFixIAT : boolean;
	OriginalImportAddressTableAddress : LongInt;
	OriginalImportAddressTableSize : LongInt;
	StrippedCOM : boolean;
	DontFixCOM : boolean;
	OriginalCOMTableAddress : LongInt;
	OriginalCOMTableSize : LongInt;
  end;

  ImportEnumData = ^IMPORT_ENUM_DATA;
  IMPORT_ENUM_DATA = packed record
	NewDll : boolean;
	NumberOfImports : LongInt;
	ImageBase : LongInt;
	BaseImportThunk : LongInt;
	ImportThunk : LongInt;
	APIName : PAnsiChar;
	DLLName : PAnsiChar;
  end;
  
  ThreadItemData = ^THREAD_ITEM_DATA;
  THREAD_ITEM_DATA = packed record
	hThread : THandle;
	dwThreadId : LongInt;
	ThreadStartAddress : LongInt;
	ThreadLocalBase : LongInt;
  end;
  
  LibraryItemData = ^LIBRARY_ITEM_DATA;
  LIBRARY_ITEM_DATA = packed record
	hFile : THandle;
	BaseOfDll : Pointer;
	hFileMapping : THandle;
	hFileMappingView : Pointer;
	szLibraryPath:array[1..260] of AnsiChar;
	szLibraryName:array[1..260] of AnsiChar;
  end;
  
  ProcessItemData = ^PROCESS_ITEM_DATA;
  PROCESS_ITEM_DATA = packed record
	hProcess : THandle;
	dwProcessId : LongInt;
	hThread : THandle;
	dwThreadId : LongInt;
	hFile : THandle;
	BaseOfImage : Pointer;
	ThreadStartAddress : Pointer;
	ThreadLocalBase : Pointer;
  end;
  
  HandlerArray = ^HANDLER_ARRAY;
  HANDLER_ARRAY = packed record
	ProcessId : LongInt;
	hHandle : THandle;
  end;

  HookEntry = ^HOOK_ENTRY;
  HOOK_ENTRY = packed record
	IATHook : boolean;
	HookType : BYTE;
	HookSize : LongInt;
	HookAddress : Pointer;
	RedirectionAddress : Pointer;
	HookBytes:array[1..14] of BYTE;
	OriginalBytes:array[1..14] of BYTE;
	IATHookModuleBase : Pointer;
	IATHookNameHash : LongInt;
	HookIsEnabled : boolean;
	HookIsRemote : boolean;
	PatchedEntry : Pointer;
	RelocationInfo:array[1..7] of LongInt;
	RelocationCount : LongInt;
  end;

  PluginInformation = ^PLUGIN_INFORMATION;
  PLUGIN_INFORMATION = packed record
	PluginName:array[1..64] of AnsiChar;
	PluginMajorVersion : LongInt;
	PluginMinorVersion : LongInt;
	PluginBaseAddress : LongInt;
	TitanDebuggingCallBack : Pointer;
	TitanRegisterPlugin : Pointer;
	TitanReleasePlugin : Pointer;
	TitanResetPlugin : Pointer;
	PluginDisabled : boolean;
  end;
const
{Registers}
	UE_EAX = 1;
	UE_EBX = 2;
	UE_ECX = 3;
	UE_EDX = 4;
	UE_EDI = 5;
	UE_ESI = 6;
	UE_EBP = 7;
	UE_ESP = 8;
	UE_EIP = 9;
	UE_EFLAGS = 10;
	UE_DR0 = 11;
	UE_DR1 = 12;
	UE_DR2 = 13;
	UE_DR3 = 14;
	UE_DR6 = 15;
	UE_DR7 = 16;
	UE_CIP = 35;
	UE_CSP = 36;
	UE_SEG_GS = 37;
	UE_SEG_FS = 38;
	UE_SEG_ES = 39;
	UE_SEG_DS = 40;
	UE_SEG_CS = 41;
	UE_SEG_SS = 42;
{Constants}
	UE_PE_OFFSET = 0;
	UE_IMAGEBASE = 1;
	UE_OEP = 2;
	UE_SIZEOFIMAGE = 3;
	UE_SIZEOFHEADERS = 4;
	UE_SIZEOFOPTIONALHEADER = 5;
	UE_SECTIONALIGNMENT = 6;
	UE_IMPORTTABLEADDRESS = 7;
	UE_IMPORTTABLESIZE = 8;
	UE_RESOURCETABLEADDRESS = 9;
	UE_RESOURCETABLESIZE = 10;
	UE_EXPORTTABLEADDRESS = 11;
	UE_EXPORTTABLESIZE = 12;
	UE_TLSTABLEADDRESS = 13;
	UE_TLSTABLESIZE = 14;
	UE_RELOCATIONTABLEADDRESS = 15;
	UE_RELOCATIONTABLESIZE = 16;
	UE_TIMEDATESTAMP = 17;
	UE_SECTIONNUMBER = 18;
	UE_CHECKSUM = 19;
	UE_SUBSYSTEM = 20;
	UE_CHARACTERISTICS = 21;
	UE_NUMBEROFRVAANDSIZES = 22;
	UE_SECTIONNAME = 23;
	UE_SECTIONVIRTUALOFFSET = 24;
	UE_SECTIONVIRTUALSIZE = 25;
	UE_SECTIONRAWOFFSET = 26;
	UE_SECTIONRAWSIZE = 27;
	UE_SECTIONFLAGS = 28;

	UE_CH_BREAKPOINT = 1;
	UE_CH_SINGLESTEP = 2;
	UE_CH_ACCESSVIOLATION = 3;
	UE_CH_ILLEGALINSTRUCTION = 4;
	UE_CH_NONCONTINUABLEEXCEPTION = 5;
	UE_CH_ARRAYBOUNDSEXCEPTION = 6;
	UE_CH_FLOATDENORMALOPERAND = 7;
	UE_CH_FLOATDEVIDEBYZERO = 8;
	UE_CH_INTEGERDEVIDEBYZERO = 9;
	UE_CH_INTEGEROVERFLOW = 10;
	UE_CH_PRIVILEGEDINSTRUCTION = 11;
	UE_CH_PAGEGUARD = 12;
	UE_CH_EVERYTHINGELSE = 13;
	UE_CH_CREATETHREAD = 14;
	UE_CH_EXITTHREAD = 15;
	UE_CH_CREATEPROCESS = 16;
	UE_CH_EXITPROCESS = 17;
	UE_CH_LOADDLL = 18;
	UE_CH_UNLOADDLL = 19;
	UE_CH_OUTPUTDEBUGSTRING = 20;
	
	UE_FUNCTION_STDCALL = 1;
	UE_FUNCTION_CCALL = 2;
	UE_FUNCTION_FASTCALL = 3;
	UE_FUNCTION_STDCALL_RET = 4;
	UE_FUNCTION_CCALL_RET = 5;
	UE_FUNCTION_FASTCALL_RET = 6;
	UE_FUNCTION_STDCALL_CALL = 7;
	UE_FUNCTION_CCALL_CALL = 8;
	UE_FUNCTION_FASTCALL_CALL = 9;
	UE_PARAMETER_BYTE = 0;
	UE_PARAMETER_WORD = 1;
	UE_PARAMETER_DWORD = 2;
	UE_PARAMETER_QWORD = 3;
	UE_PARAMETER_PTR_BYTE = 4;
	UE_PARAMETER_PTR_WORD = 5;
	UE_PARAMETER_PTR_DWORD = 6;
	UE_PARAMETER_PTR_QWORD = 7;
	UE_PARAMETER_STRING = 8;
	UE_PARAMETER_UNICODE = 9;

	UE_CMP_NOCONDITION = 0;
	UE_CMP_EQUAL = 1;
	UE_CMP_NOTEQUAL = 2;
	UE_CMP_GREATER = 3;
	UE_CMP_GREATEROREQUAL = 4;
	UE_CMP_LOWER = 5;
	UE_CMP_LOWEROREQUAL = 6;
	UE_CMP_REG_EQUAL = 7;
	UE_CMP_REG_NOTEQUAL = 8;
	UE_CMP_REG_GREATER = 9;
	UE_CMP_REG_GREATEROREQUAL = 10;
	UE_CMP_REG_LOWER = 11;
	UE_CMP_REG_LOWEROREQUAL = 12;
	UE_CMP_ALWAYSFALSE = 13;
	UE_OPTION_HANDLER_RETURN_HANDLECOUNT = 1;
	UE_OPTION_HANDLER_RETURN_ACCESS = 2;
	UE_OPTION_HANDLER_RETURN_FLAGS = 3;
	UE_OPTION_HANDLER_RETURN_TYPENAME = 4;

	UE_BREAKPOINT_INT3 = 1;
	UE_BREAKPOINT_LONG_INT3 = 2;
	UE_BREAKPOINT_UD2 = 3;

	UE_BPXREMOVED = 0;
	UE_BPXACTIVE = 1;
	UE_BPXINACTIVE = 2;

	UE_BREAKPOINT = 0;
	UE_SINGLESHOOT = 1;
	UE_HARDWARE = 2;
	UE_MEMORY = 3;
	UE_MEMORY_READ = 4;
	UE_MEMORY_WRITE = 5;
	UE_BREAKPOINT_TYPE_INT3 = $10000000;
	UE_BREAKPOINT_TYPE_LONG_INT3 = $20000000;
	UE_BREAKPOINT_TYPE_UD2 = $30000000;

	UE_HARDWARE_EXECUTE = 4;
	UE_HARDWARE_WRITE = 5;
	UE_HARDWARE_READWRITE = 6;

	UE_HARDWARE_SIZE_1 = 7;
	UE_HARDWARE_SIZE_2 = 8;
	UE_HARDWARE_SIZE_4 = 9;

	UE_ON_LIB_LOAD = 1;
	UE_ON_LIB_UNLOAD = 2;
	UE_ON_LIB_ALL = 3;

	UE_APISTART = 0;
	UE_APIEND = 1;

	UE_PLATFORM_x86 = 1;
	UE_PLATFORM_x64 = 2;
	UE_PLATFORM_ALL = 3;

	UE_ACCESS_READ = 0;
	UE_ACCESS_WRITE = 1;
	UE_ACCESS_ALL = 2;
	
	UE_HIDE_BASIC = 1;

	UE_ENGINE_ALOW_MODULE_LOADING = 1;
	UE_ENGINE_AUTOFIX_FORWARDERS = 2;
	UE_ENGINE_PASS_ALL_EXCEPTIONS = 3;
	UE_ENGINE_NO_CONSOLE_WINDOW = 4;
	UE_ENGINE_BACKUP_FOR_CRITICAL_FUNCTIONS = 5;
	UE_ENGINE_CALL_PLUGIN_CALLBACK = 6;
	UE_ENGINE_RESET_CUSTOM_HANDLER = 7;
	UE_ENGINE_CALL_PLUGIN_DEBUG_CALLBACK = 8;

	UE_OPTION_REMOVEALL = 1;
	UE_OPTION_DISABLEALL = 2;
	UE_OPTION_REMOVEALLDISABLED = 3;
	UE_OPTION_REMOVEALLENABLED = 4;

	UE_STATIC_DECRYPTOR_XOR = 1;
	UE_STATIC_DECRYPTOR_SUB = 2;
	UE_STATIC_DECRYPTOR_ADD = 3;
	
	UE_STATIC_DECRYPTOR_FOREWARD = 1;
	UE_STATIC_DECRYPTOR_BACKWARD = 2;

	UE_STATIC_KEY_SIZE_1 = 1;
	UE_STATIC_KEY_SIZE_2 = 2;
	UE_STATIC_KEY_SIZE_4 = 4;
	UE_STATIC_KEY_SIZE_8 = 8;
	
	UE_STATIC_APLIB = 1;
	UE_STATIC_APLIB_DEPACK = 2;
	UE_STATIC_LZMA = 3;
	
	UE_STATIC_HASH_MD5 = 1;
	UE_STATIC_HASH_SHA1 = 2;
	UE_STATIC_HASH_CRC32 = 3;
	
	UE_RESOURCE_LANGUAGE_ANY = -1;

	UE_DEPTH_SURFACE = 0;
	UE_DEPTH_DEEP = 1;
	
	UE_UNPACKER_CONDITION_SEARCH_FROM_EP = 1;
	
	UE_UNPACKER_CONDITION_LOADLIBRARY = 1;
	UE_UNPACKER_CONDITION_GETPROCADDRESS = 2;
	UE_UNPACKER_CONDITION_ENTRYPOINTBREAK = 3;
	UE_UNPACKER_CONDITION_RELOCSNAPSHOT1 = 4;
	UE_UNPACKER_CONDITION_RELOCSNAPSHOT2 = 5;

	UE_FIELD_OK = 0;
	UE_FIELD_BROKEN_NON_FIXABLE = 1;
	UE_FIELD_BROKEN_NON_CRITICAL = 2;
	UE_FIELD_BROKEN_FIXABLE_FOR_STATIC_USE = 3;
	UE_FIELD_BROKEN_BUT_CAN_BE_EMULATED = 4;
	UE_FILED_FIXABLE_NON_CRITICAL = 5;
	UE_FILED_FIXABLE_CRITICAL = 6;
	UE_FIELD_NOT_PRESET = 7;
	UE_FIELD_NOT_PRESET_WARNING = 8;

	UE_RESULT_FILE_OK = 10;
	UE_RESULT_FILE_INVALID_BUT_FIXABLE = 11;
	UE_RESULT_FILE_INVALID_AND_NON_FIXABLE = 12;
	UE_RESULT_FILE_INVALID_FORMAT = 13;
	
	UE_PLUGIN_CALL_REASON_PREDEBUG = 1;
	UE_PLUGIN_CALL_REASON_EXCEPTION = 2;
	UE_PLUGIN_CALL_REASON_POSTDEBUG = 3;

	TEE_HOOK_NRM_JUMP = 1;
	TEE_HOOK_NRM_CALL = 3;
	TEE_HOOK_IAT = 5;

function FindEx(hProcess:THandle; MemoryStart,MemorySize:LongInt; SearchPattern:Pointer; PatternSize:LongInt; WildCard:Pointer): LongInt;
function EngineCloseHandle(myHandle:THandle):boolean;
function MapFileEx(szFileName :PChar; ReadOrWrite:DWORD;var FileHandle:THandle;var FileSize:DWORD;var FileMap:THandle;var FileMapVA:DWORD; SizeModifier:DWORD):Boolean;
function EngineValidateHeader(FileMapVA:DWORD; hFileProc:THandle; ImageBase:DWORD; DOSHeader:PImageDosHeader; IsFile:Boolean):Boolean;
function GetPE32DataFromMappedFile(FileMapVA:DWORD; WhichSection,WhichData:DWORD):DWORD;
function GetPE32Data(szFileName:PChar; WhichSection,WhichData:LongInt):LongInt;
procedure UnMapFileEx(FileHandle:THandle; FileSize:DWORD;FileMap:THandle; FileMapVA:DWORD);

implementation

function EngineCloseHandle(myHandle:THandle):boolean;
var
	HandleFlags:DWORD;
begin
	Result := false;
	if(GetHandleInformation(myHandle,HandleFlags)) then
		if(CloseHandle(myHandle)) then
			Result := true
end;

function MapFileEx(szFileName :PChar; ReadOrWrite:DWORD;var FileHandle:THandle;var FileSize:DWORD;var FileMap:THandle;var FileMapVA:DWORD; SizeModifier:DWORD):Boolean;
var
	hFile:THandle;
	FileAccess:DWORD;
	FileMapType:DWORD;
	FileMapViewType:DWORD;
	mfFileSize:DWORD;
	mfFileMap:THandle;
	mfFileMapVA:Pointer;

begin
  Result:=false;
  FileMapVA := 0;
  FileSize := 0;
  FileHandle := 0;
	if(ReadOrWrite = UE_ACCESS_READ) then
	begin
		FileAccess := GENERIC_READ;
		FileMapType := PAGE_READONLY;
		FileMapViewType := FILE_MAP_READ;
	end
	else
		if(ReadOrWrite = UE_ACCESS_WRITE) then
		begin
			FileAccess := GENERIC_WRITE;
			FileMapType := PAGE_READWRITE;
			FileMapViewType := FILE_MAP_WRITE;
		end
			else
				if(ReadOrWrite = UE_ACCESS_ALL)  then
				begin
					FileAccess := GENERIC_READ+GENERIC_WRITE+GENERIC_EXECUTE;
					FileMapType := PAGE_EXECUTE_READWRITE;
					FileMapViewType := FILE_MAP_WRITE;
				end
				else
					begin
						FileAccess		:= GENERIC_READ+GENERIC_WRITE+GENERIC_EXECUTE;
						FileMapType		:= PAGE_EXECUTE_READWRITE;
						FileMapViewType := FILE_MAP_ALL_ACCESS;
					end;
	hFile := CreateFileA(szFileName, FileAccess, FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile <> INVALID_HANDLE_VALUE) then
	begin
		FileHandle := hFile;
		mfFileSize := GetFileSize(hFile,nil);
		mfFileSize := mfFileSize + SizeModifier;
		FileSize := mfFileSize;
		mfFileMap := CreateFileMappingA(hFile, nil, FileMapType, 0, mfFileSize, nil);
		if(mfFileMap <> 0) then
		begin
			FileMap := mfFileMap;
			mfFileMapVA := MapViewOfFile(mfFileMap, FileMapViewType, 0, 0, 0);
			if(mfFileMapVA <> nil) then
			begin
        FileMapVA:= DWORD(mfFileMapVA);
				Result:=true;
				Exit;
			end;
		end;
		EngineCloseHandle(hFile);
	end;

end;

procedure UnMapFileEx(FileHandle:THandle; FileSize:DWORD;FileMap:THandle; FileMapVA:DWORD);
begin
	if(UnmapViewOfFile(ptr(FileMapVA))) then
	begin
		EngineCloseHandle(FileMap);
		SetFilePointer(FileHandle,FileSize,nil,FILE_BEGIN);
		SetEndOfFile(FileHandle);
		EngineCloseHandle(FileHandle);
	end;
end;



function EngineValidateHeader(FileMapVA:DWORD; hFileProc:THandle; ImageBase:DWORD; DOSHeader:PImageDosHeader; IsFile:Boolean):Boolean;
var
	ModuleInfo:TModuleInfo;
	MemorySize:DWORD;
	PEHeader32:PImageNtHeaders ;
	RemotePEHeader32:PImageNtHeaders;
	MemoryInfo:TMemoryBasicInformation;
	NumberOfBytesRW:DWORD;
begin
	Result := False;
	if(IsFile) then
	begin
		if(hFileProc = 0) then
		begin
			VirtualQueryEx(GetCurrentProcess, ptr(FileMapVA), MemoryInfo, sizeof(MEMORY_BASIC_INFORMATION));
			VirtualQueryEx(GetCurrentProcess, MemoryInfo.AllocationBase, MemoryInfo, sizeof(MEMORY_BASIC_INFORMATION));
			MemorySize := DWORD(DWORD(MemoryInfo.AllocationBase) + DWORD(MemoryInfo.RegionSize) - DWORD(FileMapVA));
		end
		else
			MemorySize := GetFileSize(hFileProc, nil);
		try
			if(DOSHeader.e_magic = $5A4D) then
				if(DWORD(DOSHeader._lfanew + sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)) < MemorySize) then
				begin
					PEHeader32 := PImageNtHeaders(DWORD(DOSHeader) + DWORD(DOSHeader._lfanew));
					if(PEHeader32.Signature = $4550) then
						Result := True;
				end;
		except
			on E : Exception do result := False;
		end;
	end
	else
	begin
		ZeroMemory(@ModuleInfo, sizeof(TModuleInfo));
    ZeroMemory(@RemotePEHeader32, sizeof(IMAGE_NT_HEADERS));
		GetModuleInformation(hFileProc, ImageBase,ModuleInfo, sizeof(TModuleInfo));
		try
			if(DOSHeader.e_magic = $5A4D) then
				if(DWORD(DOSHeader._lfanew + sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)) < ModuleInfo.SizeOfImage) then
					if(ReadProcessMemory(hFileProc, ptr(ImageBase + DWORD(DOSHeader._lfanew)), RemotePEHeader32, sizeof(IMAGE_NT_HEADERS), NumberOfBytesRW)) then
					begin
						PEHeader32 := PImageNtHeaders(RemotePEHeader32);
						if(PEHeader32.Signature = $4550) then
							Result := True;
					end;
		except
			on E : Exception do Result := False;
		end
	end;
end;

function GetPE32DataFromMappedFile(FileMapVA:DWORD; WhichSection,WhichData:DWORD):DWORD;
var
	DOSHeader:PImageDosHeader;
	PEHeader32:PImageNtHeaders;
	PEHeader64:PImageNtHeaders;
	PESections:PImageSectionHeader;
	SectionNumber:DWORD;
	FileIs64:Boolean;
begin
	Result := 0;
	if (FileMapVA <> 0) then
	begin
		DOSHeader:=PImageDosHeader(FileMapVA);
		if (EngineValidateHeader(FileMapVA, 0, 0, DOSHeader, true)) then
		begin
			PEHeader32 := PImageNtHeaders(DWORD(DOSHeader) + DWORD(DOSHeader._lfanew));
			PEHeader64 := PImageNtHeaders(DWORD(DOSHeader) + DWORD(DOSHeader._lfanew));
			if(PEHeader32.OptionalHeader.Magic = $10b) then
				FileIs64 := false
			else 
				if(PEHeader32.OptionalHeader.Magic = $20b) then
					FileIs64 := true
				else
					exit;
			if(not FileIs64) then
			begin
				PESections := PImageSectionHeader(DWORD(PEHeader32) + PEHeader32.FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
				SectionNumber := PEHeader32.FileHeader.NumberOfSections;
				if(WhichData < UE_SECTIONNAME) then
					Case WhichData Of
						UE_PE_OFFSET				: Result:= DOSHeader._lfanew;
						UE_IMAGEBASE				: Result:= PEHeader32.OptionalHeader.ImageBase;
						UE_OEP						: Result:= PEHeader32.OptionalHeader.AddressOfEntryPoint;
						UE_SIZEOFIMAGE				: Result:= PEHeader32.OptionalHeader.SizeOfImage;
						UE_SIZEOFHEADERS			: Result:= PEHeader32.OptionalHeader.SizeOfHeaders;	
						UE_SIZEOFOPTIONALHEADER		: Result:= PEHeader32.FileHeader.SizeOfOptionalHeader;
						UE_SECTIONALIGNMENT			: Result:= PEHeader32.OptionalHeader.SectionAlignment;
						UE_IMPORTTABLEADDRESS		: Result:= PEHeader32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
						UE_IMPORTTABLESIZE			: Result:= PEHeader32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
						UE_RESOURCETABLEADDRESS		: Result:= PEHeader32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;	
						UE_RESOURCETABLESIZE		: Result:= PEHeader32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
						UE_EXPORTTABLEADDRESS		: Result:= PEHeader32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
						UE_EXPORTTABLESIZE			: Result:= PEHeader32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
						UE_TLSTABLEADDRESS			: Result:= PEHeader32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
						UE_TLSTABLESIZE				: Result:= PEHeader32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
						UE_RELOCATIONTABLEADDRESS	: Result:= PEHeader32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
						UE_RELOCATIONTABLESIZE		: Result:= PEHeader32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
						UE_TIMEDATESTAMP			: Result:= PEHeader32.FileHeader.TimeDateStamp;
						UE_SECTIONNUMBER			: Result:= PEHeader32.FileHeader.NumberOfSections;
						UE_CHECKSUM					: Result:= PEHeader32.OptionalHeader.CheckSum;
						UE_SUBSYSTEM				: Result:= PEHeader32.OptionalHeader.Subsystem;
						UE_CHARACTERISTICS			: Result:= PEHeader32.FileHeader.Characteristics;
						UE_NUMBEROFRVAANDSIZES		: Result:= PEHeader32.OptionalHeader.NumberOfRvaAndSizes;
					end // End Case
				else
					if(SectionNumber >= WhichSection) then
					begin
						PESections := PImageSectionHeader(DWORD(PESections) + WhichSection * IMAGE_SIZEOF_SECTION_HEADER);
						Case WhichData Of
							UE_SECTIONNAME  : Result:= DWORD(@PESections.Name);
							UE_SECTIONVIRTUALOFFSET	: Result:= PESections.VirtualAddress;
							UE_SECTIONVIRTUALSIZE   : Result:= PESections.Misc.VirtualSize;
							UE_SECTIONRAWOFFSET		: Result:= PESections.PointerToRawData;
							UE_SECTIONRAWSIZE		: Result:= PESections.SizeOfRawData;
							UE_SECTIONFLAGS			: Result:= PESections.Characteristics;
						end; // End Case
					end; // SectionNumber >= WhichSection
			end // not FileIs64
			else
			begin
				PESections := PImageSectionHeader(DWORD(PEHeader64) + PEHeader64.FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);			
				SectionNumber := PEHeader64.FileHeader.NumberOfSections;
				if(WhichData < UE_SECTIONNAME) then
					Case WhichData Of
						UE_PE_OFFSET			: Result:= DOSHeader._lfanew;
						UE_IMAGEBASE			: Result:= PEHeader64.OptionalHeader.ImageBase;
						UE_OEP					: Result:= PEHeader64.OptionalHeader.AddressOfEntryPoint;
						UE_SIZEOFIMAGE			: Result:= PEHeader64.OptionalHeader.SizeOfImage;
						UE_SIZEOFHEADERS		: Result:= PEHeader64.OptionalHeader.SizeOfHeaders;
						UE_SIZEOFOPTIONALHEADER	: Result:= PEHeader64.FileHeader.SizeOfOptionalHeader;
						UE_SECTIONALIGNMENT		: Result:= PEHeader64.OptionalHeader.SectionAlignment;
						UE_IMPORTTABLEADDRESS	: Result:= PEHeader64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
						UE_IMPORTTABLESIZE		: Result:= PEHeader64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
						UE_RESOURCETABLEADDRESS	: Result:= PEHeader64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
						UE_RESOURCETABLESIZE	: Result:= PEHeader64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
						UE_EXPORTTABLEADDRESS	: Result:= PEHeader64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
						UE_EXPORTTABLESIZE		: Result:= PEHeader64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
						UE_TLSTABLEADDRESS		: Result:= PEHeader64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
						UE_TLSTABLESIZE			: Result:= PEHeader64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;	
						UE_RELOCATIONTABLEADDRESS: Result:= PEHeader64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
						UE_RELOCATIONTABLESIZE	: Result:= PEHeader64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
						UE_TIMEDATESTAMP		: Result:= PEHeader64.FileHeader.TimeDateStamp;
						UE_SECTIONNUMBER		: Result:= PEHeader64.FileHeader.NumberOfSections;
						UE_CHECKSUM				: Result:= PEHeader64.OptionalHeader.CheckSum;
						UE_SUBSYSTEM			: Result:= PEHeader64.OptionalHeader.Subsystem;
						UE_CHARACTERISTICS		: Result:= PEHeader64.FileHeader.Characteristics;
						UE_NUMBEROFRVAANDSIZES	: Result:= PEHeader64.OptionalHeader.NumberOfRvaAndSizes;										
					end // End Case
				else
					if(SectionNumber >= WhichSection) then
					begin
						PESections := PImageSectionHeader(DWORD(PESections) + WhichSection * IMAGE_SIZEOF_SECTION_HEADER);
						Case WhichData Of
							UE_SECTIONNAME 			: Result:= DWORD(@PESections.Name);
							UE_SECTIONVIRTUALOFFSET	: Result:= PESections.VirtualAddress;
							UE_SECTIONVIRTUALSIZE	: Result:= PESections.Misc.VirtualSize;
							UE_SECTIONRAWOFFSET		: Result:= PESections.PointerToRawData;
							UE_SECTIONRAWSIZE 		: Result:= PESections.SizeOfRawData;
							UE_SECTIONFLAGS 		: Result:= PESections.Characteristics;
						end; // End Case
					end;	
			end; // FileIs64
		end; // EngineValidateHeader
	end;
end;


Function GetPE32Data(szFileName:PChar; WhichSection,WhichData:LongInt):LongInt;
var
	FileHandle:THandle;
	FileSize:DWORD;
	FileMap:THandle;
	FileMapVA:DWORD;
begin
	Result:=0;
	if(MapFileEx(szFileName, UE_ACCESS_READ, FileHandle, FileSize, FileMap, FileMapVA, 0)) Then
	begin
		Result:= GetPE32DataFromMappedFile(FileMapVA, WhichSection, WhichData);
		UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
	end;
end;

function FindEx(hProcess:THandle; MemoryStart,MemorySize:LongInt; SearchPattern:Pointer; PatternSize:LongInt; WildCard:Pointer): LongInt;
var
	i,j:Integer;
	Return:LongInt;
	ueReadBuffer:Pointer;
	SearchBuffer,CompareBuffer:PChar;
	memoryInformation:TMemoryBasicInformation;
  ueNumberOfBytesRead:DWord;
	nWildCard:BYTE;

begin
nWildCard:=$00;
Return := 0;
Result := 0;
ueReadBuffer:=nil;
SearchBuffer:=nil;
CompareBuffer:=nil;

if(WildCard = nil) then
	WildCard:= @nWildCard;
if(hProcess <> 0) and (MemoryStart <> 0) and (MemorySize <> 0) then
begin
	if(hProcess <> GetCurrentProcess()) then
	begin
		ueReadBuffer:= VirtualAlloc(nil, MemorySize, MEM_COMMIT, PAGE_READWRITE);
		if(not ReadProcessMemory(hProcess, ptr(MemoryStart), ueReadBuffer, MemorySize, ueNumberOfBytesRead))then
		begin
			if(ueNumberOfBytesRead = 0) then
			begin
				if(VirtualQueryEx(hProcess, ptr(MemoryStart), memoryInformation, SizeOf(memoryInformation)) <> 0) then
				begin
					MemorySize := (DWORD(memoryInformation.BaseAddress) + memoryInformation.RegionSize - DWORD(MemoryStart));
					if( not ReadProcessMemory(hProcess, ptr(MemoryStart), ueReadBuffer, MemorySize, ueNumberOfBytesRead)) then
					begin
						VirtualFree(ueReadBuffer, 0, MEM_RELEASE);
						Result:=0;
					end
					else
						SearchBuffer := ueReadBuffer;
				end
				else
					VirtualFree(ueReadBuffer, 0, MEM_RELEASE);
			end
			else
				SearchBuffer :=  ueReadBuffer;
		end
		else
			SearchBuffer :=  ueReadBuffer;
	end
	else
		SearchBuffer := Ptr(MemoryStart);
	Try
		CompareBuffer := SearchPattern;
		i:=0;
		while (i < MemorySize) and (Return = 0) do
		begin
			for j := 0 to (PatternSize-1) do
				if(CompareBuffer[j] <> PChar(WildCard)[0]) and (SearchBuffer[i + j] <> CompareBuffer[j]) then
					break;
			if(j = PatternSize) then
				Return:= MemoryStart + i;
			Inc(i);
		end;
		VirtualFree(ueReadBuffer, 0, MEM_RELEASE);
    Result:=Return;
	except on EAccessViolation Do	VirtualFree(ueReadBuffer, 0, MEM_RELEASE);
	end; // End Try
end;
end;

(*
function TLSGrabCallBackDataW(szFileName:PChar; ArrayOfCallBacks:Pointer;var NumberOfCallBacks:DWORD):boolean;
var
	PIMAGE_DOS_HEADER DOSHeader;
	PIMAGE_NT_HEADERS32 PEHeader32;
	PIMAGE_NT_HEADERS64 PEHeader64;
	HANDLE FileHandle;
	DWORD FileSize;
	HANDLE FileMap;
	ULONG_PTR FileMapVA;
	BOOL FileIs64;
	PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86;	
	PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64;
	ULONG_PTR TLSDirectoryAddress;
	ULONG_PTR TLSCallBackAddress;
	ULONG_PTR TLSCompareData = NULL;
	DWORD NumberOfTLSCallBacks = NULL;
begin
	if(MapFileExW(szFileName, UE_ACCESS_READ,FileHandle, FileSize, FileMap, FileMapVA, nil)){
		DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
		if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true)){
			PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
			PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
			if(PEHeader32->OptionalHeader.Magic == 0x10B){
				FileIs64 = false;
			}else if(PEHeader32->OptionalHeader.Magic == 0x20B){
				FileIs64 = true;
			}else{
				UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
				return(false);
			}
			if(!FileIs64){
				if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL){
					TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader32->OptionalHeader.ImageBase + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
					TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
					if(TLSDirectoryX86->AddressOfCallBacks != NULL){
						TLSCallBackAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryX86->AddressOfCallBacks, true);
						while(memcmp((LPVOID)TLSCallBackAddress, &TLSCompareData, sizeof ULONG_PTR) != NULL){
							RtlMoveMemory(ArrayOfCallBacks, (LPVOID)TLSCallBackAddress, sizeof ULONG_PTR);
							ArrayOfCallBacks = (LPVOID)((ULONG_PTR)ArrayOfCallBacks + sizeof ULONG_PTR);
							TLSCallBackAddress = TLSCallBackAddress + sizeof ULONG_PTR;
							NumberOfTLSCallBacks++;
						}
						*NumberOfCallBacks = NumberOfTLSCallBacks;
						UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
						return(true);
					}else{
						*NumberOfCallBacks = NULL;
						UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
						return(false);
					}
				}else{
					*NumberOfCallBacks = NULL;
					UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
					return(false);	
				}
			}else{
				if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL){
					TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
					TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
					if(TLSDirectoryX64->AddressOfCallBacks != NULL){
						TLSCallBackAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryX64->AddressOfCallBacks, true);
						while(memcmp((LPVOID)TLSCallBackAddress, &TLSCompareData, sizeof ULONG_PTR) != NULL){
							RtlMoveMemory(ArrayOfCallBacks, (LPVOID)TLSCallBackAddress, sizeof ULONG_PTR);
							ArrayOfCallBacks = (LPVOID)((ULONG_PTR)ArrayOfCallBacks + sizeof ULONG_PTR);
							TLSCallBackAddress = TLSCallBackAddress + sizeof ULONG_PTR;
							NumberOfTLSCallBacks++;
						}
						*NumberOfCallBacks = NumberOfTLSCallBacks;
						UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
						return(true);
					}else{
						*NumberOfCallBacks = NULL;
						UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
						return(false);
					}
				}else{
					*NumberOfCallBacks = NULL;
					UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
					return(false);	
				}
			}
		}else{
			*NumberOfCallBacks = NULL;
			UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
			return(false);		
		}
	}
	return(false);
end;
*)

end.
