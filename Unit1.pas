unit Unit1;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls,TlHelp32,ADF_Functions, ExtCtrls, Buttons, ComCtrls,
  Menus, XPMan;

type
  TForm1 = class(TForm)
    Memo1: TMemo;
    Method: TRadioGroup;
    Start: TSpeedButton;
    SpeedButton2: TSpeedButton;
    Label1: TLabel;
    Image1: TImage;
    DFExit: TSpeedButton;
    StatusB: TStatusBar;
    LogMenu: TPopupMenu;
    Copy1: TMenuItem;
    SelectAll1: TMenuItem;
    N1: TMenuItem;
    SaveAs1: TMenuItem;
    SaveToLogFile2: TMenuItem;
    SaveDialog1: TSaveDialog;
    XPManifest1: TXPManifest;
    OpenDialog1: TOpenDialog;
    procedure StartClick(Sender: TObject);
    procedure DFExitClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure MethodClick(Sender: TObject);
    procedure N1Click(Sender: TObject);
    procedure Copy1Click(Sender: TObject);
    procedure SelectAll1Click(Sender: TObject);
    procedure SaveToLogFile2Click(Sender: TObject);
    procedure LogMenuPopup(Sender: TObject);
    procedure SpeedButton2Click(Sender: TObject);
    { Private declarations }
  public
    { Public declarations }
  end;
var
  Form1: TForm1;

implementation

{$R *.dfm}

//*******************************************
Const
  ADF_Version = '0.4';
//*******************************************
procedure Clear;
begin
form1.Memo1.Clear;
end;

procedure Println(Text:String);
begin
  form1.Memo1.Lines.Add(Text);
end;

function BypassCreateMutex(hProc:TProcessInformation; ExeFilePath:String):Boolean;
var
  PatchBytes : array[0..5] of BYTE;
  OriginalBytes: array[0..1] of BYTE;
  PatchBytesSize,NumberOfBytes,OEP:Cardinal;
  Times:Integer;
begin
Result:=False;
PatchBytes[0] := $B8;
PatchBytes[1] := $01;
PatchBytes[2] := $00;
PatchBytes[3] := $00;
PatchBytes[4] := $00;
PatchBytes[5] := $C3;
PatchBytesSize :=  6;
OEP:=GetFileOEP(PChar(ExeFilePath+#0));
if OEP <> 0 then
  Println('Getting OEP :OK')
else
begin
  Println('Getting OEP :Failed');
  exit;
end;
if MakeInfiniteLoop(hProc.hProcess,ptr(OEP),@OriginalBytes) then
  PrintLn('Making Loop :OK')
else
  PrintLn('Making Loop :Failed');
ResumeThread(hProc.hThread);
Times := 0;
While (Times < 40) do
begin
  if BypassAPI(hProc.hProcess,'kernel32.dll','CreateMutexA',@PatchBytes,PatchBytesSize) then
  begin
    Result:=True;
    break;
  end;
  Sleep(100);
  Inc(Times);
end;
if WriteProcessMemory(hProc.hProcess,ptr(OEP),@OriginalBytes,2,NumberOfBytes) then
  Println('Restoring Bytes:OK')
else
  Println('Restoring Bytes:Failed');
end;

function PatchExistsProcess:boolean;
var
  hProc,Addr,Pid,hWindow,Tid:Cardinal;
begin
  Result:=False;
  Println('Searching for Deep Freeze process...');
  hWindow:=GetDFreezWindow;
  Tid:=GetWindowThreadProcessId(hWindow,Pid);
  if Pid = 0 then
  begin
    Println('Deep Freeze process not found');
    exit;
  end;
  Println('Deep Freeze process found :OK');
  Println('Deep Freeze Pid : '+IntToStr(Pid));
  Println('Trying to open process to get its handle...');
  hProc := OpenProcess(PROCESS_ALL_ACCESS, False,Pid);
  if hProc = 0 then
  begin
    Println('Process opened :Failed.');
    exit;
  end;
  Println('Process opened :OK');
  Println('Process handle is :'+IntToStr(hProc));
  Println('Checking this process...');
  if IsMemoryPatched(hProc) then
  begin
    Println('This process is already patched.');
    ShowDFLoginWindow(Tid);
    CloseHandle(hProc);
    Result := True;
    exit;
  end;
  Addr:=FindMagicBytes(hProc);
  if Addr <>0 then
  begin
    Println('Magic bytes found :OK');
    if PatchMemory(hProc,Addr) then
    begin
      Println('Target Bypassed :OK');
      ShowDFLoginWindow(Tid);
      Result:=True;
    end
    else
      Println('Target Bypassed :Failed');
  end
  else
    Println('Magic bytes :Not found.');
  CloseHandle(hProc);
end;

function PatchNewProcess:boolean;
var
  Dir:String; // Deep Freeze Directory
  Addr:Cardinal;
  StartInfo:TStartupInfo;
  ProcInfo:TProcessInformation;
  times:integer;
begin
Result:=False;
Println('Searching for Deep Freeze directory...');
Dir:=GetDirFromReg;
if not FileExists(Dir)then
begin
  Dir:=GetDirFromWind;
  if not FileExists(Dir)then
  begin
    ShowMessage('Deep Freeze directory not found'+#$D+#$A+'Can you choose Deep-Freeze file!');
    if Form1.OpenDialog1.Execute then
      Dir:=Form1.OpenDialog1.FileName;
    if not FileExists(Dir)then
    begin
      Println('Deep Freeze directory :Not found');
      exit;
    end;
  end;
end;
Println('Deep Freeze directory :Found ');
Println('Trying to create new process...');
{ fill with known state }
FillChar(StartInfo,SizeOf(TStartupInfo),#0);
FillChar(ProcInfo,SizeOf(TProcessInformation),#0);
StartInfo.cb := SizeOf(TStartupInfo);
if CreateProcess(PChar(Dir+#0),PChar('0 0 106917'+#0),nil,nil,False,CREATE_SUSPENDED,nil,nil,StartInfo,ProcInfo) then
  begin
  Println('New process created :OK');
  Println('Process id is : '+IntToStr(ProcInfo.dwProcessId)+' , Handle : '+IntToStr(ProcInfo.hProcess));

  Println('Trying to bypass API function...');
  if BypassCreateMutex(ProcInfo,Dir) then
    Println('Bypass API function :OK')
  else
    Println('Bypass API function :Failed');
  Println('Checking this process...');
  times :=0;
  repeat
    Sleep(400);
    Addr:=FindMagicBytes(ProcInfo.hProcess);
    inc(times);
  until (addr <> 0) or (times >= 20);
  if Addr <> 0 then
    begin
    Println('Magic bytes found :OK');
    if PatchMemory(ProcInfo.hProcess,Addr) then
      begin
      Println('Target Bypassed :OK');
      //sleep(100);
      ShowDFLoginWindow(ProcInfo.dwThreadId);
      Result:=True;
      end // for PatchMemory
    else
      Println('Target Bypassed :Failed');
    end // for FindMagicBytes
  else
    Println('Magic bytes :Not found');
  end // for Create Process
else
  Println('New process created :Failed');
end; // end PatchNewProcess function
//*******************************************
procedure TForm1.StartClick(Sender: TObject);
var
  ResultValue:Boolean;
begin
Start.Enabled := False;
Method.Enabled := False;

ResultValue:= False;
if not Method.ItemIndex in [0..1] then
  exit;
Clear;
Println('Operation started.');
if Method.Buttons[0].Checked then
begin
  Println('Method : Open New Process.');
  ResultValue := PatchNewProcess;
end
else if Method.Buttons[1].Checked then
     begin
        Println('Method : Bypass Exists Process.');
        ResultValue := PatchExistsProcess;
     end;
if ResultValue then
begin
  Println('Operation complete :OK');
  StatusB.Panels[2].Text := 'Operation complete';
  end
else
begin
  Println('Operation complete :Failed');
  StatusB.Panels[2].Text := 'Operation Failed';
end;

Start.Enabled := True;
Method.Enabled := True;
end;

procedure TForm1.DFExitClick(Sender: TObject);
begin
Application.Terminate;
end;

procedure TForm1.FormCreate(Sender: TObject);
var
  Version:String;
  Status:DWORD;
begin
    
  Status := GetDFStatus;
  Version := GetDFVersion;
  if (Status = DF_STATUS_UNKNOWN) and (Version = 'unKnown') then
  begin
    StatusB.Panels[2].Text := 'DFreeze not detected';
    Method.Enabled := False;
  end
  else
    StatusB.Panels[2].Text := 'Deep Freeze detected';
  case Status of
    DF_STATUS_THAWED : StatusB.Panels[0].Text := 'Status : Thawed';
    DF_STATUS_FROZEN : StatusB.Panels[0].Text := 'Status : Frozen';
  else
    StatusB.Panels[0].Text := 'Status : unKnown';
  end;
  if Version <> '' then
    StatusB.Panels[1].Text := 'Version : '+Trim(Version)
  else
    StatusB.Panels[1].Text := 'Version : unKnown';
end;


procedure TForm1.MethodClick(Sender: TObject);
begin
  Start.Enabled := True;
  StatusB.Panels[2].Text := 'Ready';
end;

procedure TForm1.N1Click(Sender: TObject);
begin
Clear;
end;

procedure TForm1.Copy1Click(Sender: TObject);
begin
Memo1.CopyToClipboard;
end;

procedure TForm1.SelectAll1Click(Sender: TObject);
begin
Memo1.SelectAll;
end;

procedure TForm1.SaveToLogFile2Click(Sender: TObject);
var
  FileName,Text,Version,Dir:String;
begin
  if Memo1.Text = '' then
    exit;
  SaveDialog1.Filter :='Log Files (*.txt)|*.txt';
  SaveDialog1.FileName := 'ADF_log_file';
  if SaveDialog1.Execute then
  begin
    FileName := SaveDialog1.FileName;
    if ExtractFileExt(FileName) = '' then
      FileName := FileName + '.txt';
    if FileExists(FileName) then
      if MessageBox(Application.Handle,PChar(FileName+' already exists.'+#$D+#$A+'Do you want to replace it?'),'Save to log file',MB_YESNO+MB_ICONWARNING) <> IDYES then
        exit;
    Text := Text+'Log file generated by Anti Deep Freeze'+#$D+#$A;
    Text := Text+'By aljeelany | © AT4RE 2010 | wwww.at4re.com'+#$D+#$A;
    Text := Text+'**********************************'+#$D+#$A;
    Text := Text+'Anti Deep Freeze version : '+ADF_Version+#$D+#$A;
    Text := Text+'Date : '+DateTimeToStr(Now)+#$D+#$A;
    Text := Text+'Operating system : '+GetWinVersion+#$D+#$A;
    Version := GetDFVersion;
    Text := Text+'Deep Freeze version : '+Version+#$D+#$A;
    Text := Text+'Deep Freeze status : '+DFStatusToStr(GetDFStatus)+#$D+#$A;
    Dir := GetDirFromReg;
    if not FileExists(Dir) then
      Dir := GetDirFromWind;
    if not FileExists(Dir) then
      Dir := 'Not found';
    Text := Text+'Deep Freeze Directory : '+Dir+#$D+#$A;
    Text := Text+'**********************************'+#$D+#$A;
    Text := Text+'Log Data : '+#$D+#$A;
    Text := Text+Memo1.Text;
    SaveTextToFile(FileName,Text);
  end;
end;

procedure TForm1.LogMenuPopup(Sender: TObject);
var i:integer;
begin
  if Memo1.Text = '' then
    for i:=0 to logMenu.Items.Count-1 do
      LogMenu.Items[i].Enabled := False
  else
    for i:=0 to logMenu.Items.Count-1 do
      LogMenu.Items[i].Enabled := True;
end;

procedure TForm1.SpeedButton2Click(Sender: TObject);
begin
ShowMessage('Anti Deep Freeze v.0.4'+#$D+#$A+'By aljeelany | © AT4RE 2010'+#$D+#$A'GFXed : SiM && HOUDINI'+#$D+#$A+'www.at4re.com');
end;

end.
