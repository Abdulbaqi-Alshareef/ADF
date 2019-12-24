program ADF;

uses
  Forms,
  Unit1 in 'Unit1.pas' {Form1},
  ADF_Functions in 'ADF_Functions.pas';

{$R *.res}



begin
  Application.Initialize;
  Application.Title := 'Anti Deep Freeze';
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
