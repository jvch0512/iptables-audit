{$mode objfpc}{$H+}
program main;

uses SysUtils, Classes, iptaudit;

procedure Usage;
begin
  WriteLn(StdErr, 'usage: iptables-audit PATH [--tsv] [--fail-on medium|high|critical]');
  WriteLn(StdErr, 'Exit: 0 ok, 1 findings at or above --fail-on, 2 bad input.');
  Halt(2);
end;

function IsRulesFile(const N: string): Boolean;
var e: string;
begin
  e := LowerCase(ExtractFileExt(N));
  Result := (e = '.rules') or (e = '.v4') or (e = '.iptables') or (e = '.save');
end;

procedure Collect(const Base, Dir: string; Files: TStringList);
var sr: TSearchRec; full, rel: string;
begin
  if FindFirst(IncludeTrailingPathDelimiter(Dir) + '*', faAnyFile, sr) = 0 then
  begin
    repeat
      if (sr.Name = '.') or (sr.Name = '..') then Continue;
      full := IncludeTrailingPathDelimiter(Dir) + sr.Name;
      if (sr.Attr and faDirectory) <> 0 then Collect(Base, full, Files)
      else if IsRulesFile(sr.Name) then
      begin
        rel := Copy(full, Length(Base) + 2, MaxInt);
        Files.Add(rel);
      end;
    until FindNext(sr) <> 0;
    FindClose(sr);
  end;
end;

function ReadAll(const Path: string): string;
var fs: TFileStream; n: Int64;
begin
  Result := '';
  fs := TFileStream.Create(Path, fmOpenRead or fmShareDenyNone);
  try
    n := fs.Size;
    if n > 4000000 then n := 4000000;
    SetLength(Result, n);
    if n > 0 then fs.ReadBuffer(Result[1], n);
  finally
    fs.Free;
  end;
end;

var
  path, failOn, a: string;
  tsv: Boolean;
  i, k, failRank: Integer;
  files: TStringList;
  all: TFindings;
  base: string;
begin
  path := ''; failOn := ''; tsv := False;
  i := 1;
  while i <= ParamCount do
  begin
    a := ParamStr(i);
    if a = '--tsv' then tsv := True
    else if a = '--fail-on' then
    begin
      Inc(i);
      if i > ParamCount then Usage;
      failOn := ParamStr(i);
      if (failOn <> 'medium') and (failOn <> 'high') and (failOn <> 'critical') then Usage;
    end
    else if (Length(a) > 0) and (a[1] = '-') then Usage
    else if path <> '' then Usage
    else path := a;
    Inc(i);
  end;
  if path = '' then Usage;
  if not (FileExists(path) or DirectoryExists(path)) then
  begin
    WriteLn(StdErr, 'error: no such file or directory: ', path);
    Halt(2);
  end;
  files := TStringList.Create;
  SetLength(all, 0);
  try
    if DirectoryExists(path) then
    begin
      base := ExcludeTrailingPathDelimiter(path);
      Collect(base, base, files);
      files.Sort;
    end
    else files.Add(ExtractFileName(path));
    for i := 0 to files.Count - 1 do
    begin
      if DirectoryExists(path) then
        Audit(ReadAll(ExcludeTrailingPathDelimiter(path) + '/' + files[i]), files[i], all)
      else
        Audit(ReadAll(path), files[i], all);
    end;
    SortFindings(all);
    if tsv then WriteLn('# ', files.Count, ' files, ', Length(all), ' findings')
    else WriteLn(files.Count, ' files, ', Length(all), ' findings');
    for k := 0 to High(all) do
    begin
      if tsv then WriteLn(all[k].Sev, #9, all[k].Rule, #9, all[k].Where, #9, all[k].Msg)
      else
      begin
        WriteLn(Format('%-8s %s %s', [UpperCase(all[k].Sev), all[k].Rule, all[k].Where]));
        WriteLn('         ', all[k].Msg);
      end;
    end;
    if failOn <> '' then
    begin
      failRank := RankOf(failOn);
      for k := 0 to High(all) do
        if all[k].Rank <= failRank then Halt(1);
    end;
  finally
    files.Free;
  end;
end.
