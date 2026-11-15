{$mode objfpc}{$H+}
unit iptaudit;

interface

type
  TFinding = record
    Rank: Integer;
    Sev, Rule, Where, Msg: string;
  end;
  TFindings = array of TFinding;

procedure Audit(const Text, Lbl: string; var F: TFindings);
procedure SortFindings(var F: TFindings);
function RankOf(const Sev: string): Integer;

implementation

uses SysUtils, Classes;

function RankOf(const Sev: string): Integer;
begin
  if Sev = 'critical' then Result := 0
  else if Sev = 'high' then Result := 1
  else if Sev = 'medium' then Result := 2
  else if Sev = 'low' then Result := 3
  else Result := 4;
end;

procedure Add(var F: TFindings; const Sev, Rule, Lbl: string; Line: Integer; const Msg: string);
var n: Integer;
begin
  n := Length(F);
  SetLength(F, n + 1);
  F[n].Rank := RankOf(Sev);
  F[n].Sev := Sev;
  F[n].Rule := Rule;
  F[n].Where := Lbl + ':' + IntToStr(Line);
  F[n].Msg := Msg;
end;

function LineOf(const W: string): Integer;
var p: Integer;
begin
  p := LastDelimiter(':', W);
  Result := StrToIntDef(Copy(W, p + 1, 20), 0);
end;

procedure SortFindings(var F: TFindings);
var i, j: Integer; t: TFinding;
  function Less(const a, b: TFinding): Boolean;
  var fa, fb: string;
  begin
    if a.Rank <> b.Rank then Exit(a.Rank < b.Rank);
    fa := Copy(a.Where, 1, LastDelimiter(':', a.Where) - 1);
    fb := Copy(b.Where, 1, LastDelimiter(':', b.Where) - 1);
    if fa <> fb then Exit(fa < fb);
    if LineOf(a.Where) <> LineOf(b.Where) then Exit(LineOf(a.Where) < LineOf(b.Where));
    Result := a.Rule < b.Rule;
  end;
begin
  for i := 1 to High(F) do
  begin
    t := F[i];
    j := i - 1;
    while (j >= 0) and Less(t, F[j]) do
    begin
      F[j + 1] := F[j];
      Dec(j);
    end;
    F[j + 1] := t;
  end;
end;

{ Replaces the inside of double quoted text so that spaces in comments do not split tokens. }
function BlankQuotes(const S: string): string;
var i: Integer; inq: Boolean;
begin
  Result := S;
  inq := False;
  for i := 1 to Length(Result) do
  begin
    if Result[i] = '"' then inq := not inq
    else if inq then Result[i] := '_';
  end;
end;

procedure Tokens(const S: string; L: TStringList);
var i, st: Integer;
begin
  L.Clear;
  i := 1;
  while i <= Length(S) do
  begin
    while (i <= Length(S)) and (S[i] in [' ', #9]) do Inc(i);
    st := i;
    while (i <= Length(S)) and not (S[i] in [' ', #9]) do Inc(i);
    if i > st then L.Add(Copy(S, st, i - st));
  end;
end;

type
  TRule = record
    Chain, Src, Target, Proto, Dport: string;
    Restricted: Boolean;     { -s, -m set, -m iprange }
    Matches: Integer;        { number of match options other than -j }
    Established: Boolean;
  end;

function ParseRule(const Line: string; out R: TRule): Boolean;
var L: TStringList; i: Integer; t, nxt: string;
begin
  R.Chain := ''; R.Src := ''; R.Target := ''; R.Proto := ''; R.Dport := '';
  R.Restricted := False; R.Matches := 0; R.Established := False;
  L := TStringList.Create;
  try
    Tokens(BlankQuotes(Line), L);
    Result := (L.Count >= 2) and (L[0] = '-A');
    if not Result then Exit;
    R.Chain := L[1];
    i := 2;
    while i < L.Count do
    begin
      t := L[i];
      if i + 1 < L.Count then nxt := L[i + 1] else nxt := '';
      if (t = '-s') or (t = '--source') then
      begin
        R.Src := nxt;
        if (nxt <> '0.0.0.0/0') and (nxt <> '::/0') and (nxt <> '!') and (nxt <> '') then R.Restricted := True;
        Inc(R.Matches); Inc(i);
      end
      else if (t = '-j') or (t = '-g') or (t = '--jump') then begin R.Target := nxt; Inc(i); end
      else if (t = '-p') or (t = '--protocol') then begin R.Proto := nxt; Inc(R.Matches); Inc(i); end
      else if (t = '--dport') or (t = '--destination-port') or (t = '--dports') or (t = '--destination-ports') then
      begin R.Dport := nxt; Inc(R.Matches); Inc(i); end
      else if (t = '-m') or (t = '--match') then
      begin
        if (nxt = 'set') or (nxt = 'iprange') then R.Restricted := True;
        if nxt <> 'comment' then Inc(R.Matches);
        Inc(i);
      end
      else if (t = '--ctstate') or (t = '--state') then
      begin
        if (Pos('ESTABLISHED', UpperCase(nxt)) > 0) or (Pos('RELATED', UpperCase(nxt)) > 0) then R.Established := True;
        Inc(i);
      end
      else if (t = '-i') or (t = '-o') or (t = '-d') or (t = '--in-interface') or (t = '--out-interface') or (t = '--destination') then
      begin Inc(R.Matches); Inc(i); end;
      Inc(i);
    end;
  finally
    L.Free;
  end;
end;

{ True when the port list (e.g. "22", "22,80", "1024:65535") contains port P; Span gets the widest range size. }
function PortHas(const List: string; P: Integer; out Span: Integer): Boolean;
var parts: TStringList; k, a, b, c: Integer; item: string;
begin
  Result := False;
  Span := 0;
  parts := TStringList.Create;
  try
    parts.Delimiter := ',';
    parts.StrictDelimiter := True;
    parts.DelimitedText := List;
    for k := 0 to parts.Count - 1 do
    begin
      item := Trim(parts[k]);
      if item = '' then Continue;
      c := Pos(':', item);
      if c > 0 then
      begin
        a := StrToIntDef(Copy(item, 1, c - 1), -1);
        b := StrToIntDef(Copy(item, c + 1, 10), -1);
        if (a >= 0) and (b >= a) then
        begin
          if b - a + 1 > Span then Span := b - a + 1;
          if (P >= a) and (P <= b) then Result := True;
        end;
      end
      else
      begin
        a := StrToIntDef(item, -1);
        if (a = P) then Result := True;
        if (Span < 1) and (a >= 0) then Span := 1;
      end;
    end;
  finally
    parts.Free;
  end;
end;

const
  HighPorts: array[0..14] of Integer = (23, 135, 139, 445, 1433, 2375, 2376, 3306, 5432, 5900, 5984, 6379, 9200, 11211, 27017);
  MedPorts: array[0..2] of Integer = (21, 22, 3389);

procedure Audit(const Text, Lbl: string; var F: TFindings);
var
  L: TStringList;
  i, k, span: Integer;
  line, curTable, chain, pol: string;
  R: TRule;
  inPolicy, fwPolicy: string;
  inFinalDrop, fwFinalDrop, inEst: Boolean;
  inFirstLine, fwFirstLine: Integer;
  hit: Boolean;
begin
  L := TStringList.Create;
  try
    L.Text := Text;
    curTable := '';
    inPolicy := 'ACCEPT'; fwPolicy := 'ACCEPT';
    inFinalDrop := False; fwFinalDrop := False; inEst := False;
    inFirstLine := 0; fwFirstLine := 0;
    for i := 0 to L.Count - 1 do
    begin
      line := Trim(L[i]);
      if (line = '') or (line[1] = '#') then Continue;
      if line[1] = '*' then begin curTable := Copy(line, 2, 40); Continue; end;
      if line = 'COMMIT' then begin curTable := ''; Continue; end;
      if line[1] = ':' then
      begin
        k := Pos(' ', line);
        if k = 0 then Continue;
        chain := Copy(line, 2, k - 2);
        pol := Trim(Copy(line, k + 1, 20));
        if Pos(' ', pol) > 0 then pol := Copy(pol, 1, Pos(' ', pol) - 1);
        if curTable = 'filter' then
        begin
          if chain = 'INPUT' then begin inPolicy := pol; inFirstLine := i + 1; end;
          if chain = 'FORWARD' then begin fwPolicy := pol; fwFirstLine := i + 1; end;
        end;
        Continue;
      end;
      if line[1] <> '-' then
      begin
        Add(F, 'info', 'FW000', Lbl, i + 1, 'line not understood, ignored: ' + Copy(line, 1, 40));
        Continue;
      end;
      if not ParseRule(line, R) then
      begin
        Add(F, 'info', 'FW000', Lbl, i + 1, 'rule line not understood, ignored: ' + Copy(line, 1, 40));
        Continue;
      end;
      if curTable <> 'filter' then Continue;
      if R.Chain = 'INPUT' then
      begin
        inFinalDrop := (R.Matches = 0) and ((R.Target = 'DROP') or (R.Target = 'REJECT'));
        if R.Established and (R.Target = 'ACCEPT') then inEst := True;
        if (R.Target = 'ACCEPT') and (R.Matches = 0) then
          Add(F, 'high', 'FW004', Lbl, i + 1, 'unconditional ACCEPT in INPUT: every packet is allowed');
        if (R.Target = 'ACCEPT') and (R.Dport <> '') and (not R.Restricted) and ((R.Proto = 'tcp') or (R.Proto = 'udp') or (R.Proto = '')) then
        begin
          hit := False;
          for k := Low(HighPorts) to High(HighPorts) do
            if (not hit) and PortHas(R.Dport, HighPorts[k], span) then
            begin
              hit := True;
              Add(F, 'high', 'FW003', Lbl, i + 1, 'port ' + IntToStr(HighPorts[k]) + ' is open to any source address (rule opens ' + R.Dport + ')');
            end;
          if not hit then
            for k := Low(MedPorts) to High(MedPorts) do
              if (not hit) and PortHas(R.Dport, MedPorts[k], span) then
              begin
                hit := True;
                Add(F, 'medium', 'FW003', Lbl, i + 1, 'port ' + IntToStr(MedPorts[k]) + ' is open to any source address (rule opens ' + R.Dport + '): restrict it with -s');
              end;
          if PortHas(R.Dport, -1, span) then span := span;
          if span >= 1000 then
            Add(F, 'medium', 'FW006', Lbl, i + 1, 'a range of ' + IntToStr(span) + ' ports is open to any source address');
        end;
      end
      else if R.Chain = 'FORWARD' then
        fwFinalDrop := (R.Matches = 0) and ((R.Target = 'DROP') or (R.Target = 'REJECT'));
    end;
    if (inPolicy = 'ACCEPT') and (not inFinalDrop) and (inFirstLine > 0) then
      Add(F, 'high', 'FW001', Lbl, inFirstLine, 'INPUT policy is ACCEPT and no final DROP or REJECT rule closes it');
    if (fwPolicy = 'ACCEPT') and (not fwFinalDrop) and (fwFirstLine > 0) then
      Add(F, 'high', 'FW002', Lbl, fwFirstLine, 'FORWARD policy is ACCEPT and no final DROP or REJECT rule closes it');
    if ((inPolicy = 'DROP') or inFinalDrop) and (not inEst) and (inFirstLine > 0) then
      Add(F, 'low', 'FW005', Lbl, inFirstLine, 'INPUT is closed but no rule accepts ESTABLISHED,RELATED traffic: replies to your own connections are dropped');
  finally
    L.Free;
  end;
end;

end.
