{$mode objfpc}{$H+}
program tests;

uses SysUtils, Classes, iptaudit;

var
  passed, failed: Integer;

procedure Check(Ok: Boolean; const What: string);
begin
  if Ok then Inc(passed) else begin Inc(failed); WriteLn('FAIL: ', What); end;
end;

function Run(const Text: string): TFindings;
begin
  SetLength(Result, 0);
  Audit(Text, 't', Result);
end;

function Has(const Text, Rule: string): Boolean;
var f: TFindings; i: Integer;
begin
  f := Run(Text);
  Result := False;
  for i := 0 to High(f) do if f[i].Rule = Rule then Result := True;
end;

function SevOf(const Text, Rule: string): string;
var f: TFindings; i: Integer;
begin
  f := Run(Text);
  Result := '';
  for i := 0 to High(f) do if f[i].Rule = Rule then Result := f[i].Sev;
end;

function Fw(const Policy, Rules: string): string;
begin
  Result := '*filter' + LineEnding + ':INPUT ' + Policy + ' [0:0]' + LineEnding + ':FORWARD DROP [0:0]' + LineEnding +
            ':OUTPUT ACCEPT [0:0]' + LineEnding + Rules + LineEnding + 'COMMIT' + LineEnding;
end;

const
  Est = '-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT';
  Drop = '-A INPUT -j DROP';

function Cli(const Args: string): Integer;
begin
  Result := ExecuteProcess('/bin/sh', ['-c', 'build/iptables-audit ' + Args + ' >/dev/null 2>&1']);
end;

var
  f: TFindings;
  i, n, pos, k: Integer;
  s, seed, alphabet: string;
  ok: Boolean;

begin
  passed := 0; failed := 0;

  { clean rule set }
  Check(Length(Run(Fw('DROP', '-A INPUT -i lo -j ACCEPT' + LineEnding + Est + LineEnding + '-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT' + LineEnding + Drop))) = 0, 'a closed, tidy rule set has no findings');
  Check(Length(Run('')) = 0, 'empty input');

  { FW001, FW002 }
  Check(Has(Fw('ACCEPT', Est), 'FW001'), 'FW001 policy ACCEPT');
  Check(SevOf(Fw('ACCEPT', Est), 'FW001') = 'high', 'FW001 is high');
  Check(not Has(Fw('ACCEPT', Est + LineEnding + Drop), 'FW001'), 'FW001 closed by a final DROP');
  Check(not Has(Fw('ACCEPT', Est + LineEnding + '-A INPUT -j REJECT --reject-with icmp-port-unreachable'), 'FW001'), 'FW001 closed by a final REJECT');
  Check(Has(Fw('ACCEPT', '-A INPUT -p tcp -j DROP'), 'FW001'), 'FW001 a conditional DROP does not close the chain');
  Check(not Has(Fw('DROP', Est), 'FW001'), 'FW001 policy DROP');
  Check(Has('*filter' + LineEnding + ':INPUT DROP [0:0]' + LineEnding + ':FORWARD ACCEPT [0:0]' + LineEnding + 'COMMIT', 'FW002'), 'FW002 forward ACCEPT');
  Check(not Has(Fw('DROP', Est), 'FW002'), 'FW002 forward DROP');
  Check(not Has('*nat' + LineEnding + ':INPUT ACCEPT [0:0]' + LineEnding + 'COMMIT', 'FW001'), 'only the filter table is judged');

  { FW003 }
  Check(Has(Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m tcp --dport 3306 -j ACCEPT'), 'FW003'), 'FW003 mysql');
  Check(SevOf(Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m tcp --dport 6379 -j ACCEPT'), 'FW003') = 'high', 'FW003 redis is high');
  Check(SevOf(Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT'), 'FW003') = 'medium', 'FW003 ssh is medium');
  Check(Has(Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m multiport --dports 80,3306 -j ACCEPT'), 'FW003'), 'FW003 multiport');
  Check(Has(Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m tcp --dport 5000:6000 -j ACCEPT'), 'FW003'), 'FW003 range that contains a sensitive port');
  Check(not Has(Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m tcp --dport 3306 -s 10.0.0.0/8 -j ACCEPT'), 'FW003'), 'FW003 restricted by -s');
  Check(not Has(Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m tcp --dport 3306 -m set --match-set db src -j ACCEPT'), 'FW003'), 'FW003 restricted by ipset');
  Check(not Has(Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m tcp --dport 3306 -m iprange --src-range 10.0.0.1-10.0.0.9 -j ACCEPT'), 'FW003'), 'FW003 restricted by iprange');
  Check(Has(Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m tcp --dport 3306 -s 0.0.0.0/0 -j ACCEPT'), 'FW003'), 'FW003 0.0.0.0/0 is not a restriction');
  Check(not Has(Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m tcp --dport 3306 -j DROP'), 'FW003'), 'FW003 a DROP rule is fine');
  Check(not Has(Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT'), 'FW003'), 'FW003 ordinary port');
  Check(not Has(Fw('DROP', Est + LineEnding + '-A OUTPUT -p tcp -m tcp --dport 3306 -j ACCEPT'), 'FW003'), 'FW003 only INPUT');
  Check(not Has(Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m tcp --dport 3306 -m comment --comment "db from office, restrict later" -s 10.1.1.1 -j ACCEPT'), 'FW003'), 'FW003 comment with spaces and commas');

  { FW004 }
  Check(Has(Fw('DROP', Est + LineEnding + '-A INPUT -j ACCEPT'), 'FW004'), 'FW004 unconditional accept');
  Check(Has(Fw('DROP', Est + LineEnding + '-A INPUT -m comment --comment "temp" -j ACCEPT'), 'FW004'), 'FW004 comment is not a match');
  Check(not Has(Fw('DROP', Est + LineEnding + '-A INPUT -i lo -j ACCEPT'), 'FW004'), 'FW004 loopback accept');
  Check(not Has(Fw('DROP', Est + LineEnding + '-A INPUT -s 10.0.0.1 -j ACCEPT'), 'FW004'), 'FW004 accept from one host');

  { FW005 }
  Check(Has(Fw('DROP', '-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT'), 'FW005'), 'FW005 no established rule');
  Check(not Has(Fw('DROP', Est), 'FW005'), 'FW005 with ctstate');
  Check(not Has(Fw('DROP', '-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT'), 'FW005'), 'FW005 with the old state module');
  Check(not Has(Fw('ACCEPT', ''), 'FW005'), 'FW005 not for an open chain');

  { FW006 }
  Check(Has(Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m tcp --dport 20000:30000 -j ACCEPT'), 'FW006'), 'FW006 big range');
  Check(not Has(Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m tcp --dport 8000:8100 -j ACCEPT'), 'FW006'), 'FW006 small range');
  Check(not Has(Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m tcp --dport 20000:30000 -s 10.0.0.0/8 -j ACCEPT'), 'FW006'), 'FW006 restricted range');

  { FW000 and formats }
  Check(Has(Fw('DROP', 'this is not a rule'), 'FW000'), 'FW000 garbage line');
  Check(Has(Fw('DROP', '-A'), 'FW000'), 'FW000 short rule');
  Check(not Has(Fw('DROP', '# comment' + LineEnding + Est), 'FW000'), 'comments are fine');
  Check(Length(Run(StringReplace(Fw('DROP', Est + LineEnding + Drop), LineEnding, #13#10, [rfReplaceAll]))) = 0, 'CRLF input');

  { location and sorting }
  f := Run(Fw('ACCEPT', Est));
  Check((Length(f) > 0) and (f[0].Where = 't:2'), 'where is label:line');
  SetLength(f, 0);
  Audit('*filter' + LineEnding + ':INPUT ACCEPT [0:0]' + LineEnding + 'COMMIT', 'b', f);
  Audit('*filter' + LineEnding + ':INPUT ACCEPT [0:0]' + LineEnding + 'COMMIT', 'a', f);
  SortFindings(f);
  Check((Length(f) = 2) and (f[0].Where = 'a:2') and (f[1].Where = 'b:2'), 'sort by file then line');

  { hostile input }
  ok := True;
  s := '';
  for i := 1 to 20000 do s := s + '-A INPUT -p tcp ';
  try Run(s); except ok := False; end;
  Check(ok, 'one very long rule');
  try Run(StringOfChar('"', 50000)); except ok := False; end;
  try Run(StringOfChar(':', 50000)); except ok := False; end;
  try Run('*filter' + LineEnding + StringOfChar('-', 100000)); except ok := False; end;
  try Run(#0#0#0 + LineEnding + #255#254); except ok := False; end;
  try Run(Fw('DROP', '-A INPUT --dport 99999999999999999999 -j ACCEPT')); except ok := False; end;
  try Run(Fw('DROP', '-A INPUT --dport 1: -j ACCEPT' + LineEnding + '-A INPUT --dport :5 -j ACCEPT' + LineEnding + '-A INPUT --dport ,,, -j ACCEPT')); except ok := False; end;
  Check(ok, 'hostile inputs do not raise');

  { fuzz }
  seed := Fw('DROP', Est + LineEnding + '-A INPUT -p tcp -m multiport --dports 22,80,3306 -s 10.0.0.0/8 -j ACCEPT' + LineEnding +
    '-A INPUT -m comment --comment "x y" -j ACCEPT' + LineEnding + '-A INPUT -p tcp --dport 1000:5000 -j ACCEPT' + LineEnding + Drop);
  alphabet := '-:*" ,0123456789ACEPTDROPINUFWARD' + #10;
  RandSeed := 42;
  ok := True;
  for n := 1 to 3000 do
  begin
    s := seed;
    for k := 0 to Random(6) do
    begin
      if Length(s) = 0 then s := 'x';
      pos := Random(Length(s)) + 1;
      case Random(3) of
        0: s[pos] := alphabet[Random(Length(alphabet)) + 1];
        1: Delete(s, pos, 1 + Random(8));
        else Insert(alphabet[Random(Length(alphabet)) + 1], s, pos);
      end;
    end;
    try
      Run(s);
    except
      on E: Exception do begin ok := False; WriteLn('fuzz: ', E.ClassName, ' on case ', n); Break; end;
    end;
  end;
  Check(ok, 'fuzzing 3000 inputs never raises');

  { CLI }
  Check(Cli('examples') = 0, 'cli exit 0');
  Check(Cli('examples --fail-on high') = 1, 'cli --fail-on high');
  Check(Cli('examples/web/web.rules --fail-on medium') = 0, 'clean rule set passes');
  Check(Cli('/no/such/path') = 2, 'missing path');
  Check(Cli('') = 2, 'no args');
  Check(Cli('examples --bogus') = 2, 'unknown flag');
  Check(Cli('examples --fail-on nope') = 2, 'bad --fail-on');
  Check(Cli('examples --fail-on') = 2, '--fail-on without value');
  Check(Cli('examples examples') = 2, 'two paths');

  WriteLn(passed, ' passed, ', failed, ' failed');
  if failed > 0 then Halt(1);
end.
