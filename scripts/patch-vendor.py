"""Reapply reviewed, minimal dependency changes after go mod vendor."""
from pathlib import Path
patches = {
 'vendor/golang.org/x/net/http2/http2.go': [
  ('disableExtendedConnectProtocol = true', '// tunnelX only: all servers in this binary implement Extended CONNECT.\n\tdisableExtendedConnectProtocol = false')],
 'vendor/golang.org/x/net/http2/transport.go': [
  ('cc.henc.WriteField(hpack.HeaderField{Name: name, Value: value})', 'cc.henc.WriteField(hpack.HeaderField{Name: name, Value: value, Sensitive: name == "authorization" || name == "proxy-authorization"})')],

}
for name, replacements in patches.items():
 p=Path(name);text=p.read_text()
 for old,new in replacements:
  if new in text: continue
  if text.count(old)!=1: raise SystemExit('Unexpected dependency source: '+name)
  text=text.replace(old,new)
 p.write_text(text)
print('Dependency patches present.')
