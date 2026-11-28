"""Reapply reviewed, minimal dependency changes after go mod vendor."""
from pathlib import Path

file_patches = {
    'golang.org/x/net/http2/http2.go': [
        (
            'disableExtendedConnectProtocol = true',
            '// tunnelX only: all servers in this binary implement Extended CONNECT.\n\tdisableExtendedConnectProtocol = false',
        ),
        (
            'const bufWriterPoolBufferSize = 4 << 10',
            'const bufWriterPoolBufferSize = 64 << 10',
        ),
    ],
    'golang.org/x/net/http2/flow.go': [
        (
            'const inflowMinRefresh = 4 << 10',
            'const inflowMinRefresh = 64 << 10',
        ),
    ],
    'golang.org/x/net/http2/server.go': [
        (
            'handlerChunkWriteSize = 4 << 10',
            'handlerChunkWriteSize = 64 << 10',
        ),
    ],
    'golang.org/x/net/http2/transport.go': [
        (
            'cc.henc.WriteField(hpack.HeaderField{Name: name, Value: value})',
            'cc.henc.WriteField(hpack.HeaderField{Name: name, Value: value, Sensitive: name == "authorization" || name == "proxy-authorization"})',
        ),
        (
            'transportDefaultStreamFlow = 4 << 20',
            'transportDefaultStreamFlow = 16 << 20',
        ),
        (
            'cc.bw = bufio.NewWriter(stickyErrWriter{\n\t\tconn:    c,\n\t\ttimeout: conf.WriteByteTimeout,\n\t\terr:     &cc.werr,\n\t})\n\tcc.br = bufio.NewReader(c)',
            'cc.bw = bufio.NewWriterSize(stickyErrWriter{\n\t\tconn:    c,\n\t\ttimeout: conf.WriteByteTimeout,\n\t\terr:     &cc.werr,\n\t}, 64<<10)\n\tcc.br = bufio.NewReaderSize(c, 64<<10)',
        ),
    ],
    'github.com/xtls/reality/tls.go': [
        (
            'if peerPub2 == nil {\n\t\t\t\tbreak // reject outdated/strange Client Hello that doesn\'t have X25519MLKEM768 before optional X25519\n\t\t\t}',
            '// txlite: allow both X25519MLKEM768 (Chrome 131+) and standard X25519 (Shadowrocket iOS/Safari) REALITY clients.',
        ),
    ],
}

for root in ('vendor', 'gui/vendor'):
    for rel, replacements in file_patches.items():
        p = Path(root) / rel
        if not p.exists():
            continue
        text = p.read_text(encoding='utf-8')
        for old, new in replacements:
            if new in text:
                continue
            if text.count(old) != 1:
                raise SystemExit(f'Unexpected dependency source: {p} ({old!r})')
            text = text.replace(old, new)
        p.write_text(text, encoding='utf-8', newline='\n')
print('Dependency patches present.')

