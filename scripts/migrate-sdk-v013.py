#!/usr/bin/env python3
"""Migrate a bomly-sdk consumer to the v0.13 layout (plugin/ and httpkit/).

Usage: migrate-sdk-v013.py <repo root> [--skip <path substring>]...

Rewrites every *.go file (fixture source strings included, which is why this
is text-based rather than gofmt -r): identifiers move from the root package
to `sdkplugin` (github.com/bomly-dev/bomly-sdk/plugin) and `httpkit`
(github.com/bomly-dev/bomly-sdk/httpkit); import blocks gain the new paths
and drop a root import that became unused. Run gofmt afterwards.
"""
import pathlib, re, sys

ROOT = 'github.com/bomly-dev/bomly-sdk'
ALIASES = r'(?:sdk|model|plugschema|schemav1)'
PLUGIN_NAMES = ['ServeDetector', 'ServeMatcher', 'ServeAuditor', 'ServeAnalyzer', 'ServeModule',
                'ServedDetector', 'ServedMatcher', 'ServedAuditor', 'ServedAnalyzer',
                'DetectorInstaller', 'ServedDetectorRemediationProvider',
                'Client', 'HandshakeConfig', 'ClientPluginMap', 'EnvVerbosity',
                'DecodePluginConfigFromEnv', 'RawPluginConfigFromEnv', 'EnvPluginConfigFile', 'EnvPluginID']
HTTP_RENAMES = [  # longest first so prefixes never match early
    ('HTTPClientConfigFromEnv', 'ClientConfigFromEnv'),
    ('NewHTTPClientProviderFromEnv', 'NewClientProviderFromEnv'),
    ('NewHTTPClientProvider', 'NewClientProvider'),
    ('HTTPClientProvider', 'ClientProvider'),
    ('HTTPClientConfig', 'ClientConfig'),
    ('NewHTTPClient', 'NewClient'),
]
RULES = [(re.compile(r'\b' + ALIASES + r'\.(' + '|'.join(PLUGIN_NAMES) + r')\b'), r'sdkplugin.\1')]
RULES += [(re.compile(r'\b' + ALIASES + r'\.' + old + r'\b'), 'httpkit.' + new) for old, new in HTTP_RENAMES]
RULES.append((re.compile(r'\b' + ALIASES + r'\.(EnvHTTP[A-Za-z]+)\b'), r'httpkit.\1'))

IMPORT_BLOCK = re.compile(r'^import \((.*?)^\)', re.S | re.M)

def fix_imports(src):
    """Add sdkplugin/httpkit imports next to each root import whose block's code uses them; drop unused root imports."""
    def one(m):
        block = m.group(1)
        body_after = src[m.end():]
        lines = block.split('\n')
        out = []
        for line in lines:
            s = line.strip()
            if s.endswith('"' + ROOT + '"'):
                alias = s.split()[0] if len(s.split()) == 2 else 'sdk'
                # find the code this block governs: up to the next `package ` line (fixture strings) or EOF
                scope = re.split(r'^package ', body_after, maxsplit=1, flags=re.M)[0]
                keep = re.search(r'\b' + re.escape(alias) + r'\.', scope) is not None
                if keep:
                    out.append(line)
                if re.search(r'\bsdkplugin\.', scope) and 'bomly-sdk/plugin"' not in block:
                    out.append('\tsdkplugin "' + ROOT + '/plugin"')
                if re.search(r'\bhttpkit\.', scope) and 'bomly-sdk/httpkit"' not in block:
                    out.append('\t"' + ROOT + '/httpkit"')
            else:
                out.append(line)
        return 'import (' + '\n'.join(out) + ')'
    # process blocks from the last to the first so `src[m.end():]` stays valid
    pos = [m for m in IMPORT_BLOCK.finditer(src)]
    for m in reversed(pos):
        src = src[:m.start()] + one(m) + src[m.end():]
    # single-line root import
    m = re.search(r'^import (\w+ )?"' + re.escape(ROOT) + r'"\n', src, re.M)
    if m:
        alias = (m.group(1) or 'sdk ').strip()
        extra = []
        if re.search(r'\bsdkplugin\.', src): extra.append('\tsdkplugin "' + ROOT + '/plugin"')
        if re.search(r'\bhttpkit\.', src): extra.append('\t"' + ROOT + '/httpkit"')
        keep = re.search(r'\b' + re.escape(alias) + r'\.', src[m.end():]) is not None
        if extra or not keep:
            lines = ([ '\t' + m.group(0)[len('import '):].rstrip('\n') ] if keep else []) + extra
            src = src[:m.start()] + ('import (\n' + '\n'.join(lines) + '\n)\n' if lines else '') + src[m.end():]
    return src

# A fixture whose const name says "legacy" is compiled against the oldest
# supported SDK on purpose (bomly-cli test/smoke); its body is left as it is.
PROTECTED = re.compile(r'(const \w*[Ll]egacy\w* = `)(.*?)(`)', re.S)

def rewrite(text):
    for pat, rep in RULES:
        text = pat.sub(rep, text)
    return text

def migrate(path):
    src = path.read_text()
    pieces, last = [], 0
    for m in PROTECTED.finditer(src):
        pieces.append(rewrite(src[last:m.start()]))
        pieces.append(m.group(0))
        last = m.end()
    pieces.append(rewrite(src[last:]))
    new = ''.join(pieces)
    if new == src:
        return False
    new = fix_imports(new)
    path.write_text(new)
    return True

def main():
    args = sys.argv[1:]
    skips = []
    while '--skip' in args:
        i = args.index('--skip'); skips.append(args[i + 1]); del args[i:i + 2]
    root = pathlib.Path(args[0])
    changed = []
    for p in root.rglob('*.go'):
        if any(s in str(p) for s in skips):
            continue
        if migrate(p):
            changed.append(p.relative_to(root))
    for c in sorted(changed):
        print(c)
    print(f'{len(changed)} files rewritten', file=sys.stderr)

if __name__ == '__main__':
    main()
