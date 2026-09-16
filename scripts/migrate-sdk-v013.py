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
# Aliases a consumer might already use for the root package when a document
# declares no root import of its own (a dot-import, or a file we cannot parse).
FALLBACK_ALIASES = ['sdk', 'model', 'plugschema', 'schemav1']
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

def rules_for(aliases):
    """The rewrite rules for documents that refer to the root package by any of `aliases`."""
    alt = r'(?:' + '|'.join(re.escape(a) for a in aliases) + r')'
    rules = [(re.compile(r'\b' + alt + r'\.(' + '|'.join(PLUGIN_NAMES) + r')\b'), r'sdkplugin.\1')]
    rules += [(re.compile(r'\b' + alt + r'\.' + old + r'\b'), 'httpkit.' + new) for old, new in HTTP_RENAMES]
    rules.append((re.compile(r'\b' + alt + r'\.(EnvHTTP[A-Za-z]+)\b'), r'httpkit.\1'))
    return rules

IMPORT_BLOCK = re.compile(r'^import \((.*?)^\)', re.S | re.M)
IMPORT_ONE = re.compile(r'^import (\w+ )?"' + re.escape(ROOT) + r'"\n', re.M)
# A Go source embedded as a raw string (a plugin fixture a test compiles) is
# its own document: its import block governs its body, not the file around it.
# A fixture is often several raw strings joined around a value (`..." + id + "...`),
# so it ends at the first backtick that opens a line, not the first backtick.
FIXTURE = re.compile(r'`package \w+\n.*?\n`', re.S)
# A fixture whose const name says "legacy" is compiled against the oldest
# supported SDK on purpose (bomly-cli test/smoke); its body is left as it is.
PROTECTED = re.compile(r'const \w*[Ll]egacy\w* = `.*?`', re.S)

ROOT_IMPORT = re.compile(r'^\s*(?:import\s+)?(\w+\s+)?"' + re.escape(ROOT) + r'"\s*$', re.M)

def root_alias(doc):
    """The selector this document uses for the root package: its import alias, or the package name."""
    m = ROOT_IMPORT.search(doc)
    if not m:
        return None
    return (m.group(1) or 'sdk').strip()

def rewrite(doc):
    alias = root_alias(doc)
    for pat, rep in rules_for([alias] if alias else FALLBACK_ALIASES):
        doc = pat.sub(rep, doc)
    return doc

def wanted_imports(doc, block):
    extra = []
    if re.search(r'\bsdkplugin\.', doc) and 'bomly-sdk/plugin"' not in block:
        extra.append('\tsdkplugin "' + ROOT + '/plugin"')
    if re.search(r'\bhttpkit\.', doc) and 'bomly-sdk/httpkit"' not in block:
        extra.append('\t"' + ROOT + '/httpkit"')
    return extra

def fix_imports(doc):
    """One Go document: add the imports its body now needs next to the root import; drop the root import if unused."""
    m = IMPORT_BLOCK.search(doc)
    if m:
        block = m.group(1)
        out = []
        for line in block.split('\n'):
            s = line.strip()
            if s.endswith('"' + ROOT + '"'):
                alias = s.split()[0] if len(s.split()) == 2 else 'sdk'
                if re.search(r'\b' + re.escape(alias) + r'\.', doc[m.end():]):
                    out.append(line)
                out.extend(wanted_imports(doc[m.end():], block))
            else:
                out.append(line)
        return doc[:m.start()] + 'import (' + '\n'.join(out) + ')' + doc[m.end():]
    m = IMPORT_ONE.search(doc)
    if m:
        alias = (m.group(1) or 'sdk ').strip()
        body = doc[m.end():]
        lines = ['\t' + m.group(0)[len('import '):].rstrip('\n')] if re.search(r'\b' + re.escape(alias) + r'\.', body) else []
        lines += wanted_imports(body, '')
        return doc[:m.start()] + ('import (\n' + '\n'.join(lines) + '\n)\n' if lines else '') + body
    return doc

def migrate(path):
    src = path.read_text()
    protected = PROTECTED.findall(src)
    # each embedded fixture is rewritten and import-fixed on its own, then the
    # file around them with the fixtures masked out
    fixtures = []
    def stash(m):
        fixtures.append(fix_imports(rewrite(m.group(0))))
        return '\x00FIXTURE%d\x00' % (len(fixtures) - 1)
    outer = FIXTURE.sub(stash, src)
    outer = fix_imports(rewrite(outer))
    # a callable replacement is inserted verbatim, so no escaping of the fixture text
    new = re.sub(r'\x00FIXTURE(\d+)\x00', lambda m: fixtures[int(m.group(1))], outer)
    # restore every protected fixture verbatim, matched by its const name
    by_name = {o[:o.index('=')]: o for o in protected}
    new = PROTECTED.sub(lambda m: by_name.get(m.group(0)[:m.group(0).index('=')], m.group(0)), new)
    if new == src:
        return False
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
