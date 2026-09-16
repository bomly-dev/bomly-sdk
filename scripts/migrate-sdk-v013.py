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
IMPORT_ONE = re.compile(r'^import (\w+ )?"' + re.escape(ROOT) + r'"[ \t]*(//[^\n]*)?\n', re.M)
# A Go source embedded as a raw string (a plugin fixture a test compiles) is
# its own document: its import block governs its body, not the file around it.
# A fixture is often several raw strings joined around a value (`..." + id + "...`),
# so it ends at the first backtick that opens a line, not the first backtick.
FIXTURE = re.compile(r'`package \w+\n.*?\n`', re.S)
# A fixture whose const name says "legacy" is compiled against the oldest
# supported SDK on purpose (bomly-cli test/smoke); it is masked before any
# rewrite and put back verbatim, concatenated segments included.
PROTECTED = re.compile(r'const \w*[Ll]egacy\w* = `.*?\n`', re.S)
# An import line naming the root package, with or without an alias, allowing
# a trailing comment.
ROOT_IMPORT_LINE = re.compile(r'^[ \t]*(\w+[ \t]+)?"' + re.escape(ROOT) + r'"[ \t]*(//[^\n]*)?$')
ROOT_IMPORT = re.compile(r'^[ \t]*(?:import[ \t]+)?(\w+[ \t]+)?"' + re.escape(ROOT) + r'"[ \t]*(//[^\n]*)?$', re.M)
# Comments and string literals are not code: a selector mentioned in a doc
# comment must not decide which imports a file needs.
NON_CODE = re.compile(r'`[^`]*`|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|/\*.*?\*/|//[^\n]*', re.S)

def code_only(text):
    """`text` with every comment and string literal blanked, for usage checks."""
    return NON_CODE.sub(lambda m: ' ' * len(m.group(0)), text)

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

def uses(code, alias):
    return re.search(r'\b' + re.escape(alias) + r'\.', code) is not None

def wanted_imports(code, block):
    extra = []
    if uses(code, 'sdkplugin') and 'bomly-sdk/plugin"' not in block:
        extra.append('\tsdkplugin "' + ROOT + '/plugin"')
    if uses(code, 'httpkit') and 'bomly-sdk/httpkit"' not in block:
        extra.append('\t"' + ROOT + '/httpkit"')
    return extra

def fix_imports(doc):
    """One Go document: add the imports its code now needs next to the root import; drop the root import if unused."""
    m = IMPORT_BLOCK.search(doc)
    if m:
        block = m.group(1)
        code = code_only(doc[m.end():])
        out = []
        for line in block.split('\n'):
            r = ROOT_IMPORT_LINE.match(line)
            if r:
                if uses(code, (r.group(1) or 'sdk').strip()):
                    out.append(line)
                out.extend(wanted_imports(code, block))
            else:
                out.append(line)
        return doc[:m.start()] + 'import (' + '\n'.join(out) + ')' + doc[m.end():]
    m = IMPORT_ONE.search(doc)
    if m:
        alias = (m.group(1) or 'sdk ').strip()
        body = doc[m.end():]
        code = code_only(body)
        lines = ['\t' + m.group(0)[len('import '):].rstrip('\n')] if uses(code, alias) else []
        lines += wanted_imports(code, '')
        return doc[:m.start()] + ('import (\n' + '\n'.join(lines) + '\n)\n' if lines else '') + body
    return doc

def migrate(path):
    src = path.read_text()
    # legacy fixtures are masked before anything is rewritten and put back verbatim
    protected = []
    def keep(m):
        protected.append(m.group(0))
        return '\x00PROTECTED%d\x00' % (len(protected) - 1)
    masked = PROTECTED.sub(keep, src)
    # each embedded fixture is rewritten and import-fixed on its own, then the
    # file around them with the fixtures masked out
    fixtures = []
    def stash(m):
        fixtures.append(fix_imports(rewrite(m.group(0))))
        return '\x00FIXTURE%d\x00' % (len(fixtures) - 1)
    outer = FIXTURE.sub(stash, masked)
    outer = fix_imports(rewrite(outer))
    # callable replacements are inserted verbatim, so no escaping of the stored text
    new = re.sub(r'\x00FIXTURE(\d+)\x00', lambda m: fixtures[int(m.group(1))], outer)
    new = re.sub(r'\x00PROTECTED(\d+)\x00', lambda m: protected[int(m.group(1))], new)
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
