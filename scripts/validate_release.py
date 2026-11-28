import argparse
import json
import builtins
import re
import symtable
import subprocess
import sys
from pathlib import Path

import tinycss2
import yaml
from jinja2 import Environment, nodes

ROOT = Path(__file__).resolve().parents[1]


def source_files(suffix):
    return sorted(p for p in ROOT.rglob('*'+suffix) if p.is_file() and not any(part in {'vendor','venv','.venv','.git','node_modules','instance','backups','__pycache__','.pytest_cache'} for part in p.relative_to(ROOT).parts))



def undefined_python_names(path):
    source = path.read_text(encoding='utf-8')
    table = symtable.symtable(source, str(path), 'exec')
    defined = set(dir(builtins)) | {'__name__', '__file__', '__package__', '__spec__',
                                   '__loader__', '__cached__', '__builtins__', '__annotations__'}
    defined.update(s.get_name() for s in table.get_symbols()
                   if s.is_assigned() or s.is_imported() or s.is_namespace())
    def visit(scope):
        for symbol in scope.get_symbols():
            if (symbol.is_global() and symbol.is_referenced() and not symbol.is_assigned()
                    and symbol.get_name() not in defined):
                yield f'{path.relative_to(ROOT)}:{scope.get_lineno()}: unresolved {symbol.get_name()} in {scope.get_name()}'
        for child in scope.get_children():
            yield from visit(child)
    return list(visit(table))


def validate_pyright_names():
    result = subprocess.run(
        ['pyright', '--outputjson', '--pythonversion', '3.10', *[str(p.relative_to(ROOT)) for p in source_files('.py')]],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr or 'Pyright analysis did not complete.')
    report = json.loads(result.stdout)
    diagnostics = report['generalDiagnostics']
    errors = [d for d in diagnostics if d.get('rule') in {
        'reportUndefinedVariable', 'reportUnboundVariable', 'reportPossiblyUnboundVariable',
    } or (d.get('severity') == 'error' and not d.get('rule'))]
    if errors:
        raise ValueError('\n'.join(f"{d['file']}:{d['range']['start']['line'] + 1}: {d['message']}" for d in errors))
    print('Pyright undefined and unbound variable analysis passed.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--js-names', action='store_true')
    parser.add_argument('--pyright-names', action='store_true')
    args = parser.parse_args()
    unresolved = []
    for path in source_files('.py'):
        compile(path.read_bytes(), str(path), 'exec')
        unresolved.extend(undefined_python_names(path))
    if unresolved:
        raise ValueError('\n'.join(unresolved))
    print('Python global name resolution passed.')
    if args.pyright_names:
        validate_pyright_names()
    for path in source_files('.html'):
        body=path.read_text(encoding='utf-8')
        template = Environment().parse(body)
        for ref in template.find_all((nodes.Extends, nodes.Include, nodes.Import, nodes.FromImport)):
            if isinstance(ref.template, nodes.Const) and isinstance(ref.template.value, str):
                if not any((ROOT / folder / ref.template.value).is_file()
                           for folder in ('templates', 'reseller_portal/templates', 'installer/templates')):
                    raise ValueError(f'Missing template {ref.template.value} in {path.relative_to(ROOT)}')
        for asset in re.findall(r"""(?:src|href)\s*=\s*['"](/static/[^'"?#{}\s]+)""", body):
            if not (ROOT / asset.lstrip('/')).is_file():
                raise ValueError(f'Missing static asset {asset} in {path.relative_to(ROOT)}')
        for asset in re.findall(r"""filename\s*=\s*['"]([^'"]+)['"]\s*(?=[,)])""", body):
            if not any((ROOT/folder/asset).is_file() for folder in ('static','reseller_portal/static','installer/static')):
                raise ValueError(f'Missing literal asset {asset} in {path.relative_to(ROOT)}')
    for path in source_files('.css'):
        for rule in tinycss2.parse_stylesheet(path.read_text(encoding='utf-8'),skip_whitespace=True,skip_comments=True):
            if rule.type=='error':
                raise ValueError(f'{path.relative_to(ROOT)}:{rule.source_line}: {rule.message}')
    for suffix,command in (('.js',['node','--check']),('.cjs',['node','--check']),('.sh',['bash','-n'])):
        for path in source_files(suffix):
            subprocess.run([*command,str(path)],check=True)
    for path in source_files('.yml')+source_files('.yaml'):
        yaml.safe_load(path.read_text(encoding='utf-8'))
    if args.js_names:
        subprocess.run(['node', str(ROOT / 'scripts/validate_js_names.cjs')], cwd=ROOT, check=True)
    for script in ('build_frontend_assets.py','build_application_spec.py'):
        subprocess.run([sys.executable,str(ROOT/'scripts'/script),'--check'],cwd=ROOT,check=True)
    for suffix in ('.py','.html','.css','.js','.cjs','.sh','.yml','.yaml'):
        print(f'{suffix}: {len(source_files(suffix))} files checked')
    print('Release source validation passed.')


if __name__=='__main__':
    main()
