from pathlib import Path
import argparse
import re

ROOT = Path(__file__).resolve().parents[1]
GROUPS = {
    'static/css/shell-base.bundle.css': ('base.css', 'sidebar-compact.css'),
    'static/css/shell-design.bundle.css': ('modern.css', 'workspace.css', 'design-system.css', 'design-modes.css', 'refinements.css'),
    'static/css/shell-controls.bundle.css': ('workspace-refinements.css', 'control-polish.css'),
    'reseller_portal/static/css/reseller-layout.bundle.css': ('reseller-layout.css', 'reseller-refinements.css', 'reseller-visual.css'),
}


def render(target, files):
    chunks = []
    for name in files:
        source = (target.parent / name).read_text(encoding='utf-8')
        if re.search(r'@(?:charset|import|namespace)\b', source, re.I):
            raise ValueError(f'{name} contains a stylesheet-level directive; review before bundling')
        chunks.append(source.rstrip() + '\n')
    return '\n'.join(chunks).encode('utf-8')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    stale = []
    for path, files in GROUPS.items():
        target = ROOT / path
        content = render(target, files)
        if args.check:
            if not target.exists() or target.read_bytes() != content:
                stale.append(path)
        else:
            target.write_bytes(content)
    if stale:
        parser.error('Regenerate stale bundles: ' + ', '.join(stale))


if __name__ == '__main__':
    main()
