const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
let ts;
try { ts = require('typescript'); }
catch (_) { ts = require(path.join(execFileSync('npm', ['root', '-g'], {encoding:'utf8'}).trim(), 'typescript')); }
const root = path.resolve(__dirname, '..');
const skipped = new Set(['vendor', 'node_modules', 'venv', '.venv', '.git', 'instance', 'backups', '__pycache__', '.pytest_cache']);
function walk(dir) {
  return fs.readdirSync(dir, {withFileTypes:true}).flatMap(e => {
    const file = path.join(dir, e.name);
    return e.isDirectory() && !skipped.has(e.name) ? walk(file) : e.isFile() ? [file] : [];
  });
}
const files = walk(root);
const source = new Map();
const providers = {
  'static/js/dashboard-modern.js': ['Chart'],
  'static/js/index.js': ['Chart', 'toast'],
  'static/js/theme.js': ['Chart'],
  'static/js/settings.js': ['confirmDialog', 'QRCode', 'toast'],
  'static/js/subscriptions.js': ['csrfHeaders'],
  'static/js/userlink.js': ['QRCode'],
  'reseller_portal/static/js/reseller-workspace.js': ['Chart'],
  'static/js/subscription_public.js': ['DATA', 'PREVIEW_MODE', 'TOKEN', 'CONFIG_URL', 'API_URL', 'PUBLIC_SETTINGS']
};
const relative = file => path.relative(root, file).split(path.sep).join('/');
for (const file of files) {
  if (file.endsWith('.js') && !file.endsWith('.min.js')) source.set(file, fs.readFileSync(file, 'utf8'));
  if (file.endsWith('.html')) {
    let i = 0;
    for (const match of fs.readFileSync(file, 'utf8').matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
      if (/\bsrc\s*=|application\/(?:ld\+)?json/i.test(match[1])) continue;
      const body = match[2].replace(/{{[\s\S]*?}}/g, '0').replace(/{[%#][\s\S]*?[%#]}/g, '');
      if (body.trim()) source.set(`${file}.inline-${++i}.js`, body);
    }
  }
}
const opts = {allowJs:true, checkJs:true, noEmit:true, target:ts.ScriptTarget.ES2022,
  lib:['lib.es2022.d.ts','lib.dom.d.ts','lib.dom.iterable.d.ts'], types:[], skipLibCheck:true,
  moduleDetection:ts.ModuleDetectionKind.Force};
const host = ts.createCompilerHost(opts);
const original = host.getSourceFile.bind(host);
host.getSourceFile = (file, ...args) => source.has(file)
  ? ts.createSourceFile(file, source.get(file), args[0], true, ts.ScriptKind.JS)
  : original(file, ...args);
const program = ts.createProgram([...source.keys()], opts, host);
const diagnostics = [];
const nameErrors = new Set([2304, 2552, 2580, 2663, 2448, 2454, 2300, 2393, 2451]);
for (const file of source.keys()) {
  const sf = program.getSourceFile(file);
  for (const d of program.getSemanticDiagnostics(sf)) {
    if (!nameErrors.has(d.code)) continue;
    const message = ts.flattenDiagnosticMessageText(d.messageText, ' ');
    const name = message.match(/Cannot find name '([^']+)'/)?.[1];
    if (name && providers[relative(file)]?.includes(name)) continue;
    const line = sf.getLineAndCharacterOfPosition(d.start).line + 1;
    diagnostics.push(`${relative(file)}:${line}: ${message}`);
  }
}
if (diagnostics.length) { console.error(diagnostics.join('\n')); process.exitCode = 1; }
else console.log(`JavaScript name resolution passed (${source.size} first-party scripts and inline template blocks).`);
