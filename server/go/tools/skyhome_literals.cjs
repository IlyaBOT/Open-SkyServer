// Source inspection only: Acorn decodes string tokens without executing JS.
// The bundled Node Acorn is exposed explicitly by --expose-internals.
const fs = require('node:fs');
const acorn = require('internal/deps/acorn/acorn/dist/acorn');
const source = fs.readFileSync(process.argv[2], 'utf8');
const literals = [];
let error = null;
try {
  const tokenizer = acorn.tokenizer(source, { ecmaVersion: 'latest', allowHashBang: true });
  for (let token = tokenizer.getToken(); token.type.label !== 'eof'; token = tokenizer.getToken()) {
    if (token.type.label === 'string' && /<(?:div|span|p|a|ul|li|h[1-6]|img|table|section)\b/i.test(token.value)) {
      literals.push({ start: token.start, end: token.end, value: token.value });
    }
  }
} catch (e) {
  error = String(e.message);
}
process.stdout.write(JSON.stringify({ parser: `Acorn ${acorn.version}`, literals, error }));
