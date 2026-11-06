// Render the real diff component with historical and current API payloads.
// Uses existing frontend dependencies; no browser, DB or new test framework.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {createRequire} = require('node:module');
const {test, after} = require('node:test');
const frontend = path.resolve(__dirname, '../../frontend');
const dependencies = createRequire(path.join(frontend, 'package.json'));
const directory = fs.mkdtempSync(path.join(frontend, 'node_modules/.openwaf-diff-'));
after(() => fs.rmSync(directory, {recursive:true, force:true}));
const bundle = path.join(directory, 'shared.cjs');
dependencies('esbuild').buildSync({entryPoints:[path.join(frontend,'src/shared.tsx')],
 outfile:bundle,bundle:true,platform:'node',format:'cjs',packages:'external',jsx:'automatic'});
const {Difference} = require(bundle);
const React = dependencies('react');
const {renderToStaticMarkup} = dependencies('react-dom/server');
const {MantineProvider} = dependencies('@mantine/core');
const render = diff => renderToStaticMarkup(React.createElement(MantineProvider, null,
 React.createElement(Difference, {diff}))).replace(/<style\b[^>]*>[\s\S]*?<\/style>/g,'').replace(/<[^>]*>/g,'');

test('unrecorded bootstrap/legacy diffs render as unavailable, never unchanged', () => {
 for (const diff of [{},undefined,null, {routes:{}}, {routes:{added:null},upstreams:[]}]) {
  const html = render(diff);
  assert.match(html,/unavailable/i);
  assert.doesNotMatch(html,/unchanged|: none/);
 }
});

test('recorded changes and recorded empty lists retain their meaning', () => {
 const html = render({routes:{added:['checkout'],changed:[],removed:[]},
  upstreams:{added:[],changed:['payments'],removed:[]},trusted_proxies_changed:false,
  global_rules_changed:true,error_pages_changed:false});
 assert.match(html,/added: checkout/);
 assert.match(html,/changed: payments/);
 assert.match(html,/: none/);
 assert.match(html,/Global rules: changed/);
 assert.match(html,/Trusted proxies:.*unchanged/);
 assert.doesNotMatch(html,/unavailable/i);
 const partial = render({routes:{added:[],changed:[],removed:[]}});
 assert.match(partial,/unavailable/i);
 assert.match(partial,/: none/);
 assert.doesNotMatch(partial,/unchanged/);
 const malformed = render({routes:{added:[{}],changed:[],removed:[]}});
 assert.match(malformed,/added: unavailable/);
 assert.match(malformed,/changed: none/);
 assert.doesNotMatch(malformed,/\[object Object\]/);
});
