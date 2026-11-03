import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync(new URL('../tool/risk-navigator.html',import.meta.url),'utf8');
const code=source.slice(source.indexOf('function selectLatestByLine('),source.indexOf('function renderVersionRowsTable('));
const context=vm.createContext({parseMajorMinor:release=>{const [major,minor]=release.split('.');return {major,minor};}});
vm.runInContext(code,context);
test('OSERA rows survive collapse without joining below-threshold runs',()=>{
 const rows=[1,2,3].map(n=>({release:`1.2.${n}`,is_safe:true}));
 rows.push({release:'1.2.3.1-osera-9',osera:true,is_safe:null,notes:'published patch'});
 rows.push(...[4,5,6].map(n=>({release:`1.2.${n}`,is_safe:true})));
 const result=context.collapseVersionRows(rows);
 assert.equal(result.length,3);assert.equal(result[1].osera,true);assert.equal(result[1].is_safe,null);
 assert.equal(result[1].notes,'published patch');
});
test('latest filters retain separate OSERA standouts and latest upstream release',()=>{
 const rows=[{release:'1.2.3'},{release:'1.2.3.1-osera-9',osera:true},{release:'1.3.0'},{release:'1.3.0.1-osera-1',osera:true}];
 const result=context.selectLatestByLine(rows,'latest-major');
 assert.equal(result.length,3);assert.ok(result.some(r=>r.release==='1.3.0'));
 assert.equal(result.filter(r=>r.osera).length,2);
});
