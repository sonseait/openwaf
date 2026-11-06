// Node >=22.18 type stripping; no additional frontend test dependency.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {appendLog,appendMetric,trimMetrics} from '../../frontend/src/telemetry-state.ts';
import {investigationParams,investigationLink,defaultRange} from '../../frontend/src/investigation-state.ts';

test('investigation URLs preserve safe metadata without captured content',()=>{
 const input=new URLSearchParams({route_id:'checkout',config_version:'12',action:'blocked',rule_id:'941101',start_ms:'1000',end_ms:'2000',authorization:'private',body:'private',query:'private',path:'/api?token=private'});
 const safe=investigationParams(input);
 assert.equal(safe.get('route_id'),'checkout');assert.equal(safe.get('config_version'),'12');
 assert(!safe.has('body'));assert(!safe.has('authorization'));assert(!safe.has('query'));assert(!safe.has('path'));
 const url=investigationLink('/routes/checkout',safe,{version:12});
 assert(url.includes('version=12'));assert(!url.includes('private'));
 assert.deepEqual(defaultRange(safe),{start:1000,end:2000});
});

test('long-tab and repeated reconnect input stays bounded without duplicating breakdowns',()=>{
 let logs=[],metrics=[];const now=Date.now();
 for(let i=0;i<12000;i++){
  logs=appendLog(logs,{epoch:'live',sequence:i});
  metrics=appendMetric(metrics,{epoch:'live',sequence:i,observed_at_unix_ms:now-120000+i*10,dimensions:{countries:[{label:'VN',received:i}]}});
 }
 assert.equal(logs.length,1000);assert.equal(metrics.length,900);
 assert(metrics.every(m=>!m.dimensions));
 assert.equal(appendLog(logs,logs.at(-1)),logs);
 assert.equal(appendMetric(metrics,metrics.at(-1)),metrics);
 const restarted=appendMetric(metrics,{epoch:'restart',sequence:1,observed_at_unix_ms:now});assert.equal(restarted.length,1);
 assert.equal(trimMetrics(metrics,now+16*60000).length,0);
});
