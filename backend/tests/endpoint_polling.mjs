// Node >=22.18; uses the installed frontend dependency, no new test library.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createRequire} from 'node:module';
import {currentEndpointHealth} from '../../frontend/src/uptime-state.ts';
import {configCacheOptions,observeConfigVersion} from '../../frontend/src/config-cache.ts';
const require=createRequire(new URL('../../frontend/package.json',import.meta.url));
const {QueryClient,QueryObserver}=require('@tanstack/react-query');

test('endpoint health follows identity through reordering and expires on pause/error/TTL',()=>{
 const a={key:'pool-a',upstream_id:'a',address:'backend:8080',protocol:'http',health:{available:true,reason:'healthy',phase:'healthy',checked_at_ms:1000,valid_for_ms:2000}};
 const b={...a,key:'pool-b',upstream_id:'b',health:{...a.health,available:false,reason:'connection_failed'}};
 const page={observed_at_unix_ms:1000,config_version:7,endpoints:[b,a],operations:[]};
 assert.equal(currentEndpointHealth(page.endpoints[0],page,1500,false).available,false);
 assert.equal(currentEndpointHealth(page.endpoints[1],page,1500,false).available,true);
 assert.equal(currentEndpointHealth(a,page,3000,false),undefined);
 assert.equal(currentEndpointHealth(a,page,1500,true),undefined);
 assert.equal(currentEndpointHealth({...a,health:null},page,1500,false),undefined);
 for(const missing of ['observed_at_unix_ms','config_version']) assert.equal(currentEndpointHealth(a,{...page,[missing]:undefined},1500,false),undefined);
 for(const missing of ['checked_at_ms','valid_for_ms']) assert.equal(currentEndpointHealth({...a,health:{...a.health,[missing]:undefined}},page,1500,false),undefined);
 assert.equal(currentEndpointHealth({...a,health:{...a.health,phase:'pending'}},page,1500,false),undefined);
});

function cache(){
 const client=new QueryClient({defaultOptions:{queries:{retry:false,staleTime:0,gcTime:0}}});
 client.setQueryDefaults(['config'],configCacheOptions);
 return client;
}
test('config reuses fresh data across unmount, revalidates stale data and respects mutation invalidation',async()=>{
 const client=cache();let reads=0;
 const options={queryKey:['config'],queryFn:async()=>({active_version:++reads})};
 try{
  const observer=new QueryObserver(client,options);const unsubscribe=observer.subscribe(()=>{});
  await client.fetchQuery(options);unsubscribe();
  assert.equal(client.getQueryData(['config']).active_version,1);
  await client.fetchQuery(options);assert.equal(reads,1);
  await client.invalidateQueries({queryKey:['config']});
  await client.fetchQuery(options);assert.equal(reads,2);
  client.setQueryData(['config'],{active_version:2},{updatedAt:Date.now()-30001});
  await client.fetchQuery(options);assert.equal(reads,3);
  assert.equal(client.getQueryDefaults(['config']).gcTime,60000);
  assert.deepEqual(client.getQueryDefaults(['recorded-body','private']),{});
 }finally{client.clear();}
});
test('observed active version refetches mounted config once and only invalidates inactive cache',async()=>{
 const client=cache();let reads=0;
 const options={queryKey:['config'],queryFn:async()=>({active_version:++reads})};
 try{
  await client.fetchQuery(options);
  await observeConfigVersion(client,1);assert.equal(reads,1);
  const observer=new QueryObserver(client,options);const unsubscribe=observer.subscribe(()=>{});
  await observeConfigVersion(client,2);assert.equal(reads,2);
  await observeConfigVersion(client,2);assert.equal(reads,2);
  unsubscribe();
  await observeConfigVersion(client,3);assert.equal(reads,2);
  assert.equal(client.getQueryState(['config']).isInvalidated,true);
  await observeConfigVersion(client,3);assert.equal(reads,2);
  await client.fetchQuery(options);assert.equal(reads,3);
  client.removeQueries({queryKey:['config']});
  await observeConfigVersion(client,4);assert.equal(reads,3);
 }finally{client.clear();}
});
