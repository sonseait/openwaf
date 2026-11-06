// Offline UI contract checks against built assets, with intercepted API fixtures.
// No listening socket, live database, credentials or external service is used.
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');const path=require('node:path');
const {chromium}=require(process.env.OPENWAF_PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const browser=await chromium.launch({headless:true,channel:'chrome'});
 try {
  const context=await browser.newContext();const page=await context.newPage();const errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  const root=path.resolve(__dirname,'../../frontend/dist');let polls=0;let simulated;
  const evidence={samples:15,upstream_404:15,gateway_404:0,denials:0,errors:0,capacity_errors:0,distinct_paths:15,paths_saturated:false,request_ids:['a'.repeat(32)]};
  let incident={id:1,revision:1,detector:'endpoint_probing',scope:'app:opaque',route_id:'app',config_version:7,state:'open',quality:'observed',first_ms:1000,last_ms:2000,window_start_ms:0,window_end_ms:10000,evidence};
  await page.route('**/*',async route=>{
   const u=new URL(route.request().url());const json=value=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
   if(u.pathname==='/api/v1/auth/session')return json({username:'fixture',csrf_token:'fixture-csrf',expires_at:'2099-01-01T00:00:00Z'});
   if(u.pathname==='/api/v1/security/detectors'){polls++;return json({mode:'observe_only',quality:'gap',dropped:1,pending:1,persistence_errors:1,keys:2,max_keys:1024,observed_at_unix_ms:2000,truncated:false,windows:[{detector:'endpoint_probing',route:'app',scope:'opaque',quality:'gap',firing:true,evidence}]});}
   if(u.pathname==='/api/v1/security/incidents')return json({items:[incident],total:1,truncated:false,retention_days:7});
   if(u.pathname==='/api/v1/security/incidents/1'){incident={...incident,state:JSON.parse(route.request().postData()).state,revision:incident.revision+1};return route.fulfill({status:204});}
   if(u.pathname==='/api/v1/config')return json({active_version:7,draft_revision:8,active:{routes:[],upstreams:[]},draft:{routes:[],upstreams:[]}});
   if(u.pathname==='/api/v1/security/simulate'){simulated=JSON.parse(route.request().postData());return json({config_version:7,live_state_mutated:false,outputs:{active:{route_id:'app',crs:{status:'off'},not_simulated:['forward_auth','identity_quotas']}}});}
   if(u.pathname.startsWith('/api/'))return route.fulfill({status:404,contentType:'application/json',body:'{}'});
   let file=u.pathname.startsWith('/assets/')?path.join(root,u.pathname):path.join(root,'index.html');
   const contentType=file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html';
   return route.fulfill({status:200,contentType,body:await fs.readFile(file)});
  });
  await page.goto('http://openwaf.fixture/abuse');
  await page.getByRole('heading',{name:'Abuse observations & incidents',exact:true}).waitFor();
  await page.getByText('Recent events (0)',{exact:true}).click();
  await page.getByText('Ordered by request start; concurrent events do not imply causality. Path values are process-local hashes.',{exact:true}).waitFor({state:'visible'});
  await page.getByText('Data gap or persistence degradation.',{exact:false}).waitFor();
  await page.getByRole('button',{name:'endpoint_probing #1',exact:true}).click();
  await page.getByRole('button',{name:'Acknowledge',exact:true}).click();
  await page.getByRole('button',{name:'Reopen',exact:true}).waitFor();
  await page.getByRole('button',{name:'Pause observations',exact:true}).click();let before=polls;
  await page.waitForTimeout(5500);assert.equal(polls,before,'pause stops polling');
  await page.getByRole('link',{name:'Security simulator',exact:true}).click();
  await page.getByRole('heading',{name:'Security simulator',exact:true}).waitFor();
  await page.getByLabel('Hostname',{exact:true}).fill('app.test');
  await page.getByRole('button',{name:'Run isolated simulation',exact:true}).click();
  await page.getByRole('heading',{name:'Simulation outputs',exact:true}).waitFor();
  assert.equal(simulated.expected_active_version,7);assert.equal(simulated.expected_draft_revision,8);assert.equal(simulated.request.method,'GET');
  await page.getByRole('button',{name:'Clear payload and result',exact:true}).click();
  await page.getByRole('heading',{name:'Simulation outputs',exact:true}).waitFor({state:'detached'});
  assert.deepEqual(errors,[]);await context.close();
  console.log('PASS offline Chromium fixtures: gap/error rendering, incident drilldown/ACK, polling pause, simulator versioned request and clear');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
