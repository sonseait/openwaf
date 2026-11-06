// Invoked by endpoint_polling.py against a real isolated gateway/PostgreSQL.
const assert = require('node:assert/strict');
const {chromium} = require(process.env.OPENWAF_PLAYWRIGHT_MODULE || 'playwright');
(async () => {
 const browser=await chromium.launch({headless:true,channel:'chrome'});
 try {
  const base=process.env.OPENWAF_BROWSER_BASE;
  const context=await browser.newContext({extraHTTPHeaders:{Cookie:process.env.OPENWAF_BROWSER_COOKIE}});
  const page=await context.newPage();const errors=[],requests=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('request',r=>requests.push(new URL(r.url())));
  const configs=()=>requests.filter(u=>u.pathname==='/api/v1/config').length;
  const polls=()=>requests.filter(u=>u.pathname==='/api/v1/operations/endpoints');
  await page.goto(`${base}/uptime`);
  await page.getByRole('heading',{name:'Uptime',exact:true}).waitFor();
  await page.waitForTimeout(10500);
  assert(polls().length>=3,'uptime polls every five seconds');
  assert(polls().every(u=>u.searchParams.get('summary')==='true'));
  assert.equal(configs(),0,'uptime health must not fetch config');
  await page.locator('a[href="/discovery"]').first().click();
  await page.getByRole('heading',{name:'Endpoint diagnostics & maintenance',exact:true}).waitFor();
  await page.waitForTimeout(5500);
  assert.equal(configs(),0,'discovery health must not fetch config');
  await page.getByRole('button',{name:'Pause endpoint refresh',exact:true}).click();
  const pausedCount=polls().length;
  await page.waitForTimeout(5500);
  assert.equal(polls().length,pausedCount,'pause must stop endpoint polling');
  const initialConfig=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/config'&&r.status()===200);
  await page.locator('a[href="/playground"]').first().click();
  await initialConfig;
  assert.equal(configs(),1);
  await page.locator('a[href="/service-map"]').first().click();
  await page.waitForTimeout(500);
  assert.equal(configs(),1,'fresh config reused across navigation');
  // Apply using real session/CSRF outside page traffic so UI request counts stay exact.
  const mutationHeaders={'X-CSRF-Token':process.env.OPENWAF_BROWSER_CSRF,Origin:process.env.OPENWAF_BROWSER_ORIGIN};
  const current=await (await context.request.get(`${base}/api/v1/config`)).json();
  const applied=await context.request.post(`${base}/api/v1/config/apply`,{headers:mutationHeaders,data:{expected_active_version:current.active_version,expected_draft_revision:current.draft_revision}});
  assert.equal(applied.status(),200);
  const version=(await applied.json()).active_version;
  const observed=page.waitForResponse(async r=>new URL(r.url()).pathname==='/api/v1/operations/endpoints'&&r.status()===200&&(await r.json()).config_version===version);
  await page.locator('a[href="/discovery"]').first().click();
  await observed;
  await page.waitForTimeout(200);
  assert.equal(configs(),1,'version change invalidates inactive config without background full fetch');
  const refreshed=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/v1/config'&&r.status()===200);
  await page.locator('a[href="/playground"]').first().click();
  await refreshed;
  assert.equal(configs(),2,'changed version revalidated on next config consumer');
  assert.deepEqual(errors,[]);
  await context.close();
  console.log('PASS Chromium: Uptime/Discovery summary polling with zero config reads, pause, navigation cache and apply/version invalidation');
 } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
