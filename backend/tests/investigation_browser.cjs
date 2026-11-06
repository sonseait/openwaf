// Optional browser regression invoked by body_recording.py against its isolated
// gateway. Install Playwright outside the product dependency tree and set
// OPENWAF_PLAYWRIGHT_MODULE to that installation's entry point.
const assert = require('node:assert/strict');
const {chromium} = require(process.env.OPENWAF_PLAYWRIGHT_MODULE || 'playwright');
(async () => {
 const browser=await chromium.launch({headless:true,channel:"chrome"});
 try {
  const base=process.env.OPENWAF_BROWSER_BASE;
  const context=await browser.newContext({viewport:{width:1440,height:1000},extraHTTPHeaders:{Cookie:process.env.OPENWAF_BROWSER_COOKIE}});
  const page=await context.newPage();const errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  const params=new URLSearchParams({start_ms:process.env.OPENWAF_BROWSER_START,end_ms:String(Date.now()+1),route_id:'record'});
  await page.goto(`${base}/routes/record?${params}`);
  await page.getByRole('heading',{name:'Effective configuration',exact:true}).waitFor();
  await page.getByLabel('Configuration snapshot').selectOption('draft');
  await page.getByText(/saved_draft · version draft/).waitFor();
  await page.getByLabel('Configuration snapshot').selectOption('active');
  await page.getByRole('link',{name:'Investigate requests',exact:true}).click();
  await page.getByRole('heading',{name:'Request investigation',exact:true}).waitFor();
  assert.equal(new URL(page.url()).searchParams.get('route_id'),'record');
  assert.equal(await page.getByLabel('Exact route ID',{exact:true}).inputValue(),'record');
  await page.getByRole('link',{name:'Statistics for this selection',exact:true}).click();
  await page.getByRole('heading',{name:'Operational views',exact:true}).waitFor();
  await page.getByRole('tab',{name:'Protection',exact:true}).click();
  await page.getByText(/Would-block is a primary WAF result/).waitFor();
  await page.getByRole('tab',{name:'Investigation',exact:true}).click();
  await page.getByRole('heading',{name:'Top routes',exact:true}).waitFor();
  await page.getByRole('tab',{name:'Capacity',exact:true}).click();
  await page.getByRole('link',{name:'Process RAM / FD / dependency observations',exact:true}).waitFor();
  await page.goBack(); // The request selection survives navigation and browser back.
  assert.equal(new URL(page.url()).searchParams.get('route_id'),'record');
  await page.goto(`${base}/routes/record?version=${process.env.OPENWAF_BROWSER_VERSION}&${params}`);
  await page.getByText(/historical_config · version/).waitFor();
  await page.getByText('Unavailable for historical or draft snapshots',{exact:true}).waitFor();
  await page.getByRole('button',{name:'Pause',exact:true}).click();
  await page.getByText('Paused',{exact:true}).first().waitFor();
  await page.keyboard.press('Tab');
  assert(await page.evaluate(()=>document.activeElement!==document.body));
  await page.setViewportSize({width:390,height:844});
  const originalScheme=await page.locator('html').getAttribute('data-mantine-color-scheme');
  await page.getByRole('button',{name:'Toggle color scheme',exact:true}).click();
  assert.notEqual(await page.locator('html').getAttribute('data-mantine-color-scheme'),originalScheme);
  await page.getByRole('button',{name:'Toggle color scheme',exact:true}).click();
  assert.equal(await page.locator('html').getAttribute('data-mantine-color-scheme'),originalScheme);
  await page.getByRole('heading',{name:/Route · record/}).waitFor();
  // Data tables may scroll internally; the document itself must fit mobile.
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1),'mobile document overflow');
  assert.deepEqual(errors,[]);
  await context.close();
  console.log('PASS Chromium route snapshots, preserved filters/back, operational tabs, history, pause, keyboard, mobile and dark media');
 } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
