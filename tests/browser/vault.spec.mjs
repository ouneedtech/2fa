import { test, expect } from '@playwright/test';
import { VaultAgent } from '../../scripts/agent.mjs';
const PASSWORD='Synthetic-test-password-2026!';
test('full browser journey, four languages, themes, mobile, encryption and delegated API restrictions',async({page,request,browser})=>{
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto('/');
  await expect(page.locator('#auth')).toBeVisible();
  await page.locator('[data-lang="en"]').click();
  await expect(page.locator('#authTitle')).toHaveText('Make a space of your own');
  await page.locator('#setupToken').fill('local-preview-only-setup-token-000000000');
  await page.locator('#username').fill('admin');await page.locator('#password').fill(PASSWORD);await page.locator('#confirmPassword').fill(PASSWORD);
  await page.locator('#authSubmit').click();await expect(page.locator('#workspace')).toBeVisible();
  await expect(page.locator('#cards')).toContainText('A space for your first');
  for(const [lang,title]of [['zh-CN','你的验证器'],['ko','내 인증기'],['zh-TW','你的驗證器'],['en','Your authenticators']]){
    await page.locator(`[data-lang="${lang}"]`).click();await expect(page.locator('h1').last()).toHaveText(title);await expect(page.locator('html')).toHaveAttribute('lang',lang);
  }
  await page.locator('#theme').click();await expect(page.locator('html')).toHaveAttribute('data-theme','dark');
  await page.screenshot({path:'.local/qa/empty-dark.png',fullPage:true});
  await page.locator('#theme').click();
  await page.locator('#add').click();
  await page.locator('#entryLabel').fill('alice@example.com');await page.locator('#entryIssuer').fill('GitHub');await page.locator('#entrySecret').fill('JBSW Y3DP EHPK 3PXP');
  await page.locator('#entryForm button[type=submit]').click();await expect(page.locator('.otp-card')).toHaveCount(1);await expect(page.locator('.digits')).toHaveText(/\d{3} \d{3}/);
  await page.locator('#add').click();await page.locator('#entryUri').fill('otpauth://totp/Cloudflare:admin%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=60&algorithm=SHA256');await page.locator('#entryUri').blur();await page.locator('#entryForm button[type=submit]').click();await expect(page.locator('.otp-card')).toHaveCount(2);
  // A malicious-looking name is rendered as text. No network images/scripts are injected.
  await page.locator('#add').click();await page.locator('#entryLabel').fill('<img src=x onerror=alert(1)>');await page.locator('#entryIssuer').fill('Test');await page.locator('#entrySecret').fill('JBSWY3DPEHPK3PXP');await page.locator('#entryForm button[type=submit]').click();await expect(page.locator('.otp-card')).toHaveCount(3);await expect(page.locator('#cards img')).toHaveCount(0);
  const cipher=await page.evaluate(async()=>await(await fetch('/api/entries')).json());expect(JSON.stringify(cipher)).not.toContain('alice@example.com');expect(JSON.stringify(cipher)).not.toContain('JBSWY');
  await page.screenshot({path:'.local/qa/vault-light.png',fullPage:true});await page.locator('#theme').click();await page.screenshot({path:'.local/qa/vault-dark.png',fullPage:true});
  await page.setViewportSize({width:390,height:844});await expect(page.locator('.otp-card').first()).toBeVisible();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await page.screenshot({path:'.local/qa/mobile-dark.png',fullPage:true});await page.setViewportSize({width:1280,height:900});
  // Refresh drops the decryption key and every plaintext entry from the DOM.
  await page.reload();await expect(page.locator('#authTitle')).toHaveText('Welcome back');await expect(page.locator('#cards')).toBeEmpty();await expect(page.locator('html')).toHaveAttribute('data-theme','dark');
  await page.locator('#password').fill('incorrect-password');await page.locator('#authSubmit').click();await expect(page.locator('#authError')).toContainText('Incorrect password');
  await page.locator('#password').fill(PASSWORD);await page.locator('#authSubmit').click();await expect(page.locator('.otp-card')).toHaveCount(3);
  await page.locator('[data-tab="agent"]').click();await page.locator('#agentConsent').check();await page.locator('#agentForm button[type=submit]').click();await expect(page.locator('#grantPanel')).toBeVisible();
  const grant=JSON.parse(await page.locator('#grantOutput').inputValue());const agent=new VaultAgent(grant,{allowLocalhost:true});
  const codes=await agent.codes();expect(codes).toHaveLength(3);expect(codes[0].code).toMatch(/^\d{6,8}$/);
  const headers={Authorization:'Bearer '+grant.token};
  expect((await request.delete('/api/entries/'+codes[0].id,{headers})).status()).toBe(403);
  expect((await request.post('/api/tokens',{headers,data:{days:1}})).status()).toBe(403);
  expect((await request.get('/api/users',{headers})).status()).toBe(403);
  await expect(agent.add({label:'Denied',secret:'JBSWY3DPEHPK3PXP'})).rejects.toThrow('agent_read_only');
  await page.locator('#tokenList button').first().click();await page.locator('#confirmOk').click();await expect(page.locator('#tokenList')).toContainText('No active tokens');await expect(agent.codes()).rejects.toThrow('unauthorized');
  await page.locator('#tokenPermission').selectOption('add');await page.locator('#agentConsent').check();await page.locator('#agentForm button[type=submit]').click();await expect(page.locator('#grantPanel')).toBeVisible();
  const writerGrant=JSON.parse(await page.locator('#grantOutput').inputValue());const writer=new VaultAgent(writerGrant,{allowLocalhost:true});await writer.add({label:'Agent-created',issuer:'Agent',secret:'JBSWY3DPEHPK3PXP'});
  expect((await request.delete('/api/entries/'+codes[0].id,{headers:{Authorization:'Bearer '+writerGrant.token}})).status()).toBe(403);
  await page.locator('#lock').click();await expect(page.locator('#grantOutput')).toHaveValue('');await expect(page.locator('#cards')).toBeEmpty();await page.locator('#password').fill(PASSWORD);await page.locator('#authSubmit').click();await expect(page.locator('.otp-card')).toHaveCount(4);
  // Child user has a fresh vault and no administration access.
  await page.locator('[data-tab="admin"]').click();await page.locator('#createUser').click();await page.locator('#newUsername').fill('alice');await page.locator('#newPassword').fill(PASSWORD);await page.locator('#newConfirm').fill(PASSWORD);await page.locator('#userForm button[type=submit]').click();await expect(page.locator('#userList')).toContainText('alice');
  const childContext=await browser.newContext();const child=await childContext.newPage();await child.goto('/');await child.locator('[data-lang="en"]').click();await child.locator('#username').fill('alice');await child.locator('#password').fill(PASSWORD);await child.locator('#authSubmit').click();await expect(child.locator('#workspace')).toBeVisible();await expect(child.locator('#adminTab')).toBeHidden();await expect(child.locator('.otp-card')).toHaveCount(0);
  expect(await child.evaluate(async()=>(await fetch('/api/users')).status)).toBe(403);
  // Parent can remove a member and their existing sessions stop working.
  await page.locator('#userList .danger').click();await page.locator('#confirmOk').click();await expect(page.locator('#userList')).not.toContainText('alice');expect(await child.evaluate(async()=>(await fetch('/api/me')).status)).toBe(401);await childContext.close();
  // Browser deletion remains explicitly confirmed.
  await page.locator('[data-tab="vault"]').click();await page.locator('.remove').first().click();await page.locator('#confirmCancel').click();await expect(page.locator('.otp-card')).toHaveCount(4);await page.locator('.remove').first().click();await page.locator('#confirmOk').click();await expect(page.locator('.otp-card')).toHaveCount(3);
  // Escape after a previous confirmation must not reuse the old affirmative result.
  await page.locator('.remove').first().click();await page.keyboard.press('Escape');await expect(page.locator('#confirmDialog')).not.toBeVisible();await expect(page.locator('.otp-card')).toHaveCount(3);
  await page.locator('#logout').click();await expect(page.locator('#authTitle')).toHaveText('Add an authenticator');expect(await page.evaluate(async()=>(await fetch('/api/me')).status)).toBe(401);
  expect(errors).toEqual([]);
});
