import { defineConfig } from '@playwright/test';
import { existsSync } from 'node:fs';
const baseURL=process.env.TEST_BASE_URL||'http://127.0.0.1:8788';
const channel=process.env.PLAYWRIGHT_CHANNEL||(existsSync('C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe')?'msedge':undefined);
export default defineConfig({
  testDir:'./tests/browser',
  fullyParallel:false,
  workers:1,
  timeout:60000,
  outputDir:'.local/qa/results',
  reporter:[['list']],
  use:{baseURL, headless:true, browserName:'chromium', launchOptions:{channel}, screenshot:'only-on-failure', trace:'off'},
  webServer:process.env.TEST_BASE_URL?undefined:{command:'node scripts/preview.mjs',url:baseURL,reuseExistingServer:false,timeout:30000}
});
