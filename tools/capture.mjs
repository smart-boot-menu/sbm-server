import { spawn } from 'node:child_process';
import { access, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const base = process.env.SBM_URL ?? 'https://localhost:18443';
const secret = process.env.SBM_BOOTSTRAP_SECRET ?? '';
const deviceId = process.env.SBM_DEVICE_ID ?? '';
const sim = process.env.SBM_SIM ?? join(root, 'target/debug/sbm-sim');
const state = process.env.SBM_STATE ?? '';
const outDir = process.env.SBM_SHOTS ?? join(root, 'docs/screenshots');
const chromeCandidates = [
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary'
];

const profile = await mkdtemp(join(tmpdir(), 'sbm-chrome-'));
const chromePath = await existingChrome();
const debugPort = 9333;
const chrome = spawn(
  chromePath,
  [
    '--headless=new',
    '--disable-gpu',
    '--hide-scrollbars',
    `--remote-debugging-port=${debugPort}`,
    '--ignore-certificate-errors',
    '--host-resolver-rules=MAP localhost 127.0.0.1',
    '--no-first-run',
    '--no-default-browser-check',
    `--user-data-dir=${profile}`,
    '--window-size=1440,900',
    'about:blank'
  ],
  { stdio: 'ignore' }
);

try {
  await waitForDebugger();
  const page = await openTab(`${base}/login`);
  const socket = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  const cdp = client(socket);
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width: 1440,
    height: 900,
    deviceScaleFactor: 1,
    mobile: false
  });
  await shot(cdp, 'login.png', "document.querySelector('h1')?.textContent === 'Console'");
  await cdp.eval(`(() => {
    const input = document.querySelector('input[type=password]');
    const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    set.call(input, ${JSON.stringify(secret)});
    input.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
  await delay(200);
  const clicked = await cdp.eval(`(() => {
    const button = [...document.querySelectorAll('button')].find((item) => item.textContent.includes('Sign in for the lab'));
    if (!button || button.disabled) return 'disabled';
    button.click();
    return 'clicked';
  })()`);
  if (clicked !== 'clicked') throw new Error(`lab sign-in button was ${clicked}`);
  await shot(cdp, 'devices.png', "document.querySelector('h1')?.textContent === 'Devices'");
  if (deviceId) {
    await cdp.send('Page.navigate', { url: `${base}/devices/${deviceId}` });
    await shot(cdp, 'device.png', 'document.body.innerText.includes("Reported targets")');
    await cdp.eval(`(() => {
      const button = [...document.querySelectorAll('button')].find((item) => item.textContent.includes('Queue next boot'));
      button.click();
    })()`);
    await shot(
      cdp,
      'device-queued.png',
      'document.body.innerText.includes("The command is queued. The device has not applied it, and no reboot has happened.") && document.body.innerText.includes("requested")',
      'Command history'
    );
    await run(sim, ['once', '--state', state, '--mode', 'uefi']);
    await shot(
      cdp,
      'device-executed.png',
      'document.body.innerText.includes("The simulator recorded the selection. No machine rebooted.") && document.body.innerText.includes("executed")',
      'Command history'
    );
    await cdp.send('Page.navigate', { url: `${base}/enroll` });
    await shot(cdp, 'enroll.png', "document.querySelector('h1')?.textContent === 'One-time token'");
    await cdp.send('Page.navigate', { url: `${base}/audit` });
    await shot(cdp, 'audit.png', "document.querySelector('h1')?.textContent === 'Audit'");
    await cdp.send('Page.navigate', { url: `${base}/security` });
    await shot(cdp, 'security.png', "document.querySelector('h1')?.textContent === 'Security'");
    await cdp.send('Page.navigate', { url: `${base}/devices/${deviceId}` });
    await waitUntil(cdp, 'document.body.innerText.includes("Authorize recovery view")');
    await cdp.eval(`(() => {
      [...document.querySelectorAll('button')].find((item) => item.textContent.includes('Authorize recovery view')).click();
    })()`);
    await waitUntil(cdp, "document.querySelector('h1')?.textContent === 'Remote view'");
    const session = await cdp.eval(`location.pathname.split('/').pop()`);
    const vnc = spawn(sim, ['recovery', '--state', state, '--session', session, '--kind', 'vnc'], { stdio: 'ignore' });
    const term = spawn(sim, ['recovery', '--state', state, '--session', session, '--kind', 'terminal'], { stdio: 'ignore' });
    try {
      await delay(1500);
      await shot(cdp, 'recovery.png', "document.querySelector('h1')?.textContent === 'Remote view'");
    } finally {
      vnc.kill('SIGTERM');
      term.kill('SIGTERM');
    }
  }
  socket.close();
} finally {
  chrome.kill('SIGTERM');
  await delay(200);
  await rm(profile, { recursive: true, force: true });
}

async function existingChrome() {
  for (const path of chromeCandidates) {
    try {
      await access(path);
      return path;
    } catch {
      // try the next install
    }
  }
  throw new Error('Google Chrome was not found');
}

async function waitForDebugger() {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${debugPort}/json/version`);
      if (response.ok) return;
    } catch {
      // Chrome is still starting.
    }
    await delay(100);
  }
  throw new Error('Chrome remote debugging did not open');
}

async function openTab(url) {
  const response = await fetch(`http://127.0.0.1:${debugPort}/json/new?${encodeURIComponent(url)}`, { method: 'PUT' });
  if (!response.ok) {
    const fallback = await fetch(`http://127.0.0.1:${debugPort}/json/new?${url}`);
    if (!fallback.ok) throw new Error(`could not open a tab: ${fallback.status}`);
    return fallback.json();
  }
  return response.json();
}

function client(socket) {
  let next = 0;
  const pending = new Map();
  socket.addEventListener('message', (event) => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) reject(new Error(JSON.stringify(message.error)));
      else resolve(message.result);
    }
  });
  return {
    send(method, params = {}) {
      const id = ++next;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        socket.send(JSON.stringify({ id, method, params }));
      });
    },
    async eval(expression) {
      const result = await this.send('Runtime.evaluate', {
        expression,
        awaitPromise: true,
        returnByValue: true
      });
      if (result.exceptionDetails) {
        throw new Error(result.exceptionDetails.text || JSON.stringify(result.exceptionDetails));
      }
      return result.result?.value;
    }
  };
}

async function waitUntil(cdp, expression) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    const ready = await cdp.eval(`Boolean(${expression})`);
    if (ready) return;
    await delay(250);
  }
  const text = await cdp.eval('document.body?.innerText?.slice(0, 800)');
  throw new Error(`timed out waiting for ${expression}\n${text}`);
}

async function shot(cdp, name, expression, heading) {
  await waitUntil(cdp, expression);
  if (heading) {
    await cdp.eval(`(() => {
      const node = [...document.querySelectorAll('h2')].find((item) => item.textContent.includes(${JSON.stringify(heading)}));
      node?.scrollIntoView({ block: 'start' });
    })()`);
  }
  await delay(300);
  const image = await cdp.send('Page.captureScreenshot', { format: 'png' });
  await writeFile(join(outDir, name), Buffer.from(image.data, 'base64'));
}

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: 'inherit' });
    child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`${command} exited ${code}`))));
  });
}
