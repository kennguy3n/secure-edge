// Secure Edge — Electron main process.
//
// Responsibilities:
//   * Create the system tray on app ready (no visible window on startup).
//   * Provide a tray context menu (Status / Open Settings / Quit).
//   * Create a BrowserWindow on-demand and DESTROY it on close to free
//     Chromium memory (per ARCHITECTURE.md).
//   * Poll the Go agent's /api/status endpoint every 10s and reflect the
//     reachability state in the tray icon and tray tooltip.

import { app, BrowserWindow, Menu, Tray, nativeImage, ipcMain } from 'electron';
import * as path from 'path';
import * as http from 'http';
import { autoUpdater } from 'electron-updater';

const AGENT_PORT = Number(process.env.SECURE_EDGE_AGENT_PORT ?? 8080);
const AGENT_HOST = process.env.SECURE_EDGE_AGENT_HOST ?? '127.0.0.1';
const HEALTH_INTERVAL_MS = 10_000;

type View = 'status' | 'settings' | 'proxy';

let tray: Tray | null = null;
let window: BrowserWindow | null = null;
let healthTimer: NodeJS.Timeout | null = null;
let lastHealthy: boolean | null = null;
let updateAvailable = false;
let proxyRunning: boolean | null = null;

function rendererPath(): string {
  // In production main.ts is compiled to dist/main.js and the renderer
  // is at dist/renderer/index.html relative to it.
  return path.join(__dirname, 'renderer', 'index.html');
}

function trayIconPath(healthy: boolean): string {
  // The packaged tray icons live next to the main bundle.
  const name = healthy ? 'tray-icon.png' : 'tray-icon-error.png';
  return path.join(__dirname, '..', 'resources', name);
}

function buildTrayImage(healthy: boolean) {
  const img = nativeImage.createFromPath(trayIconPath(healthy));
  if (img.isEmpty()) {
    // Fall back to a tiny generated image so we still have *something*
    // in the tray on developer setups without the packaged assets.
    return nativeImage.createFromDataURL(
      'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAQAAAC1+jfqAAAAH0lEQVR42mNk+M9ABDDxQTQYwoAxYwQTAAB1AAGAVPjnXgAAAABJRU5ErkJggg==',
    );
  }
  return img;
}

function showView(view: View) {
  if (!window) {
    window = new BrowserWindow({
      width: 600,
      height: 500,
      show: false,
      resizable: true,
      title: 'Secure Edge',
      webPreferences: {
        preload: path.join(__dirname, 'preload.js'),
        contextIsolation: true,
        nodeIntegration: false,
      },
    });
    window.removeMenu();
    window.on('close', () => {
      // Destroy the window so Chromium fully releases its memory.
      window?.destroy();
      window = null;
    });

    const devURL = process.env.VITE_DEV_SERVER_URL;
    if (devURL) {
      window.loadURL(`${devURL}#${view}`);
    } else {
      window.loadFile(rendererPath(), { hash: view });
    }
  } else {
    window.webContents.send('navigate', view);
  }
  window.once('ready-to-show', () => window?.show());
  if (window.isVisible()) window.focus();
}

function buildMenu(): Menu {
  // Render a non-clickable status line for the proxy. "unknown" means
  // the /api/proxy/status poll has not returned yet (Phase 1–3 agents
  // return 503, in which case we display "unavailable").
  let proxyLabel = 'Proxy: …';
  if (proxyRunning === true) proxyLabel = 'Proxy: Active';
  else if (proxyRunning === false) proxyLabel = 'Proxy: Inactive';

  const template: Electron.MenuItemConstructorOptions[] = [
    { label: 'Status', click: () => showView('status') },
    { label: 'Open Settings', click: () => showView('settings') },
    { label: 'Advanced DLP (Proxy)', click: () => showView('proxy') },
    { type: 'separator' },
    { label: proxyLabel, enabled: false },
  ];
  if (updateAvailable) {
    template.push({ type: 'separator' });
    template.push({
      label: 'Update available — install and restart',
      click: () => autoUpdater.quitAndInstall(),
    });
  }
  template.push({ type: 'separator' });
  template.push({ label: 'Quit', role: 'quit' });
  return Menu.buildFromTemplate(template);
}

function refreshTrayMenu(): void {
  tray?.setContextMenu(buildMenu());
}

function updateTrayHealth(healthy: boolean) {
  if (!tray) return;
  if (healthy === lastHealthy) return;
  lastHealthy = healthy;
  tray.setImage(buildTrayImage(healthy));
  tray.setToolTip(healthy ? 'Secure Edge: agent running' : 'Secure Edge: agent unreachable');
}

function pingAgent(): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: AGENT_HOST,
        port: AGENT_PORT,
        path: '/api/status',
        method: 'GET',
        timeout: 2000,
      },
      (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      },
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}

// pingProxy returns true when the agent reports the local MITM proxy
// as running, false otherwise (including 503 from agents that have
// not wired the proxy controller).
function pingProxy(): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: AGENT_HOST,
        port: AGENT_PORT,
        path: '/api/proxy/status',
        method: 'GET',
        timeout: 2000,
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          resolve(false);
          return;
        }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          body += chunk;
        });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(body) as { running?: boolean };
            resolve(parsed.running === true);
          } catch {
            resolve(false);
          }
        });
      },
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}

async function tickHealth() {
  const [ok, proxyOk] = await Promise.all([pingAgent(), pingProxy()]);
  updateTrayHealth(ok);
  if (proxyOk !== proxyRunning) {
    proxyRunning = proxyOk;
    refreshTrayMenu();
  }
}

function startHealthPolling() {
  if (healthTimer) return;
  void tickHealth();
  healthTimer = setInterval(() => void tickHealth(), HEALTH_INTERVAL_MS);
}

function stopHealthPolling() {
  if (!healthTimer) return;
  clearInterval(healthTimer);
  healthTimer = null;
}

app.whenReady().then(() => {
  // macOS: prevent the Dock icon from appearing when the app starts
  // hidden in the menu bar.
  if (process.platform === 'darwin' && app.dock) {
    app.dock.hide();
  }

  tray = new Tray(buildTrayImage(false));
  tray.setToolTip('Secure Edge');
  tray.setContextMenu(buildMenu());
  tray.on('click', () => showView('status'));

  ipcMain.handle('secure-edge:get-agent-base', () =>
    `http://${AGENT_HOST}:${AGENT_PORT}`,
  );

  startHealthPolling();

  // electron-updater wiring. The auto-update feed URL comes from
  // electron-builder.yml's publish.github block. We surface availability
  // in the tray menu but never silently install — the user explicitly
  // clicks "Update available" to apply. The "install and restart" menu
  // item only appears after `update-downloaded` fires, because
  // autoUpdater.quitAndInstall() requires the update file on disk;
  // `update-available` only signals that metadata was fetched.
  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = false;
  autoUpdater.on('update-downloaded', () => {
    updateAvailable = true;
    refreshTrayMenu();
  });
  autoUpdater.on('error', (err) => {
    // Update failures are not fatal — log to stderr and continue.
    console.error('auto-update error:', err);
  });
  // Dev runs (no packaged app) cannot self-update; suppress the call.
  if (app.isPackaged) {
    void autoUpdater.checkForUpdatesAndNotify().catch((err) => {
      console.error('checkForUpdatesAndNotify failed:', err);
    });
  }
});

// Keep the tray (and main process) alive when the settings window closes.
// The standard Electron behaviour on macOS already does this; on other
// platforms we simply do nothing in the handler.
app.on('window-all-closed', () => {
  // intentional no-op: the tray icon is the entrypoint to the app.
});

app.on('before-quit', () => {
  stopHealthPolling();
});
