import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { app, BrowserWindow, dialog, ipcMain, Menu, nativeImage } from 'electron';
import {
  enrichSitesWithSshState,
  getServer,
  listServers,
  removeServer,
  removeSiteSshState,
  resolveServerCredentials,
  saveServer,
  saveSiteSshState
} from './store.js';
import {
  disableSiteSsh,
  enrichSitesWithLocalSshConfig,
  getSshConfigPath,
  listBtSites,
  provisionSiteSsh,
  resolveManagedSite,
  testBtSite,
  validateServerAccess
} from './ssh.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isDev = Boolean(process.env.VITE_DEV_SERVER_URL);
const appIconPath = path.join(__dirname, '../assets/app-icon.png');

const getAppIcon = () => {
  const icon = nativeImage.createFromPath(appIconPath);
  return icon.isEmpty() ? appIconPath : icon;
};

const isBlockedShortcut = (input) => {
  const key = String(input.key || '').toLowerCase();
  const commandOrControl = input.meta || input.control;
  const commandOrControlShift = commandOrControl && input.shift;

  return (
    key === 'f5' ||
    (commandOrControl && key === 'r') ||
    key === 'f12' ||
    (commandOrControlShift && ['i', 'j', 'c'].includes(key)) ||
    (input.meta && input.alt && key === 'i')
  );
};

const installWindowGuards = (win) => {
  win.webContents.on('context-menu', (event) => {
    event.preventDefault();
  });

  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-attach-webview', (event) => {
    event.preventDefault();
  });
  win.webContents.on('will-navigate', (event, url) => {
    const expectedDevUrl = process.env.VITE_DEV_SERVER_URL;
    const isAllowedDevUrl = Boolean(expectedDevUrl && url.startsWith(expectedDevUrl));
    const isAllowedFileUrl = url.startsWith('file://');
    if (!isAllowedDevUrl && !isAllowedFileUrl) {
      event.preventDefault();
    }
  });

  win.webContents.on('before-input-event', (event, input) => {
    if (isBlockedShortcut(input)) {
      event.preventDefault();
    }
  });
};

const createWindow = async () => {
  const appIcon = getAppIcon();
  const win = new BrowserWindow({
    width: 1220,
    height: 820,
    minWidth: 980,
    minHeight: 680,
    title: '宝塔站点 SSH',
    icon: appIcon,
    backgroundColor: '#f8fafc',
    webPreferences: {
      preload: path.join(__dirname, '../preload/preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      devTools: false
    }
  });

  installWindowGuards(win);

  if (isDev) {
    await win.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else {
    await win.loadFile(path.join(__dirname, '../../dist/index.html'));
  }
};

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  if (process.platform === 'darwin' && app.dock) {
    app.dock.setIcon(getAppIcon());
  }
  createWindow();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

const isTrustedSender = (event) => {
  const senderUrl = String(event.senderFrame?.url || '');
  if (!senderUrl) return false;
  if (isDev) {
    return senderUrl.startsWith(String(process.env.VITE_DEV_SERVER_URL || ''));
  }
  return senderUrl.startsWith('file://');
};

const safeHandle = (channel, handler) => {
  ipcMain.handle(channel, async (event, payload) => {
    try {
      if (!isTrustedSender(event)) {
        throw new Error('IPC 来源无效，请重启应用后重试');
      }
      return { ok: true, data: await handler(payload) };
    } catch (error) {
      return { ok: false, error: error.message || String(error) };
    }
  });
};

const requireServer = async (serverId) => {
  const server = await getServer(serverId);
  if (!server) {
    throw new Error('服务器不存在，请重新选择');
  }
  return server;
};

safeHandle('servers:list', listServers);
safeHandle('servers:save', saveServer);
safeHandle('servers:validate-access', async (server) => validateServerAccess(await resolveServerCredentials(server)));
safeHandle('servers:remove', removeServer);
safeHandle('sites:list', async (serverId) => {
  const server = await requireServer(serverId);
  const sites = await listBtSites(server);
  const withStoredState = await enrichSitesWithSshState(serverId, sites);
  return enrichSitesWithLocalSshConfig(server, withStoredState);
});
safeHandle('site:test', async ({ serverId, site }) => {
  const server = await requireServer(serverId);
  return testBtSite(server, await resolveManagedSite(server, site));
});
safeHandle('site:provision', async ({ serverId, site, options }) => {
  const server = await requireServer(serverId);
  const managedSite = await resolveManagedSite(server, site);
  const result = await provisionSiteSsh(server, managedSite, options);
  await saveSiteSshState(serverId, managedSite, result);
  return result;
});
safeHandle('site:disable', async ({ serverId, site, options }) => {
  const server = await requireServer(serverId);
  const managedSite = await resolveManagedSite(server, site);
  const result = await disableSiteSsh(server, managedSite, options);
  await removeSiteSshState(serverId, managedSite);
  return result;
});
safeHandle('local:ssh-config-path', async () => getSshConfigPath());

safeHandle('keys:select-private', async () => {
  const result = await dialog.showOpenDialog({
    title: '选择 root 私钥',
    properties: ['openFile', 'showHiddenFiles'],
    filters: [{ name: 'SSH private key', extensions: ['pem', 'key', '*'] }]
  });

  if (result.canceled || !result.filePaths.length) {
    return '';
  }

  return result.filePaths[0];
});

safeHandle('keys:select-local-key-path', async ({ defaultPath } = {}) => {
  const fallbackPath = path.join(app.getPath('home'), '.ssh', 'bt-ssh', 'site_ed25519');
  const result = await dialog.showSaveDialog({
    title: '选择本地密钥保存路径',
    defaultPath: defaultPath || fallbackPath,
    buttonLabel: '使用此路径',
    filters: [{ name: 'SSH private key', extensions: ['*'] }]
  });

  if (result.canceled || !result.filePath) {
    return '';
  }

  return result.filePath;
});
