import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { app, safeStorage } from 'electron';

const emptyState = {
  servers: [],
  siteSsh: {}
};

const getStorePath = () => path.join(app.getPath('userData'), 'servers.json');
const encryptedSecretPrefix = 'enc:v1:';
const hasControlChars = (value) => /[\u0000-\u001f\u007f]/.test(String(value || ''));

const encryptSecret = (value) => {
  const secret = String(value || '');
  if (!secret) return '';
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('系统安全存储不可用，无法保存服务器凭据');
  }
  return `${encryptedSecretPrefix}${safeStorage.encryptString(secret).toString('base64')}`;
};

const decryptSecret = (value) => {
  const stored = String(value || '');
  if (!stored) return '';
  if (!stored.startsWith(encryptedSecretPrefix)) {
    return stored;
  }

  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('系统安全存储不可用，无法读取服务器凭据');
  }

  return safeStorage.decryptString(Buffer.from(stored.slice(encryptedSecretPrefix.length), 'base64'));
};

const encryptStoredSecret = (value) => {
  const stored = String(value || '');
  if (!stored || stored.startsWith(encryptedSecretPrefix)) return stored;
  return encryptSecret(stored);
};

const serverHasSecret = (server, field) => Boolean(String(server?.[field] || ''));

const redactServer = (server) => ({
  ...server,
  password: '',
  passphrase: '',
  hasPassword: serverHasSecret(server, 'password'),
  hasPassphrase: serverHasSecret(server, 'passphrase')
});

const decryptServer = (server) => ({
  ...server,
  password: decryptSecret(server.password),
  passphrase: decryptSecret(server.passphrase)
});

const readState = async () => {
  try {
    const content = await fs.readFile(getStorePath(), 'utf8');
    const parsed = JSON.parse(content);
    return {
      ...emptyState,
      ...parsed,
      servers: Array.isArray(parsed.servers) ? parsed.servers : [],
      siteSsh: parsed.siteSsh && typeof parsed.siteSsh === 'object' ? parsed.siteSsh : {}
    };
  } catch (error) {
    if (error.code === 'ENOENT') {
      return emptyState;
    }
    throw error;
  }
};

const writeState = async (state) => {
  const storePath = getStorePath();
  await fs.mkdir(path.dirname(storePath), { recursive: true, mode: 0o700 });
  await fs.writeFile(storePath, JSON.stringify(state, null, 2), 'utf8');
  await fs.chmod(storePath, 0o600);
};

const expandHome = (filePath) => {
  if (filePath === '~') return os.homedir();
  if (filePath?.startsWith('~/')) return path.join(os.homedir(), filePath.slice(2));
  return filePath;
};

const validateServer = async (server) => {
  if (server.name.length > 80) {
    throw new Error('名称不能超过 80 个字符');
  }

  if (!server.host) {
    throw new Error('请填写服务器地址');
  }

  if (/^https?:\/\//i.test(server.host) || /[/?#]/.test(server.host) || /\s/.test(server.host)) {
    throw new Error('服务器地址只支持 IP 或域名');
  }

  if (hasControlChars(server.host)) {
    throw new Error('服务器地址不能包含控制字符');
  }

  if (!Number.isInteger(server.port) || server.port < 1 || server.port > 65535) {
    throw new Error('端口必须是 1 到 65535 的整数');
  }

  if (!server.username || /\s/.test(server.username)) {
    throw new Error('请填写有效的登录用户');
  }

  if (hasControlChars(server.username)) {
    throw new Error('登录用户不能包含控制字符');
  }

  if (server.authType === 'key') {
    if (!server.privateKeyPath) {
      throw new Error('请选择或填写 root 私钥路径');
    }

    if (hasControlChars(server.privateKeyPath)) {
      throw new Error('root 私钥路径不能包含控制字符');
    }

    try {
      await fs.access(expandHome(server.privateKeyPath));
    } catch {
      throw new Error('root 私钥文件不存在或不可读取');
    }
  } else if (!server.password.trim()) {
    throw new Error('请填写 root 密码');
  }

  if (server.hostFingerprint && !/^SHA256:[A-Za-z0-9+/=]+$/.test(server.hostFingerprint)) {
    throw new Error('SSH 主机指纹格式无效，请重新校验服务器');
  }
};

const endpointKey = (server) =>
  `${String(server.host || '').trim().toLowerCase()}:${Number(server.port || 22)}`;

export const listServers = async () => {
  const state = await readState();
  return state.servers.map(redactServer);
};

export const getServer = async (serverId) => {
  const state = await readState();
  const server = state.servers.find((item) => item.id === serverId);
  return server ? decryptServer(server) : undefined;
};

export const saveServer = async (server) => {
  const now = new Date().toISOString();
  const state = await readState();
  const requestedId = server.id || crypto.randomUUID();
  const authType = server.authType === 'key' ? 'key' : 'password';
  const incomingEndpoint = endpointKey(server);
  const sameEndpoint = state.servers.find((item) => endpointKey(item) === incomingEndpoint);
  const sameId = state.servers.find((item) => item.id === requestedId);
  const existing = sameEndpoint || sameId;
  const deduped = Boolean(sameEndpoint && sameEndpoint.id !== requestedId);
  const shouldKeepPassword = authType === 'password' && !String(server.password || '') && existing?.password;
  const shouldKeepPassphrase = authType === 'key' && !String(server.passphrase || '') && existing?.passphrase;

  const normalized = {
    id: requestedId,
    name: server.name?.trim() || server.host?.trim() || '未命名服务器',
    host: server.host?.trim(),
    port: Number(server.port || 22),
    username: server.username?.trim() || 'root',
    authType,
    hostFingerprint: String(server.hostFingerprint || existing?.hostFingerprint || '').trim(),
    hostFingerprintAlgo: String(server.hostFingerprintAlgo || existing?.hostFingerprintAlgo || '').trim(),
    password: authType === 'password' ? (shouldKeepPassword ? encryptStoredSecret(existing.password) : encryptSecret(server.password)) : '',
    privateKeyPath: server.privateKeyPath?.trim() || '',
    passphrase: authType === 'key' ? (shouldKeepPassphrase ? encryptStoredSecret(existing.passphrase) : encryptSecret(server.passphrase)) : '',
    createdAt: server.createdAt || now,
    updatedAt: now
  };

  await validateServer(decryptServer(normalized));

  if (existing) {
    normalized.id = existing.id;
    normalized.createdAt = existing.createdAt || normalized.createdAt;
    state.servers = state.servers.filter(
      (item) => item.id !== existing.id && item.id !== requestedId && endpointKey(item) !== incomingEndpoint
    );
    state.servers.unshift(normalized);
  } else {
    state.servers.unshift(normalized);
  }

  await writeState(state);
  return { ...redactServer(normalized), deduped };
};

export const resolveServerCredentials = async (server) => {
  const state = await readState();
  const existing = state.servers.find((item) => item.id === server.id || endpointKey(item) === endpointKey(server));
  const merged = {
    ...server,
    hostFingerprint: String(server.hostFingerprint || '') || existing?.hostFingerprint || '',
    hostFingerprintAlgo: String(server.hostFingerprintAlgo || '') || existing?.hostFingerprintAlgo || '',
    password: String(server.password || '') || existing?.password || '',
    passphrase: String(server.passphrase || '') || existing?.passphrase || ''
  };
  return decryptServer(merged);
};

export const removeServer = async (serverId) => {
  const state = await readState();
  state.servers = state.servers.filter((server) => server.id !== serverId);
  if (state.siteSsh) {
    delete state.siteSsh[serverId];
  }
  await writeState(state);
  return true;
};

const getSiteStateKey = (site) => String(site?.id || site?.path || site?.name || '').trim();

const findSiteSshState = (records, site) => {
  const direct = records[getSiteStateKey(site)];
  if (direct) return direct;

  const sitePath = String(site?.path || '');
  const siteName = String(site?.name || '');
  return Object.values(records).find(
    (record) => (sitePath && record.sitePath === sitePath) || (siteName && record.siteName === siteName)
  );
};

export const enrichSitesWithSshState = async (serverId, sites) => {
  const state = await readState();
  const records = state.siteSsh?.[serverId] || {};
  return sites.map((site) => {
    const record = findSiteSshState(records, site);
    if (!record?.sshEnabled) return site;
    return {
      ...site,
      sshEnabled: true,
      sshAlias: record.sshAlias || '',
      sshUsername: record.sshUsername || '',
      sshKeyPath: record.sshKeyPath || ''
    };
  });
};

export const saveSiteSshState = async (serverId, site, sshState) => {
  const siteKey = getSiteStateKey(site);
  if (!siteKey) {
    throw new Error('站点缺少可识别的 ID、路径或名称，无法保存启用状态');
  }

  const state = await readState();
  state.siteSsh = state.siteSsh && typeof state.siteSsh === 'object' ? state.siteSsh : {};
  state.siteSsh[serverId] = state.siteSsh[serverId] && typeof state.siteSsh[serverId] === 'object' ? state.siteSsh[serverId] : {};
  state.siteSsh[serverId][siteKey] = {
    siteId: String(site?.id || ''),
    siteName: String(site?.name || ''),
    sitePath: String(site?.path || ''),
    sshEnabled: true,
    sshAlias: sshState.alias || '',
    sshUsername: sshState.username || '',
    sshKeyPath: sshState.keyPath || '',
    updatedAt: new Date().toISOString()
  };

  await writeState(state);
  return state.siteSsh[serverId][siteKey];
};

export const removeSiteSshState = async (serverId, site) => {
  const state = await readState();
  const records = state.siteSsh?.[serverId];
  if (!records) return true;

  const siteKey = getSiteStateKey(site);
  if (siteKey && records[siteKey]) {
    delete records[siteKey];
  } else {
    const record = findSiteSshState(records, site);
    const recordKey = Object.entries(records).find(([, value]) => value === record)?.[0];
    if (recordKey) delete records[recordKey];
  }

  if (Object.keys(records).length === 0) {
    delete state.siteSsh[serverId];
  }
  await writeState(state);
  return true;
};
