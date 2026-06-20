const { contextBridge, ipcRenderer } = require('electron');

const invoke = (channel, payload) => ipcRenderer.invoke(channel, payload);

contextBridge.exposeInMainWorld('btSsh', {
  listServers: () => invoke('servers:list'),
  saveServer: (server) => invoke('servers:save', server),
  validateServerAccess: (server) => invoke('servers:validate-access', server),
  removeServer: (serverId) => invoke('servers:remove', serverId),
  selectPrivateKey: () => invoke('keys:select-private'),
  selectLocalKeyPath: (defaultPath) => invoke('keys:select-local-key-path', { defaultPath }),
  listSites: (serverId) => invoke('sites:list', serverId),
  testSite: (payload) => invoke('site:test', payload),
  provisionSite: (payload) => invoke('site:provision', payload),
  disableSite: (payload) => invoke('site:disable', payload),
  getLocalConfigPath: () => invoke('local:ssh-config-path')
});
