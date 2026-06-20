import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Check,
  CircleHelp,
  FolderKey,
  KeyRound,
  Loader2,
  Plus,
  RefreshCw,
  Save,
  Search,
  Server,
  Settings,
  ShieldCheck,
  Terminal,
  Trash2,
  X
} from 'lucide-react';
import appIcon from '../assets/app-icon.png';

const emptyServerForm = {
  name: '',
  host: '',
  port: 22,
  username: 'root',
  authType: 'password',
  hostFingerprint: '',
  hostFingerprintAlgo: '',
  password: '',
  privateKeyPath: '',
  passphrase: ''
};

const defaultProvision = {
  username: '',
  alias: '',
  keyPath: ''
};

const api = window.btSsh;

const callApi = async (fn, ...args) => {
  if (!api || typeof fn !== 'function') {
    throw new Error('Electron IPC 未连接，请使用 `npm run dev` 或 `npm start` 启动桌面应用');
  }
  const result = await fn(...args);
  if (!result.ok) {
    throw new Error(result.error || '操作失败');
  }
  return result.data;
};

const toLinuxUser = (value) => {
  const cleaned = String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '_')
    .replace(/^[^a-z_]+/, '')
    .replace(/_+/g, '_')
    .slice(0, 28);
  return cleaned || 'site';
};

const toAlias = (server, site) =>
  `${server?.name || server?.host || 'bt'}-${site?.name || site?.id || 'site'}`
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);

const toPathPart = (value) =>
  String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, '_')
    .slice(0, 64);

const getSshDir = (configPath) => {
  const normalizedPath = String(configPath || '~/.ssh/config').replace(/\/+$/g, '');
  const index = normalizedPath.lastIndexOf('/');
  return index > 0 ? normalizedPath.slice(0, index) : '~/.ssh';
};

const getDefaultKeyPath = (server, username, configPath) =>
  `${getSshDir(configPath)}/bt-ssh/${toPathPart(server?.host || 'server')}/${toPathPart(username || 'site')}_ed25519`;

const getSiteKey = (site) => String(site?.id || site?.path || site?.name || '');

const summarizeSiteTest = (summary = {}) =>
  `通过 ${summary.pass || 0}，警告 ${summary.warn || 0}，失败 ${summary.fail || 0}，跳过 ${summary.skip || 0}`;

const validateServerForm = (form) => {
  const errors = {};
  const host = String(form.host || '').trim();
  const username = String(form.username || '').trim();
  const privateKeyPath = String(form.privateKeyPath || '').trim();
  const port = Number(form.port);
  const hasControlChars = (value) => /[\u0000-\u001f\u007f]/.test(String(value || ''));

  if (String(form.name || '').trim().length > 80) {
    errors.name = '名称不能超过 80 个字符';
  }

  if (!host) {
    errors.host = '请填写服务器地址';
  } else if (/^https?:\/\//i.test(host) || /[/?#]/.test(host)) {
    errors.host = '只填写 IP 或域名，不要包含协议或路径';
  } else if (/\s/.test(host)) {
    errors.host = '服务器地址不能包含空格';
  } else if (hasControlChars(host)) {
    errors.host = '服务器地址不能包含控制字符';
  }

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    errors.port = '端口必须是 1 到 65535 的整数';
  }

  if (!username) {
    errors.username = '请填写登录用户';
  } else if (/\s/.test(username)) {
    errors.username = '登录用户不能包含空格';
  } else if (hasControlChars(username)) {
    errors.username = '登录用户不能包含控制字符';
  }

  if (form.authType === 'key') {
    if (!privateKeyPath) {
      errors.privateKeyPath = '请选择或填写 root 私钥路径';
    } else if (hasControlChars(privateKeyPath)) {
      errors.privateKeyPath = 'root 私钥路径不能包含控制字符';
    }
  } else if (!String(form.password || '').trim() && !form.hasPassword) {
    errors.password = '请填写 root 密码';
  }

  return errors;
};

const summarizeValidationError = (message) => {
  if (/^HOST_FINGERPRINT_UNKNOWN\|/.test(message)) return '校验暂停：发现新的 SSH 主机指纹';
  if (/^HOST_FINGERPRINT_MISMATCH\|/.test(message)) return '校验失败：SSH 主机指纹不匹配';
  if (/认证失败|authentication/i.test(message)) return '校验失败：认证失败，请检查密码/私钥';
  if (/超时|timeout|ETIMEDOUT/i.test(message)) return '校验失败：连接超时，请检查地址/端口/防火墙';
  if (/拒绝连接|ECONNREFUSED/i.test(message)) return '校验失败：端口拒绝，请确认 SSH 已启动';
  if (/无法解析|ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(message)) return '校验失败：地址无法解析，请检查 IP/域名';
  if (/不是 root|UID=/i.test(message)) return '校验失败：当前用户不是 root';
  if (/\/root|root 权限|写入测试文件/i.test(message)) return '校验失败：无法写入 /root，权限不足';
  if (/IPC 未连接/i.test(message)) return 'IPC 未连接，请使用 `npm run dev` 或 `npm start` 启动桌面应用';
  return message || '校验失败，请检查服务器配置';
};

const parseFingerprintValidation = (message) => {
  const text = String(message || '');
  if (text.startsWith('HOST_FINGERPRINT_UNKNOWN|')) {
    const [, fingerprint] = text.split('|');
    return {
      type: 'unknown',
      fingerprint: fingerprint || '',
      detail: `首次连接到该服务器。请先在带外渠道核对 SSH 主机指纹，再点击“信任指纹并保存”。\n${fingerprint || ''}`
    };
  }

  if (text.startsWith('HOST_FINGERPRINT_MISMATCH|')) {
    const [, expectedFingerprint, fingerprint] = text.split('|');
    return {
      type: 'mismatch',
      fingerprint: fingerprint || '',
      expectedFingerprint: expectedFingerprint || '',
      detail: `SSH 主机指纹与已保存记录不一致，已阻止连接。\n已保存: ${expectedFingerprint || '未知'}\n当前返回: ${fingerprint || '未知'}`
    };
  }

  return null;
};

const getErrorSolution = (message) => {
  if (!/setfacl|安装 acl|缺少 acl/i.test(String(message || ''))) return null;

  return {
    title: '安装 ACL 工具',
    reason: '启用站点 SSH 需要使用 setfacl 给专用用户授权站点目录。当前服务器缺少 setfacl，通常安装 acl 包即可。',
    commands: [
      ['Debian / Ubuntu（root）', 'apt-get update && apt-get install -y acl'],
      ['Debian / Ubuntu（普通用户）', 'sudo apt-get update && sudo apt-get install -y acl'],
      ['CentOS / RHEL / Rocky / AlmaLinux（root）', 'yum install -y acl || dnf install -y acl'],
      ['CentOS / RHEL / Rocky / AlmaLinux（普通用户）', 'sudo yum install -y acl || sudo dnf install -y acl']
    ],
    note: '安装完成后，回到应用重新点击“启用”。'
  };
};

function App() {
  const [servers, setServers] = useState([]);
  const [selectedId, setSelectedId] = useState('');
  const [serverForm, setServerForm] = useState(emptyServerForm);
  const [serverFormErrors, setServerFormErrors] = useState({});
  const [serverValidation, setServerValidation] = useState({ status: 'idle', text: '' });
  const [editingServer, setEditingServer] = useState(null);
  const [serverDialogOpen, setServerDialogOpen] = useState(false);
  const [sites, setSites] = useState([]);
  const [selectedSiteId, setSelectedSiteId] = useState('');
  const [search, setSearch] = useState('');
  const [activeSite, setActiveSite] = useState(null);
  const [provisionForm, setProvisionForm] = useState(defaultProvision);
  const [sshConfigPath, setSshConfigPath] = useState('');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState(null);
  const [solutionDialog, setSolutionDialog] = useState(null);
  const [confirmDialog, setConfirmDialog] = useState(null);
  const [logLines, setLogLines] = useState([]);

  const selectedServer = useMemo(
    () => servers.find((server) => server.id === selectedId),
    [servers, selectedId]
  );

  const selectedSite = useMemo(
    () => sites.find((site) => getSiteKey(site) === selectedSiteId),
    [sites, selectedSiteId]
  );

  const filteredSites = useMemo(() => {
    const keyword = search.trim().toLowerCase();
    if (!keyword) return sites;
    return sites.filter((site) =>
      [site.name, site.path, site.note, ...(site.domains || [])]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(keyword))
    );
  }, [search, sites]);

  useEffect(() => {
    if (!api) return;
    loadServers();
    api.getLocalConfigPath().then((result) => {
      if (result.ok) setSshConfigPath(result.data);
    });
  }, []);

  useEffect(() => {
    if (!selectedId && servers.length) {
      setSelectedId(servers[0].id);
    }
  }, [servers, selectedId]);

  useEffect(() => {
    setSites([]);
    setSelectedSiteId('');
    setActiveSite(null);
  }, [selectedId]);

  useEffect(() => {
    if (message?.type !== 'success' || message.exiting) return undefined;
    const messageId = message.id;
    const hideTimer = window.setTimeout(() => {
      setMessage((current) => (current?.id === messageId ? { ...current, exiting: true } : current));
    }, 3000);
    return () => window.clearTimeout(hideTimer);
  }, [message]);

  useEffect(() => {
    if (!message?.exiting) return undefined;
    const messageId = message.id;
    const removeTimer = window.setTimeout(() => {
      setMessage((current) => (current?.id === messageId ? null : current));
    }, 250);
    return () => window.clearTimeout(removeTimer);
  }, [message]);

  const loadServers = async () => {
    try {
      const list = await callApi(api.listServers);
      setServers(list);
    } catch (error) {
      notify('error', error.message);
    }
  };

  const addLog = (type, text) => {
    setLogLines((prev) => [
      { id: crypto.randomUUID(), time: new Date().toLocaleTimeString(), type, text },
      ...prev
    ].slice(0, 80));
  };

  const notify = (type, text) => {
    setMessage({ id: crypto.randomUUID(), type, text, solution: type === 'error' ? getErrorSolution(text) : null });
    addLog(type, text);
  };

  const dismissMessage = () => {
    setMessage((current) => (current ? { ...current, exiting: true } : current));
  };

  const requestConfirm = ({ title, message: confirmMessage, confirmText = '确定', cancelText = '取消', danger = false }) =>
    new Promise((resolve) => {
      setConfirmDialog({
        id: crypto.randomUUID(),
        title,
        message: confirmMessage,
        confirmText,
        cancelText,
        danger,
        resolve
      });
    });

  const closeConfirm = (confirmed) => {
    confirmDialog?.resolve?.(confirmed);
    setConfirmDialog(null);
  };

  const runBusy = async (key, task, successText) => {
    setBusy(key);
    try {
      const data = await task();
      if (successText) notify('success', successText(data));
      return data;
    } catch (error) {
      notify('error', error.message);
      throw error;
    } finally {
      setBusy('');
    }
  };

  const openNewServer = () => {
    setEditingServer(null);
    setServerForm(emptyServerForm);
    setServerFormErrors({});
    setServerValidation({ status: 'idle', text: '' });
    setServerDialogOpen(true);
  };

  const editServer = (server) => {
    setEditingServer(server.id);
    setServerForm({ ...emptyServerForm, ...server });
    setServerFormErrors({});
    setServerValidation({ status: 'idle', text: '' });
    setServerDialogOpen(true);
  };

  const closeServerDialog = () => {
    if (busy === 'server-save') return;
    setServerFormErrors({});
    setServerValidation({ status: 'idle', text: '' });
    setServerDialogOpen(false);
  };

  const saveCurrentServer = async ({ trustFingerprint = false } = {}) => {
    const errors = validateServerForm(serverForm);
    setServerFormErrors(errors);

    if (Object.keys(errors).length > 0) {
      setServerValidation({ status: 'error', text: '表单有误', detail: '请先修正服务器配置表单' });
      return;
    }

    setBusy('server-save');
    setServerValidation({ status: 'checking', text: '校验中' });

    try {
      const wasEditing = Boolean(editingServer);
      const fingerprintPayload = trustFingerprint
        ? {
            hostFingerprint: serverValidation.fingerprint || serverForm.hostFingerprint,
            hostFingerprintAlgo: 'SHA256'
          }
        : {};
      const accessResult = await callApi(api.validateServerAccess, {
        ...serverForm,
        ...fingerprintPayload,
        id: editingServer || serverForm.id
      });
      const savedServer = await callApi(api.saveServer, {
        ...serverForm,
        ...fingerprintPayload,
        id: editingServer || serverForm.id
      });
      await loadServers();
      setSelectedId(savedServer.id);
      if (wasEditing) {
        setEditingServer(savedServer.id);
        setServerForm({ ...emptyServerForm, ...savedServer });
      } else {
        setEditingServer(null);
        setServerForm(emptyServerForm);
      }
      setServerValidation({
        status: savedServer.deduped ? 'warning' : 'success',
        text: savedServer.deduped ? '发现重复，已更新' : wasEditing ? '保存成功' : '添加成功',
        detail: `${savedServer.deduped ? '相同 IP/域名和端口已存在，已更新原服务器。' : 'SSH 校验通过。'}用户 ${accessResult.whoami || 'root'}，UID=${accessResult.uid}`
      });
    } catch (error) {
      const detail = error.message || '连接校验失败';
      const fingerprintInfo = parseFingerprintValidation(detail);
      setServerValidation(
        fingerprintInfo
          ? {
              status: fingerprintInfo.type === 'unknown' ? 'warning' : 'error',
              text: summarizeValidationError(detail),
              detail: fingerprintInfo.detail,
              fingerprint: fingerprintInfo.fingerprint,
              expectedFingerprint: fingerprintInfo.expectedFingerprint || '',
              fingerprintType: fingerprintInfo.type
            }
          : { status: 'error', text: summarizeValidationError(detail), detail }
      );
    } finally {
      setBusy('');
    }
  };

  const deleteServer = async (serverId) => {
    const server = servers.find((item) => item.id === serverId);
    const confirmed = await requestConfirm({
      title: '删除服务器配置？',
      message: `${server?.name || '当前服务器'} 会从侧栏移除。本地 SSH key 和 ~/.ssh/config 不会自动删除。`,
      confirmText: '删除',
      cancelText: '取消',
      danger: true
    });
    if (!confirmed) return false;
    await runBusy(`server-delete-${serverId}`, async () => {
      await callApi(api.removeServer, serverId);
      await loadServers();
      if (selectedId === serverId) {
        setSelectedId('');
      }
    }, () => '已删除服务器配置');
    return true;
  };

  const deleteCurrentServer = async () => {
    if (!editingServer) return;
    const removed = await deleteServer(editingServer);
    if (!removed) return;
    setEditingServer(null);
    setServerForm(emptyServerForm);
    setServerFormErrors({});
    setServerValidation({ status: 'idle', text: '' });
    setServerDialogOpen(false);
  };

  const loadSites = async () => {
    if (!selectedServer) return;
    const list = await runBusy(
      'sites-load',
      () => callApi(api.listSites, selectedServer.id),
      (data) => `已读取 ${data.length} 个站点`
    );
    const previousState = new Map(
      sites.map((site) => [
        getSiteKey(site),
        {
          sshEnabled: Boolean(site.sshEnabled),
          sshAlias: site.sshAlias,
          sshUsername: site.sshUsername,
          sshKeyPath: site.sshKeyPath
        }
      ])
    );
    setSites(
      list.map((site) => ({
        ...site,
        ...(previousState.get(getSiteKey(site)) || {})
      }))
    );
    setSelectedSiteId('');
  };

  const choosePrivateKey = async () => {
    const filePath = await callApi(api.selectPrivateKey);
    if (filePath) {
      setServerForm((prev) => ({ ...prev, privateKeyPath: filePath }));
      setServerFormErrors((prev) => ({ ...prev, privateKeyPath: '' }));
      setServerValidation({ status: 'idle', text: '' });
    }
  };

  const openProvision = (site) => {
    const username = toLinuxUser(site.name || site.id || 'site');
    setActiveSite(site);
    setProvisionForm({
      username,
      alias: toAlias(selectedServer, site),
      keyPath: getDefaultKeyPath(selectedServer, username, sshConfigPath)
    });
  };

  const updateProvisionUsername = (value) => {
    const username = toLinuxUser(value);
    setProvisionForm((prev) => {
      const previousDefaultPath = getDefaultKeyPath(selectedServer, prev.username, sshConfigPath);
      const shouldUpdateKeyPath = !prev.keyPath || prev.keyPath === previousDefaultPath;
      return {
        ...prev,
        username,
        keyPath: shouldUpdateKeyPath ? getDefaultKeyPath(selectedServer, username, sshConfigPath) : prev.keyPath
      };
    });
  };

  const chooseProvisionKeyPath = async () => {
    const filePath = await callApi(api.selectLocalKeyPath, provisionForm.keyPath);
    if (filePath) {
      setProvisionForm((prev) => ({ ...prev, keyPath: filePath }));
    }
  };

  const testSite = async (site) => {
    if (!selectedServer) return;
    const siteName = site.name || site.path || '未命名站点';
    const busyKey = `site-test-${site.id || getSiteKey(site)}`;
    addLog('info', `开始测试站点：${siteName}`);
    setBusy(busyKey);
    try {
      const result = await callApi(api.testSite, {
        serverId: selectedServer.id,
        site
      });
      result.checks.forEach((check) => {
        const logType = check.status === 'fail' ? 'error' : check.status === 'pass' ? 'success' : 'info';
        addLog(logType, `${siteName} / ${check.label}：${check.message}`);
      });
      const summaryText = `站点测试完成：${siteName}（${summarizeSiteTest(result.summary)}）`;
      notify((result.summary?.fail || 0) > 0 ? 'error' : 'success', summaryText);
    } catch (error) {
      notify('error', `站点测试失败：${siteName}（${error.message}）`);
    } finally {
      setBusy('');
    }
  };

  const provisionSite = async () => {
    if (!selectedServer || !activeSite) return;
    const siteName = activeSite.name || activeSite.path || '未命名站点';
    addLog('info', `开始启用站点 SSH：${siteName}（用户 ${provisionForm.username}）`);
    const result = await runBusy(
      'site-provision',
      () =>
        callApi(api.provisionSite, {
          serverId: selectedServer.id,
          site: activeSite,
          options: provisionForm
        }),
      (data) => `启用完成：${siteName}（${data.directCommand || `ssh ${data.username}@${selectedServer.host}`}）`
    );
    const enabledSiteKey = getSiteKey(activeSite);
    setSites((prev) =>
      prev.map((site) =>
        getSiteKey(site) === enabledSiteKey
          ? {
              ...site,
              sshEnabled: true,
              sshAlias: result.alias,
              sshUsername: result.username,
              sshKeyPath: result.keyPath
            }
          : site
      )
    );
    setSelectedSiteId(enabledSiteKey);
    setActiveSite(null);
    notify('info', `本地秘钥: ${result.keyPath}`);
  };

  const disableSite = async (site) => {
    if (!selectedServer) return;
    const siteName = site.name || site.path || '未命名站点';
    const username = site.sshUsername || toLinuxUser(site.name || site.id || 'site');
    const alias = site.sshAlias || toAlias(selectedServer, site);
    const confirmed = await requestConfirm({
      title: `禁用 ${site.name} 的站点 SSH？`,
      message: `远程用户 ${username} 会被锁定，并移除本地 SSH 配置。`,
      confirmText: '确定',
      cancelText: '取消',
      danger: true
    });
    if (!confirmed) return;
    addLog('info', `开始禁用站点 SSH：${siteName}（用户 ${username}）`);
    await runBusy(
      `site-disable-${site.id}`,
      () =>
        callApi(api.disableSite, {
          serverId: selectedServer.id,
          site,
          options: { username, alias, keyPath: site.sshKeyPath }
      }),
      (data) => `禁用完成：${siteName}（${data.stdout || `用户 ${data.username}`}）`
    );
    const disabledSiteKey = getSiteKey(site);
    setSites((prev) =>
      prev.map((item) =>
        getSiteKey(item) === disabledSiteKey
          ? {
              ...item,
              sshEnabled: false,
              sshAlias: '',
              sshUsername: ''
            }
          : item
      )
    );
    setSelectedSiteId(disabledSiteKey);
  };

  return (
    <div className="flex h-screen bg-slate-50 text-slate-900">
      <aside className="flex w-[304px] shrink-0 flex-col border-r border-slate-200 bg-white">
        <div className="flex h-16 items-center justify-between border-b border-slate-200 px-4">
          <div className="flex items-center gap-2">
            <img className="h-9 w-9 rounded-md" src={appIcon} alt="" />
            <div>
              <h1 className="text-base font-semibold leading-tight">宝塔站点 SSH</h1>
              <p className="text-xs text-slate-500">站点专用账号管理</p>
            </div>
          </div>
          <IconButton title="新增服务器" onClick={openNewServer}>
            <Plus size={18} />
          </IconButton>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto p-3 scrollbar-thin">
          {servers.length === 0 ? (
            <EmptySidebar />
          ) : (
            <div className="space-y-2">
              {servers.map((server) => (
                <div
                  key={server.id}
                  className={`flex w-full items-start gap-2 rounded-md border p-3 text-left transition ${
                    selectedId === server.id
                      ? 'border-sky-300 bg-sky-50 text-sky-950'
                      : 'border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50'
                  }`}
                >
                  <button className="min-w-0 flex-1 text-left" onClick={() => setSelectedId(server.id)} type="button">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-semibold">{server.name}</div>
                      <div className="mt-1 truncate text-xs text-slate-500">
                        {server.username}@{server.host}:{server.port}
                      </div>
                    </div>
                  </button>
                  <button
                    className="grid h-8 w-8 shrink-0 place-items-center rounded-md text-slate-500 hover:bg-slate-100 hover:text-slate-800"
                    title="编辑服务器"
                    aria-label={`编辑服务器 ${server.name}`}
                    onClick={() => editServer(server)}
                    type="button"
                  >
                    <Settings size={15} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

      </aside>

      <main className="relative flex min-w-0 flex-1 flex-col">
        <Header
          server={selectedServer}
          selectedSite={selectedSite}
          busy={busy}
          onLoadSites={loadSites}
        />

        <StatusBar message={message} onOpenSolution={setSolutionDialog} onDismiss={dismissMessage} />

        <div className="flex min-h-0 flex-1 flex-col">
          <section className="min-h-0 min-w-0 flex-1 overflow-y-auto p-5 scrollbar-thin">
            {!selectedServer ? (
              api ? <EmptyMain /> : <DesktopOnlyState />
            ) : (
              <>
                <Toolbar
                  search={search}
                  setSearch={setSearch}
                  count={filteredSites.length}
                  total={sites.length}
                  configPath={sshConfigPath}
                />
                <SiteTable
                  sites={filteredSites}
                  selectedSiteId={selectedSiteId}
                  busy={busy}
                  onSelect={(site) => setSelectedSiteId(getSiteKey(site))}
                  onTest={testSite}
                  onProvision={openProvision}
                  onDisable={disableSite}
                />
              </>
            )}
          </section>

          <Inspector logLines={logLines} />
        </div>
      </main>

      {activeSite ? (
        <ProvisionDialog
          site={activeSite}
          server={selectedServer}
          form={provisionForm}
          setForm={setProvisionForm}
          busy={busy}
          onClose={() => setActiveSite(null)}
          onUsernameChange={updateProvisionUsername}
          onPickKeyPath={chooseProvisionKeyPath}
          onConfirm={provisionSite}
        />
      ) : null}

      {serverDialogOpen ? (
        <ServerDialog
          form={serverForm}
          setForm={setServerForm}
          errors={serverFormErrors}
          setErrors={setServerFormErrors}
          validation={serverValidation}
          setValidation={setServerValidation}
          editing={Boolean(editingServer)}
          busy={busy}
          onClose={closeServerDialog}
          onSave={saveCurrentServer}
          onDelete={deleteCurrentServer}
          onPickKey={choosePrivateKey}
        />
      ) : null}

      {solutionDialog ? (
        <SolutionDialog solution={solutionDialog} onClose={() => setSolutionDialog(null)} />
      ) : null}

      {confirmDialog ? (
        <ConfirmDialog dialog={confirmDialog} onCancel={() => closeConfirm(false)} onConfirm={() => closeConfirm(true)} />
      ) : null}
    </div>
  );
}

function ConfirmDialog({ dialog, onCancel, onConfirm }) {
  return (
    <div className="fixed inset-0 z-[70] grid place-items-center bg-slate-900/35 p-6">
      <div
        className="w-full max-w-[520px] rounded-md bg-white shadow-xl"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-message"
      >
        <div className="flex items-start gap-4 border-b border-slate-200 p-5">
          <img className="h-12 w-12 shrink-0 rounded-xl" src={appIcon} alt="" />
          <div className="min-w-0">
            <h3 id="confirm-dialog-title" className="text-lg font-semibold text-slate-900">
              {dialog.title}
            </h3>
            <p id="confirm-dialog-message" className="mt-2 text-sm leading-6 text-slate-600">
              {dialog.message}
            </p>
          </div>
        </div>
        <div className="flex justify-end gap-2 border-t border-slate-200 bg-slate-50 p-4">
          <button
            className="h-9 rounded-md border border-slate-300 bg-white px-4 text-sm font-semibold text-slate-700 hover:bg-slate-100"
            onClick={onCancel}
            type="button"
          >
            {dialog.cancelText}
          </button>
          <button
            className={`h-9 rounded-md px-4 text-sm font-semibold text-white ${
              dialog.danger ? 'bg-rose-600 hover:bg-rose-700' : 'bg-sky-600 hover:bg-sky-700'
            }`}
            onClick={onConfirm}
            type="button"
          >
            {dialog.confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}

function ServerDialog({ form, setForm, errors, setErrors, validation, setValidation, editing, busy, onClose, onSave, onDelete, onPickKey }) {
  const update = (field, value) => {
    setForm((prev) => ({
      ...prev,
      [field]: value,
      ...(field === 'host' || field === 'port'
        ? { hostFingerprint: '', hostFingerprintAlgo: '' }
        : {})
    }));
    setErrors((prev) => ({ ...prev, [field]: '' }));
    setValidation({ status: 'idle', text: '' });
  };
  const isSaving = busy === 'server-save';
  const isDeleting = String(busy).startsWith('server-delete-');

  return (
    <div className="fixed inset-0 z-30 grid place-items-center bg-slate-900/35 p-6">
      <div
        className="w-full max-w-[620px] rounded-md bg-white shadow-xl"
        role="dialog"
        aria-modal="true"
        aria-labelledby="server-dialog-title"
      >
        <div className="flex items-start justify-between border-b border-slate-200 p-5">
          <div>
            <div className="flex items-center gap-2">
              <Server size={18} className="text-sky-700" />
              <h3 id="server-dialog-title" className="text-lg font-semibold">
                {editing ? '编辑服务器' : '新增服务器'}
              </h3>
              <Tip text="凭据只保存在本机 Electron userData 目录。生产环境可继续接入系统钥匙串。" />
            </div>
            <p className="mt-1 text-sm text-slate-500">保存后不会自动关闭，请通过关闭或取消按钮返回主界面。</p>
          </div>
          <IconButton title="关闭" onClick={onClose} disabled={isSaving || isDeleting}>
            <X size={18} />
          </IconButton>
        </div>
        <div className="grid grid-cols-2 gap-3 p-5">
          <TextField label="名称" value={form.name} onChange={(value) => update('name', value)} placeholder="生产服务器" error={errors.name} />
          <TextField label="端口" type="number" value={form.port} onChange={(value) => update('port', value)} error={errors.port} />
          <div className="col-span-2">
            <TextField label="地址" value={form.host} onChange={(value) => update('host', value)} placeholder="1.2.3.4" error={errors.host} />
          </div>
          <TextField label="用户" value={form.username} onChange={(value) => update('username', value)} placeholder="root" error={errors.username} />
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-600">认证</label>
            <div className="grid grid-cols-2 rounded-md border border-slate-200 bg-white p-0.5">
              {[
                ['password', '密码'],
                ['key', '私钥']
              ].map(([value, label]) => (
                <button
                  key={value}
                  className={`h-8 rounded text-xs font-medium ${
                    form.authType === value ? 'bg-sky-600 text-white' : 'text-slate-600 hover:bg-slate-100'
                  }`}
                  onClick={() => {
                    update('authType', value);
                    setErrors((prev) => ({ ...prev, password: '', privateKeyPath: '' }));
                  }}
                  type="button"
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
          {form.authType === 'password' ? (
            <div className="col-span-2">
              <TextField
                label="root 密码"
                type="password"
                value={form.password}
                onChange={(value) => update('password', value)}
                placeholder={form.hasPassword ? '留空则沿用已保存密码' : '服务器 root 密码'}
                error={errors.password}
              />
            </div>
          ) : (
            <>
              <div className="col-span-2">
                <label className="mb-1 block text-xs font-medium text-slate-600">root 私钥</label>
                <div className="flex gap-2">
                  <input
                    className={`h-9 min-w-0 flex-1 rounded-md border bg-white px-3 text-sm outline-none focus:ring-2 ${
                      errors.privateKeyPath
                        ? 'border-rose-300 focus:border-rose-500 focus:ring-rose-100'
                        : 'border-slate-300 focus:border-sky-500 focus:ring-sky-100'
                    }`}
                    value={form.privateKeyPath}
                    onChange={(event) => update('privateKeyPath', event.target.value)}
                    placeholder="~/.ssh/id_rsa"
                    aria-invalid={Boolean(errors.privateKeyPath)}
                  />
                  <IconButton title="选择私钥" onClick={onPickKey}>
                    <FolderKey size={17} />
                  </IconButton>
                </div>
                {errors.privateKeyPath ? <FieldError>{errors.privateKeyPath}</FieldError> : null}
              </div>
              <div className="col-span-2">
                <TextField
                  label="私钥口令"
                  type="password"
                  value={form.passphrase}
                  onChange={(value) => update('passphrase', value)}
                  placeholder="可留空"
                />
              </div>
            </>
          )}
          {form.hostFingerprint ? (
            <div className="col-span-2 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs leading-5 text-slate-700">
              已保存 SSH 主机指纹：<code className="font-mono">{form.hostFingerprint}</code>
            </div>
          ) : null}
        </div>
        <div className="flex min-h-16 items-center justify-between gap-4 border-t border-slate-200 bg-slate-50 p-4">
          <ValidationStatus validation={validation} />
          <div className="flex shrink-0 justify-end gap-2">
            {editing ? (
              <button
                className="inline-flex h-9 items-center gap-2 rounded-md border border-rose-200 bg-white px-3 text-sm font-semibold text-rose-600 hover:bg-rose-50 disabled:opacity-60"
                onClick={onDelete}
                disabled={isSaving || isDeleting}
                type="button"
              >
                {isDeleting ? <Loader2 size={16} className="animate-spin" /> : <Trash2 size={16} />}
                删除
              </button>
            ) : null}
            <button
              className="h-9 rounded-md border border-slate-300 bg-white px-3 text-sm font-semibold text-slate-700 hover:bg-slate-100 disabled:opacity-60"
              onClick={onClose}
              disabled={isSaving || isDeleting}
              type="button"
            >
              取消
            </button>
            <button
              className="inline-flex h-9 items-center gap-2 rounded-md bg-sky-600 px-3 text-sm font-semibold text-white shadow-sm hover:bg-sky-700 disabled:opacity-60"
              onClick={onSave}
              disabled={isSaving || isDeleting}
              type="button"
            >
              <Save size={16} />
              保存服务器
            </button>
            {['unknown', 'mismatch'].includes(validation.fingerprintType) && validation.fingerprint ? (
              <button
                className="inline-flex h-9 items-center gap-2 rounded-md border border-amber-300 bg-amber-50 px-3 text-sm font-semibold text-amber-900 hover:bg-amber-100 disabled:opacity-60"
                onClick={() => onSave({ trustFingerprint: true })}
                disabled={isSaving || isDeleting}
                type="button"
              >
                <ShieldCheck size={16} />
                {validation.fingerprintType === 'mismatch' ? '更新指纹并保存' : '信任指纹并保存'}
              </button>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}

function Header({ server, selectedSite, busy, onLoadSites }) {
  return (
    <header className="flex h-16 shrink-0 items-center justify-between border-b border-slate-200 bg-white px-5">
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <h2 className="truncate text-lg font-semibold">{server ? server.name : '未选择服务器'}</h2>
          {server ? <span className="rounded bg-slate-100 px-2 py-0.5 text-xs text-slate-600">{server.host}</span> : null}
          {selectedSite ? <span className="rounded bg-emerald-50 px-2 py-0.5 text-xs text-emerald-700">{selectedSite.name}</span> : null}
        </div>
        <p className="mt-0.5 text-xs text-slate-500">读取宝塔站点后，为指定站点创建免密 SSH 登录账号。</p>
      </div>
      <div className="flex items-center gap-2">
        <ActionButton icon={RefreshCw} label="读取站点" busy={busy === 'sites-load'} onClick={onLoadSites} disabled={!server} primary />
      </div>
    </header>
  );
}

function Toolbar({ search, setSearch, count, total, configPath }) {
  return (
    <div className="mb-4 flex items-center justify-between gap-4">
      <div>
        <div className="flex items-center gap-2">
          <h3 className="text-base font-semibold">站点列表</h3>
          <span className="rounded bg-slate-100 px-2 py-0.5 text-xs text-slate-500">
            {count}/{total}
          </span>
          <Tip text={`启用后会写入 ${configPath || '~/.ssh/config'}，可直接使用 ssh 用户名@服务器地址 登录。`} />
        </div>
        <p className="mt-1 text-xs text-slate-500">不会修改站点属主，通过 ACL 授权专用用户访问。</p>
      </div>
      <div className="relative w-[320px]">
        <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
        <input
          className="h-9 w-full rounded-md border border-slate-300 bg-white pl-9 pr-3 text-sm outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-100"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="搜索站点、路径或域名"
        />
      </div>
    </div>
  );
}

function SiteTable({ sites, selectedSiteId, busy, onSelect, onTest, onProvision, onDisable }) {
  if (sites.length === 0) {
    return (
      <div className="grid h-[360px] place-items-center rounded-md border border-dashed border-slate-300 bg-white">
        <div className="text-center">
          <KeyRound size={34} className="mx-auto text-slate-400" />
          <div className="mt-3 text-sm font-semibold text-slate-700">暂无站点数据</div>
          <div className="mt-1 text-xs text-slate-500">点击右上角“读取站点”从宝塔数据库加载。</div>
        </div>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-md border border-slate-200 bg-white">
      <table className="w-full table-fixed border-collapse text-left">
        <thead className="bg-slate-100 text-xs font-semibold uppercase tracking-wide text-slate-500">
          <tr>
            <th className="w-[30%] px-4 py-3">站点</th>
            <th className="px-4 py-3">目录</th>
            <th className="w-[280px] px-4 py-3 text-right">操作</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {sites.map((site) => (
            <tr
              key={site.id || `${site.name}-${site.path}`}
              className={`cursor-pointer hover:bg-slate-50 ${
                getSiteKey(site) === selectedSiteId ? 'bg-sky-50 outline outline-1 outline-sky-200' : ''
              }`}
              onClick={() => onSelect(site)}
            >
              <td className="px-4 py-3 align-top">
                <div className="flex min-w-0 items-center gap-2">
                  <div className="truncate text-sm font-semibold">{site.name || site.note || '未命名站点'}</div>
                  {site.sshEnabled ? <span className="shrink-0 rounded bg-emerald-50 px-1.5 py-0.5 text-[11px] font-medium text-emerald-700">SSH</span> : null}
                </div>
                <div className="mt-1 text-xs text-slate-500">ID {site.id || '-'}</div>
              </td>
              <td className="px-4 py-3 align-top">
                <div className="truncate text-sm text-slate-700">{site.path || '-'}</div>
                {site.sshKeyPath ? (
                  <div className="mt-1 truncate text-xs text-slate-500">本地秘钥: {site.sshKeyPath}</div>
                ) : null}
              </td>
              <td className="px-4 py-3 align-top">
                <div className="flex justify-end gap-2">
                  <button
                    className="inline-flex h-8 shrink-0 items-center gap-1 whitespace-nowrap rounded-md border border-slate-300 bg-white px-2.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-60"
                    onClick={(event) => {
                      event.stopPropagation();
                      onTest(site);
                    }}
                    disabled={busy === `site-test-${site.id || getSiteKey(site)}` || !site.sshEnabled}
                    type="button"
                  >
                    {busy === `site-test-${site.id || getSiteKey(site)}` ? <Loader2 size={14} className="animate-spin" /> : <ShieldCheck size={14} />}
                    测试
                  </button>
                  <button
                    className="inline-flex h-8 shrink-0 items-center gap-1 whitespace-nowrap rounded-md bg-emerald-600 px-2.5 text-xs font-semibold text-white hover:bg-emerald-700 disabled:bg-slate-200 disabled:text-slate-500"
                    onClick={(event) => {
                      event.stopPropagation();
                      onProvision(site);
                    }}
                    disabled={Boolean(site.sshEnabled)}
                    type="button"
                  >
                    <KeyRound size={14} />
                    {site.sshEnabled ? '已启用' : '启用'}
                  </button>
                  <button
                    className="inline-flex h-8 shrink-0 items-center gap-1 whitespace-nowrap rounded-md border border-slate-300 bg-white px-2.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-60"
                    onClick={(event) => {
                      event.stopPropagation();
                      onDisable(site);
                    }}
                    disabled={busy === `site-disable-${site.id}` || !site.sshEnabled}
                    type="button"
                  >
                    {busy === `site-disable-${site.id}` ? <Loader2 size={14} className="animate-spin" /> : <X size={14} />}
                    禁用
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Inspector({ logLines }) {
  return (
    <section className="flex h-56 min-h-44 shrink-0 flex-col border-t border-slate-200 bg-white">
      <div className="flex min-h-0 flex-1 flex-col p-4">
        <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
          <Terminal size={16} className="text-sky-600" />
          操作日志
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto rounded-md border border-slate-200 bg-slate-950 p-3 font-mono text-xs text-slate-100 scrollbar-thin">
          {logLines.length === 0 ? (
            <div className="text-slate-400">等待操作...</div>
          ) : (
            logLines.map((line) => (
              <div key={line.id} className="mb-2 leading-5">
                <span className="text-slate-500">[{line.time}]</span>{' '}
                <span className={line.type === 'error' ? 'text-rose-300' : line.type === 'success' ? 'text-emerald-300' : 'text-sky-300'}>
                  {line.text}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </section>
  );
}

function ProvisionDialog({ site, server, form, setForm, busy, onClose, onUsernameChange, onPickKeyPath, onConfirm }) {
  const update = (field, value) => setForm((prev) => ({ ...prev, [field]: value }));
  return (
    <div className="fixed inset-0 z-30 grid place-items-center bg-slate-900/35 p-6">
      <div className="w-full max-w-[560px] rounded-md bg-white shadow-xl">
        <div className="flex items-start justify-between border-b border-slate-200 p-5">
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-lg font-semibold">启用站点 SSH</h3>
              <Tip text="应用会生成本地 ed25519 密钥，远程写入 authorized_keys，并使用 setfacl 授权站点目录。" />
            </div>
            <p className="mt-1 text-sm text-slate-500">{site.name} · {server?.host}</p>
          </div>
          <IconButton title="关闭" onClick={onClose}>
            <X size={18} />
          </IconButton>
        </div>
        <div className="space-y-4 p-5">
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-600">站点路径</label>
            <code className="block rounded-md border border-slate-200 bg-slate-100 px-3 py-2 text-sm text-slate-700">{site.path}</code>
          </div>
          <div className="max-w-[260px]">
            <TextField label="远程用户名" value={form.username} onChange={onUsernameChange} />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-600">本地密钥保存路径</label>
            <div className="flex gap-2">
              <input
                className="h-9 min-w-0 flex-1 rounded-md border border-slate-300 bg-white px-3 text-sm outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-100"
                value={form.keyPath}
                onChange={(event) => update('keyPath', event.target.value)}
                placeholder="~/.ssh/bt-ssh/site_ed25519"
              />
              <IconButton title="选择保存路径" onClick={onPickKeyPath}>
                <FolderKey size={17} />
              </IconButton>
            </div>
          </div>
          <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-xs leading-5 text-amber-900">
            ACL 会追加专用用户权限，不会 chown 站点目录。若目录文件很多，首次递归授权可能需要一点时间。
          </div>
        </div>
        <div className="flex justify-end gap-2 border-t border-slate-200 bg-slate-50 p-4">
          <button className="h-9 rounded-md border border-slate-300 bg-white px-3 text-sm font-semibold text-slate-700 hover:bg-slate-100" onClick={onClose} type="button">
            取消
          </button>
          <button
            className="inline-flex h-9 items-center gap-2 rounded-md bg-emerald-600 px-3 text-sm font-semibold text-white hover:bg-emerald-700 disabled:opacity-60"
            onClick={onConfirm}
            disabled={busy === 'site-provision'}
            type="button"
          >
            {busy === 'site-provision' ? <Loader2 size={16} className="animate-spin" /> : <KeyRound size={16} />}
            创建并写入配置
          </button>
        </div>
      </div>
    </div>
  );
}

function StatusBar({ message, onOpenSolution, onDismiss }) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (!message) return undefined;
    if (message.exiting) {
      setVisible(false);
      return undefined;
    }

    setVisible(false);
    const frame = window.requestAnimationFrame(() => setVisible(true));
    return () => window.cancelAnimationFrame(frame);
  }, [message?.id, message?.exiting]);

  if (!message) return null;

  const palette = {
    info: 'border-sky-200 bg-sky-50 text-sky-800',
    success: 'border-emerald-200 bg-emerald-50 text-emerald-800',
    error: 'border-rose-200 bg-rose-50 text-rose-800'
  };
  const Icon = message.type === 'error' ? AlertTriangle : message.type === 'success' ? Check : Terminal;
  const messageTextClass =
    message.type === 'error'
      ? 'min-w-0 flex-1 whitespace-normal break-words leading-5'
      : 'min-w-0 flex-1 truncate';
  return (
    <div
      className={`absolute left-1/2 top-4 z-50 flex min-h-10 max-w-[min(640px,calc(100%_-_32px))] -translate-x-1/2 items-start gap-2 rounded-md border px-4 py-3 text-sm shadow-lg transition-all duration-200 ease-out ${
        visible ? 'translate-y-0 opacity-100' : '-translate-y-8 opacity-0'
      } ${palette[message.type] || palette.info}`}
    >
      <Icon size={16} className="mt-0.5 shrink-0" />
      <span className={messageTextClass}>{message.text}</span>
      {message.solution ? (
        <button
          className="mt-0.5 shrink-0 text-sm font-semibold leading-5 underline-offset-2 hover:underline"
          onClick={() => onOpenSolution(message.solution)}
          type="button"
        >
          解决方案
        </button>
      ) : null}
      <button
        className="grid h-6 w-6 shrink-0 place-items-center rounded opacity-80 hover:bg-black/5 hover:opacity-100"
        onClick={onDismiss}
        title="关闭提示"
        aria-label="关闭提示"
        type="button"
      >
        <X size={16} />
      </button>
    </div>
  );
}

function SolutionDialog({ solution, onClose }) {
  return (
    <div className="fixed inset-0 z-[60] grid place-items-center bg-slate-900/35 p-6">
      <div className="w-full max-w-[560px] rounded-md bg-white shadow-xl">
        <div className="flex items-start justify-between border-b border-slate-200 p-5">
          <div>
            <h3 className="text-lg font-semibold">{solution.title}</h3>
            <p className="mt-1 text-sm leading-6 text-slate-600">{solution.reason}</p>
          </div>
          <IconButton title="关闭" onClick={onClose}>
            <X size={18} />
          </IconButton>
        </div>
        <div className="space-y-3 p-5">
          {solution.commands.map(([label, command]) => (
            <div key={label}>
              <div className="mb-1 text-xs font-semibold text-slate-500">{label}</div>
              <code className="block overflow-x-auto rounded-md bg-slate-950 px-3 py-2 font-mono text-xs text-slate-100">
                {command}
              </code>
            </div>
          ))}
          <div className="rounded-md border border-sky-200 bg-sky-50 p-3 text-xs leading-5 text-sky-800">
            {solution.note}
          </div>
        </div>
        <div className="flex justify-end border-t border-slate-200 bg-slate-50 p-4">
          <button
            className="h-9 rounded-md bg-sky-600 px-3 text-sm font-semibold text-white hover:bg-sky-700"
            onClick={onClose}
            type="button"
          >
            知道了
          </button>
        </div>
      </div>
    </div>
  );
}

function ValidationStatus({ validation }) {
  const status = validation?.status || 'idle';
  const text = validation?.text || '连接校验';
  const detail = validation?.detail || text;

  if (status === 'checking') {
    return (
      <div className="flex min-w-0 flex-1 items-center gap-2 text-sm font-medium text-sky-700" title={detail}>
        <Loader2 size={16} className="shrink-0 animate-spin" />
        <span className="min-w-0 leading-5">{text}</span>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="flex min-w-0 flex-1 items-center gap-2 text-sm font-medium text-rose-700" title={detail}>
        <AlertTriangle size={16} className="shrink-0" />
        <span className="min-w-0 leading-5">{text}</span>
      </div>
    );
  }

  if (status === 'success') {
    return (
      <div className="flex min-w-0 flex-1 items-center gap-2 text-sm font-medium text-emerald-700" title={detail}>
        <Check size={16} className="shrink-0" />
        <span className="min-w-0 leading-5">{text}</span>
      </div>
    );
  }

  if (status === 'warning') {
    return (
      <div className="flex min-w-0 flex-1 items-center gap-2 text-sm font-medium text-amber-700" title={detail}>
        <AlertTriangle size={16} className="shrink-0" />
        <span className="min-w-0 leading-5">{text}</span>
      </div>
    );
  }

  return (
    <div className="flex min-w-0 flex-1 items-center gap-2 text-sm font-medium text-slate-500">
      <ShieldCheck size={16} className="shrink-0" />
      <span>连接校验</span>
    </div>
  );
}

function TextField({ label, value, onChange, type = 'text', placeholder = '', error = '' }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-slate-600">{label}</span>
      <input
        className={`h-9 w-full rounded-md border bg-white px-3 text-sm outline-none focus:ring-2 ${
          error
            ? 'border-rose-300 focus:border-rose-500 focus:ring-rose-100'
            : 'border-slate-300 focus:border-sky-500 focus:ring-sky-100'
        }`}
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        aria-invalid={Boolean(error)}
      />
      {error ? <FieldError>{error}</FieldError> : null}
    </label>
  );
}

function FieldError({ children }) {
  return <div className="mt-1 text-xs leading-5 text-rose-600">{children}</div>;
}

function ActionButton({ icon: Icon, label, onClick, busy, disabled, primary }) {
  return (
    <button
      className={`inline-flex h-9 items-center gap-2 rounded-md px-3 text-sm font-semibold transition disabled:opacity-55 ${
        primary
          ? 'bg-sky-600 text-white hover:bg-sky-700'
          : 'border border-slate-300 bg-white text-slate-700 hover:bg-slate-50'
      }`}
      onClick={onClick}
      disabled={disabled || busy}
      type="button"
    >
      {busy ? <Loader2 size={16} className="animate-spin" /> : <Icon size={16} />}
      {label}
    </button>
  );
}

function IconButton({ children, title, onClick, disabled, danger }) {
  return (
    <button
      className={`grid h-9 max-h-9 min-h-9 w-9 min-w-9 max-w-9 shrink-0 place-items-center rounded-md border p-0 leading-none transition disabled:opacity-50 ${
        danger
          ? 'border-rose-200 bg-white text-rose-600 hover:bg-rose-50'
          : 'border-slate-300 bg-white text-slate-700 hover:bg-slate-50'
      }`}
      title={title}
      aria-label={title}
      onClick={onClick}
      disabled={disabled}
      type="button"
    >
      {children}
    </button>
  );
}

function Tip({ text }) {
  return (
    <span className="group relative inline-flex">
      <CircleHelp size={15} className="text-slate-400" />
      <span className="pointer-events-none absolute left-1/2 top-6 z-40 hidden w-64 -translate-x-1/2 rounded-md border border-slate-200 bg-white p-2 text-xs font-normal leading-5 text-slate-600 shadow-lg group-hover:block">
        {text}
      </span>
    </span>
  );
}

function EmptySidebar() {
  return (
    <div className="rounded-md border border-dashed border-slate-300 p-4 text-center">
      <Server size={28} className="mx-auto text-slate-400" />
      <div className="mt-2 text-sm font-semibold text-slate-700">还没有服务器</div>
      <div className="mt-1 text-xs leading-5 text-slate-500">点击顶部加号填写 root 登录信息。</div>
    </div>
  );
}

function EmptyMain() {
  return (
    <div className="grid h-full place-items-center">
      <div className="text-center">
        <Terminal size={42} className="mx-auto text-slate-400" />
        <div className="mt-3 text-base font-semibold text-slate-700">选择或添加服务器</div>
        <div className="mt-1 text-sm text-slate-500">随后可以读取宝塔站点并启用专用 SSH。</div>
      </div>
    </div>
  );
}

function DesktopOnlyState() {
  return (
    <div className="grid h-full place-items-center">
      <div className="max-w-md text-center">
        <Terminal size={42} className="mx-auto text-slate-400" />
        <div className="mt-3 text-base font-semibold text-slate-700">请在桌面应用中运行</div>
        <div className="mt-1 text-sm leading-6 text-slate-500">
          当前页面没有连接到 Electron 主进程。请使用 <code>npm run dev</code> 或 <code>npm start</code> 启动桌面应用后再继续。
        </div>
      </div>
    </div>
  );
}

export default App;
