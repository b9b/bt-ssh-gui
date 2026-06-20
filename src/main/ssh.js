import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { Client } from 'ssh2';

const execFileAsync = promisify(execFile);
const commandTimeoutMs = 45_000;

const shellQuote = (value) => `'${String(value).replaceAll("'", "'\"'\"'")}'`;
const fingerprintAlgorithm = 'SHA256';
const hasControlChars = (value) => /[\u0000-\u001f\u007f]/.test(String(value || ''));

class HostFingerprintError extends Error {
  constructor(code, fingerprint, expectedFingerprint = '') {
    super(code);
    this.code = code;
    this.fingerprint = fingerprint;
    this.expectedFingerprint = expectedFingerprint;
  }
}

const buildHostFingerprint = (key) => `${fingerprintAlgorithm}:${createHash('sha256').update(key).digest('base64')}`;

const connect = async (server) => {
  const client = new Client();
  let fingerprintError;
  const config = {
    host: server.host,
    port: Number(server.port || 22),
    username: server.username || 'root',
    readyTimeout: 15_000,
    hostVerifier: (key) => {
      const fingerprint = buildHostFingerprint(key);
      const trustedFingerprint = String(server.hostFingerprint || '').trim();
      if (!trustedFingerprint) {
        fingerprintError = new HostFingerprintError('ERR_HOST_FINGERPRINT_UNKNOWN', fingerprint);
        return false;
      }
      if (trustedFingerprint !== fingerprint) {
        fingerprintError = new HostFingerprintError('ERR_HOST_FINGERPRINT_MISMATCH', fingerprint, trustedFingerprint);
        return false;
      }
      return true;
    }
  };

  if (server.authType === 'key') {
    if (!server.privateKeyPath) {
      throw new Error('请先选择 root 私钥');
    }
    config.privateKey = await fs.readFile(expandHome(server.privateKeyPath), 'utf8');
    if (server.passphrase) {
      config.passphrase = server.passphrase;
    }
  } else {
    config.password = server.password || '';
  }

  return new Promise((resolve, reject) => {
    client
      .on('ready', () => resolve(client))
      .on('error', (error) => reject(fingerprintError || error))
      .connect(config);
  });
};

export const runRemote = async (server, command, options = {}) => {
  const client = await connect(server);
  const timeoutMs = options.timeoutMs || commandTimeoutMs;

  try {
    return await new Promise((resolve, reject) => {
      let stdout = '';
      let stderr = '';
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          client.end();
          reject(new Error('远程命令执行超时'));
        }
      }, timeoutMs);

      client.exec(command, (error, stream) => {
        if (error) {
          clearTimeout(timer);
          settled = true;
          reject(error);
          return;
        }

        stream
          .on('close', (code) => {
            if (settled) return;
            clearTimeout(timer);
            settled = true;
            const result = { code, stdout, stderr };
            if (code === 0 || options.allowNonZero) {
              resolve(result);
            } else {
              reject(new Error(stderr.trim() || stdout.trim() || `远程命令失败：${code}`));
            }
          })
          .on('data', (data) => {
            stdout += data.toString();
          });

        stream.stderr.on('data', (data) => {
          stderr += data.toString();
        });
      });
    });
  } finally {
    client.end();
  }
};

export const validateServerAccess = async (server) => {
  const command = [
    'set -e',
    'who="$(whoami 2>/dev/null || true)"',
    'uid="$(id -u 2>/dev/null || true)"',
    'gid="$(id -g 2>/dev/null || true)"',
    'home="${HOME:-}"',
    'root_probe="no"',
    'probe="/root/.bt-ssh-gui-root-test-$$"',
    'if [ "$uid" = "0" ] && touch "$probe" >/dev/null 2>&1; then',
    '  rm -f "$probe" >/dev/null 2>&1 || true',
    '  root_probe="yes"',
    'fi',
    "printf 'whoami=%s\\nuid=%s\\ngid=%s\\nhome=%s\\nrootProbe=%s\\n' \"$who\" \"$uid\" \"$gid\" \"$home\" \"$root_probe\""
  ].join('\n');
  let result;
  try {
    result = await runRemote(server, command, { timeoutMs: 20_000 });
  } catch (error) {
    throw new Error(formatConnectionError(error));
  }
  const details = Object.fromEntries(
    result.stdout
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        const index = line.indexOf('=');
        return index >= 0 ? [line.slice(0, index), line.slice(index + 1)] : [line, ''];
      })
  );

  if (details.uid !== '0') {
    throw new Error(`连接成功，但当前用户不是 root（UID=${details.uid || '未知'}）。请使用 root 密码或 root 私钥登录。`);
  }

  if (details.rootProbe !== 'yes') {
    throw new Error('连接成功，但无法在 /root 写入测试文件，请确认当前账号具备完整 root 权限。');
  }

  return {
    connected: true,
    root: true,
    whoami: details.whoami || 'root',
    uid: Number(details.uid),
    gid: Number(details.gid),
    home: details.home || ''
  };
};

const formatConnectionError = (error) => {
  const message = error?.message || String(error);

  if (/All configured authentication methods failed/i.test(message)) {
    return 'SSH 认证失败，请检查 root 密码、私钥或私钥口令';
  }

  if (/Timed out|timeout|ETIMEDOUT/i.test(message)) {
    return 'SSH 连接超时，请检查服务器地址、端口和安全组/防火墙';
  }

  if (/ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(message)) {
    return '服务器地址无法解析，请检查 IP 或域名';
  }

  if (/ECONNREFUSED/i.test(message)) {
    return 'SSH 端口拒绝连接，请检查端口是否正确以及 SSH 服务是否启动';
  }

  if (/Permission denied/i.test(message)) {
    return 'SSH 权限被拒绝，请检查 root 登录是否允许';
  }

  if (error?.code === 'ERR_HOST_FINGERPRINT_UNKNOWN') {
    return `HOST_FINGERPRINT_UNKNOWN|${error.fingerprint}`;
  }

  if (error?.code === 'ERR_HOST_FINGERPRINT_MISMATCH') {
    return `HOST_FINGERPRINT_MISMATCH|${error.expectedFingerprint}|${error.fingerprint}`;
  }

  return `SSH 连接测试失败：${message}`;
};

const formatRemoteReadError = (error) => {
  const message = formatConnectionError(error);
  if (message.startsWith('HOST_FINGERPRINT_UNKNOWN|')) {
    return '服务器 SSH 主机指纹尚未信任。请先打开服务器设置，点击“保存服务器”，核对指纹后再点击“信任指纹并保存”。';
  }
  if (message.startsWith('HOST_FINGERPRINT_MISMATCH|')) {
    return '服务器 SSH 主机指纹与已保存记录不一致。请先打开服务器设置，确认主机密钥变更无误后，再点击“更新指纹并保存”。';
  }
  return message.replace(/^SSH 连接测试失败：/, '远程脚本执行失败：');
};

export const listBtSites = async (server) => {
  const marker = '__BT_SSH_GUI_SITES__';
  const script = String.raw`MARKER='__BT_SSH_GUI_SITES__'
json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

emit_wwwroot_shell() {
  reason="$1"
  if [ ! -d /www/wwwroot ]; then
    escaped_reason="$(json_escape "$reason；同时未找到 /www/wwwroot 站点目录")"
    printf '%s{"ok":false,"error":"%s"}\n' "$MARKER" "$escaped_reason"
    exit 0
  fi

  items=""
  count=0
  for path in /www/wwwroot/*; do
    [ -d "$path" ] || continue
    name="$(basename "$path")"
    case "$name" in
      default|html) continue ;;
    esac
    name_json="$(json_escape "$name")"
    path_json="$(json_escape "$path")"
    item="{\"id\":\"$name_json\",\"name\":\"$name_json\",\"path\":\"$path_json\",\"status\":\"\",\"note\":\"目录扫描\",\"addtime\":\"\",\"domains\":[]}"
    if [ "$count" -eq 0 ]; then
      items="$item"
    else
      items="$items,$item"
    fi
    count=$((count + 1))
  done

  if [ "$count" -eq 0 ]; then
    escaped_reason="$(json_escape "$reason；/www/wwwroot 下没有可用站点目录")"
    printf '%s{"ok":false,"error":"%s"}\n' "$MARKER" "$escaped_reason"
    exit 0
  fi

  escaped_reason="$(json_escape "$reason")"
  printf '%s{"ok":true,"source":"wwwroot","warning":"%s","sites":[%s]}\n' "$MARKER" "$escaped_reason" "$items"
  exit 0
}

PY_BIN="$(command -v python3 2>/dev/null || true)"
if [ -z "$PY_BIN" ]; then
  emit_wwwroot_shell "远程服务器未安装 python3，已改用 /www/wwwroot 目录扫描"
fi

DB_PATH=""
for candidate in /www/server/panel/data/default.db /www/server/panel/data/db/default.db /www/server/panel/data/database/default.db; do
  if [ -f "$candidate" ]; then
    DB_PATH="$candidate"
    break
  fi
done

if [ -z "$DB_PATH" ] && [ -d /www/server/panel ]; then
  DB_PATH="$(find /www/server/panel -maxdepth 5 -type f -name default.db 2>/dev/null | head -n 1 || true)"
fi

BT_DB_PATH="$DB_PATH" "$PY_BIN" - <<'PY'
import json
import os
import sys

MARKER = "__BT_SSH_GUI_SITES__"

def emit(payload):
    print(MARKER + json.dumps(payload, ensure_ascii=False))

def list_wwwroot(reason):
    root = "/www/wwwroot"
    if not os.path.isdir(root):
        return {
            "ok": False,
            "error": reason + "；同时未找到 /www/wwwroot 站点目录"
        }

    sites = []
    for name in sorted(os.listdir(root)):
        if name in ("default", "html"):
            continue
        path = os.path.join(root, name)
        if not os.path.isdir(path):
            continue
        sites.append({
            "id": name,
            "name": name,
            "path": path,
            "status": "",
            "note": "目录扫描",
            "addtime": "",
            "domains": []
        })

    if not sites:
        return {
            "ok": False,
            "error": reason + "；/www/wwwroot 下没有可用站点目录"
        }

    return {
        "ok": True,
        "source": "wwwroot",
        "warning": reason,
        "sites": sites
    }

try:
    import sqlite3
except Exception:
    emit(list_wwwroot("Python 缺少 sqlite3 模块，已改用 /www/wwwroot 目录扫描"))
    sys.exit(0)

db_path = os.environ.get("BT_DB_PATH", "").strip()
if not db_path:
    emit(list_wwwroot("未找到宝塔数据库 default.db，已改用 /www/wwwroot 目录扫描"))
    sys.exit(0)

if not os.path.exists(db_path):
    emit(list_wwwroot("宝塔数据库不存在：" + db_path + "，已改用 /www/wwwroot 目录扫描"))
    sys.exit(0)

try:
    conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    conn.row_factory = sqlite3.Row
except Exception as exc:
    emit(list_wwwroot("无法打开宝塔数据库：" + str(exc) + "，已改用 /www/wwwroot 目录扫描"))
    sys.exit(0)

def table_exists(name):
    row = conn.execute("select name from sqlite_master where type='table' and name=?", (name,)).fetchone()
    return row is not None

def table_columns(name):
    return [row["name"] for row in conn.execute("pragma table_info(%s)" % name).fetchall()]

sites = []
domains_by_site = {}

try:
    if table_exists("domain"):
        for item in conn.execute("select * from domain"):
            row = dict(item)
            pid = str(row.get("pid") or row.get("site_id") or row.get("siteId") or "")
            name = row.get("name") or row.get("domain") or ""
            if pid and name:
                domains_by_site.setdefault(pid, []).append(str(name))

    if not table_exists("sites"):
        tables = [row["name"] for row in conn.execute("select name from sqlite_master where type='table' order by name").fetchall()]
        emit(list_wwwroot("宝塔数据库中没有 sites 表，已改用 /www/wwwroot 目录扫描。已找到表：" + ", ".join(tables[:12])))
        sys.exit(0)

    site_columns = set(table_columns("sites"))
    order_sql = " order by id desc" if "id" in site_columns else ""
    rows = conn.execute("select * from sites" + order_sql).fetchall()
    for item in rows:
        row = dict(item)
        site_id = str(row.get("id") or row.get("site_id") or row.get("siteId") or row.get("name") or "")
        name = row.get("name") or row.get("ps") or row.get("site_name") or row.get("siteName") or ""
        path = row.get("path") or row.get("site_path") or row.get("root_path") or ""
        sites.append({
            "id": site_id,
            "name": str(name),
            "path": str(path),
            "status": row.get("status"),
            "note": str(row.get("ps") or row.get("note") or ""),
            "addtime": str(row.get("addtime") or row.get("add_time") or ""),
            "domains": domains_by_site.get(site_id, [])
        })

    if sites:
        emit({"ok": True, "source": "database", "dbPath": db_path, "sites": sites})
    else:
        emit(list_wwwroot("宝塔数据库 sites 表为空，已改用 /www/wwwroot 目录扫描"))
except Exception as exc:
    emit(list_wwwroot("读取宝塔数据库失败：" + str(exc) + "，已改用 /www/wwwroot 目录扫描"))
PY`;

  let result;
  try {
    result = await runRemote(server, script, { timeoutMs: 30_000 });
  } catch (error) {
    throw new Error(`读取宝塔站点失败：${formatRemoteReadError(error)}`);
  }

  const line = result.stdout
    .split(/\r?\n/)
    .reverse()
    .find((item) => item.startsWith(marker));

  if (!line) {
    const output = [result.stdout.trim(), result.stderr.trim()].filter(Boolean).join('\n').slice(0, 300);
    throw new Error(output ? `读取宝塔站点失败：远程脚本没有返回有效结果。${output}` : '读取宝塔站点失败：远程脚本没有返回有效结果');
  }

  let parsed;
  try {
    parsed = JSON.parse(line.slice(marker.length));
  } catch (error) {
    throw new Error(`读取宝塔站点失败：远程结果解析失败：${error.message}`);
  }

  if (!parsed.ok) {
    throw new Error(parsed.error || '读取宝塔站点失败');
  }
  return parsed.sites || [];
};

export const testBtSite = async (server, site) => {
  const sitePath = String(site.path || '').trim();
  if (!sitePath.startsWith('/')) {
    throw new Error('站点路径必须是绝对路径');
  }

  const siteName = String(site.name || site.id || path.basename(sitePath) || 'site').trim();
  const sshUsername = normalizeLinuxUser(site.sshUsername || site.name || site.id || 'site');
  const marker = '__BT_SSH_GUI_SITE_TEST__';
  const command = buildSiteTestCommand({ sitePath, sshUsername, marker });
  const result = await runRemote(server, command, { timeoutMs: 90_000, allowNonZero: true });
  const checks = parseSiteTestOutput(result.stdout, marker);

  if (!checks.length) {
    const output = [result.stdout.trim(), result.stderr.trim()].filter(Boolean).join('\n').slice(0, 300);
    throw new Error(output ? `站点测试没有返回有效结果：${output}` : '站点测试没有返回有效结果');
  }

  const summary = checks.reduce(
    (acc, check) => {
      acc[check.status] = (acc[check.status] || 0) + 1;
      return acc;
    },
    { pass: 0, warn: 0, fail: 0, skip: 0 }
  );

  return { siteName, summary, checks };
};

const getSiteIdentity = (site) => ({
  id: String(site?.id || ''),
  path: String(site?.path || ''),
  name: String(site?.name || '')
});

export const resolveManagedSite = async (server, requestedSite) => {
  const requested = getSiteIdentity(requestedSite);
  const sites = await listBtSites(server);
  const matched = sites.find((site) => {
    const current = getSiteIdentity(site);
    if (requested.id && current.id !== requested.id) return false;
    if (requested.path && current.path !== requested.path) return false;
    if (requested.name && current.name !== requested.name) return false;
    return Boolean(requested.id || requested.path || requested.name);
  });

  if (!matched) {
    throw new Error('站点不存在、已变更，或不再属于当前服务器，请重新读取站点列表后再操作');
  }

  const sitePath = String(matched.path || '').trim();
  if (!sitePath.startsWith('/')) {
    throw new Error('站点路径无效，必须是绝对路径');
  }

  return matched;
};

export const provisionSiteSsh = async (server, site, options = {}) => {
  const sitePath = String(site.path || '').trim();
  if (!sitePath.startsWith('/')) {
    throw new Error('站点路径必须是绝对路径');
  }

  const username = normalizeLinuxUser(options.username || site.name || site.id || 'site');
  const alias = normalizeHostAlias(options.alias || `${server.name || server.host}-${site.name || username}`);
  const keyPath = await ensureLocalKey(server, site, username, options.keyPath);
  const publicKey = await fs.readFile(`${keyPath}.pub`, 'utf8');

  const command = buildProvisionCommand({ username, sitePath, publicKey });
  const result = await runRemote(server, command, { timeoutMs: 120_000 });
  await upsertSshConfig({
    alias,
    host: server.host,
    port: server.port || 22,
    username,
    identityFile: keyPath
  });

  return {
    alias,
    username,
    keyPath,
    directCommand: `ssh ${username}@${server.host}`,
    stdout: result.stdout.trim()
  };
};

export const disableSiteSsh = async (server, site, options = {}) => {
  const sitePath = String(site.path || '').trim();
  const username = normalizeLinuxUser(options.username || site.name || site.id || 'site');
  const alias = normalizeHostAlias(options.alias || `${server.name || server.host}-${site.name || username}`);
  const command = [
    `USER_NAME=${shellQuote(username)}`,
    `SITE_PATH=${shellQuote(sitePath)}`,
    'if id "$USER_NAME" >/dev/null 2>&1; then passwd -l "$USER_NAME" >/dev/null 2>&1 || true; fi',
    'if command -v setfacl >/dev/null 2>&1 && [ -d "$SITE_PATH" ]; then',
    '  find "$SITE_PATH" ! -name ".user.ini" -exec setfacl -x "u:${USER_NAME}" {} + 2>/dev/null || true',
    '  find "$SITE_PATH" -type d -exec setfacl -d -x "u:${USER_NAME}" {} + 2>/dev/null || true',
    'fi',
    'printf "站点 SSH 已禁用：%s" "$USER_NAME"'
  ].join('\n');
  const result = await runRemote(server, command, { timeoutMs: 120_000, allowNonZero: true });
  await removeSshConfigBlock({
    alias,
    host: server.host,
    port: server.port || 22,
    identityFile: getLocalKeyPath(server, username, options.keyPath)
  });
  return {
    alias,
    username,
    stdout: result.stdout.trim() || result.stderr.trim()
  };
};

export const getSshConfigPath = () => path.join(os.homedir(), '.ssh', 'config');

const expandHome = (filePath) => {
  if (!filePath) return filePath;
  if (filePath === '~') return os.homedir();
  if (filePath.startsWith('~/')) return path.join(os.homedir(), filePath.slice(2));
  return filePath;
};

const normalizeLinuxUser = (value) => {
  const cleaned = String(value)
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '_')
    .replace(/^[^a-z_]+/, '')
    .replace(/_+/g, '_')
    .slice(0, 28);
  return cleaned || `site_${Date.now().toString(36)}`;
};

const normalizeHostAlias = (value) =>
  String(value)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64) || `bt-site-${Date.now().toString(36)}`;

const safePathPart = (value) =>
  String(value)
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, '_')
    .slice(0, 64);

const normalizeLocalKeyPath = (filePath) => {
  const rawPath = String(filePath || '').trim();
  if (!rawPath) return '';
  if (rawPath.endsWith('.pub')) {
    throw new Error('本地密钥保存路径应填写私钥路径，不要以 .pub 结尾');
  }
  if (hasControlChars(rawPath)) {
    throw new Error('本地密钥保存路径不能包含控制字符');
  }
  return path.resolve(expandHome(rawPath));
};

const ensureSafeSshConfigValue = (value, label) => {
  const text = String(value || '');
  if (!text.trim()) {
    throw new Error(`${label}不能为空`);
  }
  if (hasControlChars(text)) {
    throw new Error(`${label}不能包含控制字符`);
  }
  return text;
};

const quoteSshConfigValue = (value) => `"${String(value).replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;

const getLocalKeyPath = (server, username, customPath = '') => {
  const normalizedPath = normalizeLocalKeyPath(customPath);
  if (normalizedPath) return normalizedPath;
  const keyDir = path.join(os.homedir(), '.ssh', 'bt-ssh', safePathPart(server.host));
  return path.join(keyDir, `${safePathPart(username)}_ed25519`);
};

const ensureLocalKey = async (server, site, username, customPath = '') => {
  const keyPath = getLocalKeyPath(server, username, customPath);
  const keyDir = path.dirname(keyPath);
  await fs.mkdir(keyDir, { recursive: true, mode: 0o700 });

  try {
    await fs.access(keyPath);
  } catch {
    await execFileAsync('ssh-keygen', [
      '-t',
      'ed25519',
      '-N',
      '',
      '-C',
      `bt-ssh-gui ${server.host} ${site.name || site.id || username}`,
      '-f',
      keyPath
    ]);
    await fs.chmod(keyPath, 0o600);
  }

  try {
    await fs.access(`${keyPath}.pub`);
    return keyPath;
  } catch {
    const { stdout } = await execFileAsync('ssh-keygen', ['-y', '-f', keyPath]);
    await fs.writeFile(`${keyPath}.pub`, `${stdout.trim()}\n`, 'utf8');
    await fs.chmod(keyPath, 0o600);
    await fs.chmod(`${keyPath}.pub`, 0o644);
    return keyPath;
  }
};

const buildProvisionCommand = ({ username, sitePath, publicKey }) => {
  const escapedKey = publicKey.trim();
  return [
    'set -e',
    `USER_NAME=${shellQuote(username)}`,
    `SITE_PATH=${shellQuote(sitePath)}`,
    `PUBLIC_KEY=${shellQuote(escapedKey)}`,
    'if ! command -v setfacl >/dev/null 2>&1; then echo "缺少 setfacl，请先安装 acl" >&2; exit 40; fi',
    'if ! command -v useradd >/dev/null 2>&1; then echo "缺少 useradd" >&2; exit 41; fi',
    'if [ ! -d "$SITE_PATH" ]; then echo "站点目录不存在：$SITE_PATH" >&2; exit 42; fi',
    'apply_acl() { find "$SITE_PATH" ! -name ".user.ini" -exec setfacl -m "$1" {} +; }',
    'apply_default_acl() { find "$SITE_PATH" -type d -exec setfacl -d -m "$1" {} +; }',
    'if id "$USER_NAME" >/dev/null 2>&1; then',
    '  USER_HOME="$(getent passwd "$USER_NAME" | cut -d: -f6)"',
    '  MANAGED_USER=no',
    '  if [ -L "$USER_HOME/site" ] && [ "$(readlink "$USER_HOME/site" 2>/dev/null || true)" = "$SITE_PATH" ]; then MANAGED_USER=yes; fi',
    '  if [ -f "$USER_HOME/.ssh/authorized_keys" ] && grep -q "bt-ssh-gui" "$USER_HOME/.ssh/authorized_keys"; then MANAGED_USER=yes; fi',
    '  if [ "$MANAGED_USER" != "yes" ]; then echo "远程用户已存在且不像本工具管理的站点账号：$USER_NAME。请换一个远程用户名。" >&2; exit 43; fi',
    'else',
    '  useradd -m -s /bin/bash "$USER_NAME"',
    'fi',
    'passwd -l "$USER_NAME" >/dev/null 2>&1 || true',
    'USER_HOME="$(getent passwd "$USER_NAME" | cut -d: -f6)"',
    'install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "$USER_HOME/.ssh"',
    'printf "%s\\n" "$PUBLIC_KEY" > "$USER_HOME/.ssh/authorized_keys"',
    'chown "$USER_NAME:$USER_NAME" "$USER_HOME/.ssh/authorized_keys"',
    'chmod 600 "$USER_HOME/.ssh/authorized_keys"',
    'ln -sfn "$SITE_PATH" "$USER_HOME/site"',
    'chown -h "$USER_NAME:$USER_NAME" "$USER_HOME/site" || true',
    'apply_acl "u:${USER_NAME}:rwx"',
    'apply_default_acl "u:${USER_NAME}:rwx"',
    'if id www >/dev/null 2>&1; then apply_acl u:www:rwx || true; apply_default_acl u:www:rwx || true; fi',
    'printf "已创建/更新用户 %s，并授权访问 %s" "$USER_NAME" "$SITE_PATH"'
  ].join('\n');
};

const buildSiteTestCommand = ({ sitePath, sshUsername, marker }) => [
  `MARKER=${shellQuote(marker)}`,
  `SITE_PATH=${shellQuote(sitePath)}`,
  `SSH_USER=${shellQuote(sshUsername)}`,
  'clean() { printf "%s" "$1" | tr "\\r\\n|" "   "; }',
  'emit() { printf "%s%s|%s|%s\\n" "$MARKER" "$1" "$(clean "$2")" "$(clean "$3")"; }',
  'TEST_OUTPUT="$(mktemp /tmp/bt-ssh-site-test.XXXXXX)" || exit 1',
  'TARGETS_FILE="$(mktemp /tmp/bt-ssh-site-targets.XXXXXX)" || exit 1',
  'cleanup_temp() { rm -f "$TEST_OUTPUT" "$TARGETS_FILE" "$TARGET_FILE" 2>/dev/null || true; }',
  'trap cleanup_temp EXIT',
  'run_as_site_user() { su -s /bin/sh -c "$1" "$SSH_USER" >"$TEST_OUTPUT" 2>&1; }',
  'last_error() { clean "$(cat "$TEST_OUTPUT" 2>/dev/null || true)"; }',
  'cleanup_path() { rm -rf "$1" 2>/dev/null || true; }',
  '',
  'if [ ! -d "$SITE_PATH" ]; then',
  '  emit fail "站点目录" "$SITE_PATH 不存在或不是目录"',
  '  exit 0',
  'fi',
  '',
  'if ! id "$SSH_USER" >/dev/null 2>&1; then',
  '  emit fail "SSH 账号" "用户 $SSH_USER 不存在，请先启用站点 SSH"',
  '  exit 0',
  'fi',
  'emit pass "SSH 账号" "用户 $SSH_USER 存在"',
  '',
  'printf "%s\\n" "$SITE_PATH" > "$TARGETS_FILE"',
  'find "$SITE_PATH" -mindepth 1 -maxdepth 2 -type d \\',
  '  ! -name ".git" ! -name "node_modules" ! -name "vendor" ! -name "cache" \\',
  '  ! -path "*/.git/*" ! -path "*/node_modules/*" ! -path "*/vendor/*" ! -path "*/cache/*" \\',
  '  2>/dev/null | head -n 5 >> "$TARGETS_FILE"',
  '',
  'TARGET_COUNT="$(wc -l < "$TARGETS_FILE" | tr -d " ")"',
  'if [ "$TARGET_COUNT" -le 1 ]; then',
  '  emit warn "测试范围" "未找到现有子目录，仅测试站点根目录"',
  'else',
  '  emit pass "测试范围" "将测试站点根目录和 $((TARGET_COUNT - 1)) 个子目录"',
  'fi',
  '',
  'test_target() {',
  '  target="$1"',
  '  label="${target#$SITE_PATH}"',
  '  [ -n "$label" ] || label="/"',
  '  TARGET_FILE="$(mktemp /tmp/bt-ssh-site-target.XXXXXX)" || return 1',
  '  printf "%s" "$target" > "$TARGET_FILE"',
  '  chown "$SSH_USER" "$TARGET_FILE" 2>/dev/null || true',
  '  chmod 600 "$TARGET_FILE" 2>/dev/null || true',
  '  load_target="target=\\"\\$(cat \\"$TARGET_FILE\\")\\""',
  '  token="_bt_ssh_perm_test_$$"',
  '  dir="$token-dir"',
  '  renamed_dir="$token-dir-renamed"',
  '  file="$token-file.txt"',
  '  cleanup_path "$target/$dir"',
  '  cleanup_path "$target/$renamed_dir"',
  '  cleanup_path "$target/$file"',
  '',
  '  if run_as_site_user "$load_target; mkdir \\"\\$target/$dir\\""; then emit pass "$label 新建目录" "$SSH_USER 可在 $target 新建目录"; else emit fail "$label 新建目录" "$(last_error)"; cleanup_path "$target/$dir"; fi',
  '  if run_as_site_user "$load_target; mv \\"\\$target/$dir\\" \\"\\$target/$renamed_dir\\""; then emit pass "$label 编辑目录" "$SSH_USER 可重命名目录"; else emit fail "$label 编辑目录" "$(last_error)"; cleanup_path "$target/$dir"; cleanup_path "$target/$renamed_dir"; fi',
  '  if run_as_site_user "$load_target; printf %s bt-ssh-test > \\"\\$target/$file\\""; then emit pass "$label 新建文件" "$SSH_USER 可在 $target 新建文件"; else emit fail "$label 新建文件" "$(last_error)"; cleanup_path "$target/$file"; fi',
  '  if run_as_site_user "$load_target; printf %s edited >> \\"\\$target/$file\\""; then emit pass "$label 编辑文件" "$SSH_USER 可编辑文件内容"; else emit fail "$label 编辑文件" "$(last_error)"; cleanup_path "$target/$file"; fi',
  '  if run_as_site_user "$load_target; rm -f \\"\\$target/$file\\" && test ! -e \\"\\$target/$file\\""; then emit pass "$label 删除文件" "$SSH_USER 可删除文件"; else emit fail "$label 删除文件" "$(last_error)"; cleanup_path "$target/$file"; fi',
  '  if run_as_site_user "$load_target; rmdir \\"\\$target/$renamed_dir\\" && test ! -e \\"\\$target/$renamed_dir\\""; then emit pass "$label 删除目录" "$SSH_USER 可删除目录"; else emit fail "$label 删除目录" "$(last_error)"; cleanup_path "$target/$renamed_dir"; fi',
  '  rm -f "$TARGET_FILE" 2>/dev/null || true',
  '  TARGET_FILE=""',
  '}',
  '',
  'while IFS= read -r target; do',
  '  [ -d "$target" ] || continue',
  '  test_target "$target"',
  'done < "$TARGETS_FILE"',
  'cleanup_temp'
].join('\n');

const parseSiteTestOutput = (stdout, marker) =>
  stdout
    .split(/\r?\n/)
    .filter((line) => line.startsWith(marker))
    .map((line) => {
      const [status = 'warn', label = '检查项', message = ''] = line.slice(marker.length).split('|');
      return {
        status: ['pass', 'warn', 'fail', 'skip'].includes(status) ? status : 'warn',
        label,
        message
      };
    });

const readSshConfig = async () => {
  try {
    return await fs.readFile(getSshConfigPath(), 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return '';
    throw error;
  }
};

const resolveExistingLocalKeyPath = async (filePath) => {
  const normalizedPath = normalizeLocalKeyPath(filePath);
  if (!normalizedPath) return '';

  try {
    await fs.access(normalizedPath);
    return normalizedPath;
  } catch {
    return '';
  }
};

const writeSshConfig = async (content) => {
  const configPath = getSshConfigPath();
  await fs.mkdir(path.dirname(configPath), { recursive: true, mode: 0o700 });
  await fs.writeFile(configPath, content, 'utf8');
  await fs.chmod(configPath, 0o600);
};

const blockMarkers = (alias) => ({
  start: `# >>> bt-ssh-gui ${alias}`,
  end: `# <<< bt-ssh-gui ${alias}`
});

const endpointMarkers = (host, port) => ({
  start: `# >>> bt-ssh-gui endpoint ${host}:${port}`,
  end: `# <<< bt-ssh-gui endpoint ${host}:${port}`
});

const escapeRegExp = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const blockRegExp = ({ start, end }) =>
  new RegExp(`\\n?${escapeRegExp(start)}[\\s\\S]*?${escapeRegExp(end)}\\n?`, 'g');

const getManagedBlock = (content, markers) => {
  const match = content.match(blockRegExp(markers));
  return match?.[0] || '';
};

const removeManagedBlock = (content, markers) => content.replace(blockRegExp(markers), '\n').trimEnd();

const parseIdentityFiles = (block) =>
  block
    .split(/\r?\n/)
    .map((line) => line.match(/^\s*IdentityFile\s+(.+?)\s*$/)?.[1])
    .map((value) => value?.replace(/^"(.*)"$/, '$1').replace(/\\"/g, '"').replace(/\\\\/g, '\\'))
    .filter(Boolean);

const buildEndpointBlock = ({ host, port, identityFiles }) => {
  const safeHost = ensureSafeSshConfigValue(host, 'SSH 主机');
  const { start, end } = endpointMarkers(host, port);
  return [
    start,
    `Host ${safeHost}`,
    `  HostName ${safeHost}`,
    `  Port ${port}`,
    ...identityFiles.map((identityFile) => `  IdentityFile ${quoteSshConfigValue(ensureSafeSshConfigValue(identityFile, 'SSH 密钥路径'))}`),
    '  IdentitiesOnly yes',
    end
  ].join('\n');
};

const buildAliasBlock = ({ alias, host, port, username, identityFile }) => {
  const safeAlias = ensureSafeSshConfigValue(alias, 'SSH 别名');
  const safeHost = ensureSafeSshConfigValue(host, 'SSH 主机');
  const safeUsername = ensureSafeSshConfigValue(username, 'SSH 用户');
  const { start, end } = blockMarkers(alias);
  return [
    start,
    `Host ${safeAlias}`,
    `  HostName ${safeHost}`,
    `  Port ${port}`,
    `  User ${safeUsername}`,
    `  IdentityFile ${quoteSshConfigValue(ensureSafeSshConfigValue(identityFile, 'SSH 密钥路径'))}`,
    '  IdentitiesOnly yes',
    end
  ].join('\n');
};

const joinConfigSections = (sections) => `${sections.filter(Boolean).join('\n\n')}\n`;

const removeAliasBlock = (content, alias) => removeManagedBlock(content, blockMarkers(alias));

const removeEndpointBlock = (content, host, port) => removeManagedBlock(content, endpointMarkers(host, port));

const getEndpointIdentities = (content, host, port) =>
  parseIdentityFiles(getManagedBlock(content, endpointMarkers(host, port)));

const uniqueValues = (values) => [...new Set(values.filter(Boolean))];

const upsertSshConfig = async ({ alias, host, port, username, identityFile }) => {
  const current = await readSshConfig();
  const identityFiles = uniqueValues([...getEndpointIdentities(current, host, port), identityFile]);
  const content = removeAliasBlock(removeEndpointBlock(current, host, port), alias);
  const endpointBlock = buildEndpointBlock({ host, port, identityFiles });
  const aliasBlock = buildAliasBlock({ alias, host, port, username, identityFile });
  await writeSshConfig(joinConfigSections([endpointBlock, content.trim(), aliasBlock]));
};

const removeSshConfigBlock = async ({ alias, host, port, identityFile }) => {
  const current = await readSshConfig();
  const identityFiles = uniqueValues(getEndpointIdentities(current, host, port).filter((filePath) => filePath !== identityFile));
  const content = removeAliasBlock(removeEndpointBlock(current, host, port), alias);
  const endpointBlock = identityFiles.length ? buildEndpointBlock({ host, port, identityFiles }) : '';
  await writeSshConfig(joinConfigSections([endpointBlock, content.trim()]));
};

const parseSshDirective = (block, directive) =>
  block
    .split(/\r?\n/)
    .map((line) => line.match(new RegExp(`^\\s*${directive}\\s+(.+?)\\s*$`, 'i'))?.[1])
    .find(Boolean);

const getConfiguredSiteState = (content, server, site) => {
  const username = normalizeLinuxUser(site.sshUsername || site.name || site.id || 'site');
  const alias = normalizeHostAlias(site.sshAlias || `${server.name || server.host}-${site.name || username}`);
  const block = getManagedBlock(content, blockMarkers(alias));
  if (!block) return null;

  const configuredHost = parseSshDirective(block, 'HostName');
  const configuredPort = Number(parseSshDirective(block, 'Port') || 22);
  if (configuredHost !== server.host || configuredPort !== Number(server.port || 22)) return null;

  return {
    sshEnabled: true,
    sshAlias: alias,
    sshUsername: parseSshDirective(block, 'User') || username,
    sshKeyPath: parseSshDirective(block, 'IdentityFile') || getLocalKeyPath(server, username)
  };
};

export const enrichSitesWithLocalSshConfig = async (server, sites) => {
  const content = await readSshConfig();
  return Promise.all(
    sites.map(async (site) => {
      const configuredState = site.sshEnabled ? null : getConfiguredSiteState(content, server, site);
      const mergedSite = configuredState ? { ...site, ...configuredState } : site;
      const existingKeyPath = await resolveExistingLocalKeyPath(mergedSite.sshKeyPath);

      if (!existingKeyPath) {
        return {
          ...mergedSite,
          sshKeyPath: ''
        };
      }

      return {
        ...mergedSite,
        sshKeyPath: existingKeyPath
      };
    })
  );
};
