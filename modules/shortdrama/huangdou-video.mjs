// RexHub 短剧插件公共运行时：内置 HTTP 服务、代理出站、封面解密。
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import zlib from 'node:zlib';

const VERSION = '1.0.1';
const PROXY = String(process.env.REXHUB_PLUGIN_PROXY || '').trim();
const UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';
const MEDIA_KEY = Buffer.from('f5d965df75336270', 'utf8');
const MEDIA_IV = Buffer.from('97b60394abc2fbe1', 'utf8');

function proxyAuth(p) {
  if (!p.username) return {};
  const raw = decodeURIComponent(p.username) + ':' + decodeURIComponent(p.password || '');
  return { 'Proxy-Authorization': 'Basic ' + Buffer.from(raw, 'utf8').toString('base64') };
}

function openTarget(urlStr, options) {
  const opts = options || {};
  const u = new URL(urlStr);
  const isHttps = u.protocol === 'https:';
  const method = (opts.method || 'GET').toUpperCase();
  const headers = Object.assign({}, opts.headers || {});
  const timeout = Number(opts.timeout || 20000);
  return new Promise((resolve, reject) => {
    let req = null;
    const start = () => {
      if (!req) return;
      req.setTimeout(timeout, () => req.destroy(new Error('请求超时')));
      req.on('error', reject);
      if (opts.body) req.write(opts.body);
      req.end();
    };
    if (!PROXY) {
      const mod = isHttps ? https : http;
      req = mod.request(
        {
          hostname: u.hostname,
          port: Number(u.port || (isHttps ? 443 : 80)),
          path: u.pathname + u.search,
          method,
          headers,
          servername: isHttps ? u.hostname : undefined,
        },
        resolve,
      );
      start();
      return;
    }
    const p = new URL(PROXY.indexOf('://') >= 0 ? PROXY : 'http://' + PROXY);
    if (!isHttps) {
      req = http.request(
        {
          host: p.hostname,
          port: Number(p.port || 80),
          path: urlStr,
          method,
          headers: Object.assign({}, headers, { Host: u.host }, proxyAuth(p)),
        },
        resolve,
      );
      start();
      return;
    }
    const connect = http.request({
      host: p.hostname,
      port: Number(p.port || 80),
      method: 'CONNECT',
      path: u.hostname + ':' + Number(u.port || 443),
      headers: Object.assign(
        { Host: u.hostname + ':' + Number(u.port || 443) },
        proxyAuth(p),
      ),
      timeout,
    });
    connect.once('connect', (response, socket) => {
      if (response.statusCode !== 200) {
        socket.destroy();
        reject(new Error('代理连接失败：' + response.statusCode));
        return;
      }
      req = https.request(
        {
          host: u.hostname,
          port: Number(u.port || 443),
          path: u.pathname + u.search,
          method,
          headers,
          socket,
          servername: u.hostname,
          agent: false,
        },
        resolve,
      );
      start();
    });
    connect.once('error', reject);
    connect.setTimeout(timeout, () => connect.destroy(new Error('代理连接超时')));
    connect.end();
  });
}

async function fetchBuffer(urlStr, options) {
  const opts = Object.assign({ retries: 1 }, options || {});
  let lastError = null;
  for (let attempt = 0; attempt <= Number(opts.retries || 0); attempt += 1) {
    try {
      const response = await openTarget(urlStr, opts);
      const status = Number(response.statusCode || 0);
      const chunks = [];
      await new Promise((resolve, reject) => {
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', resolve);
        response.on('error', reject);
      });
      const body = Buffer.concat(chunks);
      if (status >= 400) {
        const error = new Error('上游 HTTP ' + status);
        error.status = status;
        error.body = body;
        throw error;
      }
      return { status, headers: response.headers || {}, body };
    } catch (error) {
      lastError = error;
      if (attempt >= Number(opts.retries || 0)) break;
      await new Promise((resolve) => setTimeout(resolve, 400 * (attempt + 1)));
    }
  }
  throw lastError || new Error('请求失败');
}

async function fetchJson(urlStr, options) {
  const result = await fetchBuffer(urlStr, options);
  const text = result.body.toString('utf8', 0, Math.min(result.body.length, 4 * 1024 * 1024));
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error('上游返回不是合法 JSON：' + String(error.message || error));
  }
}

function isImage(bytes) {
  if (!bytes || bytes.length < 4) return false;
  return (
    bytes.subarray(0, 3).toString('hex') === 'ffd8ff' ||
    bytes.subarray(0, 8).toString('hex') === '89504e470d0a1a0a' ||
    bytes.subarray(0, 6).toString('ascii') === 'GIF87a' ||
    bytes.subarray(0, 6).toString('ascii') === 'GIF89a' ||
    (bytes.length > 12 && bytes.subarray(0, 4).toString('ascii') === 'RIFF' && bytes.subarray(8, 12).toString('ascii') === 'WEBP')
  );
}

function imageMime(bytes) {
  if (!bytes || bytes.length < 4) return 'image/jpeg';
  if (bytes.subarray(0, 3).toString('hex') === 'ffd8ff') return 'image/jpeg';
  if (bytes.subarray(0, 8).toString('hex') === '89504e470d0a1a0a') return 'image/png';
  if (bytes.subarray(0, 4).toString('ascii') === 'RIFF') return 'image/webp';
  if (bytes.subarray(0, 4).toString('ascii').indexOf('GIF') === 0) return 'image/gif';
  return 'image/jpeg';
}

function decryptCover(bytes) {
  const usable = bytes.length - (bytes.length % 16);
  if (usable < 16) return null;
  const decipher = crypto.createDecipheriv('aes-128-cbc', MEDIA_KEY, MEDIA_IV);
  decipher.setAutoPadding(false);
  let plain = Buffer.concat([decipher.update(bytes.subarray(0, usable)), decipher.final()]);
  if (plain.subarray(0, 3).toString('hex') === 'ffd8ff') {
    const end = plain.lastIndexOf(Buffer.from([0xff, 0xd9]));
    if (end >= 0) return plain.subarray(0, end + 2);
  }
  if (plain.subarray(0, 8).toString('hex') === '89504e470d0a1a0a') {
    const end = plain.indexOf(Buffer.from('IEND', 'ascii'));
    if (end >= 0) return plain.subarray(0, end + 8);
  }
  plain = plain.subarray(0, plain.length - 8);
  return isImage(plain) ? plain : null;
}

function privateHost(hostname) {
  const host = String(hostname || '').toLowerCase();
  if (!host) return true;
  if (host === 'localhost' || host.endsWith('.local')) return true;
  if (host === '::1' || host === '[::1]') return true;
  if (/^127\./.test(host) || /^10\./.test(host) || /^169\.254\./.test(host)) return true;
  if (/^192\.168\./.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
  return false;
}

function required(value, message) {
  const text = String(value == null ? '' : value).trim();
  if (!text) throw new Error(message || '缺少参数');
  return text;
}

function jsonResponse(status, payload) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

const HD_LINES = [
  'https://lzlukvca.cc',
  'https://psfxhhox.top',
  'https://sxqirtho.top',
  'https://qicuknlj.top',
  'https://hddj05.com',
  'https://hddj06.com',
  'https://hddj07.com',
  'https://hvthtcpa.top',
];
const HD_PLATFORM_KEY = '7961beb44246e3012ce228d6b5ced05a';
const HD_UA =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1';
const HD_ENUM = [
  ['yuandou', '黄豆原创'],
  ['mod', '魔改短剧'],
  ['caibian', '擦边短剧'],
  ['zhenren', '真人短剧'],
  ['erciyuan', '动漫'],
  ['aiman', '影院'],
  ['zongyi', '贤者'],
  ['heiliao', '黑料'],
];

let hdToken = '';
let hdUserId = '';
let hdLive = '';
let hdNav = null;
const hdFilters = {};
const hdSession = crypto.randomBytes(16).toString('hex');
const hdDevice = crypto.randomBytes(16).toString('hex');

function hdKeys(rid) {
  return crypto
    .createHmac('sha256', HD_PLATFORM_KEY)
    .update(Buffer.from(String(rid).replace(/-/g, ''), 'hex'))
    .digest();
}

function hdDecode(blob, rid) {
  if (!blob || !blob.length) return {};
  if (blob.length < 32) {
    try {
      return JSON.parse(blob.toString('utf8'));
    } catch (error) {
      return {};
    }
  }
  try {
    const decipher = crypto.createDecipheriv('aes-256-cbc', hdKeys(rid), blob.subarray(0, 16));
    let plain = Buffer.concat([decipher.update(blob.subarray(16)), decipher.final()]);
    if (plain[0] === 0x1f && plain[1] === 0x8b) plain = zlib.gunzipSync(plain);
    return JSON.parse(plain.toString('utf8'));
  } catch (error) {
    try {
      return JSON.parse(blob.toString('utf8'));
    } catch (ignored) {
      return {};
    }
  }
}

function hdRequest(host, path, data) {
  const rid = crypto.randomUUID();
  const iv = crypto.randomBytes(16);
  const token = hdToken && hdUserId ? hdToken + '_' + hdUserId : hdToken;
  const raw = JSON.stringify({
    token,
    deviceId: hdDevice,
    data: data || {},
  });
  const cipher = crypto.createCipheriv('aes-256-cbc', hdKeys(rid), iv);
  const body = Buffer.concat([iv, cipher.update(zlib.gzipSync(Buffer.from(raw, 'utf8'))), cipher.final()]);
  const ts = Math.floor(Date.now() / 1000);
  const hostClean = host.replace(/^https?:\/\//, '').replace(/\/$/, '');
  const sign =
    crypto
      .createHash('md5')
      .update('Dart|' + hdSession + '|' + rid + '|' + ts + '|' + hostClean + '/api' + path)
      .digest('hex') +
    '-' +
    ts;
  return {
    rid,
    url: host + '/api' + path,
    options: {
      method: 'POST',
      headers: {
        'User-Agent': HD_UA,
        Accept: '*/*',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        Origin: host,
        Referer: host + '/home',
        version: '1.0.0',
        deviceType: 'web',
        time: String(ts),
        sign,
        requestId: rid,
        sessionId: hdSession,
        deviceBrand: '',
        deviceModel: '',
        systemName: '',
        systemVersion: '',
      },
      body,
      timeout: 20000,
      retries: 0,
    },
  };
}

async function hdApi(path, data, silent) {
  const hosts = [];
  if (hdLive) hosts.push(hdLive);
  HD_LINES.forEach(function (host) {
    if (hosts.indexOf(host) < 0) hosts.push(host);
  });
  let lastError = null;
  for (let i = 0; i < hosts.length; i += 1) {
    const host = hosts[i];
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const request = hdRequest(host, path, data);
        const response = await fetchBuffer(request.url, request.options);
        const payload = hdDecode(response.body, request.rid);
        if (!payload || typeof payload !== 'object') continue;
        if (payload.status === 'n' && String(payload.errorCode || payload.error || '') === '2002') {
          hdToken = '';
          hdUserId = '';
          continue;
        }
        hdLive = host;
        return payload;
      } catch (error) {
        lastError = error;
      }
    }
  }
  if (silent) return {};
  throw new Error('黄豆请求失败：' + String((lastError && lastError.message) || path));
}

async function hdEnsureLogin() {
  if (hdToken && hdUserId) return;
  const payload = await hdApi(
    '/login/device',
    {
      line_code: 'china_1',
      channel_code: '',
      share_code: '',
      clipboard_text: '',
      device_info: {
        browserName: 'BrowserName.safari',
        language: 'zh-CN',
        userAgent: HD_UA,
        platform: 'iPhone',
      },
    },
    true,
  );
  const data = (payload && payload.data) || {};
  if (data.token) {
    hdToken = String(data.token);
    hdUserId = String(data.user_id || '');
  }
}

function hdRows(payload) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') return [];
  const keys = ['list', 'items', 'data', 'records'];
  for (let i = 0; i < keys.length; i += 1) {
    const value = payload[keys[i]];
    if (Array.isArray(value)) return value;
    if (value && typeof value === 'object') {
      const nested = hdRows(value);
      if (nested.length) return nested;
    }
  }
  return [];
}

async function hdNavList() {
  if (hdNav) return hdNav;
  const payload = await hdApi('/drama/navList', {}, true);
  const node = (payload && payload.data) || payload;
  const list = node && Array.isArray(node.list) ? node.list : [];
  hdNav = list.filter(function (item) {
    return item && item.code;
  });
  return hdNav;
}

async function hdNavFilter(code) {
  if (hdFilters[code]) return hdFilters[code];
  const payload = await hdApi('/drama/navFilter', { code }, true);
  const node = (payload && payload.data) || payload;
  const list = node && Array.isArray(node.list) ? node.list : [];
  hdFilters[code] = list.filter(function (item) {
    return item && typeof item === 'object';
  });
  return hdFilters[code];
}

async function hdResolveCode(category) {
  const value = String(category || '').trim();
  if (!value) return '';
  const nav = await hdNavList();
  if (nav.some(function (item) { return String(item.code) === value; })) return value;
  const nameMap = {};
  HD_ENUM.forEach(function (pair) { nameMap[pair[0]] = pair[1]; });
  const label = nameMap[value] || '';
  if (label) {
    for (let i = 0; i < nav.length; i += 1) {
      const name = String(nav[i].name || '');
      if (name && (name.indexOf(label) >= 0 || label.indexOf(name) >= 0)) {
        return String(nav[i].code);
      }
    }
  }
  return value;
}

function hdShow(raw) {
  if (!raw || typeof raw !== 'object') return null;
  let id = String(raw.id || raw.drama_id || '').trim();
  if (!id) return null;
  id = id.replace(/^rp_/, '');
  const cover = String(raw.img_y || raw.img_x || raw.img || raw.cover || raw.pic || '').trim();
  const tags = [];
  if (raw.category) tags.push(String(raw.category));
  return {
    id,
    title: String(raw.name || raw.title || id).trim(),
    cover,
    description: String(raw.description || '').trim(),
    total: Number(raw.episode_count || raw.free_episodes || raw.total || 0) || 0,
    finished: String(raw.update_status) === '1' || String(raw.update_label || '').indexOf('全') >= 0,
    tags,
    hot: Number(raw.hot_rate || raw.hot || 0) || 0,
  };
}

const SOURCE = {
  name: '黄豆短剧',
  async list(params) {
    await hdEnsureLogin().catch(function () {});
    const page = params.page || 1;
    const category = (params.category || 'hot').trim();
    const sort = (params.sort || '').trim().toLowerCase();
    const order = category === 'new' || sort === 'new' ? 'new' : 'hot';
    if (category && category !== 'hot' && category !== 'new' && category !== 'all') {
      try {
        const code = await hdResolveCode(category);
        const tabs = await hdNavFilter(code);
        const picked = tabs[0];
        if (picked && picked.tab) {
          const payload = await hdApi('/drama/navBlock', {
            code,
            tab: String(picked.tab),
            page: String(page),
          }, true);
          const blocks = hdRows((payload && payload.data) || payload);
          const items = [];
          blocks.forEach(function (block) {
            const nested = block.items || block.dramas;
            if (Array.isArray(nested)) items.push.apply(items, nested);
            else if (block.id || block.drama_id) items.push(block);
          });
          const shows = items.map(hdShow).filter(function (item) { return item; });
          if (shows.length) return shows.slice(0, 24);
        }
        if (picked && picked.filter && typeof picked.filter === 'object') {
          const request = { page: String(page), page_size: '24' };
          ['cat_id', 'tag_id', 'source'].forEach(function (key) {
            if (picked.filter[key] != null && String(picked.filter[key]) !== '') {
              request[key] = picked.filter[key];
            }
          });
          if (sort === 'hot' || sort === 'new') request.order = sort + ':top';
          else if (picked.filter.order) request.order = picked.filter.order;
          const payload = await hdApi('/drama/list', request, true);
          const shows = hdRows((payload && payload.data) || payload).map(hdShow).filter(function (item) { return item; });
          if (shows.length) return shows;
        }
      } catch (error) {
        // 频道接口失败时回退到通用列表
      }
    }
    const payload = await hdApi('/drama/list', {
      page: String(page),
      page_size: '24',
      order,
    });
    return hdRows((payload && payload.data) || payload).map(hdShow).filter(function (item) { return item; });
  },
  async search(params) {
    await hdEnsureLogin().catch(function () {});
    const payload = await hdApi('/drama/list', {
      page: String(params.page || 1),
      page_size: '30',
      keywords: params.keyword,
    });
    return hdRows((payload && payload.data) || payload).map(hdShow).filter(function (item) { return item; });
  },
  async detail(id) {
    await hdEnsureLogin().catch(function () {});
    const payload = await hdApi('/drama/detail', { id });
    const data = (payload && payload.data) || {};
    const episodes = [];
    const raw = Array.isArray(data.episodes) ? data.episodes : [];
    raw.forEach(function (episode, index) {
      const n = Number(episode.seq || episode.episode || episode.ep || index + 1) || index + 1;
      episodes.push({
        key: String(n),
        episode: n,
        title: String(episode.name || episode.title || '第' + n + '集'),
        duration: Number(episode.duration || 0) || 0,
      });
    });
    const total = Number(data.episode_count || data.free_episodes || episodes.length || 0) || episodes.length;
    if (!episodes.length && total) {
      for (let n = 1; n <= Math.min(total, 500); n += 1) {
        episodes.push({ key: String(n), episode: n, title: '第' + n + '集', duration: 0 });
      }
    }
    return {
      id,
      title: String(data.name || data.title || id),
      cover: String(data.img_y || data.img_x || data.img || data.cover || '').trim(),
      description: String(data.description || ''),
      total,
      finished: String(data.update_status) === '1' || String(data.update_label || '').indexOf('全') >= 0,
      tags: [],
      episodes,
    };
  },
  async resolve(id, episodeKey) {
    await hdEnsureLogin().catch(function () {});
    const seq = Math.max(1, Number(episodeKey || 1) || 1);
    try {
      const payload = await hdApi('/drama/play', { id, seq: String(seq) }, true);
      const data = (payload && payload.data) || {};
      const lines = Array.isArray(data.lines) ? data.lines : [];
      const picked =
        lines.find(function (line) { return String(line.name) === 'free' && line.url; }) ||
        lines.find(function (line) { return line.url; });
      if (picked && picked.url) return String(picked.url);
    } catch (error) {
      // 播放签名接口失败时回退到免签线路
    }
    const host = (hdLive || HD_LINES[0]).replace(/\/$/, '');
    return host + '/api/drama/hls/' + encodeURIComponent(id) + '/' + seq + '/play.m3u8?line=free';
  },
};


function normalizeList(items) {
  return (items || []).filter(function (item) {
    return item && item.id && item.title;
  });
}

async function handleList(query) {
  const page = Math.max(1, Number(query.get('page') || 1) || 1);
  const category = String(query.get('category') || query.get('group') || '').trim();
  const sort = String(query.get('sort') || '').trim();
  const items = await SOURCE.list({ page, category, sort });
  return { items: normalizeList(items) };
}

async function handleSearch(query) {
  const keyword = String(query.get('keyword') || query.get('q') || query.get('keywords') || '').trim();
  const page = Math.max(1, Number(query.get('page') || 1) || 1);
  if (!keyword) return { items: [] };
  const items = await SOURCE.search({ keyword, page });
  return { items: normalizeList(items) };
}

async function handleDetail(rawId) {
  const id = required(decodeURIComponent(rawId), '缺少影片 ID');
  const data = await SOURCE.detail(id);
  const episodes = (data.episodes || [])
    .filter(function (episode) {
      return episode && episode.key != null && episode.key !== '';
    })
    .map(function (episode, index) {
      return {
        id: id + '_' + String(episode.key),
        episode: Number(episode.episode || index + 1),
        title: String(episode.title || '第' + (episode.episode || index + 1) + '集'),
        duration: Number(episode.duration || 0) || 0,
      };
    });
  return {
    id,
    type: 'url',
    title: String(data.title || id),
    cover: String(data.cover || ''),
    description: String(data.description || ''),
    tags: Array.isArray(data.tags) ? data.tags : [],
    total: Number(data.total || episodes.length) || episodes.length,
    finished: Boolean(data.finished),
    episodes,
  };
}

async function handleStream(rawId) {
  const id = required(decodeURIComponent(rawId), '缺少分集 ID');
  const split = id.lastIndexOf('_');
  if (split <= 0) throw new Error('分集 ID 不合法');
  const videoId = id.slice(0, split);
  const episodeKey = id.slice(split + 1);
  const url = await SOURCE.resolve(videoId, episodeKey);
  if (!url) throw new Error('未获取到播放地址');
  return url;
}

async function handleRequest(request) {
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
        'Access-Control-Allow-Headers': '*',
      },
    });
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return jsonResponse(405, { error: { code: 'METHOD_NOT_ALLOWED', message: '仅支持 GET' } });
  }
  const url = new URL(request.url || '/', 'http://127.0.0.1');
  const path = url.pathname.replace(/\/+$/, '') || '/';
  if (path === '/' || path === '/health') {
    return jsonResponse(200, { ok: true, name: SOURCE.name, version: VERSION });
  }
  if (path === '/v1/list') {
    return jsonResponse(200, await handleList(url.searchParams));
  }
  if (path === '/v1/search') {
    return jsonResponse(200, await handleSearch(url.searchParams));
  }
  const detailMatch = path.match(/^\/v1\/detail\/([^/]+)$/);
  if (detailMatch) {
    return jsonResponse(200, await handleDetail(detailMatch[1]));
  }
  const streamMatch = path.match(/^\/v1\/episodes\/([^/]+)\/stream$/);
  if (streamMatch) {
    const target = await handleStream(streamMatch[1]);
    if (url.searchParams.get('json') === '1') {
      return jsonResponse(200, { url: target });
    }
    return new Response(null, {
      status: 302,
      headers: {
        Location: target,
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': '*',
      },
    });
  }
  if (path === '/v1/cover') {
    const target = String(url.searchParams.get('url') || '').trim();
    if (!/^https:\/\//i.test(target)) throw new Error('封面地址不合法');
    const parsed = new URL(target);
    if (privateHost(parsed.hostname)) throw new Error('封面地址不允许指向内网');
    const upstream = await fetchBuffer(target, {
      headers: {
        'User-Agent': UA,
        Accept: 'image/avif,image/webp,image/apng,image/*,*/*;q=0.8',
      },
      timeout: 20000,
      retries: 1,
    });
    let bytes = upstream.body;
    if (!isImage(bytes)) {
      const decrypted = decryptCover(bytes);
      if (!decrypted) throw new Error('封面解密失败');
      bytes = decrypted;
    }
    return new Response(bytes, {
      status: 200,
      headers: {
        'Content-Type': imageMime(bytes),
        'Content-Length': String(bytes.length),
        'Cache-Control': 'public, max-age=1800',
        'Access-Control-Allow-Origin': '*',
      },
    });
  }
  return jsonResponse(404, { error: { code: 'NOT_FOUND', message: '接口不存在' } });
}

export default {
  async fetch(request) {
    try {
      return await handleRequest(request);
    } catch (error) {
      return jsonResponse(502, {
        error: { code: 'UPSTREAM_FAILED', message: String((error && error.message) || error) },
      });
    }
  },
};
