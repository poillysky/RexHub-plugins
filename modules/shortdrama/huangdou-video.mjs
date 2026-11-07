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

const LOGO_BASE64 = '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';

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

function hdTabId(tab, index) {
  const tid = String((tab && tab.tab) || '').trim();
  if (tid) return tid;
  const filter = tab && typeof tab.filter === 'object' ? tab.filter : {};
  const keys = ['cat_id', 'tag_id', 'source'];
  for (let i = 0; i < keys.length; i += 1) {
    const value = filter[keys[i]];
    if (value != null && String(value).trim() !== '') return keys[i] + ':' + value;
  }
  return 'i:' + index;
}

function hdPickTab(tabs, want) {
  if (!tabs || !tabs.length) return null;
  const value = String(want || '').trim();
  if (!value) return tabs[0];
  for (let i = 0; i < tabs.length; i += 1) {
    if (hdTabId(tabs[i], i) === value) return tabs[i];
  }
  const index = Number(value);
  if (Number.isInteger(index) && index >= 0 && index < tabs.length) return tabs[index];
  return tabs[0];
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

async function hdList(params) {
  await hdEnsureLogin().catch(function () {});
  const page = params.page || 1;
  const category = (params.category || 'hot').trim();
  const sort = (params.sort || '').trim().toLowerCase();
  const order = category === 'new' || sort === 'new' ? 'new' : 'hot';
  if (category && category !== 'hot' && category !== 'new' && category !== 'all') {
    try {
      const code = await hdResolveCode(category);
      const tabs = await hdNavFilter(code);
      const picked = hdPickTab(tabs, params.tab);
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
}

const SOURCE = {
  name: '黄豆短剧',
  async list(params) {
    return hdList(params);
  },
  async ranks() {
    await hdEnsureLogin().catch(function () {});
    const groups = [
      {
        id: 'recommend',
        title: '推荐',
        ranks: [
          { id: 'hot', title: '热门', filters: [] },
          { id: 'new', title: '最新', filters: [] },
        ],
      },
    ];
    try {
      const nav = await hdNavList();
      const channels = [];
      for (let i = 0; i < nav.length; i += 1) {
        const code = String(nav[i].code || '').trim().toLowerCase();
        if (!code || code === 'hot' || code === 'new') continue;
        let filters = [];
        try {
          const tabs = await hdNavFilter(code);
          const items = tabs
            .map(function (tab, index) {
              const id = hdTabId(tab, index);
              return { id, title: String(tab.name || id) };
            })
            .filter(function (item) { return item.id && item.title; });
          if (items.length) filters = [{ title: '分类', items }];
        } catch (error) {
          filters = [];
        }
        channels.push({
          id: code,
          title: String(nav[i].name || code),
          filters,
        });
      }
      if (channels.length) groups.push({ id: 'channel', title: '频道', ranks: channels });
    } catch (error) {
      // 导航接口失败时只保留推荐
    }
    return groups;
  },
  async rank(params) {
    const items = await hdList({
      page: params.page || 1,
      category: params.rank || 'hot',
      sort: params.rank === 'new' ? 'new' : 'hot',
      tab: params.filter || '',
    });
    return { items, hasMore: items.length >= 20 };
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
  const tab = String(query.get('tab') || '').trim();
  const items = await SOURCE.list({ page, category, sort, tab });
  return { items: normalizeList(items) };
}

async function handleRanks(query) {
  const group = String(query.get('group') || '').trim();
  if (!group) {
    const groups = typeof SOURCE.ranks === 'function' ? await SOURCE.ranks() : [];
    return { groups };
  }
  const page = Math.max(1, Number(query.get('page') || 1) || 1);
  const rank = String(query.get('rank') || '').trim();
  const filter = String(query.get('filter') || '').trim();
  if (typeof SOURCE.rank !== 'function') return { items: [] };
  const payload = await SOURCE.rank({ group, rank, filter, page });
  return {
    items: normalizeList(payload.items || []),
    hasMore: Boolean(payload.hasMore),
  };
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
  if (path === '/v1/ranks') {
    return jsonResponse(200, await handleRanks(url.searchParams));
  }
  if (path === '/v1/logo') {
    if (typeof LOGO_BASE64 !== 'string' || !LOGO_BASE64) {
      return jsonResponse(404, { error: { code: 'NOT_FOUND', message: '未内置 Logo' } });
    }
    const bytes = Buffer.from(LOGO_BASE64, 'base64');
    return new Response(bytes, {
      status: 200,
      headers: {
        'Content-Type': 'image/png',
        'Content-Length': String(bytes.length),
        'Cache-Control': 'public, max-age=86400',
        'Access-Control-Allow-Origin': '*',
      },
    });
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
