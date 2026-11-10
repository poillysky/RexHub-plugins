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
  if (host === '::1' || host === '[::1]' || host === '[::]' || host === '::') return true;
  if (host === '0.0.0.0' || host === '[::ffff:0.0.0.0]') return true;
  if (/^\[::ffff:/i.test(host)) return true;
  if (/^127\./.test(host) || /^10\./.test(host) || /^169\.254\./.test(host)) return true;
  if (/^192\.168\./.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(host)) return true;
  return false;
}

function pageLimit(value, fallback) {
  const text = String(value == null ? '' : value).trim();
  if (!text) return fallback;
  const n = Number(text);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(24, Math.max(1, Math.floor(n)));
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

const YG_LINES = [
  'https://www.yeguodj.com/api.php',
  'https://yeguodj.com/api.php',
  'https://analyze.buxefaex.cc/api.php',
  'https://adviser.tjecfkte.cc/api.php',
];
const YG_SITE = 'https://www.yeguodj.com';
const YG_KEY = Buffer.from('2acf7e91e9864673', 'utf8');
const YG_IV = Buffer.from('1c29882d3ddfcfd6', 'utf8');
const YG_OAUTH = crypto.randomBytes(16).toString('hex');
const YG_FALLBACK_THEMES = [
  ['theme:7', '野果原创'],
  ['theme:8', '真人短剧'],
  ['theme:9', '魔改漫剧'],
  ['theme:10', '网红改编'],
  ['theme:11', 'PMV裸舞'],
];

let ygApiBase = YG_LINES[0];
let ygOptions = null;
let ygThemes = null;

function ygDecrypt(blob) {
  const encrypted = Buffer.from(String(blob).replace(/ /g, '+').trim(), 'base64');
  const decipher = crypto.createDecipheriv('aes-128-cbc', YG_KEY, YG_IV);
  return JSON.parse(
    Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8'),
  );
}

function ygCommon() {
  return {
    bundleId: 'com.pwa.mater',
    version: '1.3.2',
    oauth_type: 'web',
    language: 'zh',
    via: 'pwa',
    oauth_id: YG_OAUTH,
    trace_id: YG_OAUTH,
    token: '',
  };
}

async function ygCall(route, params, method) {
  const values = ygCommon();
  Object.keys(params || {}).forEach(function (key) {
    const value = params[key];
    if (value == null) return;
    values[key] = String(value);
  });
  const form = new URLSearchParams(values).toString();
  const lines = ygApiBase
    ? [ygApiBase].concat(YG_LINES.filter(function (line) { return line !== ygApiBase; }))
    : YG_LINES.slice();
  // 主线故障时不能把 4 条线路 × 20 秒串完，整体预算 12 秒
  const deadline = Date.now() + 12000;
  let lastError = null;
  for (let i = 0; i < lines.length; i += 1) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    const api = lines[i];
    const url = api.replace(/\/$/, '') + route;
    try {
      const options = {
        headers: {
          'User-Agent': UA,
          Accept: 'application/json, text/plain, */*',
          Referer: YG_SITE + '/',
          Origin: YG_SITE,
        },
        timeout: Math.min(6000, remaining),
        retries: 0,
      };
      if ((method || 'POST').toUpperCase() === 'GET') {
        const response = await fetchBuffer(url + '?' + form, options);
        return ygUnwrap(response.body);
      }
      options.method = 'POST';
      options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      options.body = form;
      const response = await fetchBuffer(url, options);
      return ygUnwrap(response.body);
    } catch (error) {
      lastError = error;
    }
  }
  throw new Error('野果请求失败：' + String((lastError && lastError.message) || route));
}

function ygUnwrap(body) {
  const envelope = JSON.parse(body.toString('utf8'));
  if (Number(envelope.errcode) !== 0) {
    throw new Error('野果返回 ' + envelope.errcode + ' ' + String(envelope.msg || ''));
  }
  if (typeof envelope.data !== 'string' || !envelope.data) {
    throw new Error('野果返回缺少加密数据');
  }
  const payload = ygDecrypt(envelope.data);
  const data = payload && typeof payload === 'object' && 'data' in payload ? payload.data : payload;
  return data && typeof data === 'object' ? data : { value: data };
}

async function ygContentOptions() {
  if (ygOptions) return ygOptions;
  try {
    ygOptions = await ygCall('/api/home/contentOptions', {}, 'GET');
  } catch (error) {
    ygOptions = {};
  }
  return ygOptions;
}

async function ygThemeList() {
  if (ygThemes) return ygThemes;
  try {
    const options = await ygContentOptions();
    const block = (options.video_filter && options.video_filter.theme) || {};
    const rows = Array.isArray(block.list) ? block.list : [];
    const out = [];
    rows.forEach(function (row) {
      if (!row || row.value == null) return;
      const name = String(row.name || '').trim();
      if (name) out.push(['theme:' + String(row.value), name]);
    });
    ygThemes = out.length ? out : YG_FALLBACK_THEMES.slice();
  } catch (error) {
    ygThemes = YG_FALLBACK_THEMES.slice();
  }
  return ygThemes;
}

async function ygFilterGroups() {
  const dimensions = [
    ['setting', '设定'],
    ['background', '背景'],
    ['time', '时间'],
  ];
  const options = await ygContentOptions();
  const videoFilter = (options && options.video_filter) || {};
  const groups = [];
  dimensions.forEach(function (pair) {
    const block = videoFilter[pair[0]] || {};
    const rows = Array.isArray(block.list) ? block.list : [];
    const items = rows
      .filter(function (row) {
        return row && row.value != null && String(row.value) !== '0';
      })
      .map(function (row) {
        return { id: pair[0] + ':' + String(row.value), title: String(row.name || row.value) };
      });
    if (items.length) groups.push({ title: pair[1], items });
  });
  return groups;
}

function ygCover(raw) {
  const url = String((raw && raw.cover) || '').trim();
  return url ? '/v1/cover?url=' + encodeURIComponent(url) : '';
}

function ygShow(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const id = String(raw.video_id || raw.id || '').trim();
  if (!id) return null;
  const tags = [];
  if (Array.isArray(raw.tags)) {
    raw.tags.forEach(function (tag) {
      if (typeof tag === 'string' && tag.trim()) tags.push(tag.trim());
      else if (tag && typeof tag === 'object') {
        const name = String(tag.name || tag.title || '').trim();
        if (name) tags.push(name);
      }
    });
  }
  return {
    id,
    title: String(raw.title || id).trim(),
    cover: ygCover(raw),
    description: String(raw.description || '').trim(),
    total: Number(raw.episode_count || raw.episodes || raw.total_serial || 0) || 0,
    finished: String(raw.serialize_status) === '2',
    tags,
    hot: Number(raw.play_count || raw.hot || 0) || 0,
  };
}

const SOURCE = {
  name: '野果短剧',
  async list(params) {
    const page = params.page || 1;
    const limit = pageLimit(params.limit, 24);
    const category = (params.category || 'hot').trim();
    const sort = (params.sort || '').trim().toLowerCase();
    const request = { page, limit };
    if (category.indexOf('theme:') === 0) request.theme = category.slice(6);
    else if (/^\d+$/.test(category)) request.theme = category;
    if (category === 'new' || sort === 'new') request.recommend = '2';
    else request.recommend = '1';
    const data = await ygCall('/api/theater/exploreList', request, 'POST');
    const rows = Array.isArray(data.list) ? data.list : [];
    return rows.map(ygShow).filter(function (item) { return item; });
  },
  async ranks() {
    let filters = [];
    try {
      filters = await ygFilterGroups();
    } catch (error) {
      filters = [];
    }
    const groups = [
      {
        id: 'recommend',
        title: '推荐',
        ranks: [
          { id: 'hot', title: '热门', filters },
          { id: 'new', title: '最新', filters },
        ],
      },
    ];
    const themes = await ygThemeList();
    groups.push({
      id: 'theme',
      title: '主题',
      ranks: themes.map(function (pair) {
        return { id: pair[0], title: pair[1], filters };
      }),
    });
    return groups;
  },
  async rank(params) {
    const rank = String(params.rank || 'hot');
    const limit = pageLimit(params.limit, 24);
    const request = { page: params.page || 1, limit };
    if (rank.indexOf('theme:') === 0) request.theme = rank.slice(6);
    request.recommend = rank === 'new' ? '2' : '1';
    const filter = String(params.filter || '');
    const matched = filter.match(/^(setting|background|time):(.+)$/);
    if (matched) request[matched[1]] = matched[2];
    const data = await ygCall('/api/theater/exploreList', request, 'POST');
    const rows = Array.isArray(data.list) ? data.list : [];
    const items = rows.map(ygShow).filter(function (item) { return item; });
    return { items, hasMore: items.length >= limit };
  },
  async search(params) {
    const data = await ygCall(
      '/api/search/result',
      {
        keyword: params.keyword,
        tab: 'video',
        page: params.page || 1,
        limit: pageLimit(params.limit, 24),
      },
      'POST',
    );
    const rows = Array.isArray(data.list) ? data.list : [];
    return rows.map(ygShow).filter(function (item) { return item; });
  },
  async detail(id) {
    const data = await ygCall(
      '/api/playlet/detail',
      { video_id: id, id, episode_id: '0', related_limit: '0' },
      'POST',
    );
    const episodes = [];
    const rows = Array.isArray(data.episodes) ? data.episodes : [];
    rows.forEach(function (episode) {
      if (!episode || episode.is_adv === true || episode.is_adv === 1 || episode.is_adv === '1') return;
      const key = String(episode.id || '').trim();
      const n = Number(episode.sort || 0) || 0;
      if (!key || n < 1) return;
      episodes.push({
        key,
        episode: n,
        title: String(episode.title || '第' + n + '集'),
        duration: Number(episode.duration || 0) || 0,
      });
    });
    episodes.sort(function (a, b) { return a.episode - b.episode; });
    const total = Number(data.episode_count || episodes.length || 0) || episodes.length;
    return {
      id,
      title: String(data.title || id),
      cover: ygCover(data),
      description: String(data.description || ''),
      total,
      finished: String(data.serialize_status) === '2',
      tags: Array.isArray(data.tags) ? data.tags : [],
      episodes,
    };
  },
  async resolve(id, episodeKey) {
    const data = await ygCall(
      '/api/playlet/play',
      { playlet_id: id, video_id: id, episode_id: String(episodeKey) },
      'POST',
    );
    let url = String(data.video_url || data.video_url_h265 || data.m3u8 || '').trim();
    if (url.indexOf('//') === 0) url = 'https:' + url;
    return url;
  },
};


function normalizeList(items) {
  return (items || []).filter(function (item) {
    return item && item.id && item.title;
  });
}

async function handleList(query) {
  const page = Math.max(1, Number(query.get('page') || 1) || 1);
  const limit = pageLimit(query.get('limit'), 24);
  const category = String(query.get('category') || query.get('group') || '').trim();
  const sort = String(query.get('sort') || '').trim();
  const tab = String(query.get('tab') || '').trim();
  const items = normalizeList(await SOURCE.list({ page, category, sort, tab, limit }));
  const hasMore = items.length >= limit;
  return { items, hasMore, nextPage: hasMore ? page + 1 : null };
}

async function handleRanks(query) {
  const group = String(query.get('group') || '').trim();
  if (!group) {
    const groups = typeof SOURCE.ranks === 'function' ? await SOURCE.ranks() : [];
    return { groups };
  }
  const page = Math.max(1, Number(query.get('page') || 1) || 1);
  const limit = pageLimit(query.get('limit'), 24);
  const rank = String(query.get('rank') || '').trim();
  const filter = String(query.get('filter') || '').trim();
  if (typeof SOURCE.rank !== 'function') return { items: [] };
  const payload = await SOURCE.rank({ group, rank, filter, page, limit });
  const items = normalizeList(payload.items || []);
  const hasMore = Boolean(payload.hasMore) && items.length > 0;
  return { items, hasMore, nextPage: hasMore ? page + 1 : null };
}

async function handleSearch(query) {
  const keyword = String(query.get('keyword') || query.get('q') || query.get('keywords') || '').trim();
  const page = Math.max(1, Number(query.get('page') || 1) || 1);
  const limit = pageLimit(query.get('limit'), 24);
  if (!keyword) return { items: [], hasMore: false, nextPage: null };
  const items = normalizeList(await SOURCE.search({ keyword, page, limit }));
  const hasMore = items.length >= limit;
  return { items, hasMore, nextPage: hasMore ? page + 1 : null };
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
