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
  let lastError = null;
  for (let i = 0; i < lines.length; i += 1) {
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
        timeout: 20000,
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
    cover: String(raw.cover || '').trim(),
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
    const category = (params.category || 'hot').trim();
    const sort = (params.sort || '').trim().toLowerCase();
    const request = { page, limit: 24 };
    if (category.indexOf('theme:') === 0) request.theme = category.slice(6);
    else if (/^\d+$/.test(category)) request.theme = category;
    if (category === 'new' || sort === 'new') request.recommend = '2';
    else request.recommend = '1';
    const data = await ygCall('/api/theater/exploreList', request, 'POST');
    const rows = Array.isArray(data.list) ? data.list : [];
    return rows.map(ygShow).filter(function (item) { return item; });
  },
  async search(params) {
    const data = await ygCall(
      '/api/search/result',
      { keyword: params.keyword, tab: 'video', page: params.page || 1, limit: 20 },
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
      cover: String(data.cover || ''),
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
