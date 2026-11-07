// RexHub 短剧插件公共运行时：内置 HTTP 服务、代理出站、封面解密。
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import zlib from 'node:zlib';

const VERSION = '1.0.0';
const PROXY = String(process.env.REXHUB_PLUGIN_PROXY || '').trim();
const LISTEN_PORT = Number(process.env.REXHUB_PLUGIN_PORT || 0);
const LISTEN_HOST = String(process.env.REXHUB_PLUGIN_HOST || '127.0.0.1');
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

function sendJson(response, status, payload) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
  });
  response.end(body);
}

const HG_BASE = 'https://huangguoai.com';
const HG_HEADERS = {
  'User-Agent': UA,
  Accept: 'application/json, text/plain, */*',
  Referer: HG_BASE + '/',
};

function hgRows(payload) {
  const node = payload && typeof payload.data === 'object' && payload.data ? payload.data : payload;
  if (!node || typeof node !== 'object') return [];
  const keys = ['items', 'list', 'videos', 'rows', 'results', 'data'];
  for (let i = 0; i < keys.length; i += 1) {
    const value = node[keys[i]];
    if (Array.isArray(value)) return value;
  }
  return [];
}

function hgCover(raw) {
  const url = String((raw && raw.cover) || (raw && raw.vod_pic) || (raw && raw.pic) || '').trim();
  return url ? '/v1/cover?url=' + encodeURIComponent(url) : '';
}

function hgItem(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const id = String(raw.id || raw.vod_id || raw.video_id || raw.drama_id || '').trim();
  if (!id) return null;
  const tags = [];
  const rawTags = raw.tags || raw.tag_links || [];
  if (Array.isArray(rawTags)) {
    rawTags.forEach(function (tag) {
      if (typeof tag === 'string' && tag.trim()) tags.push(tag.trim());
      else if (tag && typeof tag === 'object') {
        const name = String(tag.name || tag.title || tag.tag || '').trim();
        if (name) tags.push(name);
      }
    });
  }
  return {
    id,
    title: String(raw.title || raw.vod_name || raw.name || id).trim(),
    cover: hgCover(raw),
    description: String(raw.description || '').trim(),
    total: Number(raw.episode_count || raw.total_episodes || raw.total || 0) || 0,
    finished: Boolean(raw.is_finished),
    tags,
    hot: Number(raw.hot || raw.heat || raw.metric_value || 0) || 0,
  };
}

const SOURCE = {
  name: '黄果短剧',
  async list(params) {
    const page = params.page || 1;
    const category = (params.category || 'hot').trim();
    const sort = (params.sort || '').trim().toLowerCase();
    let url;
    if (category === 'rank' || category === 'ranks') {
      url = HG_BASE + '/api/ranks/hot?page=' + encodeURIComponent(page);
    } else if (/^ai-/.test(category)) {
      url =
        HG_BASE +
        '/api/videos/category/' +
        encodeURIComponent(category) +
        '?page=' +
        encodeURIComponent(page) +
        '&size=24&sort=' +
        encodeURIComponent(sort === 'new' ? 'new' : 'hot');
    } else {
      const order = category === 'new' || sort === 'new' ? 'new' : 'hot';
      url =
        HG_BASE +
        '/api/videos?page=' +
        encodeURIComponent(page) +
        '&page_size=24&sort=' +
        encodeURIComponent(order);
    }
    const payload = await fetchJson(url, { headers: HG_HEADERS, timeout: 20000, retries: 1 });
    return hgRows(payload).map(hgItem).filter(function (item) {
      return item;
    });
  },
  async search(params) {
    const url =
      HG_BASE +
      '/api/search?q=' +
      encodeURIComponent(params.keyword) +
      '&page=' +
      encodeURIComponent(params.page || 1);
    const payload = await fetchJson(url, { headers: HG_HEADERS, timeout: 20000, retries: 1 });
    return hgRows(payload).map(hgItem).filter(function (item) {
      return item;
    });
  },
  async detail(id) {
    const payload = await fetchJson(HG_BASE + '/api/videos/' + encodeURIComponent(id), {
      headers: HG_HEADERS,
      timeout: 20000,
      retries: 1,
    });
    const data = (payload && payload.data) || {};
    const episodes = [];
    const raw = Array.isArray(data.episodes) ? data.episodes : [];
    raw.forEach(function (episode, index) {
      const n = Number(episode.ep_num || episode.episode || index + 1) || index + 1;
      episodes.push({
        key: String(n),
        episode: n,
        title: String(episode.title || '第' + n + '集'),
        duration: Number(episode.duration || 0) || 0,
      });
    });
    const total = Number(data.episode_count || episodes.length || 0) || episodes.length;
    if (!episodes.length && total) {
      for (let n = 1; n <= Math.min(total, 500); n += 1) {
        episodes.push({ key: String(n), episode: n, title: '第' + n + '集', duration: 0 });
      }
    }
    return {
      id,
      title: String(data.title || id),
      cover: hgCover(data),
      description: String(data.description || ''),
      total,
      finished: Boolean(data.is_finished),
      tags: [],
      episodes,
    };
  },
  async resolve(id, episodeKey) {
    const n = Math.max(1, Number(episodeKey || 1) || 1);
    const payload = await fetchJson(
      HG_BASE + '/api/videos/' + encodeURIComponent(id) + '/play?ep=' + encodeURIComponent(n),
      { headers: HG_HEADERS, timeout: 20000, retries: 1 },
    );
    const data = (payload && payload.data) || {};
    let url = String(data.video_url || data.url || '').trim();
    if (url.indexOf('//') === 0) url = 'https:' + url;
    if (!url && data.video_api) url = String(data.video_api).trim();
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

const server = http.createServer(async function (request, response) {
  try {
    if (request.method === 'OPTIONS') {
      response.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
        'Access-Control-Allow-Headers': '*',
      });
      response.end();
      return;
    }
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      sendJson(response, 405, { error: { code: 'METHOD_NOT_ALLOWED', message: '仅支持 GET' } });
      return;
    }
    const url = new URL(request.url || '/', 'http://127.0.0.1');
    const path = url.pathname.replace(/\/+$/, '') || '/';
    if (path === '/' || path === '/health') {
      sendJson(response, 200, { ok: true, name: SOURCE.name, version: VERSION });
      return;
    }
    if (path === '/v1/list') {
      sendJson(response, 200, await handleList(url.searchParams));
      return;
    }
    if (path === '/v1/search') {
      sendJson(response, 200, await handleSearch(url.searchParams));
      return;
    }
    const detailMatch = path.match(/^\/v1\/detail\/([^/]+)$/);
    if (detailMatch) {
      sendJson(response, 200, await handleDetail(detailMatch[1]));
      return;
    }
    const streamMatch = path.match(/^\/v1\/episodes\/([^/]+)\/stream$/);
    if (streamMatch) {
      const target = await handleStream(streamMatch[1]);
      if (url.searchParams.get('json') === '1') {
        sendJson(response, 200, { url: target });
        return;
      }
      response.writeHead(302, {
        Location: target,
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': '*',
      });
      response.end();
      return;
    }
    if (path === '/v1/cover') {
      const target = String(url.searchParams.get('url') || '').trim();
      if (!/^https:\/\//i.test(target)) throw new Error('封面地址不合法');
      const parsed = new URL(target);
      if (privateHost(parsed.hostname)) throw new Error('封面地址不允许指向内网');
      const upstream = await fetchBuffer(target, {
        headers: { 'User-Agent': UA, Accept: 'image/avif,image/webp,image/apng,image/*,*/*;q=0.8' },
        timeout: 20000,
        retries: 1,
      });
      let bytes = upstream.body;
      if (!isImage(bytes)) {
        const decrypted = decryptCover(bytes);
        if (!decrypted) throw new Error('封面解密失败');
        bytes = decrypted;
      }
      response.writeHead(200, {
        'Content-Type': imageMime(bytes),
        'Content-Length': String(bytes.length),
        'Cache-Control': 'public, max-age=1800',
        'Access-Control-Allow-Origin': '*',
      });
      response.end(request.method === 'HEAD' ? undefined : bytes);
      return;
    }
    sendJson(response, 404, { error: { code: 'NOT_FOUND', message: '接口不存在' } });
  } catch (error) {
    sendJson(response, 502, {
      error: { code: 'UPSTREAM_FAILED', message: String((error && error.message) || error) },
    });
  }
});

server.listen(LISTEN_PORT, LISTEN_HOST, function () {
  const address = server.address();
  const port = address && typeof address === 'object' ? address.port : LISTEN_PORT;
  process.stdout.write('REXHUB_MODULE_READY ' + JSON.stringify({ port }) + '\n');
});
