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

const HG_BASE = 'https://huangguoai.com';
const HG_HEADERS = {
  'User-Agent': UA,
  Accept: 'application/json, text/plain, */*',
  Referer: HG_BASE + '/',
};
const HG_CHANNELS = [
  ['hot', '热门'],
  ['new', '最新'],
  ['rank', '排行榜'],
  ['ai-duanju', 'AI短剧'],
  ['ai-manju', '成人漫剧'],
  ['ai-huanlian', 'AI换脸'],
  ['ai-mogai', 'AI魔改'],
];

let hgTagGroups = null;

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

async function hgCatalog(category, page, sort) {
  const cat = (category || 'hot').trim();
  const order = (sort || '').trim().toLowerCase();
  let url;
  if (cat === 'rank' || cat === 'ranks') {
    url = HG_BASE + '/api/ranks/hot?page=' + encodeURIComponent(page);
  } else if (/^ai-/.test(cat)) {
    url =
      HG_BASE +
      '/api/videos/category/' +
      encodeURIComponent(cat) +
      '?page=' +
      encodeURIComponent(page) +
      '&size=24&sort=' +
      encodeURIComponent(order === 'new' ? 'new' : 'hot');
  } else {
    const fallback = cat === 'new' || order === 'new' ? 'new' : 'hot';
    url =
      HG_BASE +
      '/api/videos?page=' +
      encodeURIComponent(page) +
      '&page_size=24&sort=' +
      encodeURIComponent(fallback);
  }
  const payload = await fetchJson(url, { headers: HG_HEADERS, timeout: 20000, retries: 1 });
  return hgRows(payload).map(hgItem).filter(function (item) {
    return item;
  });
}

async function hgTagCatalog(slug, page) {
  const path =
    '/tag/' +
    encodeURIComponent(slug) +
    '/' +
    (Number(page) > 1 ? 'page/' + Number(page) + '/' : '');
  const response = await fetchBuffer(HG_BASE + path, {
    headers: Object.assign({}, HG_HEADERS, { Accept: 'text/html,application/xhtml+xml' }),
    timeout: 25000,
    retries: 1,
  });
  const html = response.body.toString('utf8');
  const grid =
    (html.match(
      /class="hg-card-grid[^"]*"[^>]*>([\s\S]*?)(?:class="hg-channel-pager"|class="hg-pager"|<\/main>|$)/i,
    ) || [])[1] || html;
  const blocks = grid.split(/<div class="hg-drama-card"[^>]*>/).slice(1);
  const items = [];
  blocks.forEach(function (block) {
    const link = block.match(/href="\/video\/(\d+)\/"/);
    if (!link) return;
    const cover = block.match(/data-src="([^"]+)"/);
    const alt = block.match(/alt="([^"]*)"/);
    const episode = block.match(/data-ep-base="([^"]*)"/);
    let title = (alt && alt[1] ? alt[1] : '').trim();
    if (!title) {
      const body = block.match(/hg-drama-card__title"[^>]*>[\s\S]*?<a[^>]*>([\s\S]*?)<\/a>/);
      title = body ? body[1].replace(/<[^>]+>/g, '').trim() : link[1];
    }
    const episodeText = episode ? episode[1] : '';
    const total = Number((episodeText.match(/(\d+)/) || [])[1] || 0) || 0;
    items.push({
      id: link[1],
      title,
      cover: cover ? '/v1/cover?url=' + encodeURIComponent(cover[1]) : '',
      description: '',
      total,
      finished: episodeText.indexOf('全') >= 0,
      tags: [],
      hot: 0,
    });
  });
  return items;
}

async function hgTags() {
  if (hgTagGroups) return hgTagGroups;
  const payload = await fetchJson(HG_BASE + '/api/tags', {
    headers: HG_HEADERS,
    timeout: 20000,
    retries: 1,
  });
  const categories = (payload && payload.data && payload.data.categories) || [];
  hgTagGroups = categories
    .map(function (category) {
      const ranks = (category.tags || [])
        .filter(function (tag) {
          return tag && tag.slug;
        })
        .map(function (tag) {
          return {
            id: 'tag:' + String(tag.slug),
            title: String(tag.name || tag.slug),
            filters: [],
          };
        });
      return { id: 'tagcat:' + String(category.code || category.id), title: String(category.name || '题材'), ranks };
    })
    .filter(function (group) {
      return group.ranks.length > 0;
    });
  return hgTagGroups;
}

const SOURCE = {
  name: '黄果短剧',
  async list(params) {
    return hgCatalog(params.category || 'hot', params.page || 1, params.sort || '');
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
  async ranks() {
    const groups = [
      {
        id: 'channel',
        title: '频道',
        ranks: HG_CHANNELS.map(function (pair) {
          return { id: pair[0], title: pair[1], filters: [] };
        }),
      },
    ];
    try {
      const tags = await hgTags();
      groups.push.apply(groups, tags);
    } catch (error) {
      // 题材接口失败时仍保留频道
    }
    return groups;
  },
  async rank(params) {
    const rank = String(params.rank || 'hot');
    const page = params.page || 1;
    let items;
    if (rank.indexOf('tag:') === 0) {
      items = await hgTagCatalog(rank.slice(4), page);
    } else {
      items = await hgCatalog(rank, page, '');
    }
    return { items, hasMore: items.length >= 20 };
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
