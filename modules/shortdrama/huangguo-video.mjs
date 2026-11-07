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
