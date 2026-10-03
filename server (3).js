import express from 'express';
import compression from 'compression';
import * as cheerio from 'cheerio';
import { handleRequest as falHandleRequest, resolveProxyConfig, DEFAULT_PROXY_ROUTE as FAL_PROXY_ROUTE } from '@fal-ai/server-proxy';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import net from 'node:net';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const FAL_KEY = process.env.FAL_KEY || (process.env.FAL_KEY_ID && process.env.FAL_KEY_SECRET ? `${process.env.FAL_KEY_ID}:${process.env.FAL_KEY_SECRET}` : '');
const APP_PASSWORD = process.env.APP_PASSWORD || '';
const ALLOW_PUBLIC = process.env.ALLOW_PUBLIC === 'true';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.createHash('sha256').update(`${APP_PASSWORD}|${FAL_KEY}|ad-video`).digest('hex');
const SESSION_DAYS = 30;

// ключ на сервере используем только если вход защищён паролем (или явно разрешено публично)
const SERVER_KEY = !!FAL_KEY && (!!APP_PASSWORD || ALLOW_PUBLIC);
if (FAL_KEY && !APP_PASSWORD && !ALLOW_PUBLIC) {
  console.warn('⚠️  FAL_KEY задан, но APP_PASSWORD нет. Чтобы чужие люди не тратили ваш баланс, серверный ключ отключён — задайте APP_PASSWORD (или ALLOW_PUBLIC=true, если понимаете риск).');
}

const app = express();
app.set('trust proxy', 1); // Railway работает за прокси — нужно для secure-cookie
app.disable('x-powered-by');
app.use(compression());
app.use(express.json({ limit: '1mb' }));

// ---------- вход по паролю (подписанная cookie, без базы данных) ----------
const sign = (v) => crypto.createHmac('sha256', SESSION_SECRET).update(v).digest('base64url');
function makeToken() { const exp = Date.now() + SESSION_DAYS * 864e5; return `${exp}.${sign(String(exp))}`; }
function validToken(t) {
  if (!t) return false;
  const [exp, sig] = String(t).split('.');
  if (!exp || !sig || +exp < Date.now()) return false;
  const a = Buffer.from(sig), b = Buffer.from(sign(exp));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const cookies = (req) => Object.fromEntries((req.headers.cookie || '').split(';').map((c) => c.trim().split('=')).filter((p) => p[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join('='))]));
const loggedIn = (req) => !APP_PASSWORD || validToken(cookies(req).session);
function requireAuth(req, res, next) {
  if (loggedIn(req)) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

const attempts = new Map(); // простая защита от перебора пароля
app.post('/api/login', (req, res) => {
  if (!APP_PASSWORD) return res.json({ ok: true });
  const ip = req.ip, now = Date.now();
  const a = (attempts.get(ip) || []).filter((t) => now - t < 15 * 60e3);
  if (a.length >= 10) return res.status(429).json({ error: 'Слишком много попыток. Подождите 15 минут.' });
  const given = Buffer.from(String((req.body && req.body.password) || ''));
  const real = Buffer.from(APP_PASSWORD);
  const ok = given.length === real.length && crypto.timingSafeEqual(given, real);
  if (!ok) { a.push(now); attempts.set(ip, a); return res.status(401).json({ error: 'Неверный пароль' }); }
  attempts.delete(ip);
  res.setHeader('Set-Cookie', `session=${encodeURIComponent(makeToken())}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${req.secure ? '; Secure' : ''}`);
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/config', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ serverKey: SERVER_KEY, auth: !!APP_PASSWORD, loggedIn: loggedIn(req) });
});
app.get('/health', (req, res) => res.send('ok'));

// ---------- прокси к fal.ai: ключ подставляется на сервере, браузер его не видит ----------
// разрешены только модели, которые использует приложение
const ALLOWED_ENDPOINTS = [
  'fal-ai/any-llm{,/**}',
  'openai/gpt-image-2{,/**}',
  'fal-ai/flux{,/**}', 'fal-ai/flux-pro{,/**}',
  'fal-ai/minimax/**', 'fal-ai/kling-video/**', 'fal-ai/elevenlabs/**',
  'CassetteAI/**', 'cassetteai/**',
];
const falConfig = resolveProxyConfig({
  allowedEndpoints: ALLOWED_ENDPOINTS,
  allowUnauthorizedRequests: false,
  isAuthenticated: async () => true, // доступ уже проверил requireAuth (пароль)
  resolveFalAuth: async () => `Key ${FAL_KEY}`,
});
async function falProxy(req, res) {
  await falHandleRequest({
    id: 'express',
    method: req.method,
    getRequestBody: async () => JSON.stringify(req.body),
    getHeaders: () => req.headers,
    getHeader: (name) => req.headers[name],
    sendHeader: (name, value) => res.setHeader(name, value),
    respondWith: (status, data) => res.status(status).json(data),
    sendResponse: async (r) => {
      const type = r.headers.get('content-type') || '';
      if (type.includes('application/json')) return res.status(r.status).json(await r.json());
      return res.status(r.status).send(Buffer.from(await r.arrayBuffer()));
    },
  }, falConfig).catch((e) => { if (!res.headersSent) res.status(502).json({ error: 'fal.ai недоступен: ' + e.message }); });
}

app.all(FAL_PROXY_ROUTE, (req, res, next) => {
  if (!SERVER_KEY) return res.status(404).json({ error: 'Серверный ключ fal не настроен' });
  next();
}, requireAuth, falProxy);

// ---------- чтение сайта: текст и фото товара ----------
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v = ip.toLowerCase();
  if (v.startsWith('::ffff:')) return isPrivateIp(v.slice(7));
  return v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80');
}
async function assertPublicUrl(u) {
  const url = new URL(u);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Нужна ссылка http(s)');
  if (url.port && !['80', '443'].includes(url.port)) throw new Error('Недопустимый порт');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const ips = net.isIP(host) ? [host] : (await dns.lookup(host, { all: true })).map((r) => r.address);
  if (!ips.length || ips.some(isPrivateIp)) throw new Error('Недопустимый адрес');
  return url;
}
async function fetchPage(u) {
  let url = await assertPublicUrl(u);
  for (let i = 0; i < 4; i++) {
    const r = await fetch(url, {
      redirect: 'manual', signal: AbortSignal.timeout(15000),
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36', 'Accept-Language': 'ru,en;q=0.8', Accept: 'text/html,application/xhtml+xml' },
    });
    if (r.status >= 300 && r.status < 400 && r.headers.get('location')) { url = await assertPublicUrl(new URL(r.headers.get('location'), url).href); continue; }
    if (!r.ok) throw new Error(`Сайт ответил ${r.status}`);
    const reader = r.body.getReader(); const chunks = []; let size = 0;
    for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > 4e6) { reader.cancel(); break; } chunks.push(value); }
    return { html: Buffer.concat(chunks).toString('utf8'), finalUrl: url.href };
  }
  throw new Error('Слишком много перенаправлений');
}
const BAD_IMG = /(logo|icon|sprite|favicon|avatar|pixel|tracking|badge|payment|visa|mastercard|paypal|flag|placeholder|loader|spinner|arrow|rating|social|facebook|instagram|twitter|youtube|tiktok|whatsapp|telegram)/i;
function parsePage(html, base) {
  const $ = cheerio.load(html);
  const meta = (n) => $(`meta[property="${n}"]`).attr('content') || $(`meta[name="${n}"]`).attr('content') || '';
  const imgs = [meta('og:image'), meta('og:image:secure_url'), meta('twitter:image')];
  const facts = [];
  // данные о товаре из разметки JSON-LD (её используют почти все магазины)
  $('script[type="application/ld+json"]').each((_, el) => {
    try {
      const walk = (o) => {
        if (!o || typeof o !== 'object') return;
        if (Array.isArray(o)) return o.forEach(walk);
        const type = [].concat(o['@type'] || []).join(',');
        if (/Product|Offer|Service|Course|Book|SoftwareApplication/i.test(type)) {
          if (o.name) facts.push(`Product: ${o.name}`);
          if (o.description) facts.push(String(o.description).slice(0, 600));
          if (o.brand) facts.push(`Brand: ${o.brand.name || o.brand}`);
          const offer = [].concat(o.offers || [])[0];
          if (offer && offer.price) facts.push(`Price: ${offer.price} ${offer.priceCurrency || ''}`);
          [].concat(o.image || []).forEach((im) => imgs.unshift(typeof im === 'string' ? im : im.url || im.contentUrl));
        }
        Object.values(o).forEach((v) => typeof v === 'object' && walk(v));
      };
      walk(JSON.parse($(el).contents().text()));
    } catch {}
  });
  $('img').each((_, el) => {
    const e = $(el);
    const ss = e.attr('srcset') || e.attr('data-srcset');
    if (ss) { const parts = ss.split(',').map((x) => x.trim().split(/\s+/)[0]).filter(Boolean); imgs.push(parts[parts.length - 1]); }
    imgs.push(e.attr('data-src') || e.attr('data-lazy-src') || e.attr('src'));
  });
  const images = [];
  for (const u of imgs) {
    if (!u || /^data:/i.test(u)) continue;
    try {
      const abs = new URL(u.trim(), base).href;
      if (!/^https?:/i.test(abs) || /\.(svg|gif|ico)(\?|$)/i.test(abs) || BAD_IMG.test(abs)) continue;
      if (!images.includes(abs)) images.push(abs);
    } catch {}
    if (images.length >= 15) break;
  }
  $('script,style,noscript,svg,nav,footer,header form').remove();
  const heads = $('h1,h2,h3').map((_, e) => $(e).text().trim()).get().filter(Boolean).slice(0, 12).join(' | ');
  const body = $('p,li').map((_, e) => $(e).text().trim()).get().filter((t) => t.length > 20).join(' ');
  const text = [`Title: ${meta('og:title') || $('title').text().trim()}`, `Description: ${meta('og:description') || meta('description')}`, ...facts, `Headings: ${heads}`, body]
    .join('\n').replace(/[ \t]+/g, ' ').replace(/\n\s*\n/g, '\n').trim().slice(0, 4000);
  return { text, images };
}
app.get('/api/read', requireAuth, async (req, res) => {
  try {
    let u = String(req.query.url || '').trim();
    if (!u) return res.status(400).json({ error: 'Нет ссылки' });
    if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
    const { html, finalUrl } = await fetchPage(u);
    res.json(parsePage(html, finalUrl));
  } catch (e) {
    res.status(422).json({ error: e.message || 'Не удалось прочитать сайт', text: '', images: [] });
  }
});

// ---------- скачивание готовых файлов (картинки, видео, звук) для браузера ----------
// запасной путь, если браузер не может забрать файл из хранилища fal напрямую
const MEDIA_MAX = 200e6;
app.get('/api/media', requireAuth, async (req, res) => {
  try {
    let url = await assertPublicUrl(String(req.query.url || ''));
    let r;
    for (let i = 0; i < 4; i++) {
      r = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(120000), headers: { 'User-Agent': 'Mozilla/5.0 ad-video-generator' } });
      if (r.status >= 300 && r.status < 400 && r.headers.get('location')) { url = await assertPublicUrl(new URL(r.headers.get('location'), url).href); continue; }
      break;
    }
    if (!r.ok) return res.status(502).json({ error: `источник ответил ${r.status}` });
    const type = r.headers.get('content-type') || 'application/octet-stream';
    if (!/^(image|video|audio)\/|octet-stream/i.test(type)) return res.status(415).json({ error: 'это не медиафайл' });
    const len = +r.headers.get('content-length') || 0;
    if (len > MEDIA_MAX) return res.status(413).json({ error: 'файл слишком большой' });
    res.setHeader('Content-Type', type);
    if (len) res.setHeader('Content-Length', len);
    res.setHeader('Cache-Control', 'private, max-age=3600');
    let size = 0;
    const reader = r.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > MEDIA_MAX) { reader.cancel(); return res.end(); }
      if (!res.write(value)) await new Promise((ok) => res.once('drain', ok));
    }
    res.end();
  } catch (e) {
    if (!res.headersSent) res.status(422).json({ error: e.message || 'не удалось скачать файл' });
    else res.end();
  }
});

// ---------- страница ----------
// index.html может лежать в папке public/ или рядом с server.js (если при загрузке на GitHub папка потерялась).
// Если копий две — берём ту, у которой номер версии новее (<meta name="app-version">).
const pageVersion = (f) => (fs.readFileSync(f, 'utf8').match(/<meta name="app-version" content="([^"]+)"/) || [])[1] || '0';
const PAGES = [path.join(__dirname, 'public', 'index.html'), path.join(__dirname, 'index.html')].filter((p) => fs.existsSync(p));
const PAGE = PAGES.sort((a, b) => pageVersion(b).localeCompare(pageVersion(a), 'en', { numeric: true }))[0];
const PAGE_VERSION = PAGE ? pageVersion(PAGE) : '';
if (!PAGE) console.error('❌ Не найден index.html — загрузите его в репозиторий в папку public/ (или рядом с server.js).');
else {
  console.log(`  Страница: ${path.relative(__dirname, PAGE)}, версия ${PAGE_VERSION}`);
  if (PAGES.length > 1) console.log(`  ⚠️ Найдено несколько index.html: ${PAGES.map((p) => `${path.relative(__dirname, p)} (версия ${pageVersion(p)})`).join(', ')} — используется самая новая. Лишнюю копию лучше удалить из репозитория.`);
}
app.get('/api/version', (req, res) => res.set('Cache-Control', 'no-store').json({ page: PAGE ? path.relative(__dirname, PAGE) : null, version: PAGE_VERSION, copies: PAGES.map((p) => ({ file: path.relative(__dirname, p), version: pageVersion(p) })) }));
app.get('*', (req, res) => {
  if (!PAGE) return res.status(500).type('text/plain; charset=utf-8').send('Не найден файл index.html. Загрузите его в репозиторий в папку public/ (или рядом с server.js) и перезапустите деплой.');
  res.setHeader('Cache-Control', 'no-store, must-revalidate'); // страница всегда свежая после обновления
  res.sendFile(PAGE);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Генератор роликов запущен на порту ${PORT}`);
  console.log(`  Ключ fal на сервере: ${SERVER_KEY ? 'да' : 'нет (пользователи вводят свой ключ)'}`);
  console.log(`  Вход по паролю: ${APP_PASSWORD ? 'да' : 'нет'}`);
});
