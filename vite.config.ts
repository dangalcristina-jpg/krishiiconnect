import { defineConfig, type ViteDevServer, loadEnv } from 'vite';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createApiRouter } from './src/api/server';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';

const PAGES: Record<string, string> = {
  '/': 'index.html',
  '/products': 'src/pages/products.html',
  '/market-prices': 'src/pages/market-prices.html',
  '/about': 'src/pages/about.html',
  '/contact': 'src/pages/contact.html',
  '/login': 'src/pages/login.html',
  '/register': 'src/pages/register.html',
  '/admin/login': 'src/pages/admin-login.html',
  '/admin': 'src/pages/admin.html',
  '/farmer': 'src/pages/farmer.html',
  '/wholesaler': 'src/pages/wholesaler.html',
};

const ARTICLE_PAGE = 'src/pages/article.html';

function resolvePage(urlPath: string): string | null {
  const p = urlPath.split('?')[0];
  if (PAGES[p]) return PAGES[p];
  if (p.startsWith('/articles/') || p === '/articles') return ARTICLE_PAGE;
  return null;
}

function serveHtml(server: ViteDevServer) {
  return (req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void) => {
    const file = resolvePage(req.url || '');
    if (!file) return next();
    const abs = path.resolve(process.cwd(), file);
    if (!fs.existsSync(abs)) return next();
    fs.readFile(abs, 'utf-8', async (err, data) => {
      if (err) return next(err);
      try {
        const transformed = await server.transformIndexHtml(req.url || '/', data);
        res.setHeader('Content-Type', 'text/html');
        res.end(transformed);
      } catch (e) {
        next(e);
      }
    });
  };
}

export default defineConfig(({ mode }) => {
  // Load .env into process.env so the Express API can read SUPABASE_* vars.
  const env = loadEnv(mode, process.cwd(), '');
  for (const [k, v] of Object.entries(env)) {
    if (!process.env[k]) process.env[k] = v;
  }
  return {
    server: {
      port: 5173,
      host: true,
    },
    plugins: [
      {
        name: 'kc-api-and-pages',
        configureServer(server) {
          const api = express();
          api.use(express.json({ limit: '1mb' }));
          api.use(createApiRouter());
          server.middlewares.use('/api', api);
          // Multi-page HTML routing — must run before Vite's default fallback.
          server.middlewares.use(serveHtml(server));
        },
        configurePreviewServer(server) {
          const api = express();
          api.use(express.json({ limit: '1mb' }));
          api.use(createApiRouter());
          server.middlewares.use('/api', api);
          server.middlewares.use(serveHtml(server as unknown as ViteDevServer));
        },
      },
    ],
    build: {
      outDir: 'dist',
      emptyOutDir: true,
      rollupOptions: {
        input: {
          main: 'index.html',
          products: 'src/pages/products.html',
          marketPrices: 'src/pages/market-prices.html',
          about: 'src/pages/about.html',
          contact: 'src/pages/contact.html',
          login: 'src/pages/login.html',
          register: 'src/pages/register.html',
          adminLogin: 'src/pages/admin-login.html',
          admin: 'src/pages/admin.html',
          farmer: 'src/pages/farmer.html',
          wholesaler: 'src/pages/wholesaler.html',
          article: 'src/pages/article.html',
        },
      },
    },
  };
});
