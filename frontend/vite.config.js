import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// MCP_GATE_BACKEND points the dev proxy at another backend (default: the standard port)
const BACKEND = process.env.MCP_GATE_BACKEND || 'http://localhost:4568'

/**
 * The console talks to the backend through this proxy, so from the browser's point of view everything is
 * same-origin and the backend needs no CORS entry for the dev server (it has none by default: an origin listed
 * in cors.allowed_origins gets credentialed access to the admin API). The backend still checks Origin on every
 * state-changing request and on the WebSocket handshake, so a request the dev page itself made has its Origin
 * rewritten to the backend's. Requests from any other page keep their Origin and are refused as before.
 */
function sameOriginAsBackend(proxy) {
  const rewrite = (proxyReq, req) => {
    const origin = req.headers.origin
    if (origin && origin === `http://${req.headers.host}`) proxyReq.setHeader('origin', BACKEND)
  }
  proxy.on('proxyReq', rewrite)
  proxy.on('proxyReqWs', rewrite)
}

const target = { target: BACKEND, changeOrigin: true, configure: sameOriginAsBackend }

export default defineConfig({
  plugins: [react()],
  base: '/',
  build: {
    outDir: '../static/web',
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          charts: ['recharts']
        }
      }
    }
  },
  server: {
    // Note: /tokens, /clients and /consent are SPA routes and must not be proxied
    proxy: {
      '/api': target,
      '/oauth': target,
      '/.well-known': target,
      '/ws': { ...target, ws: true },
    }
  }
})
