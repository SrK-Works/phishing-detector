import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // In production this is one container (FastAPI serves the built
    // frontend), so /api is same-origin. In dev, proxy it to uvicorn.
    proxy: {
      '/api': 'http://localhost:8000',
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/setupTests.ts'],
    // e2e/ holds Playwright specs (run via `npm run test:e2e`), not Vitest
    // ones -- without this Vitest's default glob picks them up too and
    // fails trying to run Playwright's test() through its own runner.
    exclude: ['e2e/**', 'node_modules/**'],
  },
})
