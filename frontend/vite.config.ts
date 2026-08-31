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
    // Vitest's default 'threads' pool has been unreliable spawning jsdom
    // workers on GitHub Actions' Linux runners (worker init crash) even
    // though it's fine locally -- 'forks' is the documented workaround.
    pool: 'forks',
  },
})
