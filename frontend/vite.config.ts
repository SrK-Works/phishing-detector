import { defineConfig } from 'vite'
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
})
