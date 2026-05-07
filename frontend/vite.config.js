import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/parse_hashes': 'http://127.0.0.1:5000',
      '/get_api_keys': 'http://127.0.0.1:5000',
      '/add_api_key': 'http://127.0.0.1:5000',
      '/scan_one': 'http://127.0.0.1:5000',
      '/osint/api_keys': 'http://127.0.0.1:5000',
      '/osint/scan': 'http://127.0.0.1:5000',
      '/osint/hibp': 'http://127.0.0.1:5000',
      '/auth': 'http://127.0.0.1:5000'
    }
  }
})
