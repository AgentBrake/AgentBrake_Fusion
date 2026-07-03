import { resolve } from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const backendUrl = process.env.VITE_AGENTBRAKE_BACKEND_URL || process.env.AGENTBRAKE_BACKEND_URL || "http://127.0.0.1:8765";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": backendUrl
    }
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    rollupOptions: {
      input: {
        app: resolve(__dirname, "react.html")
      }
    }
  }
});
