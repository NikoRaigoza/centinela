/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// En desarrollo, /api se reenvía al backend: el panel y la API quedan en el mismo origen,
// así la cookie de renovación (httpOnly, SameSite=Strict) funciona igual que en producción.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: { "/api": { target: "http://localhost:8000", changeOrigin: false } },
  },
  build: { sourcemap: false, target: "es2022" },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/pruebas/preparar.ts"],
    css: false,
  },
});
