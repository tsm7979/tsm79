import { defineConfig } from "vite";

export default defineConfig({
  preview: {
    port: 4173,
    host: true,
    // allow the public Cloudflare quick-tunnel host
    allowedHosts: [".trycloudflare.com"],
  },
  server: {
    allowedHosts: [".trycloudflare.com"],
  },
});
