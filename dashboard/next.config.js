/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  env: {
    NEXT_PUBLIC_PROXY_URL: process.env.PROXY_URL ?? 'http://localhost:8080',
  },
};

module.exports = nextConfig;
