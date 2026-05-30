# landing-v4 — static nginx server for the v4 sovereign landing kit.
#
# The v4 kit is intentionally CDN-driven (Lenis + Three.js WebGPU via importmap),
# so there is no build step. We just serve the static folder behind nginx.
#
# Build:  docker build -t tsm-landing-v4 .
# Run:    docker run --rm -p 8080:80 tsm-landing-v4
# Visit:  http://localhost:8080

FROM nginx:1.27-alpine

# Strip the default nginx welcome page; we own everything under /usr/share/nginx/html.
RUN rm -rf /usr/share/nginx/html/*

# Copy the static kit. Everything in this directory except the Dockerfile and
# the README is part of the landing surface.
COPY index.html              /usr/share/nginx/html/
COPY landing_v4.css          /usr/share/nginx/html/
COPY landing_v4.js           /usr/share/nginx/html/
COPY engine_v4.js            /usr/share/nginx/html/
COPY colors_and_type.css     /usr/share/nginx/html/
COPY assets/                 /usr/share/nginx/html/assets/

# Conservative cache policy: HTML never cached so updates land instantly,
# CSS/JS/SVG cached for an hour (they have no fingerprinting yet).
RUN printf '%s\n' \
  'server {' \
  '  listen 80 default_server;' \
  '  server_name _;' \
  '  root /usr/share/nginx/html;' \
  '  index index.html;' \
  '' \
  '  # Tight CSP-adjacent defaults; loosen as needed once you measure.' \
  '  add_header X-Content-Type-Options nosniff;' \
  '  add_header Referrer-Policy strict-origin-when-cross-origin;' \
  '' \
  '  location = / { try_files /index.html =404; }' \
  '  location ~ \.html$ { add_header Cache-Control "no-cache"; }' \
  '  location ~* \.(css|js|svg|woff2?|png|jpg|jpeg)$ {' \
  '    add_header Cache-Control "public, max-age=3600";' \
  '  }' \
  '}' \
  > /etc/nginx/conf.d/default.conf

EXPOSE 80
HEALTHCHECK --interval=15s --timeout=3s --start-period=2s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1/ || exit 1
