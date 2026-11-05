FROM oven/bun:1.4.4

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl jq sqlite3 && \
    rm -rf /var/lib/apt/lists/* /var/log/apt /var/log/dpkg.log /var/cache/ldconfig/aux-cache
COPY package.json bun.lock* ./
RUN --mount=type=cache,target=/root/.bun/install/cache --mount=type=tmpfs,target=/tmp bun install
COPY --link . .
RUN bun build ./mount.tsx --minify --target=browser --define 'process.env.NODE_ENV="production"' --outfile ./bundle.js && \
  bun run --bun tailwindcss -i ./globals.css -o ./output.css --minify

CMD ["bun", "./render.ts"]
