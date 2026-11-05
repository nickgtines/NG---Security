FROM python:3.13-slim

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl jq sqlite3 && \
    rm -rf /var/lib/apt/lists/* /var/log/apt /var/log/dpkg.log /var/cache/ldconfig/aux-cache
COPY requirements.txt* ./
RUN --mount=type=cache,target=/root/.cache/pip \
  if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
COPY --link . .

CMD ["python", "./script.py"]
