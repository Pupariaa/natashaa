FROM node:22-slim
ENV TZ=Europe/Paris
RUN apt-get update && apt-get install -y --no-install-recommends iptables ulogd2 ca-certificates iproute2 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
CMD ["node","--max-old-space-size=8192","/app/index.js"]