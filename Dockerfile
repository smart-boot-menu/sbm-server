FROM node:22-bookworm AS web
WORKDIR /src/sbm-server
COPY web/package.json web/package-lock.json web/
RUN npm ci --prefix web
COPY web web
RUN npm run build --prefix web

FROM rust:1.100.0-bookworm AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
ARG SBM_COMMON_REV=4b432228caae40479d28c8f6f48fb7cb9cc6df85
RUN git init sbm-common \
    && git -C sbm-common remote add origin https://github.com/smart-boot-menu/sbm-common.git \
    && git -C sbm-common fetch --depth 1 origin ${SBM_COMMON_REV} \
    && git -C sbm-common checkout FETCH_HEAD
COPY . /src/sbm-server
COPY --from=web /src/sbm-server/web/build /src/sbm-server/web/build
WORKDIR /src/sbm-server
RUN cargo build --release --locked -p sbm-server

FROM debian:bookworm-slim
RUN useradd --system --uid 8443 --create-home --home-dir /data sbm
COPY --from=build /src/sbm-server/target/release/sbm-server /usr/local/bin/sbm-server
USER sbm
WORKDIR /data
ENV SBM_DATA_DIR=/data \
    SBM_BIND=0.0.0.0:8443 \
    SBM_PUBLIC_ORIGIN=https://localhost:8443 \
    SBM_RP_ID=localhost
EXPOSE 8443
ENTRYPOINT ["sbm-server"]
