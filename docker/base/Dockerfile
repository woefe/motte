FROM archlinux:latest

LABEL org.opencontainers.image.description="Motte sandbox base: opencode + shared tooling"

COPY pacman-mirrorlist /etc/pacman.d/mirrorlist
COPY opencode.json /etc/opencode/opencode.json

ENV COLORTERM=truecolor

RUN pacman -Sy --noconfirm --needed \
        ca-certificates \
        curl \
        fd \
        git \
        mise \
        # uv required for mise pypi backend
        uv \
        opencode \
        podman \
        podman-docker \
        ripgrep \
        base-devel \
    && rm -rf /var/cache/pacman/pkg/*
