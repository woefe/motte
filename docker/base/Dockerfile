FROM archlinux:latest

LABEL org.opencontainers.image.description="Motte sandbox base: opencode + shared tooling"

COPY pacman-mirrorlist /etc/pacman.d/mirrorlist
COPY opencode.json /etc/opencode/opencode.json

RUN pacman -Sy --noconfirm --needed \
        ca-certificates \
        curl \
        fd \
        git \
        mise \
        opencode \
        podman \
        podman-docker \
        ripgrep \
    && rm -rf /var/cache/pacman/pkg/*
