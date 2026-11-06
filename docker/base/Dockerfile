FROM archlinux:latest

LABEL org.opencontainers.image.description="Motte sandbox base: opencode + shared tooling"

COPY pacman-mirrorlist /etc/pacman.d/mirrorlist

ENV COLORTERM=truecolor

RUN pacman -Syu --noconfirm --needed \
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
