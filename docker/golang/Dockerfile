ARG BASE_IMAGE=ghcr.io/woefe/motte/base:latest
FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.description="Motte sandbox: Go toolchain"

RUN pacman -Syu --noconfirm --needed \
        go \
        govulncheck \
        gopls \
    && rm -rf /var/cache/pacman/pkg/*
