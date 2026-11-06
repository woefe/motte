ARG BASE_IMAGE=ghcr.io/woefe/motte/base:latest
FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.description="Motte sandbox: Ruby on Rails toolchain"

RUN pacman -Syu --noconfirm --needed \
        ruby \
        sqlite \
        nodejs \
        npm \
    && rm -rf /var/cache/pacman/pkg/*
