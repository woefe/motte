ARG BASE_IMAGE=ghcr.io/woefe/motte/base:latest
FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.description="Motte sandbox: Python/Node toolchain"

USER 0:0

RUN pacman -Syu --noconfirm --needed \
        python \
        python-pip \
        nodejs \
        npm \
    && rm -rf /var/cache/pacman/pkg/*

USER 1000:1000
