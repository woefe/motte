FROM archlinux:latest

LABEL org.opencontainers.image.description="Motte sandbox base: opencode + shared tooling"

COPY --chmod=0644 pacman-mirrorlist /etc/pacman.d/mirrorlist
COPY --chmod=0644 unprivileged-userns-setuid.hook /etc/pacman.d/hooks/unprivileged-userns-setuid.hook
# Arch's vendor drop-in in this directory overrides /etc/containers/containers.conf,
# so the motte defaults must ride in a drop-in sorting after it.
COPY --chmod=0644 containers.conf /usr/share/containers/containers.conf.d/50-motte.conf
COPY --chmod=0644 storage.conf /etc/containers/storage.conf

ENV COLORTERM=truecolor

RUN pacman -Syu --noconfirm --needed \
        ca-certificates \
        curl \
        fd \
        fuse-overlayfs \
        git \
        mise \
        # uv required for mise pypi backend
        uv \
        opencode \
        podman \
        podman-docker \
        ripgrep \
        base-devel \
    && rm -rf /var/cache/pacman/pkg/* \
    && chmod u+s /usr/bin/newuidmap /usr/bin/newgidmap \
    && touch /etc/containers/nodocker \
    && useradd --create-home --uid 1000 --shell /bin/bash motte

USER 1000:1000
