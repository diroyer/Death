FROM debian:12

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gcc \
        gdb \
        git \
        libc6-dev \
        make \
        nasm \
        net-tools \
        netcat-traditional \
        procps \
        rlwrap \
        strace \
        tmux \
        vim \
        wget \
        zsh \
    && rm -rf /var/lib/apt/lists/*

# Install Oh My Zsh without launching its interactive installer.
RUN git clone --depth=1 https://github.com/ohmyzsh/ohmyzsh.git /root/.oh-my-zsh \
    && printf '%s\n' \
        'export ZSH="/root/.oh-my-zsh"' \
        'ZSH_THEME="robbyrussell"' \
        'plugins=(git)' \
        'source "$ZSH/oh-my-zsh.sh"' \
        > /root/.zshrc

WORKDIR /workspace

CMD ["sleep", "infinity"]
