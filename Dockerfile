FROM debian:latest

# Install necessary packages
RUN apt-get update && apt-get install -y \
    git \
    vim \
    gcc \
    make \
    gdb \
    strace \
    curl \
    zsh \
    tmux \
    nasm \
    wget \
	procps \
	netcat-traditional \
	net-tools \
	rlwrap \
    && apt-get clean 

WORKDIR /root/docker

RUN if [ ! -d "/root/.oh-my-zsh" ]; then \
        sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"; \
    else \
        echo "Oh My Zsh is already installed, skipping installation."; \
    fi


COPY src/ /root/docker/src
COPY inc/ /root/docker/inc
COPY Makefile /root/docker/Makefile

# Set Zsh as default shell
CMD ["zsh"]
