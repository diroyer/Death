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

# Create working directory

# Install Oh My Zsh

#RUN useradd -ms /bin/bash docker
#
#USER docker
#
#WORKDIR /home/docker

WORKDIR /root/docker

COPY . .
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

# Set Zsh as default shell
CMD ["zsh"]
