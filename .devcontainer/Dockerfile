FROM ubuntu

# Options for setup script
ARG INSTALL_ZSH="true"
ARG UPGRADE_PACKAGES="false"
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# Install needed packages and setup non-root user. Use a separate RUN statement to add your own dependencies.
COPY common-debian.sh /tmp/library-scripts/
RUN bash /tmp/library-scripts/common-debian.sh "${INSTALL_ZSH}" "${USERNAME}" "${USER_UID}" "${USER_GID}" "${UPGRADE_PACKAGES}" \
    && apt-get clean -y && rm -rf /var/lib/apt/lists/* /tmp/library-scripts

# NOTE: Add base tools to here
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    python-is-python3 python3-pip \
    file

##
# Install Kali linux tools.
# See tool listing: https://tools.kali.org/tools-listing
# See metapackages: https://tools.kali.org/kali-metapackages
RUN export DEBIAN_FRONTEND=noninteractive && \
    wget -q -O - https://archive.kali.org/archive-key.asc | apt-key add && \
    echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" > "/etc/apt/sources.list.d/kalitools.list" && \
    apt-get -m -y -qq update && \
    apt-get -y install --no-install-recommends \
    # web
    nikto wfuzz gobuster \
    sqlmap nmap \
    # forensic
    binwalk
    # steg

##
# Wordlists
# SecLists
RUN mkdir -p /usr/share/wordlist && cd /usr/share/wordlist && \
    wget -c https://github.com/danielmiessler/SecLists/archive/master.zip -O SecList.zip && \
    (unzip -o SecList.zip || true ) && \
    rm -rf SecList.zip && mv SecLists-master seclists

##
# Put useful links to /usr/share/link directory
RUN mkdir -p /usr/share/links && \
    echo https://book.hacktricks.xyz/ >> /usr/share/links/links.txt


# Or use katoolin3 to see the menu
# RUN mkdir -p tmp && cd tmp && git clone https://github.com/s-h-3-l-l/katoolin3 && cd katoolin3 && sudo ./install.sh

# RUN export DEBIAN_FRONTEND=noninteractive && unminimize && sudo apt remove
# 