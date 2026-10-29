# Cowrie with its well-known fingerprints removed (see mkfs.py and userdb.txt).
# The upstream image is distroless (no shell), so build steps use exec-form RUN with its own Python.
FROM cowrie/cowrie:latest AS fs
USER root
COPY mkfs.py /build/mkfs.py
RUN ["/cowrie/cowrie-env/bin/python3", "/build/mkfs.py", \
     "/cowrie/cowrie-git/src/cowrie/data/fs.pickle", "/build/fs.pickle", \
     "/cowrie/cowrie-git/src/cowrie/data/txtcmds", "/build/txtcmds"]

FROM cowrie/cowrie:latest
COPY --from=fs /build/fs.pickle /cowrie/honeyjar/fs.pickle
COPY --from=fs /build/txtcmds /cowrie/honeyjar/txtcmds
COPY userdb.txt /cowrie/honeyjar/etc/userdb.txt
ENV COWRIE_SHELL_FILESYSTEM=/cowrie/honeyjar/fs.pickle \
    COWRIE_HONEYPOT_ETC_PATH=/cowrie/honeyjar/etc \
    COWRIE_HONEYPOT_CONTENTS_PATH=/cowrie/honeyfs \
    COWRIE_HONEYPOT_TXTCMDS_PATH=/cowrie/honeyjar/txtcmds \
    COWRIE_SHELL_KERNEL_VERSION=5.15.0-122-generic \
    COWRIE_SHELL_KERNEL_BUILD_STRING="#132-Ubuntu SMP Thu Aug 29 13:45:52 UTC 2024" \
    COWRIE_SHELL_HARDWARE_PLATFORM=x86_64 \
    COWRIE_SHELL_OPERATING_SYSTEM=GNU/Linux \
    COWRIE_SSH_VERSION="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
