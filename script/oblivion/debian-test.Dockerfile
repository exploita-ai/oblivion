FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 dpkg-dev systemd init-system-helpers cryptsetup-bin dmsetup e2fsprogs \
    util-linux mount fdisk udev debconf squashfs-tools libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && touch /.oblivion-package-fixture
# No controller, QEMU or native agent is started by this packaging-only fixture.
CMD ["python3", "-B", "/sources/packages/oblivion-host/tests/debian-package.py"]
