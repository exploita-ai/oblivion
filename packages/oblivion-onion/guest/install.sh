#!/bin/sh
set -eu
test "$(id -u)" = 0
groupadd --gid 1000 oblivion-http
useradd --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin oblivion-http
groupadd --gid 1002 oblivion-copy
useradd --uid 1002 --gid 1002 --no-create-home --shell /usr/sbin/nologin oblivion-copy
passwd -l root
mkdir -p /etc/oblivion /usr/libexec /source /run/oblivion-onion /run/oblivion-onion-stage
install -m 0644 /usr/lib/oblivion/onion/guest/*.service /usr/lib/oblivion/onion/guest/*.socket /etc/systemd/system/
install -m 0644 /usr/lib/oblivion/onion/guest/firewall.nft /etc/oblivion/onion-file.nft
install -m 0755 /usr/lib/oblivion/onion/guest/network.sh /usr/libexec/oblivion-onion-file-network
install -m 0755 /usr/lib/oblivion/onion/guest/stage.sh /usr/libexec/oblivion-onion-stage
install -m 0755 /usr/lib/oblivion/onion/guest/source.sh /usr/libexec/oblivion-onion-source
install -m 0755 /usr/lib/oblivion/onion/guest/copy-stop.sh /usr/libexec/oblivion-onion-copy-stop
cat >> /etc/fstab <<'EOF'
tmpfs /run/oblivion-onion tmpfs nosuid,nodev,noexec,mode=0700,uid=1000,gid=1000,size=640M,nr_inodes=8192 0 0
tmpfs /run/oblivion-onion-stage tmpfs nosuid,nodev,noexec,mode=0700,uid=1002,gid=1002,size=272M,nr_inodes=4096 0 0
EOF
mkdir -p /etc/systemd/network /etc/initramfs-tools/hooks /etc/modules-load.d /etc/udev/rules.d
cat > /etc/systemd/network/10-oblivion-file.link <<'EOF'
[Match]
MACAddress=52:54:00:6f:00:04
[Link]
Name=file0
EOF
cat > /etc/initramfs-tools/hooks/oblivion-file-link <<'EOF'
#!/bin/sh
set -eu
case "${1:-}" in prereqs) exit 0;; esac
mkdir -p "$DESTDIR/etc/systemd/network"
cp /etc/systemd/network/10-oblivion-file.link "$DESTDIR/etc/systemd/network/"
EOF
chmod 0755 /etc/initramfs-tools/hooks/oblivion-file-link
printf 'virtio_net\nvirtio_console\nnf_tables\nnft_ct\nnft_counter\n' > /etc/modules-load.d/oblivion-file.conf
printf 'virtio_net\nvirtio_console\n' >> /etc/initramfs-tools/modules
printf '%s\n' \
    'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.onion.file", OWNER="root", GROUP="root", MODE="0600", TAG+="systemd", ENV{SYSTEMD_WANTS}+="oblivion-onion-file.service"' \
    'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.onion.stage", OWNER="1002", GROUP="1002", MODE="0600"' \
    'SUBSYSTEM=="virtio-ports", ATTR{name}=="oblivion.onion.source", OWNER="1002", GROUP="1002", MODE="0600"' \
    > /etc/udev/rules.d/71-oblivion-onion-file.rules
printf '%s\n' 'SUBSYSTEM=="block", KERNEL=="vd*", ATTR{serial}=="oblivion-backup", OWNER="1000", GROUP="1000", MODE="0400"' >> /etc/udev/rules.d/71-oblivion-onion-file.rules
cat > /etc/systemd/system/oblivion-onion-file.target <<'EOF'
[Unit]
Description=Oblivion isolated file transfer VM
Requires=multi-user.target oblivion-onion-file-network.service
After=multi-user.target oblivion-onion-file-network.service
AllowIsolate=yes
EOF
ln -sf /etc/systemd/system/oblivion-onion-file.target /etc/systemd/system/default.target
update-initramfs -u -k all
