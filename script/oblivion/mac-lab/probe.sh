#!/bin/sh
# Runs only in the disposable ARM initramfs. Prints no user or session data.
set -e
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mkdir -p /proc /sys /dev /root
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
exec > /dev/hvc0 2>&1
printf 'OBLIVION_VZ_PROBE_STARTED\n'
for module in virtio_pci virtio_blk virtio_console squashfs; do modprobe "$module"; done
while [ ! -b /dev/vda ]; do sleep 1; done
mount -t squashfs -o ro /dev/vda /root
mount --bind /dev /root/dev
mount --bind /proc /root/proc
mount --bind /sys /root/sys
mount -t tmpfs tmpfs /root/run
mount -t tmpfs tmpfs /root/tmp
chroot /root /usr/bin/python3 - <<'PY'
import fcntl, json, os
descriptor = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
version = fcntl.ioctl(descriptor, 0xAE00, 0)
assert version == 12
vm = fcntl.ioctl(descriptor, 0xAE01, 0)
vcpu = fcntl.ioctl(vm, 0xAE41, 0)
print('OBLIVION_VZ_KVM ' + json.dumps({'api_version': version, 'vm_created': True, 'vcpu_created': True}), flush=True)
for fd in (vcpu, vm, descriptor): os.close(fd)
PY
printf 'OBLIVION_VZ_PROBE_FINISHED\n'
poweroff -f
