# This VM contains one Safe. All shell state belongs to that encrypted volume.
if [ "$(id -u)" = 1000 ] && mountpoint -q /vault; then
    . /usr/lib/oblivion/guest/safe-environment.sh
fi
