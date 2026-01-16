#!/bin/sh
qemu-system-x86_64 \
      -m 64M \
      -cpu qemu64 \
      -kernel bzImage \
      -drive file=rootfs.ext2,format=raw \
      -drive file=flag.txt,format=raw,if=virtio \
      -snapshot \
      -nographic \
      -monitor /dev/null \
      -no-reboot \
      -smp 1 \
      -append "root=/dev/sda rw init=/init console=ttyS0 loglevel=3 pti=on kaslr oops=panic panic=-1"
