#!/bin/bash

if [ ! -f ./.config ]; then
    cp /boot/config-$(uname -r) ./.config
    make olddefconfig
    make menuconfig
    exit 1
fi


make -j$(nproc)

pushd tools/power/cpupower
sudo make install
popd

sudo make modules_install -j$(nproc)
sudo make install

echo "Kernel for Bypassd has been built and installed."
echo "Please use grub to select the new kernel and reboot"
