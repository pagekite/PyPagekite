#!/bin/bash
IMAGE_IMG=2019-04-08-raspbian-stretch.img
IMAGE_ZIP=2019-04-08-raspbian-stretch.zip
IMAGE_URL=http://downloads.raspberrypi.org/raspbian/images/raspbian-2019-04-09/$IMAGE_ZIP

set -e
mkdir -p ~/tmp/rpi_qemu_vm
cd ~/tmp/rpi_qemu_vm

[ -e $IMAGE_ZIP ] || wget $IMAGE_URL
[ -e $IMAGE_IMG ] || unzip $IMAGE_ZIP

# See: https://github.com/lukechilds/dockerpi
docker run -it -v $(pwd)/$IMAGE_IMG:/sdcard/filesystem.img lukechilds/dockerpi:vm
