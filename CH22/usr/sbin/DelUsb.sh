#!/bin/sh
killall -9 smbd
killall -9 nmbd
sleep 1
umount -f /media/$1*
DelUsbFile $1
bcmgpio usbdown&
exit 1
