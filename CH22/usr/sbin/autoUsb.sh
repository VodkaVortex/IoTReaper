#!/bin/sh
addUsbFile $1
bcmgpio usbup&
exit 1
