ARCH:=aarch64
SUBTARGET:=mcom03
BOARDNAME:=MCom-03
CPU_TYPE:=cortex-a53
FEATURES+=ext4 dt usb pcie rtc gpio display rootfs-part boot-part

define Target/Description
	Build images for Elvees MCom-03 (1892ВА018) boards.
endef
