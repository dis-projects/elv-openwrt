ARCH:=aarch64
SUBTARGET:=mcom03
BOARDNAME:=MCom-03
CPU_TYPE:=cortex-a53
FEATURES+=targz dt usb pcie rtc gpio

define Target/Description
	Build images for Elvees MCom-03 (1892BA018) boards.
endef
