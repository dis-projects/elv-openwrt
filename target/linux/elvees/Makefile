include $(TOPDIR)/rules.mk

ARCH:=arm
BOARD:=elvees
BOARDNAME:=Elvees
SUBTARGETS:=mcom03

KERNEL_PATCHVER:=4.19

include $(INCLUDE_DIR)/target.mk

KERNELNAME:=Image dtbs

DEFAULT_PACKAGES+=bash binutils libopenssl python3 mtd busybox luci

# Docker packages
DEFAULT_PACKAGES+=docker dockerd docker-compose

# Packages for QA
DEFAULT_PACKAGES+=iperf3 hdparm i2c-tools lm-sensors nmap tinymembench

# Automatic failure recovery for network demo
DEFAULT_PACKAGES+=mwan3 luci-app-mwan3

$(eval $(call BuildTarget))
