include $(TOPDIR)/rules.mk

ARCH:=arm
BOARD:=elvees
BOARDNAME:=Elvees
SUBTARGETS:=mcom03

KERNEL_PATCHVER:=4.19

include $(INCLUDE_DIR)/target.mk

KERNELNAME:=Image dtbs

DEFAULT_PACKAGES+=bash binutils libopenssl mtd busybox luci

# Docker packages
DEFAULT_PACKAGES+=docker dockerd docker-compose

# Python packages
DEFAULT_PACKAGES+=python3 python3-pytest python3-parallel-test

# QA tools
DEFAULT_PACKAGES+=iperf3 hdparm i2c-tools lm-sensors nmap tinymembench memtester-simple

# Load balancing/failover with multiple WAN interfaces
DEFAULT_PACKAGES+=mwan3 luci-app-mwan3

$(eval $(call BuildTarget))
