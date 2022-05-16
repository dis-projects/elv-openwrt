include $(TOPDIR)/rules.mk

PKG_NAME:=tinymembench
PKG_VERSION:=0.4.9
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL=https://github.com/ssvb/tinymembench.git
PKG_SOURCE_DATE:=2017-02-15
PKG_SOURCE_VERSION:=a2cf6d7e382e3aea1eb39173174d9fa28cad15f3
PKG_MIRROR_HASH:=b5b69e3d0c19e5a55bfebe386e29196c751612e30bd5aefc2ee1df11c18e0300

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/tinymembench
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Benchmark tests the system memory (RAM) performance
	URL:=https://github.com/ssvb/tinymembench
endef

define Package/tinymembench/description
  This is a simple memory benchmark program, which tries to measure the peak
  bandwidth of sequential memory accesses and the latency of random memory
  accesses. Bandwidth is measured by running different assembly code for
  the aligned memory blocks and attempting different prefetch strategies.
endef

define Package/tinymembench/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tinymembench $(1)/usr/bin/
endef

$(eval $(call BuildPackage,tinymembench))
