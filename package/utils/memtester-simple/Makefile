include $(TOPDIR)/rules.mk

PKG_NAME:=memtester-simple
PKG_RELEASE:=1
CMAKE_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/memtester-simple
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Simple memory tester
endef

define Package/memtester-simple/description
  memtester is an effective userspace tester for stress-testing the memory subsystem.
endef

TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include

define Package/memtester-simple/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/memtester-simple $(1)/usr/bin/
endef

$(eval $(call BuildPackage,memtester-simple))
