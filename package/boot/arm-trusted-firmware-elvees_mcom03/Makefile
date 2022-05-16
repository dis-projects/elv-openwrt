include $(TOPDIR)/rules.mk

PKG_NAME:=arm-trusted-firmware-elvees_mcom03
PKG_VERSION:=2.2
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL=https://github.com/elvees/arm-trusted-firmware.git
PKG_SOURCE_DATE:=2022-01-28
PKG_SOURCE_VERSION:=d688da5f694b24c47c2b11eda78d9e4c28314de5
PKG_MIRROR_HASH:=778473ec1ea44aa605bb2c2fd07050395e45dc4ed499da0bbd723b34232b4bd8

PKG_LICENSE:=BSD-3-Clause
PKG_LICENSE_FILES:=docs/license.rst

include $(INCLUDE_DIR)/package.mk

define Package/arm-trusted-firmware-elvees_mcom03
	SECTION:=boot
	CATEGORY:=Boot Loaders
	TITLE:=ARM Trusted Firmware for Elvees MCom-03
	URL:=https://github.com/elvees/arm-trusted-firmware
	DEPENDS:=@TARGET_elvees_mcom03
	HIDDEN:=1
endef

export GCC_HONOUR_COPTS=s

MAKE_VARS = \
	CROSS_COMPILE="$(TARGET_CROSS)"

MAKE_FLAGS += \
	PLAT=mcom03 \
	bl31

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR_IMAGE)
	$(CP) $(PKG_BUILD_DIR)/build/mcom03/release/bl31.bin $(STAGING_DIR_IMAGE)/bl31.bin
endef

define Package/arm-trusted-firmware-elvees_mcom03/install
endef

$(eval $(call BuildPackage,arm-trusted-firmware-elvees_mcom03))
