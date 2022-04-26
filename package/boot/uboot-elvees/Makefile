include $(TOPDIR)/rules.mk

PKG_VERSION:=2021.01
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/elvees/u-boot.git
PKG_SOURCE_VERSION:=c65a3ac74128d89e2d20871ec1e14bf9bd2d46a5
PKG_MIRROR_HASH:=ab197f4b769a08e1b9c9ef194fcffe83f0aed314005f5a7c7dd31896ccb58806

include $(INCLUDE_DIR)/u-boot.mk
include $(INCLUDE_DIR)/package.mk

define U-Boot/Default
	BUILD_TARGET:=elvees
	UBOOT_IMAGE:=u-boot.bin
endef

define U-Boot/elvmc03smarc-ngfwcb
	NAME:=MCom-03 SMARC NGWF-CB
	BUILD_SUBTARGET:=mcom03
	BUILD_DEVICES:=elvmc03smarc-ngfwcb
	UBOOT_CONFIG:=elvmc03smarc-ngfwcb
	HIDDEN:=1
endef

define U-Boot/elvmc03smarc-rockpi-n10
	NAME:=MCom-03 SMARC Rock Pi
	BUILD_SUBTARGET:=mcom03
	BUILD_DEVICES:=elvmc03smarc-rockpi-n10
	UBOOT_CONFIG:=elvmc03smarc-rockpi
	HIDDEN:=1
endef

UBOOT_TARGETS := \
	elvmc03smarc-ngfwcb \
	elvmc03smarc-rockpi-n10

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR_IMAGE)
	$(foreach img,$(UBOOT_IMAGE), \
		$(CP) $(PKG_BUILD_DIR)/$(img) $(STAGING_DIR_IMAGE)/$(img); \
	)
endef

$(eval $(call BuildPackage/U-Boot))
