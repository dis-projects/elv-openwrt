include $(TOPDIR)/rules.mk

PKG_NAME:=mcom03-sbl

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL=https://github.com/elvees/mcom03-sbl.git
PKG_SOURCE_DATE:=2022-04-08
PKG_SOURCE_VERSION:=d9f6226dffb413b7a2c4cbd7631584cf8229b3d7
PKG_MIRROR_HASH:=cb64dbe09b3fbad2ba592e3fe9b4c869e8799419b62fed202f32847b395450f6

PKG_LICENSE:=Custom

PKG_BUILD_DEPENDS+=arm-trusted-firmware-elvees_mcom03
PKG_BUILD_DEPENDS+=uboot-elvees

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/mcom03-sbl
	SECTION:=boot
	CATEGORY:=Boot Loaders
	TITLE:=Secondary bootloader for MCom-03
	URL:=https://github.com/elvees/mcom03-sbl
	DEPENDS:=@TARGET_elvees_mcom03
endef

CMAKE_OPTIONS += \
	-DDDRINIT_PATH=$(PKG_BUILD_DIR)/ddrinit.bin \
	-DTFA_PATH=$(STAGING_DIR_IMAGE)/bl31.bin \
	-DUBOOT_PATH=$(STAGING_DIR_IMAGE)/u-boot.bin \

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./ddrinit.bin $(PKG_BUILD_DIR)/
	$(call Build/Prepare/Default)
endef

define Build/Install/Default
endef

define Package/mcom03-sbl/install
	$(INSTALL_DIR) $(BIN_DIR)/mcom03-sbl
	$(CP) $(PKG_BUILD_DIR)/sbl-aarch64.bin $(BIN_DIR)/mcom03-sbl/
	$(CP) $(PKG_BUILD_DIR)/sbl-aarch64.elf $(BIN_DIR)/mcom03-sbl/
endef

$(eval $(call BuildPackage,mcom03-sbl))
