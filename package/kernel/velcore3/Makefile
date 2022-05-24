include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=velcore3
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/elvees-elcore50
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Other modules
  DEPENDS:=@TARGET_elvees_mcom03
  TITLE:=Elvees ELcore-50 driver
  AUTOLOAD:=$(call AutoProbe,elcore50)
  FILES:= \
	$(PKG_BUILD_DIR)/elcore50.ko \
	$(PKG_BUILD_DIR)/elcore50-mmualloc.ko
endef

define KernelPackage/elvees-elcore50/description
  ELcore-50 syscall implementations.
endef

define KernelPackage/elvees-elcore50/config
	source "$(SOURCE)/Config.in"
endef

define KernelPackage/elvees-qlic
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Other modules
  DEPENDS:=@TARGET_elvees_mcom03
  TITLE:=Elvees QLIC driver
  AUTOLOAD:=$(call AutoLoad,60,qlic,1)
  FILES:= $(PKG_BUILD_DIR)/qlic.ko
endef

define KernelPackage/elvees-qlic/description
  Elvees QLIC Interrupt controller driver.
endef

define KernelPackage/elvees-vdmaacptest
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Other modules
  DEPENDS:=@TARGET_elvees_mcom03
  TITLE:=ACP testing on MCom-03
  FILES:= $(PKG_BUILD_DIR)/vdmaacptest.ko
endef

define KernelPackage/elvees-vdmaacptest/description
  Module for coherent port (ACP) testing via VDMA in MCom-03 SoC.
endef


PKG_EXTRA_KCONFIG:= \
	CONFIG_ELCORE50_VP=$(if $(CONFIG_ELCORE50_VP),y,n) \
	CONFIG_ELCORE50_NO_IRQS=$(if $(CONFIG_ELCORE50_NO_IRQS),y,n) \

PKG_EXTRA_CFLAGS:= \
	$(patsubst CONFIG_%, -D%=1, $(patsubst %=m,%,$(filter %=m,$(PKG_EXTRA_KCONFIG)))) \
	$(patsubst CONFIG_%, -D%=1, $(patsubst %=y,%,$(filter %=y,$(PKG_EXTRA_KCONFIG)))) \
	$(if $(CONFIG_TARGET_elvees_mcom03), -DELCORE3_MCOM03=1) \
	$(if $(CONFIG_VELCORE3_DRIVER_TRACE), -fno-inline) \

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(KERNEL_MAKE_FLAGS) \
		EXTRA_CFLAGS="$(PKG_EXTRA_CFLAGS) $(BUILDFLAGS)" \
		M="$(PKG_BUILD_DIR)" \
		modules
endef

define KernelPackage/elvees-elcore50/install
	$(INSTALL_DIR) $(1)/usr/include/linux
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/elcore50.h $(1)/usr/include/linux/
endef

$(eval $(call KernelPackage,elvees-elcore50))
$(eval $(call KernelPackage,elvees-qlic))
$(eval $(call KernelPackage,elvees-vdmaacptest))
