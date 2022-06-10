#
# Copyright (C) 2020-2021 CZ.NIC, z. s. p. o. (https://www.nic.cz/)
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-parallel-test
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DEPENDS+=python3/host
HOST_PYTHON3_PACKAGE_BUILD_DEPENDS:=setuptools-scm

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/python/python3-host.mk
include $(TOPDIR)/feeds/packages/lang/python/python3-package.mk

define Package/python3-parallel-test
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Run multiple tests in parallel
endef

define Package/python3-parallel-test/description
  Tools for running multiple tests in parallel
endef

$(eval $(call Py3Package,python3-parallel-test))
$(eval $(call BuildPackage,python3-parallel-test))
