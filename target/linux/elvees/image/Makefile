include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

### Devices ###
define Device/Default
	DEVICE_VENDOR := Elvees
	DEVICE_PACKAGES := \
		kmod-elvees-elcore50 \
		kmod-elvees-qlic \
		kmod-elvees-vdmaacptest \
		kmod-fb \
		kmod-hwmon-mr75202 \
		kmod-rtc-rv8803 \
		kmod-usb-hid
endef

define Device/elvmc03smarc-ngfwcb
	DEVICE_MODEL := MCom-03 SMARC NGWF-CB
	DEVICE_DTS := elvees/mcom03-elvmc03smarc-r1.0-ngfwcb-r1.0
	SUPPORTED_DEVICES := \
		elvees,elvmc03smarc-r1.0-ngfwcb-r1.0 \
		elvees,elvmc03smarc-ngfwcb
	UBOOT := elvmc03smarc-ngfwcb
endef
ifeq ($(SUBTARGET),mcom03)
	TARGET_DEVICES += elvmc03smarc-ngfwcb
endif

define Device/elvmc03smarc-rockpi-n10
	DEVICE_MODEL := MCom-03 SMARC Rock Pi N10
	DEVICE_DTS := \
		elvees/mcom03-elvmc03smarc-r1.0-rockpi-n10 \
		elvees/mcom03-elvmc03smarc-r1.0-rockpi-n10-rpi-dsi-7inch
	SUPPORTED_DEVICES := \
		elvees,elvmc03smarc-r1.0-rockpi-n10 \
		elvees,elvmc03smarc-rockpi-n10
	UBOOT := elvmc03smarc-rockpi-n10
endef
ifeq ($(SUBTARGET),mcom03)
	TARGET_DEVICES += elvmc03smarc-rockpi-n10
endif

define Image/InstallKernel
	mkdir -p $(TARGET_DIR)/boot
	$(CP) $(KDIR)/Image $(TARGET_DIR)/boot/
	$(foreach dts,$(DEVICE_DTS), $(CP) $(KDIR)/image-$(dts).dtb $(TARGET_DIR)/boot/$(dts).dtb;)
	$(CP) $(KDIR)/image-*.dtb $(TARGET_DIR)/boot/

	mkdir -p $(TARGET_DIR)/boot/extlinux/
	$(CP) ./extlinux.conf $(TARGET_DIR)/boot/extlinux/
endef

$(eval $(call BuildImage))
