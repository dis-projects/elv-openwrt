include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

FAT32_BLOCK_SIZE=1024
FAT32_BLOCKS=$(shell echo $$(($(CONFIG_TARGET_KERNEL_PARTSIZE)*1024*1024/$(FAT32_BLOCK_SIZE))))

### Image scripts ###
define Build/boot-common
	rm -f $@.boot
	mkfs.fat -n boot -C $@.boot $(FAT32_BLOCKS)
	mcopy -i $@.boot $(IMAGE_KERNEL) ::$(KERNEL_IMG)
	$(foreach dts,$(shell echo $(DEVICE_DTS)),mcopy -i $@.boot $(DTS_DIR)/$(dts).dtb ::;)
endef

define Build/sdcard-img
	./gen_sdcard_img.sh $@ $@.boot $(IMAGE_ROOTFS) \
		$(CONFIG_TARGET_KERNEL_PARTSIZE) $(CONFIG_TARGET_ROOTFS_PARTSIZE)
endef

### Devices ###
define Device/Default
	DEVICE_VENDOR := Elvees
	KERNEL := kernel-bin
	KERNEL_IMG := kernel.img
	IMAGES := sdcard.img.gz
	IMAGE/sdcard.img.gz := boot-common | sdcard-img | gzip
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

$(eval $(call BuildImage))
