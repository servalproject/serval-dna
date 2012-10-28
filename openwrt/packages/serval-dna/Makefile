include $(TOPDIR)/rules.mk

PKG_NAME:=serval-dna
PKG_VERSION:=2012-10-29
PKG_RELEASE=$(PKG_SOURCE_VERSION)

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/servalproject/serval-dna.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=be3b529504450680065008aab95e2ed3f1a5a3d5
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_FIXUP:=autoreconf

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=

include $(INCLUDE_DIR)/package.mk

define Package/serval-dna
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=serval-dna
	DEPENDS:=+libpthread +librt
endef

define Package/serval-dna/description
  Serval Daemon
endef

define Package/serval-dna/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/servald $(1)/usr/bin
endef

$(eval $(call BuildPackage,serval-dna))


