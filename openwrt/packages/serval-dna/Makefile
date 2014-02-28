# This OpwnWRT Makefile builds the Serval DNA daemon as an OpenWRT package,
# using the source code from a local working copy (possibly modified), instead
# of downloading it from GitHub.  This Makefile is intended for use by
# developers to make the edit-compile-flash-test work cycle as fast as
# possible.
#
# This Makefile is NOT SUITABLE for making public releases of the Serval DNA
# package; use the https://github.com/servalproject/openwrt-packages repository
# for that.
#
# Instructions for use
# --------------------
#
# Given:
#  - <SERVAL-DNA-REPO> (absolute path) contains a Git clone of the Serval DNA
#    repository
#  - <OPENWRT-REPO> contains a Git clone or download of the OpenWRT 12.09
#    release,
#
# To use this Makefile, simply add the following line to the
# <OPENWRT-REPO>/feeds.conf file:
#
#     src-link serval <SERVAL-DNA-REPO>/openwrt/packages
#
# For example:
#
#     src-link serval /home/username/src/batphone/jni/serval-dna/openwrt/packages
#
# Ensure that there are no other lines in feeds.conf that have 'serval' as the
# feed name.  Then, in a shell terminal, update the feed and install the
# serval-dna package:
#
#     cd <OPENWRT-REPO>
#     ./scripts/feeds update serval
#     ./scripts/feeds install -p serval serval-dna
#
# You may need to run 'make menuconfig' and ensure that the Serval DNA package
# is selected for inclusion (under Network --> Mesh networking).  Then build
# OpenWRT using 'make', which will copy the working copy from <SERVAL-DNA-REPO>
# into OpenWRT and build it using ./configure && make without having to use Git
# commit or any other special incantations.  (This ./configure && make is not
# performed in <SERVAL-DNA-REPO>, but in a temporary copy that OpenWRT takes.)
#
# Note that the entire Serval DNA source code is copied and recompiled by every
# OpenWRT 'make', because the OpenWRT build system downloads all its packages
# into a tarball and unpacks each tarball to build it.  This does not allow for
# a rapid edit-compile cycle using the OpenWRT build system, but at least it
# circumvents the need for Git commits in between editing and compiling.
#
# @author Andrew Bettison <andrew@servalproject.com>

THIS_MAKEFILE:=$(lastword $(MAKEFILE_LIST))

include $(TOPDIR)/rules.mk

PKG_NAME:=serval-dna
PKG_VERSION=devel
PKG_RELEASE=5

PKG_SOURCE_PROTO:=update-from-local-git
PKG_SOURCE_URL:=$(realpath $(dir $(THIS_MAKEFILE))../../..)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(shell cd $(PKG_SOURCE_URL) && ./version_string.sh)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_FIXUP:=autoreconf

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=

Validate/update-from-local-git=VERSION SUBDIR

define DownloadMethod/update-from-local-git
	echo "Copying files from $(PKG_SOURCE_URL)..."; \
	cd $(PKG_SOURCE_URL) && \
	git status --short >/dev/null && \
	mkdir -p $(TMP_DIR)/dl && \
	cd $(TMP_DIR)/dl && \
	rm -rf $(SUBDIR) && \
	[ \! -d $(SUBDIR) ] && \
	( cd $(PKG_SOURCE_URL) && \
		git ls-files --cached --exclude-standard | \
		cpio -p --make-directories --link --dereference --preserve-modification-time --quiet $(TMP_DIR)/dl/$(SUBDIR)) && \
	echo "Packing files..." && \
	$(call dl_pack,$(TMP_DIR)/dl/$(FILE),$(SUBDIR)) && \
	mv $(TMP_DIR)/dl/$(FILE) $(DL_DIR)/ && \
	rm -rf $(SUBDIR);
endef

include $(INCLUDE_DIR)/package.mk

define Package/serval-dna
	TITLE:=Serval DNA mesh networking daemon
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Mesh networking
	DEPENDS:=+libpthread +librt
	MAINTAINER:=Serval DNA Maintainer <serval-dna@servalproject.org>
endef

define Package/serval-dna/description
  Serval DNA is a daemon that implements the Serval Mesh network protocol as an
  overlay network encapsulated within UDP/IP packets over Wi-Fi.  The daemon,
  when running, joins the OpenWRT router to the local Serval Mesh Wi-Fi
  network.  This allows it to participate in dynamic mesh routing (using
  Serval's own mesh routing protocol), file distribution (using the Rhizome
  store-and-forward protocol), secure text messaging (using the MeshMS
  protocol), and to relay secure voice calls (using the VoMP voice-over-mesh
  protocol) and other secure Serval traffic (such as tunnelled SOCKS proxy
  connections) between Android devices running the Serval Mesh app.

  The Serval Mesh Extender device is essentially a Wi-Fi router running the
  Serval DNA daemon on OpenWRT.
endef

define Build/Configure
	echo "$(PKG_SOURCE_VERSION)" >$(PKG_BUILD_DIR)/$(CONFIGURE_PATH)/$(strip $(3))/VERSION.txt
	$(call Build/Configure/Default,$(1),$(2),$(3))
endef

define Package/serval-dna/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/servald $(1)/usr/bin
endef

$(eval $(call BuildPackage,serval-dna))
