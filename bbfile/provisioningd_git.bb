SUMMARY = "Provisioningd: Provisioning service"
DESCRIPTION = "This service monitor the provisioning status of a BMC"
HOMEPAGE = "https://github.com/abhilashraju/provisioningd"

LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://LICENSE;md5=340bb8e2a52d3a51b4914913110967a7"
DEPENDS = " \
    boost \
    gtest \
    nlohmann-json \
    openssl \
    systemd \
    sdeventplus \
    coroserver \
    sdbusplus \
"

SRC_URI = "git://github.com/abhilashraju/provisioningd.git;branch=main;protocol=https"
SRCREV = "${AUTOREV}"

S = "${WORKDIR}/git"

inherit systemd
inherit pkgconfig meson

EXTRA_OEMESON = " \
    --buildtype=minsize \
"

# Specify the source directory
S = "${WORKDIR}/git"

# Specify the installation directory
bindir = "/usr/bin"
systemd_system_unitdir = "/etc/systemd/system"
etc_dbus_conf = "/etc/dbus-1/system.d"
do_install() {
     install -d ${D}${bindir}
     install -m 0755 ${B}/provisioningd ${D}${bindir}/provisioningd
     install -d ${D}${systemd_system_unitdir}
     install -d ${D}${etc_dbus_conf}
     
     
     install -m 0644 ${S}/service/xyz.openbmc_project.Provisioning.service ${D}${systemd_system_unitdir}/
     install -m 0644 ${S}/service/xyz.openbmc_project.Provisioning.conf ${D}${etc_dbus_conf}/
}

FILES:${PN} += "/usr/bin/provisioningd"
FILES:${PN} += "/etc/systemd/system/xyz.openbmc_project.Provisioning.service"
FILES:${PN} += "/etc/dbus-1/system.d/xyz.openbmc_project.Provisioning.conf"

