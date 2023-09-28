## This file is part of Chainmail <https://github.com/monsieuremre/chainmail>
## Chainmail is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
## License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
## version. Chainmail is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
## implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
## details. You should have received a copy of the GNU General Public License along with this program. If not, see
## <https://www.gnu.org/licenses/>.

#!/bin/bash

update_everything() {
    apt update
    apt upgrade -y
    apt full-upgrade -y
    apt autoremove -y
}

harden_kernel_settings() {
    # Remove the old sysctl.conf
    rm /etc/sysctl.conf

    # Echoing our new settings
    echo "kernel.core_pattern=|/bin/false
    kernel.kptr_restrict=2
    kernel.dmesg_restrict=1
    kernel.printk=3 3 3 3
    kernel.perf_event_paranoid=3
    kernel.kexec_load_disabled=1
    kernel.yama.ptrace_scope=1
    kernel.unprivileged_bpf_disabled=1
    kernel.sysrq=132
    kernel.core_uses_pid=1

    dev.tty.ldisc_autoload=0

    vm.unprivileged_userfaultfd=0
    vm.swappiness=1
    
    # If using some architecture other than x86 the following 2 might need to be different
    vm.mmap_rnd_bits=32
    vm.mmap_rnd_compat_bits=16

    fs.suid_dumpable=0
    fs.protected_fifos=2
    fs.protected_regular=2
    fs.protected_symlinks=1
    fs.protected_hardlinks=1

    net.core.bpf_jit_harden=2
    net.ipv4.conf.all.log_martians=1
    net.ipv4.conf.default.log_martians=1
    net.ipv4.tcp_timestamps=0
    net.ipv4.tcp_syncookies=1
    net.ipv4.tcp_rfc1337=1
    net.ipv4.conf.all.rp_filter=1
    net.ipv4.conf.default.rp_filter=1
    net.ipv4.conf.all.accept_redirects=0
    net.ipv4.conf.default.accept_redirects=0
    net.ipv4.conf.all.secure_redirects=0
    net.ipv4.conf.default.secure_redirects=0
    net.ipv6.conf.all.accept_redirects=0
    net.ipv6.conf.default.accept_redirects=0
    net.ipv4.conf.all.send_redirects=0
    net.ipv4.conf.default.send_redirects=0
    net.ipv4.icmp_echo_ignore_all=1
    net.ipv4.conf.all.accept_source_route=0
    net.ipv4.conf.default.accept_source_route=0
    net.ipv6.conf.all.accept_source_route=0
    net.ipv6.conf.default.accept_source_route=0
    net.ipv6.conf.all.accept_ra=0
    net.ipv6.conf.default.accept_ra=0
    net.ipv4.tcp_sack=0
    net.ipv4.tcp_dsack=0
    net.ipv4.tcp_fack=0
    net.ipv6.conf.all.use_tempaddr=2
    net.ipv6.conf.default.use_tempaddr=2" >> /etc/sysctl.conf

    # Load in sysctl settings
    sysctl -p
}

install_packages() {
    # Various recommended packages
    apt install libpam-tmpdir pam_passwdqc -y
}

harden_kernel_mod() {
    echo "# https://www.kicksecure.com/wiki/Security-misc
    options nf_conntrack nf_conntrack_helper=0
    install firewire-core /bin/false
    install firewire_core /bin/false
    install firewire-ohci /bin/false
    install firewire_ohci /bin/false
    install firewire_sbp2 /bin/false
    install firewire-sbp2 /bin/false
    install dccp /bin/false
    install sctp /bin/false
    install rds /bin/false
    install tipc /bin/false
    install n-hdlc /bin/false
    install ax25 /bin/false
    install netrom /bin/false
    install x25 /bin/false
    install rose /bin/false
    install decnet /bin/false
    install econet /bin/false
    install af_802154 /bin/false
    install ipx /bin/false
    install appletalk /bin/false
    install psnap /bin/false
    install p8023 /bin/false
    install p8022 /bin/false
    install can /bin/false
    install atm /bin/false
    install cifs /bin/false
    install nfs /bin/false
    install nfsv3 /bin/false
    install nfsv4 /bin/false
    install ksmbd /bin/false
    install gfs2 /bin/false
    install cramfs /bin/false
    install freevxfs /bin/false
    install jffs2 /bin/false
    install hfs /bin/false
    install hfsplus /bin/false
    install udf /bin/false
    install vivid /bin/false
    # https://www.kernel.org/doc/html/latest/driver-api/mei/mei.html
    install mei /bin/false
    install mei-me /bin/false
    # https://git.launchpad.net/ubuntu/+source/kmod/tree/debian/modprobe.d/blacklist-framebuffer.conf?h=ubuntu%2Flunar
    blacklist aty128fb
    blacklist atyfb
    blacklist radeonfb
    blacklist cirrusfb
    blacklist cyber2000fb
    blacklist cyblafb
    blacklist gx1fb
    blacklist hgafb
    blacklist i810fb
    blacklist intelfb
    blacklist kyrofb
    blacklist lxfb
    blacklist matroxfb_bases
    blacklist neofb
    blacklist nvidiafb
    blacklist pm2fb
    blacklist rivafb
    blacklist s1d13xxxfb
    blacklist savagefb
    blacklist sisfb
    blacklist sstfb
    blacklist tdfxfb
    blacklist tridentfb
    blacklist vesafb
    blacklist vfb
    blacklist viafb
    blacklist vt8623fb
    blacklist udlfb
    # https://git.launchpad.net/ubuntu/+source/kmod/tree/debian/modprobe.d/blacklist.conf?h=ubuntu%2Flunar
    blacklist evbug
    blacklist usbmouse
    blacklist usbkbd
    blacklist eepro100
    blacklist de4x5
    blacklist eth1394
    blacklist snd_intel8x0m
    blacklist snd_aw2
    blacklist prism54
    blacklist bcm43xx
    blacklist garmin_gps
    blacklist asus_acpi
    blacklist snd_pcsp
    blacklist pcspkr
    blacklist amd76x_edac" >> /etc/modprobe.d/security-config.conf
}

configure_firewall() {
    # On your personal computer, chances are you don't need to allow incoming connections.
    apt install ufw -y
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw enable
}

core_dumps_disable() {
    # Core dumps can expose a lot of info. We disable them also in the kernel settings.
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "ulimit -c 0" >> /etc/profile
    echo "ProcessSizeMax=0
Storage=none" >> /etc/systemd/coredump.conf
}

better_umask() {
    # Umask determines how permissions are set for newly created files
    sed -i s/UMASK.*/UMASK\ 027/ /etc/login.defs
    echo "umask 0027" >> /etc/bash.bashrc
    echo "umask 0027" >> /etc/profile
}

harden_file_permissions() {
    # BE CAREFUL
    # Needs tuning. Uncomment last line after replacing /home/yourname with the name of your user account.
    chmod 400 /etc/cups/cupsd.conf
    chmod 600 /boot/grub/grub.cfg
    chmod 600 /etc/crontab
    chmod 644 /etc/group
    chmod 644 /etc/group-
    chmod 644 /etc/hosts.deny
    chmod 644 /etc/hosts.allow
    chmod 644 /etc/issue
    chmod 644 /etc/issue.net
    chmod 644 /etc/motd
    chmod 644 /etc/passwd
    chmod 644 /etc/passwd-
    chmod 440 /etc/sudoers
    chmod 440 /etc/sudoers.d/README
    chmod 700 /usr/bin/as
    chmod 700 /usr/bin/g++
    chmod 700 /usr/bin/gcc
    chmod 700 /root/.ssh
    chmod 700 /etc/cron.d
    chmod 700 /etc/cron.daily
    chmod 700 /etc/cron.hourly
    chmod 700 /etc/cron.weekly
    chmod 700 /etc/cron.monthly
    chmod 700 /root
    chmod 700 /boot
    chmod 700 /usr/lib/modules
    chmod 700 /lib/modules
    chmod 700 /usr/src
    chmod 700 /etc/sudoers.d
    # chmod 750 /home/yourname 

    # It is unclear which of the following is actually necessary. You can enable all of them. These make sure that the permissions are not overrides during an update by apt.
<<comment
    dpkg-statoverride --add --update root root 0400 /etc/cups/cupsd.conf
    dpkg-statoverride --add --update root root 0600 /boot/grub/grub.cfg
    dpkg-statoverride --add --update root root 0600 /etc/crontab
    dpkg-statoverride --add --update root root 0644 /etc/group
    dpkg-statoverride --add --update root root 0644 /etc/group-
    dpkg-statoverride --add --update root root 0644 /etc/hosts.deny
    dpkg-statoverride --add --update root root 0644 /etc/hosts.allow
    dpkg-statoverride --add --update root root 0644 /etc/issue
    dpkg-statoverride --add --update root root 0644 /etc/issue.net
    dpkg-statoverride --add --update root root 0644 /etc/motd
    dpkg-statoverride --add --update root root 0644 /etc/passwd
    dpkg-statoverride --add --update root root 0644 /etc/passwd-
    dpkg-statoverride --add --update root root 0640 /etc/sudoers
    dpkg-statoverride --add --update root root 0640 /etc/sudoers.d/README
    dpkg-statoverride --add --update root root 0700 /root/.ssh
    dpkg-statoverride --add --update root root 0700 /etc/cron.d
    dpkg-statoverride --add --update root root 0700 /etc/cron.daily
    dpkg-statoverride --add --update root root 0700 /etc/cron.hourly
    dpkg-statoverride --add --update root root 0700 /etc/cron.weekly
    dpkg-statoverride --add --update root root 0700 /etc/cron.monthly
    dpkg-statoverride --add --update root root 0700 /usr/bin/as
    dpkg-statoverride --add --update root root 0700 /usr/bin/g++
    dpkg-statoverride --add --update root root 0700 /usr/bin/gcc
    dpkg-statoverride --add --update root root 0755 /home
    dpkg-statoverride --add --update root root 0700 /root
    dpkg-statoverride --add --update root root 0700 /boot
    dpkg-statoverride --add --update root root 0700 /usr/lib/modules
    dpkg-statoverride --add --update root root 0700 /usr/src
    dpkg-statoverride --add --update root root 0700 /lib/modules
comment
}

better_apt() {
    apt install needrestart debsums apt-listbugs apt-listchanges needrestart debsecan debsums
    # Use https and enable sandboxing features
    sed -i 's/http/https/g' /etc/apt/sources.list
    echo "APT::Sandbox::Seccomp \"true\";" >> /etc/apt/apt.conf.d/40sandbox
}

hardened_boot() {
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT/#GRUB_CMDLINE_LINUX_DEFAULT/g' /etc/default/grub
    echo "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet spectre_v2=on spec_store_bypass_disable=on l1tf=full,force mds=full,nosmt tsx=off tsx_async_abort=full,nosmt kvm.nx_huge_pages=force nosmt=force slab_nomerge init_on_alloc=1 init_on_free=1 pti=on vsyscall=none page_alloc.shuffle=1 randomize_kstack_offset=on debugfs=off quiet loglevel=0 intel_iommu=on amd_iommu=on efi=disable_early_pci_dma random.trust_bootloader=off random.trust_cpu=off iommu.passthrough=0 iommu.strict=1\"" >> /etc/default/grub
    update-grub
}

entropy() {
    apt install jitterentropy-rngd haveged -y
    echo "jitterentropy_rng" >> /usr/lib/modules-load.d/jitterentropy.conf
}

app_armor() {
    # We enforce all installed profiles. I have tested them and had no problems of usability but your mileage might differ, so you might want to do some testing first.
    apt install apparmor-profiles apparmor-profiles-extra apparmor-utils -y
    aa-enforce /etc/apparmor.d/*
}

enforce_delay() {
    # Prevent brute force attempts by enforcinga 4 second delay.
    echo "auth optional pam_faildelay.so delay=4000000" >> /etc/pam.d/system-login
}

hardened_mounting_options() {
    # BE CAREFUL
    # THIS SECTION REQUIRES MANUAL TUNING
    # The following config is applicable if you do not have /var and /tmp as seperate partitions on your drive. If that is not the case, you need to remove the bind option from them, else it won't work.
    # /home and root partitions can also be hardened with similar options. But that requires you manually editing the entries.
    # You should modify the existing entries rather than adding extra lines to fstab for a cleaner file.
    # It is rather intuitive. A sed operation or some other work around can be used for a fully automatized hardening of mount options, which is not implemented here.
    echo "
# /tmp                          /tmp            ext4    defaults,bind,nosuid,noexec,nodev     0 2 # bind might not be needed
# /var                          /var            ext4    defaults,bind,nosuid,nodev            0 2 # bind might not be needed
/dev                          /dev            ext4    defaults,bind,nosuid,noexec           0 2
tmpfs                         /dev/shm        tmpfs   defaults,nodev,nosuid,noexec          0 0
/tmp                          /var/tmp        none    defaults,nodev,nosuid,noexec,bind     0 0
/var/log                      /var/log        ext4    defaults,bind,nosuid,noexec,nodev     0 2
/var/log/audit                /var/log/audit  ext4    defaults,bind,nosuid,noexec,nodev     0 2" >> /etc/fstab
    systemctl daemon-reload
}

update_everything
harden_kernel_settings
install_packages
harden_kernel_mod
configure_firewall
core_dumps_disable
better_umask
harden_file_permissions
better_apt
hardened_boot
entropy
app_armor
enforce_delay
hardened_mounting_options
