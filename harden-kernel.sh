#!/bin/bash

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo bash harden-kernel.sh"
    exit 1
fi

REAL_USER="${SUDO_USER:-$(logname)}"
USER_HOME=$(eval echo ~"$REAL_USER")

pacman -S --needed --noconfirm base-devel bc xmlto kmod inetutils libelf pahole cpio perl tar xz apparmor dnscrypt-proxy opendoas zsh wget || true

KERNEL_VERSION=$(curl -s https://www.kernel.org/finger_banner | grep "latest stable version" | awk '{print $NF}')

mkdir -p /usr/src/hardened-kernel
cd /usr/src/hardened-kernel

wget -c --retry-connrefused --tries=5 --show-progress "https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_VERSION%%.*}.x/linux-${KERNEL_VERSION}.tar.xz"
tar -xf "linux-${KERNEL_VERSION}.tar.xz"
cd "linux-${KERNEL_VERSION}"

zcat /proc/config.gz > .config 2>/dev/null || cp /boot/config-$(uname -r) .config

cat >> .config << 'EOF'
CONFIG_HARDENED_USERCOPY=y
CONFIG_HARDENED_USERCOPY_FALLBACK=n
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SHUFFLE_PAGE_ALLOCATOR=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
CONFIG_INIT_ON_FREE_DEFAULT_ON=y
CONFIG_PAGE_TABLE_ISOLATION=y
CONFIG_RANDOMIZE_BASE=y
CONFIG_RANDOMIZE_MEMORY=y
CONFIG_GCC_PLUGINS=n
CONFIG_STACKPROTECTOR_STRONG=y
CONFIG_SECURITY=y
CONFIG_SECURITY_APPARMOR=y
CONFIG_DEFAULT_SECURITY_APPARMOR=y
CONFIG_SECURITY_YAMA=y
CONFIG_AMD_IOMMU=y
CONFIG_AMD_IOMMU_V2=y
CONFIG_BUG_ON_DATA_CORRUPTION=y
CONFIG_LEGACY_VSYSCALL_NONE=y
CONFIG_KEXEC=n
CONFIG_HIBERNATION=n
EOF

chown -R root:root /usr/src/hardened-kernel
make clean
make olddefconfig
make -j$(nproc)
make modules_install
make install
mkinitcpio -P

HARDENED_PARAMS="mitigations=auto vsyscall=none init_on_alloc=1 init_on_free=1 security=apparmor apparmor=1 pti=on"

detect_bootloader() {
    if [ -f /boot/grub/grub.cfg ] || [ -f /boot/grub2/grub.cfg ]; then
        echo "grub"
    elif [ -d /boot/loader/entries ]; then
        echo "systemd-boot"
    else
        echo "unknown"
    fi
}

BOOTLOADER=$(detect_bootloader)
echo "Detected bootloader: $BOOTLOADER"

if [ "$BOOTLOADER" = "grub" ]; then
    sed -i "s|GRUB_CMDLINE_LINUX_DEFAULT=\"[^\"]*\"|GRUB_CMDLINE_LINUX_DEFAULT=\"quiet $HARDENED_PARAMS\"|" /etc/default/grub
    grub-mkconfig -o /boot/grub/grub.cfg

elif [ "$BOOTLOADER" = "systemd-boot" ]; then
    ENTRY=$(find /boot/loader/entries -name "*.conf" | head -1)
    if [ -z "$ENTRY" ]; then
        echo "No systemd-boot entry found in /boot/loader/entries"
        exit 1
    fi
    ROOT_UUID=$(findmnt -n -o UUID /)
    if grep -q "^options" "$ENTRY"; then
        sed -i "s|^options.*|options root=UUID=$ROOT_UUID rw $HARDENED_PARAMS|" "$ENTRY"
    else
        echo "options root=UUID=$ROOT_UUID rw $HARDENED_PARAMS" >> "$ENTRY"
    fi
    echo "Updated systemd-boot entry: $ENTRY"

else
    echo "Could not detect bootloader. Set these kernel parameters manually:"
    echo "$HARDENED_PARAMS"
fi

systemctl enable apparmor
systemctl start apparmor
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

cat > /etc/doas.conf << EOF
permit persist $REAL_USER as root
EOF
chmod 0400 /etc/doas.conf

cat > /etc/dnscrypt-proxy/dnscrypt-proxy.toml << 'EOF'
listen_addresses = ['127.0.0.1:53']
ipv4_servers = true
require_dnssec = true
require_nolog = true
require_nofilter = true
server_names = ['mullvad-doh', 'quad9-dnscrypt-ip4-filter-pri']

[sources]
  [sources.'public-resolvers']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md']
  cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
EOF

chattr -i /etc/resolv.conf 2>/dev/null || true
echo "nameserver 127.0.0.1" > /etc/resolv.conf
chattr +i /etc/resolv.conf
systemctl enable dnscrypt-proxy
systemctl start dnscrypt-proxy

CURRENT_SHELL=$(getent passwd "$REAL_USER" | cut -d: -f7)

if [ "$CURRENT_SHELL" != "/bin/zsh" ]; then
    read -rp "Your current shell is $CURRENT_SHELL. Switch to zsh? (y/n): " switch_shell
    if [ "$switch_shell" = "y" ]; then
        cat > "$USER_HOME/.zshrc" << 'EOF'
autoload -U compinit && compinit
HISTSIZE=10000
SAVEHIST=10000
HISTFILE=~/.zsh_history
setopt HIST_IGNORE_DUPS
zstyle ':completion:*' menu select
alias sudo='doas'
PROMPT='%n@%m:%~%# '
EOF
        chown "$REAL_USER:$REAL_USER" "$USER_HOME/.zshrc"
        chsh -s /bin/zsh "$REAL_USER"
    fi
else
    cat >> "$USER_HOME/.zshrc" << 'EOF'
alias sudo='doas'
EOF
fi

cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 2
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
vm.mmap_rnd_bits = 32
EOF
sysctl --system

echo "Done. Reboot and test doas before removing sudo."
read -rp "Reboot now? (y/n): " r
[[ "$r" == "y" ]] && reboot
