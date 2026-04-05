#!/usr/bin/env bash
# harden-arch.sh — run once after fresh Arch install
# https://github.com/kyore (edit to your liking)

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[-]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && err "Run as root: sudo bash harden-arch.sh"

# ── 1. Kernel hardening ──────────────────────────────────────────────────────
info "Applying sysctl kernel hardening..."
cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2
kernel.yama.ptrace_scope=2
net.ipv4.conf.all.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_ra=0
EOF
sysctl --system -q
info "Kernel params applied."

# ── 2. Firewall (nftables) ───────────────────────────────────────────────────
info "Setting up nftables firewall..."
pacman -S --noconfirm --needed nftables

cat > /etc/nftables.conf << 'EOF'
#!/usr/bin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
        # uncomment if you need SSH:
        # tcp dport 22 accept
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF

systemctl enable --now nftables
info "Firewall enabled (deny-in, allow-out)."

# ── 3. Lock root account ─────────────────────────────────────────────────────
info "Locking root password..."
passwd -l root
info "Root locked."

# ── 4. sudo timeout ──────────────────────────────────────────────────────────
info "Setting sudo timeout to 5 minutes..."
echo "Defaults timestamp_timeout=5" > /etc/sudoers.d/timeout
chmod 440 /etc/sudoers.d/timeout

# ── 5. Disable sshd if not needed ────────────────────────────────────────────
if systemctl is-enabled sshd &>/dev/null; then
    warn "sshd is enabled. Disabling... (re-enable manually if needed)"
    systemctl disable --now sshd
else
    info "sshd already disabled."
fi

# ── 6. /tmp as noexec tmpfs ──────────────────────────────────────────────────
info "Mounting /tmp as noexec tmpfs..."
if ! grep -q "^tmpfs /tmp" /etc/fstab; then
    echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    mount -o remount /tmp 2>/dev/null || true
    info "/tmp hardened in fstab (takes full effect on next boot)."
else
    warn "/tmp entry already in fstab, skipping."
fi

# ── 7. umask for new users ───────────────────────────────────────────────────
info "Setting default umask to 027..."
if ! grep -q "^umask 027" /etc/profile; then
    echo "umask 027" >> /etc/profile
fi

# ── 8. USBGuard ──────────────────────────────────────────────────────────────
read -rp "$(echo -e "${YELLOW}[?]${NC} Install USBGuard (blocks unknown USB devices)? [y/N] ")" usb
if [[ "${usb,,}" == "y" ]]; then
    pacman -S --noconfirm --needed usbguard
    # generate policy from currently connected devices
    usbguard generate-policy > /etc/usbguard/rules.conf
    systemctl enable --now usbguard
    info "USBGuard enabled with current devices whitelisted."
else
    warn "Skipping USBGuard."
fi

# ── 9. Extra sysctl (Lynis suggestions) ─────────────────────────────────────
info "Applying extra sysctl values from Lynis audit..."
cat >> /etc/sysctl.d/99-hardening.conf << 'EOF'
dev.tty.ldisc_autoload=0
fs.protected_fifos=2
fs.protected_regular=2
fs.suid_dumpable=0
kernel.sysrq=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.log_martians=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
EOF
sysctl --system -q
info "Extra sysctl params applied."

# ── 10. umask in login.defs ───────────────────────────────────────────────────
info "Hardening umask in /etc/login.defs..."
sed -i 's/^UMASK.*/UMASK\t\t027/' /etc/login.defs

# ── 11. Blacklist unused kernel modules ───────────────────────────────────────
info "Blacklisting unused/rare kernel modules..."
cat > /etc/modprobe.d/blacklist-rare.conf << 'EOF'
install firewire-ohci /bin/false
install usb-storage /bin/false
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
EOF
info "Rare modules blacklisted."

# ── 12. arch-audit (vuln package tracking) ────────────────────────────────────
info "Installing arch-audit..."
pacman -S --noconfirm --needed arch-audit
info "Run 'arch-audit' anytime to check for vulnerable packages."

# ── 13. auditd ────────────────────────────────────────────────────────────────
info "Installing and enabling auditd..."
pacman -S --noconfirm --needed audit
systemctl enable --now auditd
info "auditd enabled."

# ── 14. rkhunter (rootkit scanner) ────────────────────────────────────────────
info "Installing rkhunter..."
pacman -S --noconfirm --needed rkhunter
rkhunter --update --nocolors 2>/dev/null || true
rkhunter --propupd --nocolors 2>/dev/null || true
info "rkhunter installed. Run 'sudo rkhunter --check' periodically."

# ── 15. Lynis audit ───────────────────────────────────────────────────────────
read -rp "$(echo -e "${YELLOW}[?]${NC} Run Lynis security audit after setup? [y/N] ")" lynis

if [[ "${lynis,,}" == "y" ]]; then
    pacman -S --noconfirm --needed lynis
    lynis audit system --quick
else
    warn "Skipping Lynis. Run 'sudo lynis audit system' anytime."
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Hardening done. Reboot to apply all changes.${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
