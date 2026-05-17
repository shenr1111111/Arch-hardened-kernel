# Arch-hardened-kernel
This is a sh script for hardening your kernel on arch linux (the idea is from @linux_woodeater on tiktok)
steps 
1.chmod +x harden-kernel.sh
2.sudo bash harden-kernel.sh

this is NOT tested since i didnt have time yet
also this is for zsh ONLY you can modify it freely tho

EDIT: this script is functioning for me 
if u get an kernel panic/error the run this command
'ROOT_UUID=$(findmnt -n -o UUID /)
sudo sed -i "s|^options.*|options root=UUID=$ROOT_UUID rw mitigations=auto vsyscall=none init_on_alloc=1 init_on_free=1 security=apparmor apparmor=1 pti=on|" /boot/loader/entries/*.conf'
