#! /bin/bash
#Run as root

make
cp pam_vip.so /etc/pam.d/pam_vip.so
cp vip_pam.conf /etc/vip_pam.conf
echo "Shared object and Config file in place."

exit #
