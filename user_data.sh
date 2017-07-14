#!/bin/bash
useradd -s /bin/bash -m -d /home/{0}  -g root {0}
echo {1} | passwd {0} --stdin
echo "{0}  ALL=(ALL:ALL) ALL">> /etc/sudoers
sed -ie "s/PasswordAuthentication no/PasswordAuthentication yes/g" /etc/ssh/sshd_config
/etc/init.d/sshd restart