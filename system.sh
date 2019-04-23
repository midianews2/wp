#!/bin/bash -vx

#### 0 - Configurar TIMEZONE ####
clear
mkdir -p files
mkdir -p backup
FILES="/root/files"
BABKUP="/root/backup"
cp /etc/timezone $BABKUP/timezone
timedatectl set-timezone "America/Sao_Paulo"
date +%M > $FILES/time_inicial.file
#### LOGROTATE TIMEZONE ####

#### 1 - Verificar se ROOT E VIRTUALIZACAO ####
if [ `whoami` == 'root' ]; then
    echo -e "Você está logado como usuário: \033[01;33mROOT\033[00;37m";echo;echo
else
    echo "Voce precisa logar como ROOT para continuar";clear;echo "SAINDO...";sleep 10;exit 0 
fi
VIRT=$(hostnamectl | grep "Virtualization" |  awk '{ print $2 }')
if [ "$VIRT" = "openvz" ]; then apt-mark hold libc6; fi
chmod +x $0
#LIMPAR="clear"
#### ROOT FIM ####

#### 2 - Configurar SSHD ####
apt-get update
apt-get upgrade -y 
apt-get dist-upgrade -y 
apt-get install figlet cowsay curl -y 
apt-get install wget man git htop -y
cp /usr/games/cowsay /usr/bin/cowsay
cp /usr/games/cowthink /usr/bin/cowthink 

cat << 'EOF' > /etc/profile.d/motd.sh
#!/bin/sh
clear
figlet -c "Bem Vindo  Debin 9"
echo
echo
echo
upSeconds="$(/usr/bin/cut -d. -f1 /proc/uptime)"
secs=$((${upSeconds}%60))
mins=$((${upSeconds}/60%60))
hours=$((${upSeconds}/3600%24))
days=$((${upSeconds}/86400))
UPTIME=`printf "%d days, %02dh%02dm%02ds" "$days" "$hours" "$mins" "$secs"`
 
# get the load averages
read one five fifteen rest < /proc/loadavg
 
echo "$(tput setaf 2)
   .~~.   .~~.    `date +"%A, %e %B %Y, %r"`
  '. \ ' ' / .'   `uname -srmo`$(tput setaf 1)
   .~ .~~~..~.
  : .~.'~'.~. :   Uptime.............: ${UPTIME}
 ~ (   ) (   ) ~  Memory.............: `cat /proc/meminfo | grep MemFree | awk {'print $2'}`kB (Free) / `cat /proc/meminfo | grep MemTotal | awk {'print $2'}`kB (Total)
( : '~'.~.'~' : ) Load Averages......: ${one}, ${five}, ${fifteen} (1, 5, 15 min)
 ~ .~ (   ) ~. ~  Running Processes..: `ps ax | wc -l | tr -d " "`
  (  : '~' :  )   IP Addresses.......: `ip a | grep glo | awk '{print $2}' | head -1 | cut -f1 -d/` and `wget -q -O - http://icanhazip.com/ | tail`
   '~ .~~~. ~'    Weather............: `curl -s "http://rss.accuweather.com/rss/liveweather_rss.asp?metric=1&locCode=EUR|UK|UK001|NAILSEA|" | sed -n '/Currently:/ s/.*: \(.*\): \([0-9]*\)\([CF]\).*/\2°\3, \1/p'`
       '~'
$(tput sgr0)"
EOF
cat << 'EOF' > /etc/issue.net
###################################################################################################
###                  Todas as conexoes estao sendo monitoradas e gravadas                       ###
###            Disconecte imediatamente se voce nao for um usuario autorizado                   ###
###################################################################################################
EOF
cp /etc/ssh/sshd_config $BABKUP/sshd_config
sed -i 's/#Port 22/#Port 22/' /etc/ssh/sshd_config
sed -i 's/#AddressFamily any/AddressFamily inet/' /etc/ssh/sshd_config
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 2m/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/#StrictModes yes/StrictModes yes/' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 6/' /etc/ssh/sshd_config
sed -i 's/#MaxSessions 10/MaxSessions 10/' /etc/ssh/sshd_config
sed -i 's/#TCPKeepAlive yes/TCPKeepAlive yes/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 20/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 30/' /etc/ssh/sshd_config
sed -i 's/#UseDNS no/UseDNS no/' /etc/ssh/sshd_config
sed -i 's|#Banner none|Banner /etc/issue.net|' /etc/ssh/sshd_config
#### SSD FIM ####

#### 4 - Configurar BASRC ####
cp /root/.bashrc $BABKUP/.bashrc
cat << 'EOF' > /root/.bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.

# Note: PS1 and umask are already set in /etc/profile. You should not
# need this unless you want different defaults for root.
PS1='${debian_chroot:+($debian_chroot)}\h:\w\$ '
umask 022

# You may uncomment the following lines if you want `ls' to be colorized:
export LS_OPTIONS='--color=auto'
eval "`dircolors`"
alias ls='ls $LS_OPTIONS'
alias ll='ls $LS_OPTIONS -l'
alias l='ls $LS_OPTIONS -lha'
#
# Some more alias to avoid making mistakes:
alias rm='rm -rf'
alias cp='cp -avf'

echo never > /sys/kernel/mm/transparent_hugepage/enabled #NEW
EOF
#### BASHRC FIM ####

#### 5 - Configurar GRUB ####
cp /etc/default/grub $BABKUP/grub
sed -i 's/GRUB_TIMEOUT=5/GRUB_TIMEOUT=0/' /etc/default/grub
update-grub2
#### GRUB FIM ####

#### 6 - Configurar HOST ####
$LIMPAR
echo
echo -e "\033[01;33mDigite o seu domínio principal e pressione ENTER ou agaurde 10s para continuar: (exemplo.com)\033[00;37m" ; read -t10 HOSTNAME || HOSTNAME=$(hostname -d)
echo -e "\nEstamos usando o domínio principal: \033[01;33m ${HOSTNAME^^} \033[00;37m\n"; sleep 5
echo $HOSTNAME > $FILES/hostname.file
echo
#### HOST FIM ####

#### 7 - Configurar LOGROTATE ####
cp /etc/logrotate.conf $BABKUP/logrotate.conf
sed -i 's/#compress/compress/' /etc/logrotate.conf
#### LOGROTATE FIM ####

#### 8 - Configurar SYSCTL ####
cp /etc/sysctl.conf $BABKUP/logrotate.conf
cat << 'EOF' > /etc/sysctl.conf
# Kernel sysctl configuration file for Linux
#
# Version 1.12 - 2015-09-30
# Michiel Klaver - IT Professional
# http://klaver.it/linux/ for the latest version - http://klaver.it/bsd/ for a BSD variant
#
# This file should be saved as /etc/sysctl.conf and can be activated using the command:
# sysctl -e -p /etc/sysctl.conf
#
# For binary values, 0 is disabled, 1 is enabled.  See sysctl(8) and sysctl.conf(5) for more details.
#
# Tested with: Ubuntu 14.04 LTS kernel version 3.13
#              Debian 7 kernel version 3.2
#              CentOS 7 kernel version 3.10

#
# Intended use for dedicated server systems at high-speed networks with loads of RAM and bandwidth available
# Optimised and tuned for high-performance web/ftp/mail/dns servers with high connection-rates
# DO NOT USE at busy networks or xDSL/Cable connections where packetloss can be expected
# ----------

# Credits:
# http://www.enigma.id.au/linux_tuning.txt
# http://www.securityfocus.com/infocus/1729
# http://fasterdata.es.net/TCP-tuning/linux.html
# http://fedorahosted.org/ktune/browser/sysctl.ktune
# http://www.cymru.com/Documents/ip-stack-tuning.html
# http://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
# http://www.frozentux.net/ipsysctl-tutorial/chunkyhtml/index.html
# http://knol.google.com/k/linux-performance-tuning-and-measurement
# http://www.cyberciti.biz/faq/linux-kernel-tuning-virtual-memory-subsystem/
# http://www.redbooks.ibm.com/abstracts/REDP4285.html
# http://www.speedguide.net/read_articles.php?id=121
# http://lartc.org/howto/lartc.kernel.obscure.html
# http://en.wikipedia.org/wiki/Sysctl


###
### GENERAL SYSTEM SECURITY OPTIONS ###
###

# Controls the System Request debugging functionality of the kernel
kernel.sysrq = 0

# Controls whether core dumps will append the PID to the core filename.
# Useful for debugging multi-threaded applications.
#kernel.core_uses_pid = 1

#Allow for more PIDs
kernel.pid_max = 65535

# The contents of /proc/<pid>/maps and smaps files are only visible to
# readers that are allowed to ptrace() the process
#kernel.maps_protect = 1

#Enable ExecShield protection
#kernel.exec-shield = 1
kernel.randomize_va_space = 2

# Controls the maximum size of a message, in bytes
kernel.msgmnb = 65535

# Controls the default maxmimum size of a mesage queue
kernel.msgmax = 65535

# Restrict core dumps
fs.suid_dumpable = 0

# Hide exposed kernel pointers
kernel.kptr_restrict = 1


###
### IMPROVE SYSTEM MEMORY MANAGEMENT ###
###

# Increase size of file handles and inode cache
fs.file-max = 209708

# Do less swapping
vm.swappiness = 30
vm.dirty_ratio = 30
vm.dirty_background_ratio = 5

# specifies the minimum virtual address that a process is allowed to mmap
vm.mmap_min_addr = 4096

# 50% overcommitment of available memory
vm.overcommit_ratio = 50
vm.overcommit_memory = 0

# Set maximum amount of memory allocated to shm to 256MB
kernel.shmmax = 268435456
kernel.shmall = 268435456

# Keep at least 64MB of free RAM space available
vm.min_free_kbytes = 65535


###
### GENERAL NETWORK SECURITY OPTIONS ###
###

#Prevent SYN attack, enable SYNcookies (they will kick-in when the max_syn_backlog reached)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# Disables packet forwarding
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.forwarding = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0

# Disables IP source routing
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Enable IP spoofing protection, turn on source route verification
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP Redirect Acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Enable Log Spoofed Packets, Source Routed Packets, Redirect Packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Decrease the time default value for tcp_fin_timeout connection
net.ipv4.tcp_fin_timeout = 7

# Decrease the time default value for connections to keep alive
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Don't relay bootp
net.ipv4.conf.all.bootp_relay = 0

# Don't proxy arp for anyone
net.ipv4.conf.all.proxy_arp = 0

# Turn on the tcp_timestamps, accurate timestamp make TCP congestion control algorithms work better
net.ipv4.tcp_timestamps = 1

# Don't ignore directed pings
net.ipv4.icmp_echo_ignore_all = 0

# Enable ignoring broadcasts request
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable bad error message Protection
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Allowed local port range
net.ipv4.ip_local_port_range = 16384 65535

# Enable a fix for RFC1337 - time-wait assassination hazards in TCP
net.ipv4.tcp_rfc1337 = 1

# Do not auto-configure IPv6
#net.ipv6.conf.all.autoconf=0
#net.ipv6.conf.all.accept_ra=0
#net.ipv6.conf.default.autoconf=0
#net.ipv6.conf.default.accept_ra=0
#net.ipv6.conf.eth0.autoconf=0
#net.ipv6.conf.eth0.accept_ra=0


###
### TUNING NETWORK PERFORMANCE ###
###

# For high-bandwidth low-latency networks, use 'htcp' congestion control
# Do a 'modprobe tcp_htcp' first
net.ipv4.tcp_congestion_control = htcp

# For servers with tcp-heavy workloads, enable 'fq' queue management scheduler (kernel > 3.12)
net.core.default_qdisc = fq

# Turn on the tcp_window_scaling
net.ipv4.tcp_window_scaling = 1

# Increase the read-buffer space allocatable
net.ipv4.tcp_rmem = 8192 87380 16777216
net.ipv4.udp_rmem_min = 16384
net.core.rmem_default = 262144
net.core.rmem_max = 16777216

# Increase the write-buffer-space allocatable
net.ipv4.tcp_wmem = 8192 65536 16777216
net.ipv4.udp_wmem_min = 16384
net.core.wmem_default = 262144
net.core.wmem_max = 16777216

# Increase number of incoming connections
net.core.somaxconn = 32768

# Increase number of incoming connections backlog
net.core.netdev_max_backlog = 16384
net.core.dev_weight = 64

# Increase the maximum amount of option memory buffers
net.core.optmem_max = 65535

# Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks
net.ipv4.tcp_max_tw_buckets = 1440000

# try to reuse time-wait connections, but don't recycle them (recycle can break clients behind NAT)
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 1

# Limit number of orphans, each orphan can eat up to 16M (max wmem) of unswappable memory
net.ipv4.tcp_max_orphans = 16384
net.ipv4.tcp_orphan_retries = 0

# Increase the maximum memory used to reassemble IP fragments
net.ipv4.ipfrag_high_thresh = 512000
net.ipv4.ipfrag_low_thresh = 446464

# don't cache ssthresh from previous connection
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1

# Increase size of RPC datagram queue length
net.unix.max_dgram_qlen = 50

# Don't allow the arp table to become bigger than this
net.ipv4.neigh.default.gc_thresh3 = 2048

# Tell the gc when to become aggressive with arp table cleaning.
# Adjust this based on size of the LAN. 1024 is suitable for most /24 networks
net.ipv4.neigh.default.gc_thresh2 = 1024

# Adjust where the gc will leave arp table alone - set to 32.
net.ipv4.neigh.default.gc_thresh1 = 32

# Adjust to arp table gc to clean-up more often
net.ipv4.neigh.default.gc_interval = 30

# Increase TCP queue length
net.ipv4.neigh.default.proxy_qlen = 96
net.ipv4.neigh.default.unres_qlen = 6

# Enable Explicit Congestion Notification (RFC 3168), disable it if it doesn't work for you
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_reordering = 3

# How many times to retry killing an alive TCP connection
net.ipv4.tcp_retries2 = 15
net.ipv4.tcp_retries1 = 3

# Avoid falling back to slow start after a connection goes idle
# keeps our cwnd large with the keep alive connections (kernel > 3.6)
net.ipv4.tcp_slow_start_after_idle = 0

# Allow the TCP fastopen flag to be used, beware some firewalls do not like TFO! (kernel > 3.7)
net.ipv4.tcp_fastopen = 3

# This will enusre that immediatly subsequent connections use the new values
net.ipv4.route.flush = 1
net.ipv6.route.flush = 1

### Comments/suggestions/additions are welcome!
#https://gist.github.com/yegorg/36cf9710e8ef50fa07571db0f4b981f9
EOF
sysctl -p
#### SYSCTL FIM ####

#### 9 - Configurar GITHUBWP ####
git clone https://github.com/midianews2/wp
#### GITHUBWP FIM ####

#### 10 - TEMPO GASTO ####
date +%M > $FILES/time_final.file
ITIME=$(cat $FILES/time_inicial.file)
FTIME=$(cat $FILES/time_final.file)
$LIMPAR 
echo -e "Você gastou \033[01;33m $(($FTIME - $ITIME)) \033[00;37m minuto(s) para executar o script."
#### TEMPO GASTO FIM ####
