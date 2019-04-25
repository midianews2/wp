#!/bin/bash -vx
#https://stackoverflow.com/questions/24270733/automate-mysql-secure-installation-with-echo-command-via-a-shell-script
#https://askubuntu.com/questions/728263/how-to-complete-mariadb-servers-installation-without-being-stopped-at-enter

chmod +x $0
bkp_dir="/root/backup"
FILES="/root/files"
BABKUP="/root/backup"
mariadb_list='/etc/apt/sources.list.d/mariadb.list'
mariadb_version="10.3"
PASSWORD="adv1999"

if [ ! -f "$mariadb_list" ]; then
echo "deb http://mirror.rackspace.com/mariadb/repo/$mariadb_version/debian stretch main" >> $mariadb_list
echo "deb-src http://mirror.rackspace.com/mariadb/repo/$mariadb_version/debian stretch main" >> $mariadb_list
apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 0xF1656F24C74CD1D8 #MARIADB
apt-get update
export DEBIAN_FRONTEND="noninteractive"
debconf-set-selections <<< "mariadb-server mysql-server/root_password password $PASSWORD"
debconf-set-selections <<< "mariadb-server mysql-server/root_password_again password $PASSWORD" 
apt-get install mariadb-server mariadb-backup -y
cp /etc/mysql/my.cnf $BABKUP/my.cnf
mysql_secure_installation <<EOF
$PASSWORD
n
Y
Y
Y
Y
EOF
mkdir -p mysqltuner
wget -q http://mysqltuner.pl/ -O mysqltuner/mysqltuner.pl
wget -q https://raw.githubusercontent.com/major/MySQLTuner-perl/master/basic_passwords.txt -O mysqltuner/basic_passwords.txt
wget -q https://raw.githubusercontent.com/major/MySQLTuner-perl/master/vulnerabilities.csv -O mysqltuner/vulnerabilities.csv

touch /var/lib/mysql/server.err
sed -i 's/128K/0/' /etc/mysql/my.cnf
sed -i 's/64M/0/' /etc/mysql/my.cnf
sed -i 's/DEMAND/OFF/' /etc/mysql/my.cnf
sed -i 's/#query_cache_type/query_cache_type/' /etc/mysql/my.cnf
sed -i 's/#general_log_file/general_log_file/' /etc/mysql/my.cnf
sed -i 's/#general_log/general_log/' /etc/mysql/my.cnf
sed -i 's/#log_slow_rate_limit/log_slow_rate_limit/' /etc/mysql/my.cnf
sed -i 's/#innodb_log_file_size/#innodb_log_file_size/' /etc/mysql/my.cnf
sed -i 's/#sql_mode/sql_mode/' /etc/mysql/my.cnf
sed -i 's/50M/50M/' /etc/mysql/my.cnf

#https://fabianlee.org/2018/10/28/linux-using-sed-to-insert-lines-before-or-after-a-match/
#sed '/^anothervalue=.*/a after=me' test.txt
#sed '/^anothervalue=.*/i before=me' test.txt

sed -i '/skip-name-resolve = 1/d' /etc/mysql/my.cnf
sed -i '/performance_schema = on/d' /etc/mysql/my.cnf
sed -i '/slow_query_log = 1/d' /etc/mysql/my.cnf
sed -i '/^skip-external-locking.*/a skip-name-resolve = 1' /etc/mysql/my.cnf
sed -i '/^skip-external-locking.*/a performance_schema = on' /etc/mysql/my.cnf
sed -i '/^#slow_query_log.*/a slow_query_log = 1' /etc/mysql/my.cnf
service mysql restart
fi
