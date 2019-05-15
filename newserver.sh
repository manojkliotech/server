#!/bin/bash
#Update your domain name
echo " what is your domain name? "
read mydomain
echo "what is your server IP address? "
read ipaddress
#Installing http server
yum -y install httpd
yum -y install php*
sed -i '536s/.*/ServerSignature Off/' /etc/httpd/conf/httpd.conf
sed -i '537i ServerTokens Prod' /etc/httpd/conf/httpd.conf
#Installing the bind utilities for DNS Server
yum install bind* -y
yum install git -y
#Replace and modification of the configuration file
sed -i '11s/^/#/g' /etc/named.conf
sed -i '17s/.*/allow-query     { any; };/' /etc/named.conf
sed -i '18i allow-transfer { none; };' /etc/named.conf
sed -i '19i allow-recursion { none;};' /etc/named.conf
sed -i '20s/.*/recursion no;/' /etc/named.conf
sed -i "42i zone\"$mydomain\" IN {" /etc/named.conf
sed -i '43i type master;' /etc/named.conf
sed -i "44i file \"mail.$mydomain.zone\";" /etc/named.conf
sed -i '45i allow-update { none; };' /etc/named.conf
sed -i '46i };' /etc/named.conf
#Creating the zone file" 
touch /var/named/mail.$mydomain.zone
echo "\$TTL 86400
@   IN  SOA     ns1.$mydomain. root.mail.$mydomain. (
        2013042201  ;Serial
        3600        ;Refresh
        1800        ;Retry
        604800      ;Expire
        86400       ;Minimum TTL
)
; Specify our two nameservers
                IN      NS              ns1.$mydomain.
                IN      NS              ns2.$mydomain.
; Resolve nameserver hostnames to IP, replace with your two droplet IP addresses.
ns1             IN      A               $ipaddress
ns2             IN      A               $ipaddress

;specify MX record

@       IN      MX      10      mail.$mydomain.
; Define hostname -> IP pairs which you wish to resolve
@               IN      A               $ipaddress
www             IN      CNAME           $ipaddress
mail    IN      A       $ipaddress
mail.$mydomain    IN      A       $ipaddress
@    IN      TXT             \"v=spf1 a ipv4:$ipaddress -all\"
_dmarc       IN      TXT     \"v=DMARC1; p=none; sp=none; rua=mailto:abuse@$mydomain; ruf=mailto:abuse@$mydomain; rf=afrf; pct=100;\"
$ipaddress  IN      PTR     mail.$mydomain." > /var/named/mail.$mydomain.zone
#Initiate the named service process
service named start
chkconfig named on
#initiate the web service process
service httpd start
chkconfig httpd on
#Installing and Configure the CSF firewall
#Install the perl utilities for CSF firewall installation
yum install perl-libwww-perl -y
#move into the directories to /usr/src
cd /usr/src
#Downloading the CSF firewall archive files
wget https://download.configserver.com/csf.tgz
#Unarchive the CSF files
tar -xzf csf.tgz
cd csf
#installing the CSF firewall
sh install.sh
cd ~
#Check the Configuration are correct
perl /usr/local/csf/bin/csftest.pl
#Replace the testing feature of CSF firewall to Running
sed -i '11s/.*/TESTING = "0"/' /etc/csf/csf.conf
sed -i '139s/.*/TCP_IN = "20,21,22,25,53,3306,80,110,143,443,465,587,993,995"/' /etc/csf/csf.conf
sed -i '142s/.*/TCP_OUT = "20,21,22,25,53,3306,80,110,113,443,587,993,995"/' /etc/csf/csf.conf
#Start the CSF and LFD services
service csf start
service lfd start
chkconfig csf on
chkconfig lfd on
csf -r
#Install and enable cron job for Clamd service
yum -y install epel-release
yum install clamav clamd -y
service clamd start
chkconfig clamd on
/usr/bin/freshclam
touch /etc/cron.daily/dailyscan
echo "#!/bin/bash
SCAN_DIR=\"/home\"
LOG_FILE=\"/var/log/clamav/dailyscan.log\"
/usr/bin/clamscan -i -r $SCAN_DIR >> $LOG_FILE" > /etc/cron.daily/dailyscan
chmod +x /etc/cron.daily/dailyscan
#Installing the Maldetect
cd /usr/src
wget http://www.rfxn.com/downloads/maldetect-current.tar.gz
tar -xzf maldetect-current.tar.gz
cd maldetect-1.6.3
sh install.sh
cd ~
#Installing  the DDOS configuration file
cd /usr/src
wget http://www.inetbase.com/scripts/ddos/install.sh
sed -i '29d' install.sh
sh install.sh
cd ~
mkdir -p /var/www/$mydomain
yum install git -y
cd /var/www/$mydomain
git clone https://github.com/manojkliotech/public_html.git
chown -R apache:apache /var/www/$mydomain/public_html
chmod 755 /var/www
#touch /var/www/$mydomain/public_html/index.html
#echo "<html>
#  <head>
#    <title>www.example.com</title>
#  </head>
#  <body>
#    <h1>$mydomain
#  </body>
#</html>" > /var/www/$mydomain/public_html/index.html
echo "<VirtualHost *:80>
     ServerAdmin webmaster@$mydomain
     DocumentRoot /var/www/$mydomain/public_html
     ServerName www.$mydomain
     ServerAlias $mydomain
     ErrorLog /var/www/$mydomain/error.log
</VirtualHost> " >> /etc/httpd/conf/httpd.conf
service httpd restart
chkconfig httpd on
yum -y remove sendmail
yum -y install postfix
yum -y install cyrus-*
yum -y install dovecot
cd /usr/local/
wget https://dl.eff.org/certbot-auto
chmod a+x certbot-auto
./certbot-auto --apache -d $mydomain --agree-tos --email tech@kdev.in --noninteractive --no-redirect
./certbot-auto renew --dry-run
cd ~
sed -i '22s/.*/soft_bounce = no/' /etc/postfix/main.cf
sed -i "75s/.*/myhostname = mail.$mydomain/" /etc/postfix/main.cf
sed -i "83s/.*/mydomain = $mydomain/" /etc/postfix/main.cf
sed -i '99s/.*/myorigin = $mydomain/' /etc/postfix/main.cf
sed -i '116s/.*/inet_interfaces = all/' /etc/postfix/main.cf
sed -i '164s/.*/mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain/' /etc/postfix/main.cf
sed -i '264s/.*/mynetworks = 127.0.0.0\/8 [::1]\/128/' /etc/postfix/main.cf
sed -i '419s/.*/home_mailbox = Maildir\//' /etc/postfix/main.cf
echo "smtpd_sasl_auth_enable = yes
smtpd_sasl_type = cyrus
smtpd_sasl_security_options = noanonymous
broken_sasl_auth_clients = yes
smtpd_sasl_authenticated_header = yes
smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination
smtpd_tls_auth_only = no 
smtp_use_tls = yes
smtpd_use_tls = yes
smtp_tls_note_starttls_offer = yes
smtpd_tls_key_file = /etc/letsencrypt/live/$mydomain/fullchain.pem
smtpd_tls_cert_file = /etc/letsencrypt/live/$mydomain/privkey.pem
smtpd_tls_received_header = yes
smtpd_tls_session_cache_timeout = 3600s
tls_random_source = dev:/dev/urandom
virtual_alias_maps      = hash:/etc/postfix/virtual
header_checks           = regexp:/etc/postfix/header_checks
mime_header_checks      = pcre:/etc/postfix/body_checks " >> /etc/postfix/main.cf
sed -i '17s/.*/smtps     inet  n       -       n       -       -       smtpd/' /etc/postfix/master.cf
sed -i '18s/.*/587     inet  n       -       n       -       -       smtpd/' /etc/postfix/master.cf
#sed -i '18i \  \       -o smtpd_sasl_auth_enable=yes' /etc/postfix/master.cf
#sed -i '19i \  \       -o smtpd_reject_unlisted_sender=yes' /etc/postfix/master.cf
#sed -i '20i \  \       -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject' /etc/postfix/master.cf
#sed -i '21i \  \       -o broken_sasl_auth_clients=yes' /etc/postfix/master.cf
#postmap /etc/postfix/header_checks
touch /etc/postfix/virtual
echo "abuse@$mydomain ibwdmarc@gmail.com" > /etc/postfix/virtual
postmap /etc/postfix/virtual
touch /etc/postfix/body_checks
#rm -rf /etc/sasl2/smtpd.conf
#touch /etc/sasl2/smtpd.conf
#echo "pwcheck_method: auxprop
#auxprop_plugin: sasldb
#mech_list: PLAIN LOGIN CRAM-MD5 DIGEST-MD5 " > /etc/sasl2/smtpd.conf
rm -rf /etc/imapd.conf
touch /etc/imapd.conf
echo "virtdomains:              userid
defaultdomain:          $mydomain
servername:             $mydomain
configdirectory:        /var/lib/imap
partition-default:      /var/spool/imap
admins:                 cyrus
sievedir:               /var/lib/imap/sieve
sendmail:               /usr/sbin/sendmail.postfix
hashimapspool:          true
allowanonymouslogin:    no
allowplaintext:         yes
sasl_pwcheck_method:    auxprop

tls_key_file = /etc/letsencrypt/live/$mydomain/fullchain.pem
tls_cert_file = /etc/letsencrypt/live/$mydomain/privkey.pem
autocreatequota:                -1
createonpost:                   yes
autocreateinboxfolders:         spam
autosubscribeinboxfolders:      spam " > /etc/imapd.conf
#mkdir /etc/postfix/ssl
#cd /etc/postfix/ssl/
#openssl genrsa -des3 -rand /etc/hosts -out smtpd.key 1024
#chmod 600 smtpd.key
#openssl req -new -key smtpd.key -out smtpd.csr
#openssl x509 -req -days 365 -in smtpd.csr -signkey smtpd.key -out smtpd.crt
#penssl rsa -in smtpd.key -out smtpd.key.unencrypted
#mv -f smtpd.key.unencrypted smtpd.key
#openssl req -new -x509 -extensions v3_ca -keyout cakey.pem -out cacert.pem -days 365
#cd ~
#service saslauthd start
#chkconfig saslauthd on
service postfix start
chkconfig postfix on
sed -i '20s/.*/protocols = imap pop3 lmtp/' /etc/dovecot/dovecot.conf
sed -i '24s/.*/mail_location = maildir:~\/Maildir/' /etc/dovecot/conf.d/10-mail.conf
sed -i '9s/.*/disable_plaintext_auth = no/' /etc/dovecot/conf.d/10-auth.conf
sed -i '97s/.*/auth_mechanisms = plain login/' /etc/dovecot/conf.d/10-auth.conf
sed -i '83s/.*/user = postfix/' /etc/dovecot/conf.d/10-master.conf
sed -i '84s/.*/group = postfix/' /etc/dovecot/conf.d/10-master.conf
sed -i "12s/.*/ssl_cert = <\/etc\/letsencrypt\/live\/$mydomain\/fullchain.pem/" /etc/dovecot/conf.d/10-ssl.conf
sed -i "13s/.*/ssl_key = <\/etc\/letsencrypt\/live\/$mydomain\/privkey.pem/" /etc/dovecot/conf.d/10-ssl.conf
service dovecot start
chkconfig dovecot on
yum install squirrelmail -y
echo "Alias /squirrelmail /usr/share/squirrelmail
<Directory /usr/share/squirrelmail>
    Options Indexes FollowSymLinks
    RewriteEngine On
    AllowOverride All
    DirectoryIndex index.php
    Order allow,deny
    Allow from all
</Directory>" >> /etc/httpd/conf/httpd.conf
echo "/^Received:\sfrom\s(.*)by(.*)\(Postfix\)(.*)/   REPLACE Received: from $mydomain (localhost [IPv6:::1]) by\$2(Postfix)\$3" >> /etc/postfix/header_checks
postmap /etc/postfix/header_checks
service postfix restart
sed -i '229s/.*/short_open_tag = On/' /etc/php.ini
yum update -y
yum install opendkim -y
cp /etc/opendkim.conf{,.orig}
echo "
AutoRestart             Yes
AutoRestartRate         10/1h
LogWhy                  Yes
Syslog                  Yes
SyslogSuccess           Yes
Mode                    sv
Canonicalization        relaxed/simple
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
SignatureAlgorithm      rsa-sha256
Socket                  inet:8891@localhost
PidFile                 /var/run/opendkim/opendkim.pid
UMask                   022
UserID                  opendkim:opendkim
TemporaryDirectory      /var/tmp" > /etc/opendkim.conf
mkdir /etc/opendkim/keys/$mydomain
opendkim-genkey -D /etc/opendkim/keys/$mydomain/ -d $mydomain -s default
chown -R opendkim: /etc/opendkim/keys/$mydomain
mv /etc/opendkim/keys/$mydomain/default.private /etc/opendkim/keys/$mydomain/default
echo "default._domainkey.$mydomain $mydomain:default:/etc/opendkim/keys/$mydomain/default" >> /etc/opendkim/KeyTable
echo "*@$mydomain default._domainkey.$mydomain" >> /etc/opendkim/SigningTable
echo "
$mydomain
mail.$mydomain" >> /etc/opendkim/TrustedHosts
cat /etc/opendkim/keys/$mydomain/default.txt >> /var/named/mail.$mydomain.zone
echo "
smtpd_milters           = inet:127.0.0.1:8891
non_smtpd_milters       = $smtpd_milters
milter_default_action   = accept
milter_protocol         = 2" >> /etc/postfix/main.cf
service opendkim start
chkconfig opendkim on
service postfix restart
service named restart
useradd -s /sbin/nologin postmaster
useradd -s /sbin/nologin catchall
useradd -s /sbin/nologin webmaster
useradd -s /sbin/nologin abuse
echo x1ZE5QpOWZl| passwd postmaster --stdin
echo x1ZE5QpOWZl| passwd webmaster --stdin
echo x1ZE5QpOWZl| passwd abuse --stdin
useradd -s /sbin/nologin info
echo "info user account successfully created,Kindly update the password of info email account"
read password
echo "$password" | passwd info --stdin
echo "$password" | passwd catchall --stdin
perl /usr/share/squirrelmail/config/conf.pl
service httpd restart
chkconfig httpd on
cd ~
rm -rf server.sh
rm -rf install.sh
