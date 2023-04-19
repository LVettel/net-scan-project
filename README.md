=== Установка wmic

yum install autoconf gcc

```
Download sources from https://edcint.co.nz/checkwmiplus/download/wmic-source-v1-4-1/

tar xzvf wmi-1.4.1.tar.gz
patch /home/mikhail/Projects/wmi-1.4.1/Samba/source/lib/tls/tls.c:
// comment line
//gnutls_certificate_type_set_priority(tls->session, cert_type_priority);

//change two entry gnutls_transport_set_lowat to gnutls_priority_set_direct 
//gnutls_transport_set_lowat(tls->session, 0);
gnutls_priority_set_direct(tls->session, "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.0:+VERS-SSL3.0:%COMPAT", NULL);

cd wmi-1.4.1/Samba/source
./autogen.sh
./configure
make "CPP=gcc -E -ffreestanding"
make "CPP=gcc -E -ffreestanding" bin/wmic

sudo cp bin/wmic /usr/local/bin/
```

Выполнить sql запросы
```
сreate role net_monitor with password 'net_monitor';
alter role net_monitor with login;
сreate database net_monitor with owner 'net_monitor';

create table host_info(
  ip varchar(16) not null,
  ports varchar(256),
  dns_name varchar(128),
  os varchar(128),
  mac varchar(128),
  user_name varchar(128),
  cpu varchar(128),
  motherboard varchar(128),
  memory text,
  disk text,
  system_name varchar(128),
  description text,
  warning bool,
  verification_date timestamp not null,
  change_date timestamp not null,
  error_count int,
  CONSTRAINT addressee_pkey PRIMARY KEY (ip)
);

alter table host_info owner to net_monitor;

create table host_info_history(
  ip varchar(16) not null,
  ports varchar(256),
  dns_name varchar(128),
  os varchar(128),
  mac varchar(128),
  user_name varchar(128),
  cpu varchar(128),
  motherboard varchar(128),
  memory text,
  disk text,
  system_name varchar(128),
  create_date timestamp not null,
  CONSTRAINT fk_ip FOREIGN KEY (ip)
    REFERENCES host_info (ip)
    ON DELETE CASCADE
);

alter table host_info_history owner to net_monitor;
```

=== Установка net-scan

```
git clone https://git.btlab.ru/btlab/net-scan.git
cd net-scan
sudo python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
cp instance/config.py.example instance/config.py
```
