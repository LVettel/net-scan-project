"""Net scan util.

Usage:
  scan.py [-d]
  scan.py -h
  scan.py --version
  scan.py -i <ip>

Options:
  -h --help     Show this screen.
  --version     Show version.
  -d     Start cyclic net scan and only file loggin (not console)
  -i     Start one host scanning
"""
import wmi_client_wrapper as wmi
from icmplib import ping
from socket import *
import psycopg2
from psycopg2.extras import DictCursor
import json
from datetime import timedelta, datetime
from instance.config import *
from ipaddress import ip_network
import logging
import smtplib
import ssl
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from docopt import docopt

def scan():
    try:
        for net in NETS:
            log.info('Scan %s net' % (net,))
            hosts = list(ip_network(net).hosts())
            for host in hosts:
                scanHost(host.exploded)
    except Exception:
        log.exception("Error in scan")

def scanHost(ip):
    result = ping(ip, count=4, interval=0.2)
    if result.is_alive:
        log.info("ping to %s success!" % (ip,))
        warning = False
        description = ''

        hostName = getHostName(ip)
        if hostName == None:
            warning = True
            description += " Host name not resolved."

        ports = scanPorts(ip)
        if 22 not in ports and 3389 not in ports:
            warning = True
            description += " All managed port is closed."

        # is wmi port open
        if 135 in ports:
            wmi_info = getWmiInfo(ip)
            log.info(wmi_info)


            # Calculate warning and description
            if wmi_info is None:
                warning = True
                description += " WMI port is open, but can not get wmi info."
                save(ip, json.dumps(ports), hostName, description, warning)
            else:
                save(ip, json.dumps(ports), hostName, description, warning, wmi_info['os'], wmi_info['mac'], \
                     wmi_info['user_name'], wmi_info['cpu'], wmi_info['motherboard'], \
                     wmi_info['memory'], wmi_info['disk'], wmi_info['system_name'])
        else:
            log.info("WMI is closed")
            save(ip, json.dumps(ports), hostName, description, warning)
    else:
        log.info("ping to %s failed!" % (ip,))

def getHostName(ip):
    try:
        hostName, alias, ipAddress = gethostbyaddr(ip)
        log.info("DNS name %s = %s" % (ip, hostName))
        return hostName
    except Exception:
        log.exception("Error get host")
        return None

def getWmiInfo(ip):
    try:
        log.info("Request wmi info")
        result = {}
        wmic = wmi.WmiClientWrapper(username=WMI_USER, password=WMI_PASSWORD, host=ip)
        output = wmic.query("SELECT Name FROM Win32_Processor")
        result['cpu'] = output[0]['Name']

        output = wmic.query("SELECT IPAddress, MACAddress FROM Win32_NetworkAdapterConfiguration")
        result['mac'] = getMac(output, ip)

        output = wmic.query("SELECT Manufacturer, Product FROM Win32_BaseBoard")
        if len(output) > 0:
            result['motherboard'] = output[0]['Manufacturer'] + ', ' + output[0]['Product']
        else:
            result['motherboard'] = None

        output = wmic.query("SELECT Name, UserName FROM Win32_ComputerSystem")
        result['system_name'] = output[0]['Name']
        result['user_name'] = output[0]['UserName']

        output = wmic.query("SELECT Caption from Win32_OperatingSystem")
        result['os'] = output[0]['Caption']


        output = wmic.query("SELECT Manufacturer, Capacity FROM Win32_PhysicalMemory")
        result['memory'] = json.dumps(list(map( \
            lambda item: {'Manufacturer': item['Manufacturer'], \
                          'Capacity': getMemorySize(int(item['Capacity']), 1024)}, output)))

        output = wmic.query("SELECT Model, Size FROM Win32_DiskDrive")
        result['disk'] = json.dumps(list(map( \
            lambda item: {'Model': item['Model'], \
                          'Size': getMemorySize(int(item['Size']), 1000)}, output)))

        if result['user_name'] is None:
            output = wmic.query("SELECT LogonId from  Win32_LogonSession where (LogonType = 2 or  LogonType = 10) and AuthenticationPackage = 'Kerberos'")
            if len(output) > 0:
                logon_id = output[0]['LogonId']
                output = wmic.query("select * from Win32_LoggedOnUser")
                session_info = list(filter(lambda item: logon_id in item['Dependent'] , output))
                # log.info(session_info)
                if len(session_info) > 0:
                    #\\.\root\cimv2:Win32_Account.Domain="BTLAB",Name="xxx"
                    match = re.search(r'^.*Domain="(\w*)",Name="(\w*)"$', session_info[0]['Antecedent'])
                    if match is not None:
                        result['user_name'] = match[1] + '\\' + match[2]

        return result
    except Exception:
        log.exception("Error get WMI info")
        return None


def getMemorySize(siseInByte, multiplier):
    res = siseInByte
    count = 0
    while res > multiplier:
        res = res / multiplier
        count = count + 1

    if count == 0:
        suffix = 'B'
    elif count == 1:
        suffix = 'K'
    elif count == 2:
        suffix = 'M'
    elif count == 3:
        suffix = 'G'
    elif count == 4:
        suffix = 'T'

    return str(round(res)) + suffix

def getMac(adapters, ip):
    for adapter in adapters:
        for ipAddress in adapter['IPAddress']:
            if ip in ipAddress:
                return adapter['MACAddress']
    return None

def save(ip, ports, dns_name, description, warning, os=None, mac=None, user_name=None, cpu=None, motherboard=None, memory=None, disk=None, system_name=None):
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            cursor.execute('SELECT * FROM host_info where ip = %s', (ip,))
            if cursor.rowcount == 0:
                with conn.cursor() as insert_cursor:
                    query = ('insert into host_info '
                             '(ip, ports, dns_name, os, mac, user_name, cpu, motherboard, memory, disk, system_name, description, warning, verification_date, change_date) '
                             'values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, localtimestamp, localtimestamp)')
                    insert_cursor.execute(query, (ip, ports, dns_name, os, mac, user_name, cpu, motherboard, memory, disk, system_name, description, warning,))
            else:
                # Check change
                row = cursor.fetchall()[0]

                newValues = {}
                newValues['ports'] = ports
                newValues['dns_name'] = dns_name
                newValues['os'] = os
                newValues['mac'] = mac
                newValues['user_name'] = user_name
                newValues['cpu'] = cpu
                newValues['motherboard'] = motherboard
                newValues['memory'] = memory
                newValues['disk'] = disk
                newValues['system_name'] = system_name

                # Не доступен WMI, а ранее был доступен. Не затираем старые данные, оставляем все как есть, но увеличиваем количество ошибок
                if system_name == None and row['system_name'] != None:
                    error_count = row['error_count'] if row['error_count'] != None else 0
                    error_count = error_count + 1
                    # Допускаем только 10 ошибок
                    if error_count < 10:
                        with conn.cursor() as update_cursor:
                            query = ('update host_info set '
                                     'error_count = %s '
                                     'where ip = %s')
                            update_cursor.execute(query, (error_count, ip))
                        conn.commit()
                        return

                # Если пользователь сменился с конкретного на None то оставляем конкретного
                result_user_name = user_name
                if user_name == None and row['user_name'] != None:
                    result_user_name = row['user_name']

                # Проверяем нет ли изменения в железе
                if checkChanges(ip, row, newValues):
                    with conn.cursor() as update_cursor:
                        query = ('update host_info set '
                                 'ports = %s, dns_name = %s, os = %s, mac = %s, user_name = %s, cpu = %s, motherboard = %s, memory = %s, disk = %s, system_name = %s, description = %s, warning = %s, verification_date = localtimestamp, change_date = localtimestamp, error_count = 0 '
                                 'where ip = %s')

                        update_cursor.execute(query, (ports, dns_name, os, mac, result_user_name, cpu, motherboard, memory, disk, system_name, description, warning, ip))
                else:
                    # Изменения в железе нет, записываем только информацию о пользователе и дате проверки
                    log.info("Host %s info not changed" % (ip,))
                    with conn.cursor() as update_cursor:
                        query = ('update host_info set '
                                 'verification_date = localtimestamp, user_name = %s '
                                 'where ip = %s')
                        update_cursor.execute(query, (result_user_name, ip))

        conn.commit()

def checkChanges(ip, oldValues, newValues):
    if oldValues['dns_name'] != newValues['dns_name'] \
            or oldValues['os'] != newValues['os'] \
            or oldValues['mac'] != newValues['mac'] \
            or oldValues['cpu'] != newValues['cpu'] \
            or oldValues['motherboard'] != newValues['motherboard'] \
            or oldValues['memory'] != newValues['memory'] \
            or oldValues['disk'] != newValues['disk'] \
            or oldValues['system_name'] != newValues['system_name']:

        log.info('Host %s change detected: %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s' % \
                 (ip, \
                  oldValues['dns_name'], newValues['dns_name'], \
                  oldValues['os'], newValues['os'], \
                  oldValues['mac'], newValues['mac'], \
                  oldValues['cpu'], newValues['cpu'], \
                  oldValues['motherboard'], newValues['motherboard'], \
                  oldValues['memory'], newValues['memory'], \
                  oldValues['disk'], newValues['disk'], \
                  oldValues['system_name'], newValues['system_name']))

        log.info("Send host %s change email" % (ip,))
        if SMTP_SSL:
            context = ssl.create_default_context()
            context.check_hostname = False
            server = smtplib.SMTP_SSL(host=SMTP_HOST, port=SMTP_PORT, context=context)
        else:
            server = smtplib.SMTP(host=SMTP_HOST, port=SMTP_PORT)
        server.login(SMTP_USER, SMTP_PASSWORD)

        message = MIMEMultipart("alternative")
        message["Subject"] = "Host %s info is changed" % (ip,)
        message["From"] = SMTP_FROM
        message["To"] = SMTP_TO

        text = ('Attantion!\n\n'        
                'Host %s is changed\n'
                'Parameter\tOld Value\tNew Value\n')

        for key, value in oldValues.items():
            if key in newValues:
                text +=  key + "\t" + (value if value != None else "None") + "\t" + (newValues[key] if newValues[key] != None else "None") + "\n"

        html = """\
        <html>
          <body>
            <p>Attantion!<br>
               Host %s is changed
            </p>
            <table border='1'>
                <tr>
                    <th>Parameter</th>
                    <th>Old Value</th>
                    <th>New Value</th>
                </tr>
                """
        for key, value in oldValues.items():
            if key in newValues:
                style = '#FF00FF' if value != newValues[key] else '#F0FFFF'
                html += '<tr style="background-color: %s">' % (style,)
                html += '<td>' + key + '</td>'
                html += '<td>' +  (value if value != None else "None") + '</td>'
                html += '<td>' + (newValues[key] if newValues[key] != None else "None") + '</td>'
                html += '</tr>'

        html +="""\
            </table>
          </body>
        </html>
        """

        # Сделать их текстовыми\html объектами MIMEText
        part1 = MIMEText(text % (ip,) , "plain")
        part2 = MIMEText(html % (ip,), "html")

        # Внести HTML\текстовые части сообщения MIMEMultipart
        # Почтовый клиент сначала попытается отрендерить последнюю часть
        message.attach(part1)
        message.attach(part2)

        server.sendmail(SMTP_FROM, SMTP_TO, message.as_string())
        server.quit()
        return True
    else:
        return False


def scanPorts(ip):
    result = []
    for i in PORTS:
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(1)
        conn = s.connect_ex((ip, i))
        if(conn == 0) :
            log.info('Port %d: OPEN' % (i,))
            result.append(i)
        s.close()
    return result

def get_db_connection():
    return psycopg2.connect(dbname=DATABASE_NAME, user=DATABASE_USER, password=DATABASE_PASSWORD, host=DATABASE_HOST)

if __name__ == '__main__':
    arguments = docopt(__doc__, version="1.0.1")


    # in console loggin only if not -d parameter
    if not arguments['-d']:
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        console.setFormatter(logging.Formatter('%(levelname)-8s %(message)s'))
        logging.getLogger('scan').addHandler(console)

    file = logging.FileHandler(LOG)
    file.setLevel(logging.INFO)
    file.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logging.getLogger('scan').addHandler(file)

    log = logging.getLogger('scan')
    log.setLevel(logging.INFO)

    if arguments['-d']:
        log.info("Start cyclic scan")
        while True:
            scan()
    elif arguments['-i']:
        log.info("Scan %s" % (arguments['<ip>'],))
        scanHost(arguments['<ip>'])
    else:
        scan()