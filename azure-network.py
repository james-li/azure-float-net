#!/usr/bin/env python2
'''
Run the script before you use float ip in your HA configuration in Microsoft Azure
'''

from subprocess import Popen, PIPE
import os
import sys
import json

az_zone = os.getenv('AZURE_ZONE')
user = os.getenv('AZURE_USER')
password = os.getenv('AZURE_PASSWORD')

GROUP = os.getenv('AZURE_RESOURCE_GROUP')

#modified for your configuration
ALIAS = 'ccm'
IP = '192.168.10.18'
NIC = 'eth0'
NIC_CACHE_DIR = '/var/run/az_nic'
AZ_NIC = az_get_az_nic(NIC)


def run_az_cli(args):
     args.insert(0, 'az')
     p = Popen(args, stdout = PIPE, stderr = PIPE);
     data = p.stdout.read()
     error = p.stderr.read()
     return (p.wait(), data)

def get_local_ip(nic):
    try:
        p = Popen(['ip', 'addr', 'show', nic], stdout = PIPE, stderr = PIPE);
        for line in p.stdout.read():
            if line.start('inet '):
                return line.split()[1].split('/')
    except:
        pass
    finally:
        return None

def az_get_az_nic(nic):
    if os.getenv('AZ_NIC'):
        return os.getenv('AZ_NIC')
    AZ_NIC_CACHE_FILE = os.path.join(NIC_CACHE_DIR, nic)
    if os.access(AZ_NIC_CACHE_FILE, os.R_OK):
        return open(AZ_NIC_CACHE_FILE).read()
    local_ip = get_local_ip(nic)
    if not local_ip:
        return None
    ret, data = run_az_cli(['network', 'nic', 'list'])
    if ret:
        return None
    try:
        data_json = json.loads(data)
        for token in data_json:
            matched = False
            for ip_config in token[u'ipConfigurations']:
                if ip_config[u'privateIpAddress'].encode('utf-8') == local_ip:
                    matched = True
                    break
            if matched:
                az_nic = token[u'name'].encode('utf-8')
                os.makedirs(NIC_CACHE_DIR)
                open(AZ_NIC_CACHE_FILE, 'w').write(az_nic)
                return az_nic
    except:
        return None


def az_change_zone(zone):
    return run_az_cli(['cloud', 'set', '-n', zone])[0]

def az_login(u, p):
    return run_az_cli(['login', '-u', u, '-p', p])[0]

def az_check_login():
    return run_az_cli('account show'.split())[0] == 0



def az_check_ip(group, nic, ip):
    ret, data = run_az_cli(['network', 'nic', 'ip-config', 'list',
        '--resource-group', group,
        '--nic-name', nic])
    if ret != 0:
        return False
    try:
        data_json = json.loads(data)
        for token in data_json:
            if token[u'privateIpAddress'].encode('utf-8') == ip:
                return True
    except:
        return False

def az_check_alias(group, nic, alias):
    ret, data = run_az_cli(['network', 'nic', 'ip-config', 'list',
        '--resource-group', group,
        '--nic-name', nic])
    if ret != 0:
        return False
    try:
        data_json = json.loads(data)
        for token in data_json:
            if token[u'name'].encode('utf-8') == alias:
                return True
    except:
        return False


def az_bind_ip_alias(group, nic, alias, ip):
    if az_check_ip(group, nic, ip):
        return 0
    return run_az_cli(['network', 'nic', 'ip-config', 'create',
        '--resource-group', group,
        '--nic-name', nic,
        '-n', alias,
        '--private-ip-address', ip])[0]


def az_unbind_ip_alias(group, nic, alias):
    if not az_check_alias(group, nic, alias):
        return 0
    return run_az_cli(['network', 'nic', 'ip-config', 'delete',
        '--resource-group', group, '--nic-name', nic, '-n', alias])[0]

def start():
    return az_bind_ip_alias(GROUP, AZ_NIC, ALIAS, IP)

def stop():
    return az_unbind_ip_alias(GROUP, AZ_NIC, ALIAS)

def status():
    if az_check_alias(GROUP, AZ_NIC, ALIAS):
        return 0
    else:
        return 1


if __name__ == '__main__':
    action = sys.argv[1]
    if not AZ_NIC:
        sys.exit(-1)

    func = locals().get(action)
    if func:
        if not az_check_login():
            az_change_zone(az_zone)
            az_login(user, password)
        sys.exit(func())
    else:
        sys.exit(-1)
