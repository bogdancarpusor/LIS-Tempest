# Copyright 2014 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import netaddr
import re
import time

from oslo_log import log as logging

from tempest import config
from tempest import exceptions
from tempest.lib.common import ssh
import tempest.lib.exceptions

CONF = config.CONF

LOG = logging.getLogger(__name__)


class RemoteClientBase():

    def __init__(self, ip_address, username, password=None, pkey=None):
        ssh_timeout = CONF.validation.ssh_timeout
        connect_timeout = CONF.validation.connect_timeout

        self.ssh_client = ssh.Client(ip_address, username, password,
                                     ssh_timeout, pkey=pkey,
                                     channel_timeout=connect_timeout)

    def exec_command(self, cmd, ignore_exit_status=False):
        # Shell options below add more clearness on failures,
        # path is extended for some non-cirros guest oses (centos7)
        cmd = CONF.validation.ssh_shell_prologue + " " + cmd
        LOG.debug("Remote command: %s" % cmd)
        return self.ssh_client.exec_command(cmd, ignore_exit_status)

    def copy_over(self, source, destination):
        output = self.ssh_client.sftp(source, destination)
        return output

    def validate_authentication(self):
        """Validate ssh connection and authentication

           This method raises an Exception when the validation fails.
        """
        self.ssh_client.test_connection_auth()

    def execute_script(self, cmd, cmd_params, source, destination):
        try:
            self.copy_over(source, destination)
            cmd_args = ' '.join(str(x) for x in cmd_params)
            command = ("cd %(dest)s; chmod +x %(cmd)s; sed -i 's/\r//' %(cmd)s; "
                       './%(cmd)s %(cmd_args)s') % {
                'dest': destination,
                'cmd': cmd,
                'cmd_args': cmd_args}
            return self.exec_command(command)

        except tempest.lib.exceptions.SSHExecCommandFailed as exc:
            LOG.exception(exc)
            raise exc

        except Exception as exc:
            LOG.exception(exc)
            raise exc


class RemoteClient(RemoteClientBase):

    def hostname_equals_servername(self, expected_hostname):
        # Get host name using command "hostname"
        actual_hostname = self.exec_command("hostname").rstrip()
        return expected_hostname == actual_hostname

    def get_ram_size_in_mb(self):
        output = self.exec_command('free -m | grep Mem')
        if output:
            return output.split()[1]

    def install_ntp(self):
        os_details = self.get_os_type()
        if os_details['vendor'] in ['Fedora', 'CentOS', 'Red Hat', 'OracleServer']:
            try:
                self.exec_command('ntpstat -p 1> /dev/null 2> /dev/null')
            except tempest.lib.exceptions.SSHExecCommandFailed:
                LOG.debug('Attempting to install NTPD')
                self.exec_command('sudo yum install -y ntp ntdate ntd-doc')
                self.exec_command('sudo systemctl enable ntpd.service')
                self.exec_command('sudo ntpdate pool.ntp.org')
                self.exec_command('sudo service ntpd start')
                LOG.debug('NTPD install successfully')
            self.exec_command('sudo service ntpd restart')
        elif os_details['package'] in ['SUSE Linux', 'openSUSE']:
            pass
        elif os_details['package'] == 'deb':
            try:
                self.exec_command('ntpq -p 1> /dev/null 2> /dev/null')
            except tempest.lib.exceptions.SSHExecCommandFailed:
                LOG.debug('Attempting to install NTP')
                self.exec_command('sudo apt-get install -y ntp')
                LOG.debug('NTP installed successfully')
            self.exec_command('sudo service ntp restart')
        else:
            LOG.error('Distro not supported')
            raise tempest.lib.exceptions.NotImplemented

    def get_os_type(self):
        os_details = dict()
        if self.check_file_existence('/etc/lsb-relese'):
            if not self.check_file_existence('/etc/redhat-release') or \
                    not self.check_file_existence('/etc/centos-release') or \
                    not self.check_file_existence('/etc/fedora-release'):
                os_details['package'] = 'rpm'
                self.exec_command('sudo yum install -y redhat-lsb')
            elif not self.check_file_existence('/etc/SuSE-release'):
                self.exec_command('sudo zypper install -y lsb-release')
                os_details['package'] = ''
            elif not self.check_file_existence('/etc/debian_version'):
                os_details['package'] = 'deb'
                self.exec_command('sudo apt-get install -y lsb-release')
            else:
                LOG.error("Distro not supported")
                raise tempest.lib.exceptions.NotImplemented

        os_details['vendor'] = self.exec_command('lsb_release -i -s').strip()
        os_details['release'] = self.exec_command('lsb_release -r -s').strip()
        os_details['codename'] = self.exec_command('lsb_release -c -s').strip()
        os_details['update'] = ''
        if 'SUSE' in os_details['vendor']:
            if self.exec_command('lsb_release -i -s | grep -q openSUSE'):
                os_details['vendor'] = 'openSUSE'
            else:
                os_details['vendor'] = 'SUSE Linux'
        elif 'RedHat' in os_details['vendor']:
            os_details['vendor'] = 'Red Hat'

        return os_details

    def get_number_of_vcpus(self):
        output = self.exec_command('grep -c ^processor /proc/cpuinfo')
        return int(output)

    def get_partitions(self):
        # Return the contents of /proc/partitions
        command = 'cat /proc/partitions'
        output = self.exec_command(command)
        return output

    def get_boot_time(self):
        cmd = 'cut -f1 -d. /proc/uptime'
        boot_secs = self.exec_command(cmd)
        boot_time = time.time() - int(boot_secs)
        return time.localtime(boot_time)

    def get_kernel_version(self):
        output = self.exec_command('uname -r')
        return output

    def write_to_console(self, message):
        message = re.sub("([$\\`])", "\\\\\\\\\\1", message)
        # usually to /dev/ttyS0
        cmd = 'sudo sh -c "echo \\"%s\\" >/dev/console"' % message
        return self.exec_command(cmd)

    def ping_host(self, host, count=CONF.validation.ping_count,
                  size=CONF.validation.ping_size, nic=None):
        addr = netaddr.IPAddress(host)
        cmd = 'ping6' if addr.version == 6 else 'ping'
        if nic:
            cmd = 'sudo {cmd} -I {nic}'.format(cmd=cmd, nic=nic)
        cmd += ' -c{0} -w{0} -s{1} {2}'.format(count, size, host)
        return self.exec_command(cmd)

    def set_mac_address(self, nic, address):
        self.set_nic_state(nic=nic, state="down")
        cmd = "sudo ip link set dev {0} address {1}".format(nic, address)
        self.exec_command(cmd)
        self.set_nic_state(nic=nic, state="up")

    def get_mac_address(self, nic=""):
        show_nic = "show {nic} ".format(nic=nic) if nic else ""
        cmd = "ip addr %s| awk '/ether/ {print $2}'" % show_nic
        return self.exec_command(cmd).strip().lower()

    def get_nic_name_by_mac(self, address):
        cmd = "ip -o link | awk '/%s/ {print $2}'" % address
        nic = self.exec_command(cmd)
        return nic.strip().strip(":").lower()

    def get_nic_name_by_ip(self, address):
        cmd = "ip -o addr | awk '/%s/ {print $2}'" % address
        nic = self.exec_command(cmd)
        return nic.strip().strip(":").lower()

    def get_ip_list(self):
        cmd = "ip address"
        return self.exec_command(cmd)

    def assign_static_ip(self, nic, addr):
        cmd = "sudo ip addr add {ip}/{mask} dev {nic}".format(
            ip=addr, mask=CONF.network.tenant_network_mask_bits,
            nic=nic
        )
        return self.exec_command(cmd)

    def set_nic_state(self, nic, state="up"):
        cmd = "sudo ip link set {nic} {state}".format(nic=nic, state=state)
        return self.exec_command(cmd)

    def get_pids(self, pr_name):
        # Get pid(s) of a process/program
        cmd = "ps -ef | grep %s | grep -v 'grep' | awk {'print $1'}" % pr_name
        return self.exec_command(cmd).split('\n')

    def get_cores_no(self):
        cmd = 'grep -i processor -o /proc/cpuinfo'
        return int(self.exec_command(cmd))

    def get_dns_servers(self):
        cmd = 'cat /etc/resolv.conf'
        resolve_file = self.exec_command(cmd).strip().split('\n')
        entries = (l.split() for l in resolve_file)
        dns_servers = [l[1] for l in entries
                       if len(l) and l[0] == 'nameserver']
        return dns_servers

    def send_signal(self, pid, signum):
        cmd = 'sudo /bin/kill -{sig} {pid}'.format(pid=pid, sig=signum)
        return self.exec_command(cmd)

    def _renew_lease_udhcpc(self, fixed_ip=None):
        """Renews DHCP lease via udhcpc client. """
        file_path = '/var/run/udhcpc.'
        nic_name = self.get_nic_name_by_ip(fixed_ip)
        pid = self.exec_command('cat {path}{nic}.pid'.
                                format(path=file_path, nic=nic_name))
        pid = pid.strip()
        self.send_signal(pid, 'USR1')

    def _renew_lease_dhclient(self, fixed_ip=None):
        """Renews DHCP lease via dhclient client. """
        cmd = "sudo /sbin/dhclient -r && sudo /sbin/dhclient"
        self.exec_command(cmd)

    def renew_lease(self, fixed_ip=None):
        """Wrapper method for renewing DHCP lease via given client

        Supporting:
        * udhcpc
        * dhclient
        """
        # TODO(yfried): add support for dhcpcd
        supported_clients = ['udhcpc', 'dhclient']
        dhcp_client = CONF.scenario.dhcp_client
        if dhcp_client not in supported_clients:
            raise exceptions.InvalidConfiguration('%s DHCP client unsupported'
                                                  % dhcp_client)
        if dhcp_client == 'udhcpc' and not fixed_ip:
            raise ValueError("need to set 'fixed_ip' for udhcpc client")
        return getattr(self, '_renew_lease_' + dhcp_client)(fixed_ip=fixed_ip)

    def check_cdrom(self):
        try:
            self.exec_command("sudo lsmod | grep 'ata_piix\|isofs'")
            LOG.info('ata_piix module is present')
        except tempest.lib.exceptions.SSHExecCommandFailed as exc:
            LOG.info('ata_piix module is not present in VM')
            LOG.info('Loading ata_piix module')
            self.exec_command('sudo insmod /lib/modules`uname -r`/kerne;/drivers/ata/ata_piix.ko')
            LOG.info('ata_piix module loaded')

    def add_module(self, module_name):
        return int(
            self.exec_command('modprobe %s' % module_name)
        )

    def mount(self, dev_name, mount_path='/mnt'):
        cmd_mount = 'sudo mount /dev/%s %s' % (dev_name, mount_path)
        self.exec_command(cmd_mount)

    def umount(self, mount_path='/mnt', ignore_exit_status=False):
        self.exec_command(
            'sudo umount %s' % mount_path, ignore_exit_status=ignore_exit_status)

    def make_fs(self, dev_name, fs='ext4'):
        cmd_mkfs = 'sudo /usr/sbin/mke2fs -t %s /dev/%s' % (fs, dev_name)
        try:
            self.exec_command(cmd_mkfs)
        except tempest.lib.exceptions.SSHExecCommandFailed:
            LOG.error("Couldn't mke2fs")
            cmd_why = 'sudo ls -lR /dev'
            LOG.info("Contents of /dev: %s" % self.exec_command(cmd_why))
            raise

    def verify_lis_module(self, module):
        command = 'lsmod | grep {module} | wc -l'.format(module=module)
        output = self.exec_command(command)
        return int(output)

    def get_module_version(self, module):
        return self.exec_command(
            "modinfo %s | grep vermagic: | awk '{print $2}'" % module
        )

    def get_cpu_count(self):
        command = 'cat /proc/cpuinfo | grep processor | wc -l'
        output = self.exec_command(command)
        return int(output)

    def create_file(self, file_name):
        cmd = 'echo abc > %s' % file_name
        return self.exec_command(cmd)

    def delete_file(self, file_name):
        cmd = 'sudo rm -f %s' % file_name
        output = self.exec_command(cmd)
        return output

    def verify_daemon(self, daemon):
        cmd = 'ps cax | grep %s' % daemon
        output = self.exec_command(cmd)
        return output

    def verify_file(self, file_name):
        cmd = 'cat %s' % file_name
        return self.exec_command(cmd)

    def check_file_existence(self, file_name):
        cmd = ' [ -f %s ] && echo 0 || echo 1' % file_name
        return int(self.exec_command(cmd))

    def check_executable_file(self, file_path):
        cmd = ' [ -x %s ] && echo 0 || echo 1' % file_path
        return int(self.exec_command(cmd))

    def check_folder_existence(self, folder_path):
        cmd = ' [ -d %s ] && echo 0 || echo 1' % folder_path
        return int(self.exec_command(cmd))
    
    def check_file_size(self, file_name):
        cmd = 'wc -c < %s' % file_name
        return int(self.exec_command(cmd))

    def get_unix_time(self):
        command = 'date +%s'
        output = self.exec_command(command)
        return int(output)

    def get_disks_count(self, sleep_count=1):
        command = 'sleep ' + \
            str(sleep_count) + '; sudo fdisk -l | grep "Disk /dev/sd*" | wc -l'
        output = self.exec_command(command)
        return int(output)

    def get_disks_size(self, disk, sleep_count=1):
        command = 'sleep ' + \
            str(sleep_count) + "; sudo fdisk -l /dev/{disk}  2> /dev/null | grep Disk | grep {disk} | cut -f 5 -d ' '".format(disk=disk)
        output = self.exec_command(command)
        return int(output)

    def disk_rescan(self, sleep_count=1):
        command = 'sleep ' + \
            str(sleep_count) + '; sudo fdisk -l > /dev/null;' + \
            'echo 1 > sudo /sys/block/sdb/device/rescan'
        self.exec_command(command)

    def delete_partition(self, disk, partition=''):
        command = '(echo d; echo {partition}; echo; echo w) | sudo fdisk /dev/{disk} 2> /dev/null'\
            .format(disk=disk, partition=partition)
        self.exec_command(command)

    def recreate_partition(self, disk):
        command = '(echo d; echo n; echo; echo; echo; echo; echo w) | sudo fdisk /dev/{disk} 2> /dev/null'.format(disk=disk)
        self.exec_command(command)

    def create_new_partition(self, disk, partition='', size=''):
        cmd = '(echo n; echo p; echo; echo {partition}; echo {size}; echo; echo w) | sudo fdisk {disk}'\
            .format(disk=disk, partition=partition, size=size)
        self.exec_command(cmd)

    def grow_xfs(self, mount_path='/mnt'):
        command = 'sudo xfs_growfs -d {mount_path}'.format(
            mount_path=mount_path)
        self.exec_command(command)

    def verify_ping(self, destination_ip, dev='eth0'):
        cmd = "ping -I {dev} -c 10 {destination_ip}".format(
            dev=dev, destination_ip=destination_ip)
        return self.exec_command(cmd)

    def kvp_verify_value(self, key, value, pool):
        cmd = "chmod 755 /tmp/kvp_client; "
        self.exec_command(cmd)
        cmd = "/tmp/kvp_client {pool} | grep \"{key}; Value: {value}\"".format(
            pool=pool, key=key, value=value)

        """ kvp_client returned wrong exit code 4. Modified exec_command
            so it could ignore exit status to work around the problem.

        """
        output = self.exec_command(cmd, ignore_exit_status=True)
        if "Value: {value}".format(value=value) in output:
            return(output)
        else:
            raise Exception("Invalid KVP: " + output)


class FedoraUtils(RemoteClient):

    def get_os_type(self):
        return 'fedora'


class UbuntuUtils(RemoteClient):

    def get_os_type(self):
        return 'ubuntu'


class DebianUtils(RemoteClient):

    def get_os_type(self):
        return 'ubuntu'


class Fedora7Utils(RemoteClient):
    def get_os_type(self):
        return 'fedora7'
