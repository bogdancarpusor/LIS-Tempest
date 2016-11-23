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

from tempest import config
from oslo_log import log as logging
from tempest.lis import manager
from tempest.scenario import utils as test_utils
from tempest import test
from tempest.lib import exceptions as lib_exc
from time import sleep
from kdump_utils import config_rhel, config_sles, config_ubuntu
CONF = config.CONF

LOG = logging.getLogger(__name__)


class KDump(manager.LisBase):

    def setUp(self):
        super(KDump, self).setUp()
        # Setup image and flavor the test instance
        # Support both configured and injected values
        if not hasattr(self, 'image_ref'):
            self.image_ref = CONF.compute.image_ref
        if not hasattr(self, 'flavor_ref'):
            self.flavor_ref = CONF.compute.flavor_ref
        self.image_utils = test_utils.ImageUtils(self.manager)
        if not self.image_utils.is_flavor_enough(self.flavor_ref,
                                                 self.image_ref):
            raise self.skipException(
                '{image} does not fit in {flavor}'.format(
                    image=self.image_ref, flavor=self.flavor_ref
                )
            )
        self.host_name = ""
        self.instance_name = ""
        self.kdump_conf = "/etc/kdump.conf"
        self.dump_path = "/var/crash"
        self.sys_kexec_crash = "/sys/kernel/kexec_crash_loaded"
        self.run_ssh = CONF.validation.run_validation and \
            self.image_utils.is_sshable_image(self.image_ref)
        self.ssh_user = self.image_utils.ssh_user(self.image_ref)
        LOG.debug('Starting test for i:{image}, f:{flavor}. '
                  'Run ssh: {ssh}, user: {ssh_user}'.format(
                      image=self.image_ref, flavor=self.flavor_ref,
                      ssh=self.run_ssh, ssh_user=self.ssh_user))


    # Steps
    # Send kdump config and execute
    # Reboot
    # Send kdump execute script to vm
    # run script
    # trigger kernel panic
    # wait 200 seconds to record the event and check vm heartbeat
    # Check if booted and colect kdump results

    def kdump_exec(self):
        self.linux_client.exec_command('sysctl -w kernel.unknown_nmi_panic=1')

        #Check if kdump is loaded
        crashkernel = self.linux_client.exec_command("`grep -i crashkernel= /proc/cmdline`")
        if self.linux_client.check_file_existence(self.sys_kexec_crash) and crashkernel:
            LOG.error("Kdump is not enabled after reboot")
            raise lib_exc.CommandFailed
        else:
            LOG.info("Kdump is loaded after reboot")

        if self.distro in ["RHEL", "CentOS"]:
            bash_cmds = [
                "systemctl stauts kdump.service | grep -q 'active'",
                "service kdump status | grep 'operational'"
            ]
            sleep_interval = 70
        elif self.distro in ["openSUSE", "SUSE Linux"]:
            self.linux_client.exec_command("systemctl start atd")
            bash_cmds = [
                "systemctl is-active kdump.service | grep -q 'active'",
                "rckdump status | grep 'running'"
            ]
            sleep_interval=50
        elif self.distro == "Ubuntu":
            sleep_interval = 50
        else:
            LOG.error("Invalid distro")
            raise lib_exc.NotImplemented

        LOG.info("Waiting %i seconds for kdump to become active" % sleep_interval)
        sleep(sleep_interval)
        if self.distro == "Ubuntu":
            if self.linux_client.exec_command("cat %s" % self.sys_kexec_crash) == "1":
                    LOG.info("Kdump is active")
            else:
                LOG.error("Kdump service is not active")
                raise lib_exc.CommandFailed
        else:
            try:
                self.linux_client.exec_command(bash_cmds[0])
                LOG.info("Kdump is active")
            except lib_exc.SSHExecCommandFailed as exc:
                self.linux_client.exec_command(bash_cmds[1])
                LOG.info("Kdump is active")

        LOG.info("Preparing for kernel panic")
        self.linux_client.exec_command("sync")
        sleep(6)
        self.linux_client.exec_command("echo 1 > /proc/sys/kernel/sysrq")

    def config_kdump(self, crashkernel):
        try:
            self.linux_client.exec_command("`dmesg | grep 'Vmbus version:3.0`")
        except lib_exc.SSHExecCommandFailed as exc:
            LOG.warning("VMBus version is not 3.0. Kernel might be older or patches not included")
            LOG.warning("Test will continue but it might not work properly")

        if self.distro in ["RHEL", "CentOS"]:
            config_rhel(self.linux_client, crashkernel, "/etc/kdump.conf", "/var/crash")
        elif self.distro in ["openSUSE", "SUSE Linux"]:
            config_sles(self.linux_client, crashkernel)
        elif self.distro == "Ubuntu":
            config_ubuntu(self.linux_client, crashkernel)
        else:
            LOG.error("Distro not supported")
            raise lib_exc.NotImplemented

    def check_results(self):
        if self.distro == "Ubuntu":
            crash_file_path = "/var/crash/2*"
        else:
            crash_file_path = "/var/crash/*/vmcore"
        try:
            self.linux_client.exec_command("find %s -type f -size +10M" % crash_file_path)
            LOG.info("Proper file was found in /var/crash")
        except lib_exc.SSHExecCommandFailed as exc:
            LOG.error("No file was found in /var/crash of size greater than 10M")
            LOG.exception(exc)
            self._log_console_output()
            raise exc

    def run_kdump(self, crashkernel_size, nmi=0, vcpu=1):
        self.distro = self.linux_client.get_os_type()['vendor']
        self.config_kdump(crashkernel_size)
        self.linux_client.exec_command("reboot")
        LOG.info("Waiting for VM to have a connection")
        timeout = 200
        counter = 0
        flag = True

        while flag:
            try:
                self.host_client.run_powershell_cmd(
                    "Test-NetConnevtion %s -Port 22 -WarningAction SilentlyContinue | ? { $_.TcpTestSucceded }" % self.floating_ip['floatingip']['floating_ip_address']
                )
                flag = False
            except Exception:
                continue

        self.kdump_exec()
        #trigger kernel panic
        if nmi == 1:
            sleep(70)
            self.host_client.run_powershell_cmd("Debug-VM -Name %s -InjectNonMaskableInterrupt -Computername %s -Force" % (self.host_name))
        elif vcpu == 4:
            LOG.info("Kdump will be triggered on VCPU 3 of 4")
            self.linux_client.exec_command("taskset -c 2 echo c > /proc/sysrq-trigger 2>/dev/null &")
        else:
            self.linux_client.exec_command("echo c > /proc/sysrq-trigger 2>/dev/null &")

        LOG.info("Waiting 200 seconds to record the event")
        sleep(200)

        # Check heartbeat
        self.check_heartbeat_status(self.instance_name)
        # check connection

        self.check_results()

    @test.attr(type=['kdump'])
    @test.services('compute', 'network')
    def test_crash_single_core(self):
        self.spawn_vm()
        self.stop_vm(self.server_id)
        self.change_cpu(self.instance_name, 1)
        self.set_ram_settings(self.instance_name, 4)
        self.start_vm(self.server_id)
        self._initiate_linux_client(self.floating_ip['floatingip']['floating_ip_address'],
                                    self.ssh_user, self.keypair['private_key'])
        try:
            self.run_kdump('256@128M')
        except lib_exc.SSHExecCommandFailed as exc:
            LOG.exception(exc)
            self._log_console_output()
            raise exc

    @test.attr(type=['kdump'])
    @test.services('compute', 'network')
    def test_crash_smp(self):
        self.spawn_vm()
        self.stop_vm(self.server_id)
        self.change_cpu(self.instance_name, 2)
        self.set_ram_settings(self.instance_name, 2)
        self.start_vm(self.server_id)
        self._initiate_linux_client(self.floating_ip['floatingip']['floating_ip_address'],
                                    self.ssh_user, self.keypair['private_key'])
        try:
            self.run_kdump('256@128M', vcpu=2)
        except lib_exc.SSHExecCommandFailed as exc:
            LOG.exception(exc)
            self._log_console_output()
            raise exc

    @test.attr(type=['kdump'])
    @test.services('compute', 'network')
    def test_crash_nmi(self):
        self.spawn_vm()
        self.stop_vm(self.server_id)
        self.change_cpu(self.instance_name, 3)
        self.set_ram_settings(self.instance_name, 3)
        self.start_vm(self.server_id)
        self._initiate_linux_client(self.floating_ip['floatingip']['floating_ip_address'],
                                    self.ssh_user, self.keypair['private_key'])
        try:
            self.run_kdump('384M', nmi=1, vcpu=3)
        except lib_exc.SSHExecCommandFailed as exc:
            LOG.exception(exc)
            self._log_console_output()
            raise exc

    @test.attr(type=['kdump'])
    @test.services('compute', 'network')
    def test_crash_auto_size(self):
        self.spawn_vm()
        self.stop_vm(self.server_id)
        self.change_cpu(self.instance_name, 2)
        self.set_ram_settings(self.instance_name, 2)
        self.start_vm(self.server_id)
        self._initiate_linux_client(self.floating_ip['floatingip']['floating_ip_address'],
                                    self.ssh_user, self.keypair['private_key'])
        try:
            self.run_kdump('auto', vcpu=2)
        except lib_exc.SSHExecCommandFailed as exc:
            LOG.exception(exc)
            self._log_console_output()
            raise exc

    @test.attr(type=['kdump'])
    @test.services('compute', 'network')
    def test_crash_different_vcpu(self):
        self.spawn_vm()
        self.stop_vm(self.server_id)
        self.change_cpu(self.instance_name, 4)
        self.set_ram_settings(self.instance_name, 2)
        self.start_vm(self.server_id)
        self._initiate_linux_client(self.floating_ip['floatingip']['floating_ip_address'],
                                    self.ssh_user, self.keypair['private_key'])
        try:
            self.run_kdump('256@128M', vcpu=4)
        except lib_exc.SSHExecCommandFailed as exc:
            LOG.exception(exc)
            self._log_console_output()
            raise exc
