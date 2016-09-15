# Copyright 2014 Cloudbase Solutions Srl
# All rights reserved
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

import time
import os

from tempest import config
from tempest.lib import exceptions as lib_exc
from tempest import test
from tempest.common.utils.windows.remote_client import WinRemoteClient
from tempest.lis import manager
from oslo_log import log as logging
from tempest.scenario import utils as test_utils

CONF = config.CONF

LOG = logging.getLogger(__name__)

MAXIMUM_DELAY = 7   # 7 seconds
SLEEP_TIME = 600    # 600 seconds


class TimeSync(manager.LisBase):

    def setUp(self):
        super(TimeSync, self).setUp()
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
        self.run_ssh = CONF.validation.run_validation and \
            self.image_utils.is_sshable_image(self.image_ref)
        self.ssh_user = CONF.validation.image_ssh_user
        LOG.debug('Starting test for i:{image}, f:{flavor}. '
                  'Run ssh: {ssh}, user: {ssh_user}'.format(
                      image=self.image_ref, flavor=self.flavor_ref,
                      ssh=self.run_ssh, ssh_user=self.ssh_user))

    def check_ntp_time(self):
        try:
            max_delay = 5.0
            wait_time = 10
            self.linux_client.install_ntp()
            LOG.info('Waiting %s seconds for the ntp server to sync' % wait_time)
            self.linux_client.exec_command('sleep %d' % wait_time)

            LOG.info('Checking if VM is in sync with the ntp server')
            self.linux_client.exec_command('ntpq -p')

            LOG.debug('Getting the offset between the ntp server and internal clock')
            delay = self.linux_client.exec_command("ntpdc -c loopinfo | awk 'NR==1 {print $2}'")

            LOG.info('NTP offset is %s seconds' % delay)
            if float(delay) >= max_delay:
                # TODO - Add more details for the raised exception
                raise lib_exc.TempestException()
            LOG.info('NTP time synced')

        except lib_exc.SSHExecCommandFailed as exc:

            LOG.exception(exc)
            self._log_console_output()
            raise exc

        except Exception as exc:
            LOG.exception(exc)
            self._log_console_output()
            raise exc

    @test.attr(type=['smoke', 'core', 'timesync'])
    @test.services('compute', 'network')
    def test_time_sync_ntp(self):
        self.spawn_vm()
        self._initiate_linux_client(self.floating_ip['floatingip']['floating_ip_address'],
                                    self.ssh_user, self.keypair['private_key'])
        self.check_ntp_time()
        self.servers_client.delete_server(self.instance['id'])

    @test.attr(type=['smoke', 'core', 'timesync'])
    @test.services('compute', 'network')
    def test_time_sync_host(self):
        self.spawn_vm()
        self._initiate_linux_client(self.floating_ip['floatingip']['floating_ip_address'],
                                    self.ssh_user, self.keypair['private_key'])
        vm_time = self.get_vm_time()
        t0 = time.time()
        host_time = self.get_host_time()
        t1 = time.time()
        exec_time = t1 - t0
        LOG.debug('Duration of get_host_time %s', exec_time)
        self.assertTrue(abs(vm_time - host_time) - exec_time < MAXIMUM_DELAY)
        self.servers_client.delete_server(self.instance['id'])

    @test.attr(type=['smoke', 'core', 'timesync'])
    @test.services('compute', 'network')
    def test_time_sync_saved_state(self):
        self.spawn_vm()
        self._initiate_linux_client(self.floating_ip['floatingip']['floating_ip_address'],
                                    self.ssh_user, self.keypair['private_key'])
        self.save_vm(self.server_id)
        time.sleep(SLEEP_TIME)
        self.unsave_vm(self.server_id)
        time.sleep(120)
        vm_time = self.get_vm_time()
        t0 = time.time()
        host_time = self.get_host_time()
        t1 = time.time()
        exec_time = t1 - t0
        LOG.debug('Duration of get_host_time %s', exec_time)
        self.assertTrue(abs(vm_time - host_time) - exec_time < MAXIMUM_DELAY)
        self.servers_client.delete_server(self.instance['id'])

    @test.attr(type=['smoke', 'core', 'timesync'])
    @test.services('compute', 'network')
    def test_time_sync_paused_state(self):
        self.spawn_vm()
        self._initiate_linux_client(self.floating_ip['floatingip']['floating_ip_address'],
                                    self.ssh_user, self.keypair['private_key'])
        self.pause_vm(self.server_id)
        time.sleep(SLEEP_TIME)
        self.unpause_vm(self.server_id)
        vm_time = self.get_vm_time()
        start = time.time()
        host_time = self.get_host_time()
        finish = time.time()
        LOG.debug('Duration of get_host_time %s', finish - start)
        self.assertTrue(abs(vm_time - host_time) - (finish - start) < MAXIMUM_DELAY)
        self.servers_client.delete_server(self.instance['id'])