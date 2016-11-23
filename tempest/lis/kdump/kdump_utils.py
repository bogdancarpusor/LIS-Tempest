from tempest import config
from oslo_log import log as logging
from tempest.lib import exceptions as lib_exc

CONF = config.CONF

LOG = logging.getLogger(__name__)


def config_rhel(linux_client, crashkernel_size, kdump_conf, dump_path):
    LOG.info("Configuring RHEL")
    linux_client.exec_command("sed -i '/^path/ s/path/#path/g' %s" % kdump_conf)
    linux_client.exec_command("echo path %s >> %s" % (dump_path, kdump_conf))
    LOG.info("Updated the path to %s" % dump_path)
    linux_client.exec_command("sed -i '/^default/ s/default/#default/g' %s" % kdump_conf)
    linux_client.exec_command("echo 'default reboot' >> %s" % kdump_conf)
    LOG.info("Updated default behaviour to reboot")

    if linux_client.check_folder_existence('/boot/grub2') == 0:
        if linux_client.exec_command("grep -iq 'crashkernel=' /etc/default/grub"):
            linux_client.exec_command(
                "sed -i 's/crashkernel=\S*/crashkernel=%s/g' /etc/default/grub" % crashkernel_size)
        else:
            cmd = 'sed -i "s/^GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX=\\"crashkernel=%s /g" /etc/default/grub' % crashkernel_size
            linux_client.exec_command(cmd)
        LOG.info("Successfully updated crashkernel value in /etc/default/grub")
    elif linux_client.check_executable_file('/sbin/grubby') == 0:
        if linux_client.exec_command('grep -iq "crashkernel=" /boot/grub/grub.conf'):
            cmd = 'sed -i "s/crashkernel=\S*/crashkernel=%s/g" /boot/grub/grub.conf' % crashkernel_size
            linux_client.exec_command(cmd)
        else:
            cmd = 'sed -i "s/rootdelay=300/rootdelay=300 crashkernel=%s/g" /boot/grub/grub.conf' % crashkernel_size
            linux_client.exec_command(cmd)
        LOG.info("Successfully updated crashkernel value to: %s" % crashkernel_size)

    linux_client.exec_command('chkconfig kdump on --level 35')
    LOG.info("Kdump enabled")


def config_sles(linux_client, crashkernel_size):
    LOG.info("Configuring SLES")
    if linux_client.check_folder_existence('/boot/grub2'):
        try:
            linux_client.exec_command("grep -iq 'crashkernel=' /etc/default/grub")
            linux_client.exec_command(
                "sed -i 's/crashkernel-218M-:109M/crashkernel=%s/g' /etc/default/grub" % crashkernel_size
            )
        except lib_exc.SSHExecCommandFailed as exc:
            linux_client.exec_command(
                'sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=\\"/GRUB_CMDLINE_LINUX_DEFAULT=\\"crashkernel=%s /g" /etc/default/grub' % crashkernel_size
            )
        linux_client.exec_command("grep -iq 'crashkernel=%s' /etc/default/grub" % crashkernel_size)
        linux_client.exec_command("grub2-mkconfig -o /boot/grub2/grub.cfg")
    elif linux_client.check_folder_existence('/boot/grub'):
        try:
            linux_client.exec_command('grep -iq "crashkernel=" /boot/grub/menu.lst')
            linux_client.exec_command('sed -i "s/crashkernel=218M:-109M/crashkernel=%s/g" /boot/grub/menu.lst' % crashkernel_size)
        except lib_exc.SSHExecCommandFailed as exc:
            linux_client.exec_command('sed -i "s/rootdelay=300/rootdelay=300 crashkernel=%s/g" /boot/grub/menu.lst' % crashkernel_size)
        linux_client.exec_command('grep -iq "crashkernel=%s" /boot/grub/menu.lst' % crashkernel_size)

    try:
        linux_client.exec_command("chckconfig boot.kdump on")
    except lib_exc.SSHExecCommandFailed as exc:
        linux_client.exec_command("systemctl enable kdump.service")


def config_ubuntu(linux_client, crashkernel_size):
    LOG.info("Configuring Kdump on Ubuntu")
    linux_client.exec_command("sed -i 's/USE_KDUMP==/USE_KDUMP=1/g' /etc/default/kdump-tools")
    try:
        linux_client.exec_command("sed -i 's/crashkernel=\S*/crashkernel=%s/g' boot/grub/grub.cfg" % crashkernel_size)
        LOG.info("Updated crashkernel to %s" % crashkernel_size)
    except lib_exc.SSHExecCommandFailed as exc:
        LOG.warning("Could not set new crashkernel value")
        cmd = 'sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=\\"/GRUB_CMDLINE_LINUX_DEFAULT=\\"crashkernel=%s /g" /etc/default/grub' % crashkernel_sizel
        linux_client.exec_command(cmd)
        linux_client.exec_command("update grub")
        LOG.infO("Successfully update crashkernel value to %s" % crashkernel_size)
    linux_client.exec_command("sed -i 's/LOAD_KEXEC=true/LOAD_KEXEC=false/g' /etc/default/kexec")
