#!/usr/bin/python
#coding: utf-8 -*-

#
# (c) 2015, Patrick Galbraith <patg@patg.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Note: this code is currently under development and is full of debug code that
# writes to a text file in /tmp.
# This debug will be removed soon
#

import re
import pprint

from switchssh_procom import SwitchSSHProCom
import os
from collections import OrderedDict

pp = pprint.PrettyPrinter(indent=4)

cmd_write = "write memory\n"
cmd_quit = "quit\n"
cmd_yes = "Y\n"
cmd_no = "N\n"
cmd_disable_paging = "no page\n"
cmd_disable_interactive_mode = "session interactive-mode disable\n"
cmd_save = "write memory\n"
cmd_system_view = "enable\n"
cmd_configure_view = "configure\n"
cmd_running_config = "show run\n"
cmd_startup_config = "show config\n"
cmd_reboot = "reload\n"
cmd_exit = "exit\n"
cmd_display_vlan_all = "show vlans\n"
cmd_interfaces = "show interface brief\n"

verify_save_current_conf = \
    'Current configuration will be lost, save current configuration'
verify_filename = 'Please input the file name'
verify_filename_unchanged = 'To leave existing filename unchanged'
verify_config_file_saved = 'Configuration is saved to device successfully'
verify_reboot = 'This command will reboot the device'

read_stop = 'tty=none'
read_stop_regex = 'tty=\w+'
top_level_prompt = ">"
sys_prompt = '#'

log = open('/tmp/switch.log', 'wb')

class ProVision(object):
    def __init__(self,
                 module,
                 host,
                 username,
                 password,
                 timeout,
                 port=22,
                 private_key_file=None):
        self.module = module
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.private_key_file = private_key_file
        self.timeout = timeout
        self._failed = False
        self._changed = False
        self._message = ""
        self._paging = False
        self._interactive_mode = True

        # three levels
        self._operator_level = False
        self._manager_level = False
        self._config_level = False

        self.sw = SwitchSSHProCom(self.host,
                                  username=self.username,
                                  password=self.password,
                                  read_end="tty=none",
                                  dismiss_banner=True)

        # base operator level
        self._operator_level = True

	# dismiss banner, if there
        log.write("logged in\n")
        log.flush()
        self.dev_setup()

    def get_failed(self):
        return self._failed

    def get_changed(self):
        return self._changed

    def get_message(self):
        return self._message

    def set_failed(self, state):
        self._failed = state

    def set_changed(self, state):
        self._changed = state

    def set_message(self, message):
        self._message = message

    def append_message(self, message):
        self._message += message

    def fail(self, message=''):
        self.set_failed(True)
        self.set_message(message)
        self.module.fail_json(msg=self.get_message())

    def save(self):
        output = self.sw.exec_command(cmd_write, "ERROR: unable to write config")
        log.write("saving - output: %s\n" % output)

    def quit(self):
        self.sw.exec_command(cmd_quit, "ERROR: unable to quit level")

    def exit(self):
        self.sw.exec_command(cmd_exit, "ERROR: unable to exit")

    def _is_conseq(self, llist):
        listlen = len(llist)
        i = 1
        count = 0
        while i < listlen :
            count += (int(llist[i]) - int(llist[i-1]))
            i += 1

        log.write("count %d listlen-1 %d\n" % (count, listlen-1))
        log.write("compare %s\n" % (count == listlen-1))
        log.flush()
        return count == listlen-1

    def _single_conseq_to_range(self, num_string):
        # this is because a regex from caller will allow a-b,c-d,x-y...
        # no need to determine if it's a range if it isn't a comma-sep list
        if not re.match('^[\d\,]+$', num_string):
            return num_string
        llist = map(int, num_string.split(','))
        llist.sort()
        log.write("%s\n" % pp.pformat(llist))
        log.flush()
        if self._is_conseq(llist):
            return "%d-%d" % (min(llist), max(llist))

        return num_string

    def _cleanup_port_listing(self, port_string):
        log.write("_cleanup_port_listing()")
        log.write("port_string %s\n" % port_string)
        log.flush()
        range_string = port_string
        m = re.search('^([\d\,]{2,})$', port_string)
        if m:
            if m.group(1):
                log.write("first match\n")
                log.write("m.group(1) %s\n" % m.group(1))
                range_string = self._single_conseq_to_range(m.group(1))
                log.write("case 1 - range_string %s\n" % range_string)
                log.flush()
                return range_string

        # if pattern is something like 1,2,3,4,10-15
        m = re.search('([\d\,]{2,}),(\d+\-\d+)', port_string)
        if m:
            log.write("second match\n")
            log.write("group(1) %s group(2) %s\n" % (m.group(1), m.group(2)))
            if m.group(1) and m.group(2):
                log.write("m.group(1) %s\n" % m.group(1))
                log.flush()
                range_string = self._single_conseq_to_range(m.group(1))
                range_string += ",%s" % m.group(2)
                log.write("case 2 - range_string %s\n" % range_string)
                log.flush()
            return range_string

        # if pattern is something like 1-4,10,11,12,13,14,15
        # or even will allow a-b,c-d,x-y
        m = re.search('(\d+\-\d+)\,([\d,^-]{2,})', port_string)
        if m:
            log.write("third match\n")
            if m.group(2):
                log.write("m.group(2) %s\n" % m.group(2))
                range_string = self._single_conseq_to_range(m.group(2))
            range_string = m.group(1) + "," + range_string
            log.write("range_string %s\n" % range_string)
            log.flush()

        return range_string


    # this method enters the global config level
    def _enter_config_level(self):
        prompt = self._get_prompt()
        log.write("start enter_config_level prompt |%s|\n" % prompt)
        if not self._config_level:
            self.sw.exec_command(cmd_configure_view, "ERROR: unable to run configure")
            self._config_level = True
            self._manager_level = False
            self._operator_level = False
        log.write("return enter_config_level\n")


    def disable_interactive_mode(self):
        self.sw.send_command(cmd_disable_interactive_mode,
                "ERROR: unable to disable interactive mode")
        self._interactive_mode = False


    def _get_interfaces(self):
        interface_list = self.sw.exec_command(cmd_interfaces,
                                            "ERROR: unable to get interfaces output")
        interfaces = {}
        for line in interface_list:
            if re.match('^\s\s\d', line):
                # the columns:
                #            | Intrusion                 MDI  Flow Bcast
                # Port  Type | Alert Enabled Status Mode Mode Ctrl Limit',
                ilist = line.split()
                idict = {}
                if (len(ilist) == 10):
                        idict = { 'type': ilist[1],
                                  'intrustion_alert': ilist[3],
                                  'enabled' : ilist[4],
                                  'status': ilist[5],
                                  'mode': ilist[6],
                                  'mdi_mode' : ilist[7],
                                  'flow_control': ilist[8],
                                  'bcast_limit': ilist[9] }
                else:
                        idict = { 'type': 'gbic',
                                  'intrusion_alert': ilist[2],
                                  'enabled': ilist[3],
                                  'status': ilist[4],
                                  'mode': 'unknown',
                                  'mdi_mode': 'unknown',
                                  'flow_control': ilist[5],
                                  'bcast_limit': ilist[6] }
                interfaces[ilist[0]] = idict

        #log.write("%s" % pp.pformat(interfaces))
        return interfaces


    def _get_config(self, cmd_config):
        if cmd_config == 'show run':
            read_start = "Running configuration:"
        else:
            read_start = "Startup configuration:"

        # self.sw.send_command(cmd_config + "\n", "ERROR: unable to get switch config")
        #config_buf = self.sw.get_output(read_start, read_stop)
        config_list = self.sw.exec_command(cmd_config)
        log.write("\n_get_config cmd_config %s\n" % cmd_config)
        log.write("\n_get_config config_list:\n")
        log.write(pp.pformat(config_list))
        log.write("\n------\n")
        log.flush()
        log.write("\n_get_config config_dict:\n")
        config_dict = self._get_config_dict(config_list)
        log.write(pp.pformat(config_dict))
        log.write("\n------\n")
        return config_dict


    # get a clean dictionary representation of summary output for facts
    # this method is long and contains very specific parsing for
    # Pro Vision Switches
    def _get_config_dict(self, config_list=[]):
        config_dict = {'oobm': {},
                       'console': {},
                       'interfaces': {},
                       'vlans': {},
                       'snmp_server' : {}}

        # keep track of lines - might use for keeping track
        # of where things stop and start in the output
        line_count = 0
        vlan = ''
        oobm = False
        ipv4_list = []
        for item in config_list:
            value = ''
            key = ''
            # parse the version
            m = re.search('Created on release (.*)$', item)
            if m:
                key = 'version'
                value = m.group(1)

            # parse the hostname
            m = re.search('hostname \"(.*)\"', item)
            if m:
                key = 'hostname'
                value = m.group(1)

            m = re.search('^console ([\w\-]+) (\w+)\s?$', item)
            if m:
                config_dict['console'][m.group(1)] = m.group(2)

            m = re.search('(module \d+) (.*)$', item)
            if m:
                key = m.group(1)
                value = m.group(2)

            # parse snmp-server info
            m = re.search('^snmp-server (\w+) \"([\w\s]+)\"\s?(\w+)?$', item)
            if m:
                word1 = m.group(1)
                word2 = m.group(2)
                if m.group(3):
                    stype = m.group(3)
                    config_dict['snmp_server'][word1]= { word2: stype }
                else:
                    config_dict['snmp_server'][word1] = word2


            # yes, there happens to be a space there!
            # other outputs, no so much. No guarantee
            m = re.search('^vlan (\w+)\s?$', item)
            if m:
                ipv4_list = []
                vlan = m.group(1)
                log.write("vlan %s found\n" % vlan)
                config_dict['vlans'][vlan] = {'vlan_id': vlan}
                next
            if len(vlan):
                m = re.search('^\s+name \"(\w+)\"\s?$', item)
                if m:
                    config_dict['vlans'][vlan]['vlan_name'] = m.group(1)
                m = re.search('^\s+(\w{,2}?tagged) (.*)', item)
                if m:
                    ttype = m.group(1)
                    ports = m.group(2).replace(' ', '')
                    config_dict['vlans'][vlan][ttype] = ports

                if 'no ip address' in item:
                    ipv4_list = []
                else:
                    m = re.search('^\s+ip address ([\d\.]+) ([\d\.]+)\s?$', item)
                    if m:
                        ipv4_list.append("%s/%s" % (m.group(1), m.group(2)))

                # presense of 'exit' means that the config context level
                # for a given VLAN has ended
                if re.match('^\s+exit\s?$', item):
                    config_dict['vlans'][vlan]['ipv4'] = ipv4_list
                    vlan = ''
                    next
            # OOBM
            if re.match('^oobm\s?$', item):
                log.write("oobm found\n")
                oobm = True
                next
            if oobm:
                m = re.search('^\s+ip address (.*)\s?$', item)
                if m:
                    config_dict['oobm']['ipv4'] = m.group(1)
                if re.match('^\s+exit\s?$', item):
                    oobm = False

            if len(key):
                config_dict[key] = value
            line_count += 1

        return config_dict

    # OK, this method was very tricky. Probably endless way to do this better
    # but this works best for the varying output the switch gives you
    def _get_prompt(self):
        self.sw.send_command("\n")
        prompt = self.sw.get_output('', read_stop)
        prompt = prompt.replace("\n","")
        self._get_level(prompt)
        return prompt

    def _get_level(self, prompt):
        self._manager_level = False
        self._operator_level = False
        self._config_level = False
        log.write("checking prompt |%s|\n" % prompt)
        if re.match('^\stty.*#\s$', prompt):
            log.write("prompt is system level\n")
            self._manager_level = True
        elif re.match('^\s.*\(config\)#\s$', prompt):
            log.write("prompt is config level\n")
            self._config_level = True
        elif re.match('^.*\>\s$', prompt):
            log.write("user level\n")
            self._operator_level = True
        else:
            log.write("unknown level\n")

    # does this need to be a method with pro vision?
    def _get_vlans(self):
        vlan_buf_list = []
        vlan_id = 0
        vlan_dict = {}
        return()

    def _get_hostname(self, prompt):
        m = re.match('^\s?' + read_stop_regex + '\s(.*)\W\s$', prompt)
        if m:
            return(m.group(1))
        else:
            return 'unknown'

    def get_facts(self):
        facts = {}
        if not self.module.params.get('gather_facts'):
            return facts

        prompt = self._get_prompt()
        log.write("prompt is %s\n" % prompt)
        log.flush()
        facts['hostname'] = self._get_hostname(prompt)
        log.write("hostname %s\n" % facts['hostname'])
        facts['running'] = self._get_config(cmd_running_config)
        log.write(pp.pformat(facts))
        facts['startup_config'] = self._get_config(cmd_startup_config)
        log.write(pp.pformat(facts))
        facts['interfaces'] = self._get_interfaces()
        log.write("returning facts\n")
        log.write(pp.pformat(facts))
        log.flush()

        return facts

    #
    # this method is responsible for allowing ansible to properly
    # talk to the switch. For Pro Vision, it disables paging and
    # dismisses the login banner
    #
    def dev_setup(self):
        # dismiss banner
        self.sw.send_command(" ")

        # must do this or else output will not work for subsequent calls!
        buf = self.sw.get_output('Copyright', read_stop)
        self.sw.send_command("\n")

        # disable paging
        if not self._paging:
            self.sw.disable_paging()
        # disable verifications
        if self._interactive_mode:
            self.disable_interactive_mode()

        buf = self.sw.get_output(read_stop, read_stop)

    def reboot(self):
        prompt = self._get_prompt()

        self.sw.send_command(cmd_reboot, "ERROR: Unable to reboot")
        while True:
            read_buf = self.channel.recv(1024)
            read_buf = read_buf.replace("\r", "")
            if verify_save_current_conf in read_buf:
                if self.module.params.get('save') is True:
                    self.sw.send_command(cmd_yes)
                else:
                    self.sw.send_command(cmd_no)
                    read_buf = self.channel.recv(1024)
                    read_buf = read_buf.replace("\r", "")
            if verify_reboot in read_buf:
                self.sw.send_command(cmd_yes)
                break

        self.append_message("Please wait for the switch to resume... ")
        self.append_message("Rebooting.")
        self._changed = True
