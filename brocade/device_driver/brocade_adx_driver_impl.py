# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 Brocade Communication Systems, Inc.  All rights reserved.
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
#
# @author: Pattabi Ayyasami, Brocade Communications Systems,Inc.
#

import suds as suds

from neutron.common import log
from neutron.openstack.common import log as logging
from neutron.services.loadbalancer import constants
from neutron.services.loadbalancer.drivers.brocade.device_driver import (
    brocade_adx_exceptions as adx_exception,
    brocade_adx_service as adx_service
)

LOG = logging.getLogger(__name__)

ADX_STANDARD_PORTS = [21, 22, 23, 25, 53, 69, 80, 109, 110, 119, 123, 143, 161,
                      389, 443, 554, 636, 993, 995, 1645, 1755, 1812,
                      3389, 5060, 5061, 7070]

ADX_PREDICTOR_MAP = {
    constants.LB_METHOD_ROUND_ROBIN: 'ROUND_ROBIN',
    constants.LB_METHOD_LEAST_CONNECTIONS: 'LEAST_CONN'
}

ADX_PROTOCOL_MAP = {
    constants.PROTOCOL_TCP: 'TCP',
    constants.PROTOCOL_HTTP: 'HTTP',
    constants.PROTOCOL_HTTPS: 'SSL'
}


class BrocadeAdxDeviceDriverImpl():
    def __init__(self, plugin, device):
        self.plugin = plugin
        service_clients = (adx_service.ClientCache
                           .get_adx_service_client(device))
        self.slb_factory = service_clients[0].factory
        self.slb_service = service_clients[0].service

        self.sys_service_client = service_clients[1]

    def _adx_server(self, address, name=None):
        server = self.slb_factory.create("Server")
        server.IP = address
        if name:
            server.Name = name
        return server

    def _adx_server_port(self, address, protocol_port, name=None):
        # Create Server
        server = self._adx_server(address, name)

        # Create L4Port
        l4_port = self.slb_factory.create('L4Port')
        l4_port.NameOrNumber = protocol_port

        # Create ServerPort
        server_port = self.slb_factory.create('ServerPort')
        server_port.srvr = server
        server_port.port = l4_port
        return server_port

    def _update_real_server_port_properties(self, new_member, old_member):
        try:
            address = new_member['address']
            protocol_port = new_member['protocol_port']
            new_admin_state_up = new_member.get('admin_state_up')
            old_admin_state_up = old_member.get('admin_state_up')

            if new_admin_state_up == old_admin_state_up:
                return

            rsServerPort = self._adx_server_port(address, protocol_port)
            reply = (self.slb_service
                     .getRealServerPortConfiguration(rsServerPort))
            rsPortConfSeq = (self.slb_factory.create
                             ('ArrayOfRealServerPortConfigurationSequence'))
            reply.rsPortConfig.serverPort = rsServerPort
            rsPortAdminState = 'ENABLED'
            if not new_admin_state_up:
                rsPortAdminState = 'DISABLED'
            reply.rsPortConfig.adminState = rsPortAdminState

            rsPortConfList = [reply.rsPortConfig]
            rsPortConfSeq.RealServerPortConfigurationSequence = rsPortConfList

            (self.slb_service
             .setRealServersPortConfiguration(rsPortConfSeq))
        except suds.WebFault as e:
            raise adx_exception.ConfigError(msg=e.message)

    def _update_real_server_properties(self, new_member, old_member):
        try:
            address = new_member['address']
            new_weight = new_member.get('weight')
            old_weight = old_member.get('weight')

            if new_weight == old_weight:
                return

            rsServer = self._adx_server(address)
            reply = (self.slb_service
                     .getRealServerConfiguration(rsServer))

            rsConfSeq = (self.slb_factory.create
                         ("ArrayOfRealServerConfigurationSequence"))
            if new_weight:
                reply.rsConfig.leastConnectionWeight = new_weight

            rsConfList = []
            rsConfList.append(reply.rsConfig)
            rsConfSeq.RealServerConfigurationSequence = rsConfList

            (self.slb_service
             .setRealServersConfiguration(rsConfSeq))
        except suds.WebFault as e:
            raise adx_exception.ConfigError(msg=e.message)

    def _get_server_port_count(self, ip_address, is_virtual):
        server = self._adx_server(ip_address)
        startIndex = 1
        numRetrieved = 5
        api_call = (self.slb_service
                    .getAllVirtualServerPortsSummary if is_virtual
                    else self.slb_service.getAllRealServerPortsSummary)
        try:
            reply = api_call(server, startIndex, numRetrieved)
            return reply.genericInfo.totalEntriesAvailable
        except suds.WebFault:
            return 0

    def bind_member_to_vip(self, member, vip):
        rsIpAddress = member['address']
        rsName = rsIpAddress
        if member.get('name'):
            rsName = member['name']
        rsPort = member['protocol_port']

        vsIpAddress = vip['vip_address']
        vsPort = vip['protocol_port']
        vsName = vip['name']
        if vsName is None or vsName == '':
            vsName = vsIpAddress

        try:
            vsServerPort = self._adx_server_port(vsIpAddress, vsPort, vsName)
            rsServerPort = self._adx_server_port(rsIpAddress, rsPort, rsName)

            (self.slb_service
             .bindRealServerPortToVipPort(vsServerPort, rsServerPort))
        except suds.WebFault as e:
            raise adx_exception.ConfigError(msg=e.message)

    def unbind_member_from_vip(self, member, vip):
        rsIpAddress = member['address']
        rsName = rsIpAddress
        if member.get('name'):
            rsName = member['name']
        rsPort = member['protocol_port']

        vsIpAddress = vip['vip_address']
        vsPort = vip['protocol_port']
        vsName = vip['name']
        if vsName is None or vsName == '':
            vsName = vsIpAddress

        try:
            vsServerPort = self._adx_server_port(vsIpAddress, vsPort, vsName)
            rsServerPort = self._adx_server_port(rsIpAddress, rsPort, rsName)

            (self.slb_service
             .unbindRealServerPortFromVipPort(vsServerPort, rsServerPort))
        except suds.WebFault as e:
            raise adx_exception.ConfigError(msg=e.message)

    def bind_monitor_to_member(self, healthmonitor, member):
        healthmonitor_name = healthmonitor['id']
        rsIpAddress = member['address']
        rsName = rsIpAddress
        if member.get('name'):
            rsName = member['name']
        rsPort = member['protocol_port']
        rsAdminState = 'ENABLED' if member['admin_state_up'] else 'DISABLED'
        rsRunTimeStatus = 'UNDEFINED'

        try:
            rsServerPort = self._adx_server_port(rsIpAddress, rsPort, rsName)

            realServerPortConfig = (self.slb_factory
                                    .create('RealServerPortConfiguration'))
            realServerPortConfig.serverPort = rsServerPort
            realServerPortConfig.adminState = rsAdminState
            realServerPortConfig.runTimeStatus = rsRunTimeStatus
            realServerPortConfig.portPolicyName = healthmonitor_name
            realServerPortConfig.enablePeriodicHealthCheck = True

            rsPortSeq = (self.slb_factory
                         .create('ArrayOfRealServerPortConfigurationSequence'))
            (rsPortSeq.RealServerPortConfigurationSequence
             .append(realServerPortConfig))
            self.slb_service.setRealServersPortConfiguration(rsPortSeq)
        except suds.WebFault as e:
            raise adx_exception.ConfigError(msg=e.message)

    def unbind_monitor_from_member(self, healthmonitor, member):

        rsIpAddress = member['address']
        rsName = rsIpAddress
        if member.get('name'):
            rsName = member['name']
        rsPort = member['protocol_port']
        rsAdminState = 'ENABLED' if member['admin_state_up'] else 'DISABLED'
        rsRunTimeStatus = 'UNDEFINED'

        try:
            rsServerPort = self._adx_server_port(rsIpAddress, rsPort, rsName)

            realServerPortConfig = (self.slb_factory
                                    .create('RealServerPortConfiguration'))
            realServerPortConfig.serverPort = rsServerPort
            realServerPortConfig.adminState = rsAdminState
            realServerPortConfig.runTimeStatus = rsRunTimeStatus
            realServerPortConfig.portPolicyName = ''
            realServerPortConfig.enablePeriodicHealthCheck = False

            rsPortSeq = (self.slb_factory
                         .create('ArrayOfRealServerPortConfigurationSequence'))
            (rsPortSeq.RealServerPortConfigurationSequence
             .append(realServerPortConfig))
            self.slb_service.setRealServersPortConfiguration(rsPortSeq)
        except suds.WebFault as e:
            raise adx_exception.ConfigError(msg=e.message)

    @log.log
    def set_predictor_on_virtual_server(self, vip, lb_algorithm):
        vsIpAddress = vip.get('vip_address')
        vsName = vip.get('name')
        if vsName is None or vsName == '':
            vsName = vsIpAddress
        try:
            server = self._adx_server(vsIpAddress, vsName)
            predictorMethodConfiguration = (self.slb_factory.create
                                            ('PredictorMethodConfiguration'))
            predictor = ADX_PREDICTOR_MAP.get(lb_algorithm)
            if predictor:
                predictorMethodConfiguration.predictor = predictor
            else:
                error_message = (_('Specified LB Algorithm/Predictor %s '
                                   'not supported')) % (lb_algorithm)
                LOG.error(error_message)
                raise adx_exception.UnsupportedFeature(msg=error_message)

            (self.slb_service
             .setPredictorOnVirtualServer(server,
                                          predictorMethodConfiguration))
        except suds.WebFault as e:
            raise adx_exception.ConfigError(msg=e.message)

    @log.log
    def create_virtual_server(self, vip):
        vsIpAddress = vip.get('vip_address')
        vsName = vip.get('name')
        if vsName is None or vsName == '':
            vsName = vsIpAddress
        description = vip.get('description', '')
        vsAdminState = vip.get('admin_state_up', True)

        server = self._adx_server(vsIpAddress, vsName)

        try:
            vsSeq = (self.slb_factory
                     .create('ArrayOfVirtualServerConfigurationSequence'))
            vsConfig = (self.slb_factory
                        .create('VirtualServerConfiguration'))

            vsConfig.virtualServer = server
            vsConfig.adminState = vsAdminState
            vsConfig.description = description

            # Work Around to define a value for Enumeration Type
            vsConfig.predictor = 'ROUND_ROBIN'
            vsConfig.trackingMode = 'NONE'
            vsConfig.haMode = 'NOT_CONFIGURED'

            (vsSeq.VirtualServerConfigurationSequence
             .append(vsConfig))
            (self.slb_service.
             createVirtualServerWithConfiguration(vsSeq))
        except suds.WebFault as e:
            LOG.error(_("Exception in create_virtual_server "
                        "in device driver : %s"), e.message)
            raise adx_exception.ConfigError(msg=e.message)

    @log.log
    def update_virtual_server(self, new_vip, old_vip):
        address = new_vip.get('vip_address')
        name = new_vip.get('name')
        if name is None or name == '':
            name = address
        server = self._adx_server(address, name)
        try:
            pass
        except suds.WebFault as e:
            raise adx_exception.ConfigError(msg=e.message)

    @log.log
    def delete_virtual_server(self, vip):
        address = vip.get('vip_address')
        server = self._adx_server(address)
        vipPortCount = self._get_server_port_count(address, True)

        try:
            if vipPortCount <= 2:
                self.slb_service.deleteVirtualServer(server)
        except suds.WebFault as e:
            raise adx_exception.ConfigError(msg=e.message)

    @log.log
    def create_virtual_server_port(self, vip_port):
        load_balancer = vip_port['loadbalancer']
        vsIpAddress = load_balancer.vip_address
        vsPort = vip_port['protocol_port']
        admin_state_up = vip_port.get('admin_state_up', True)

        try:
            serverPort = self._adx_server_port(vsIpAddress, vsPort)
            vsPortSeq = (self.slb_factory.create
                         ('ArrayOfVirtualServerPortConfigurationSequence'))
            vsPortConfig = (self.slb_factory
                            .create('VirtualServerPortConfiguration'))

            vsPortConfig.virtualServer = serverPort.srvr
            vsPortConfig.port = serverPort.port
            vsPortAdminState = 'ENABLED' if admin_state_up else 'DISABLED'
            vsPortConfig.adminState = vsPortAdminState

            (vsPortSeq.VirtualServerPortConfigurationSequence
             .append(vsPortConfig))
            (self.slb_service
             .createVirtualServerPortWithConfiguration(vsPortSeq))
        except suds.WebFault as e:
            raise adx_exception.ConfigError(msg=e.message)

    @log.log
    def update_virtual_server_port(self, new_vip_port, old_vip_port):
        load_balancer = new_vip_port['loadbalancer']
        vsIpAddress = load_balancer.vip_address
        vsPort = new_vip_port['protocol_port']

        old_admin_state_up = old_vip_port['admin_state_up']
        new_admin_state_up = new_vip_port['admin_state_up']

        try:
            serverPort = self._adx_server_port(vsIpAddress, vsPort)
            if new_admin_state_up != old_admin_state_up:
                if new_admin_state_up:
                    (self.slb_service
                     .enableVirtualServerPort(serverPort))
                else:
                    (self.slb_service
                     .disableVirtualServerPort(serverPort))
        except suds.WebFault as e:
            raise adx_exception.ConfigError(msg=e.message)

    @log.log
    def delete_virtual_server_port(self, vip_port):
        load_balancer = vip_port['loadbalancer']
        vsIpAddress = load_balancer.vip_address
        vsPort = vip_port['protocol_port']
        vsServerPort = self._adx_server_port(vsIpAddress, vsPort)
        try:
            self.slb_service.deleteVirtualServerPort(vsServerPort)
        except suds.WebFault:
            pass

    def _is_port_policy_in_use(self, healthmonitor_name):
        startIndex = 1
        numRetrieved = 15
        portPolicySummaryFilter = (self.slb_factory
                                   .create('PortPolicySummaryFilter'))
        simpleFilter = (self.slb_factory
                        .create('PortPolicySummarySimpleFilter'))
        simpleFilter.field = 'POLICY_NAME'
        simpleFilter.operator = 'EQUAL_TO'
        simpleFilter.value = healthmonitor_name

        portPolicySummaryFilter.simpleFilter = simpleFilter

        try:
            reply = (self.slb_service
                     .getAllPortPolicies(startIndex,
                                         numRetrieved,
                                         portPolicySummaryFilter))
            if reply and reply.policyList:
                policyList = reply.policyList.PortPoliciesSummarySequence
                return any(policy.inUse for policy in policyList)
            else:
                # Check if Port Policy is bound to a Real Server Port
                #inUse = reply.policy.inUse
                return False
        except suds.WebFault:
            return False

    def _does_port_policy_exist(self, healthmonitor):
        name = healthmonitor['id']
        try:
            reply = self.slb_service.getPortPolicy(name)
            if reply:
                return True
        except suds.WebFault:
            return False
        return False

    @log.log
    def _validate_delay(self, monitor_type, delay):
        if monitor_type == constants.HEALTH_MONITOR_HTTP:
            if delay < 1 or delay > 120:
                raise adx_exception.UnsupportedOption(value=delay,
                                                      name="delay")
        elif monitor_type == constants.HEALTH_MONITOR_HTTPS:
            if delay < 5 or delay > 120:
                raise adx_exception.UnsupportedOption(value=delay,
                                                      name="delay")

    @log.log
    def _validate_max_retries(self, max_retries):
        if max_retries < 1 or max_retries > 5:
            raise adx_exception.UnsupportedOption(value=max_retries,
                                                  name="max_retries")

    @log.log
    def _create_update_port_policy(self, healthmonitor, is_create=True):

        name = healthmonitor['id']
        monitor_type = healthmonitor['type']
        delay = healthmonitor['delay']
        self._validate_delay(monitor_type, delay)
        max_retries = healthmonitor['max_retries']
        self._validate_max_retries(max_retries)

        if monitor_type in [constants.HEALTH_MONITOR_HTTP,
                            constants.HEALTH_MONITOR_HTTPS,
                            constants.HEALTH_MONITOR_TCP]:
            portPolicy = self.slb_factory.create('PortPolicy')
            l4Port = self.slb_factory.create('L4Port')

            if monitor_type == constants.HEALTH_MONITOR_HTTP:
                portPolicy.name = name
                l4Port.NameOrNumber = (ADX_PROTOCOL_MAP
                                       .get(constants.PROTOCOL_HTTP))
                portPolicy.port = l4Port
                portPolicy.protocol = (ADX_PROTOCOL_MAP
                                       .get(constants.PROTOCOL_HTTP))
                portPolicy.l4Check = False
            elif monitor_type == constants.HEALTH_MONITOR_HTTPS:
                portPolicy.name = name
                l4Port.NameOrNumber = (ADX_PROTOCOL_MAP
                                       .get(constants.PROTOCOL_HTTPS))
                portPolicy.port = l4Port
                portPolicy.protocol = (ADX_PROTOCOL_MAP
                                       .get(constants.PROTOCOL_HTTPS))
                portPolicy.l4Check = False
            elif monitor_type == constants.HEALTH_MONITOR_TCP:
                # TCP Monitor
                portPolicy.name = name
                portPolicy.l4Check = True

                # Setting Protocol and Port to HTTP
                # so that this can be bound to a Real Server Port
                l4Port.NameOrNumber = (ADX_PROTOCOL_MAP
                                       .get(constants.PROTOCOL_HTTP))
                portPolicy.port = l4Port
                portPolicy.protocol = (ADX_PROTOCOL_MAP
                                       .get(constants.PROTOCOL_HTTP))

            portPolicy.keepAliveInterval = delay
            portPolicy.numRetries = max_retries

            http_method = 'GET'
            url_path = '/'
            expected_codes = '200'
            if 'http_method' in healthmonitor:
                http_method = healthmonitor['http_method']
            if 'url_path' in healthmonitor:
                url_path = healthmonitor['url_path']

            start_status_codes = []
            end_status_codes = []
            if 'expected_codes' in healthmonitor:
                expected_codes = healthmonitor['expected_codes']
                # parse the expected codes.
                # Format:"200, 201, 300-400, 400-410"
                for code in map(lambda x: x.strip(' '),
                                expected_codes.split(',')):
                    if '-' in code:
                        codeRange = map(lambda x: x.strip(' '),
                                        code.split('-'))
                        start_status_codes.append(int(codeRange[0]))
                        end_status_codes.append(int(codeRange[1]))
                    else:
                        start_status_codes.append(int(code))
                        end_status_codes.append(int(code))

            if monitor_type == constants.HEALTH_MONITOR_HTTP:
                httpPortPolicy = (self.slb_factory
                                  .create('HttpPortPolicy'))
                urlHealthCheck = (self.slb_factory
                                  .create('URLHealthCheck'))
                startCodes = (self.slb_factory
                              .create('ArrayOfunsignedIntSequence'))
                endCodes = (self.slb_factory
                            .create('ArrayOfunsignedIntSequence'))

                startCodes.unsignedIntSequence = start_status_codes
                endCodes.unsignedIntSequence = end_status_codes
                urlHealthCheck.url = http_method + ' ' + url_path
                urlHealthCheck.statusCodeRangeStart = startCodes
                urlHealthCheck.statusCodeRangeEnd = endCodes
                httpPortPolicy.urlStatusCodeInfo = urlHealthCheck
                httpPortPolicy.healthCheckType = 'SIMPLE'

                portPolicy.httpPolInfo = httpPortPolicy

            elif monitor_type == constants.HEALTH_MONITOR_TCP:
                httpPortPolicy = (self.slb_factory
                                  .create('HttpPortPolicy'))
                urlHealthCheck = (self.slb_factory
                                  .create('URLHealthCheck'))
                urlHealthCheck.url = 'HEAD /'
                httpPortPolicy.urlStatusCodeInfo = urlHealthCheck
                httpPortPolicy.healthCheckType = 'SIMPLE'

                portPolicy.httpPolInfo = httpPortPolicy

            elif monitor_type == constants.HEALTH_MONITOR_HTTPS:
                sslPortPolicy = (self.slb_factory
                                 .create('HttpPortPolicy'))
                urlHealthCheck = (self.slb_factory
                                  .create('URLHealthCheck'))
                startCodes = (self.slb_factory
                              .create('ArrayOfunsignedIntSequence'))
                endCodes = (self.slb_factory
                            .create('ArrayOfunsignedIntSequence'))

                urlHealthCheck.url = http_method + ' ' + url_path
                urlHealthCheck.statusCodeRangeStart = startCodes
                urlHealthCheck.statusCodeRangeEnd = endCodes

                sslPortPolicy.urlStatusCodeInfo = urlHealthCheck
                sslPortPolicy.healthCheckType = 'SIMPLE'

                portPolicy.sslPolInfo = sslPortPolicy

            try:
                if is_create:
                    self.slb_service.createPortPolicy(portPolicy)
                else:
                    self.slb_service.updatePortPolicy(portPolicy)
            except suds.WebFault as e:
                LOG.error(_('Error in create/update port policy %s'), e)
                raise adx_exception.ConfigError(msg=e.message)

    @log.log
    def create_healthmonitor(self, healthmonitor):

        name = healthmonitor['id']
        monitor_type = healthmonitor['type']

        # Create Port Policy
        # if the Monitor Type is TCP / HTTP / HTTPS
        if monitor_type in [constants.HEALTH_MONITOR_HTTP,
                            constants.HEALTH_MONITOR_HTTPS,
                            constants.HEALTH_MONITOR_TCP]:
            if not self._does_port_policy_exist(healthmonitor):
                self._create_update_port_policy(healthmonitor)
            else:
                LOG.debug(_('Port Policy %s already exists on the device'),
                          name)
        elif monitor_type == constants.HEALTH_MONITOR_PING:
            m = _('Health Monitor of type PING not supported')
            LOG.error(m)
            raise adx_exception.UnsupportedFeature(msg=m)

    @log.log
    def delete_healthmonitor(self, healthmonitor):
        name = healthmonitor['id']
        monitor_type = healthmonitor['type']

        if monitor_type in [constants.HEALTH_MONITOR_HTTP,
                            constants.HEALTH_MONITOR_HTTPS,
                            constants.HEALTH_MONITOR_TCP]:
            if not self._does_port_policy_exist(healthmonitor):
                LOG.debug(_('Health Monitor %s does not '
                          'exist on the device'), name)
                return

            if not self._is_port_policy_in_use(name):
                try:
                    (self.slb_service
                     .deletePortPolicy(name))
                except suds.WebFault as e:
                    raise adx_exception.ConfigError(msg=e.message)
        elif monitor_type == constants.HEALTH_MONITOR_PING:
            m = _('Health Monitor of type PING not supported')
            LOG.error(m)
            raise adx_exception.UnsupportedFeature(msg=m)

    @log.log
    def update_healthmonitor(self, new_hm, old_hm):
        monitor_type = new_hm['type']

        # Create Port Policy
        # if the Monitor Type is TCP / HTTP / HTTPS
        if monitor_type in [constants.HEALTH_MONITOR_HTTP,
                            constants.HEALTH_MONITOR_HTTPS,
                            constants.HEALTH_MONITOR_TCP]:
            self._create_update_port_policy(new_hm, False)
        elif monitor_type == constants.HEALTH_MONITOR_PING:
            m = _('Health Monitor of type PING not supported')
            LOG.error(m)
            raise adx_exception.UnsupportedFeature(msg=m)

    def _create_real_server(self, member):
        address = member['address']
        weight = member['weight']
        name = address
        if member.get('name'):
            name = member['name']
        is_remote = member.get('is_remote', False)

        try:
            rs = self._adx_server(address, name)
            rsConfigSequence = (self.slb_factory.create
                                ('ArrayOfRealServerConfigurationSequence'))
            rsConfig = (self.slb_factory
                        .create('RealServerConfiguration'))

            rsConfig.realServer = rs
            rsConfig.isRemoteServer = is_remote
            rsConfig.adminState = 'ENABLED'
            rsConfig.leastConnectionWeight = weight
            rsConfig.hcTrackingMode = 'NONE'

            rsConfigSequence.RealServerConfigurationSequence.append(rsConfig)
            (self.slb_service
             .createRealServerWithConfiguration(rsConfigSequence))
        except suds.WebFault as e:
            LOG.debug(_('Error in creating Real Server %s'), e)
            pass

    def _create_real_server_port(self, member):
        address = member['address']
        port = member['protocol_port']
        admin_state_up = member['admin_state_up']
        name = address
        if member.get('name'):
            name = member['name']
        is_backup = member.get('is_backup', False)

        try:
            # Create Port Profile if it is not a standard port
            if port not in ADX_STANDARD_PORTS:
                port_profile = dict()
                port_profile['protocol_port'] = port
                self._create_port_profile(port_profile)

            rsServerPort = self._adx_server_port(address, port, name)
            rsPortSeq = (self.slb_factory
                         .create('ArrayOfRealServerPortConfigurationSequence'))
            rsPortConfig = (self.slb_factory
                            .create('RealServerPortConfiguration'))

            rsPortConfig.serverPort = rsServerPort
            rsAdminState = 'ENABLED' if admin_state_up else 'DISABLED'
            rsPortConfig.adminState = rsAdminState
            if 'max_connections' in member:
                rsPortConfig.maxConnection = member['max_connections']
            rsPortConfig.isBackup = is_backup

            # Work Around to define a value for Enumeration Type
            rsPortConfig.runTimeStatus = 'UNDEFINED'

            (rsPortSeq.RealServerPortConfigurationSequence
             .append(rsPortConfig))

            self.slb_service.createRealServerPortWithConfiguration(rsPortSeq)
        except suds.WebFault as e:
            raise adx_exception.ConfigError(msg=e.message)

    @log.log
    def create_member(self, member):
        # Create Real Server
        self._create_real_server(member)

        # Create Real Server Port
        self._create_real_server_port(member)

    @log.log
    def delete_member(self, member):
        rsPortCount = self._get_server_port_count(member['address'], False)
        try:
            rsServerPort = self._adx_server_port(member['address'],
                                                 member['protocol_port'])
            self.slb_service.deleteRealServerPort(rsServerPort)

            # Delete the Real Server
            # if this is the only port other than default port
            if rsPortCount <= 2:
                self.slb_service.deleteRealServer(rsServerPort.srvr)
        except suds.WebFault as e:
            raise adx_exception.ConfigError(msg=e.message)

    @log.log
    def update_member(self, new_member, old_member):

        self._update_real_server_properties(new_member, old_member)
        self._update_real_server_port_properties(new_member, old_member)

    @log.log
    def write_mem(self):
        try:
            self.sys_service_client.service.writeConfig()
        except Exception as e:
            raise adx_exception.ConfigError(msg=e.message)

    @log.log
    def create_pool(self, pool):
        pool_name = pool['name']

        try:
            serverGroupList = (self.slb_factory.create
                               ('ArrayOfRealServerGroupSequence'))
            realServerGroup = (self.slb_factory
                               .create('RealServerGroup'))
            realServerGroup.groupName = pool_name
            serverGroupList.RealServerGroupSequence.append(realServerGroup)

            (self.slb_service
             .createRealServerGroups(serverGroupList))
        except suds.WebFault:
            pass

    @log.log
    def update_pool(self, new_pool, old_pool):
        pass

    @log.log
    def delete_pool(self, pool):
        pool_name = pool['name']
        try:
            serverGroupList = (self.slb_factory
                               .create('ArrayOfStringSequence'))
            serverGroupList.StringSequence.append(pool_name)

            (self.slb_service
             .deleteRealServerGroups(serverGroupList))
        except suds.WebFault as e:
            raise adx_exception.ConfigError(msg=e.message)

    @log.log
    def stats(self, vip):
        bytes_in = 0
        bytes_out = 0
        active_connections = 0
        total_connections = 0

        virtualServerSummaryFilter = (self.slb_factory
                                   .create('VirtualServerSummaryFilter'))
        simpleFilter = (self.slb_factory
                        .create('VirtualServerSummarySimpleFilter'))
        simpleFilter.field = 'SERVER_IP'
        simpleFilter.operator = 'EQUAL_TO'
        simpleFilter.value = vip.get('vip_address')

        virtualServerSummaryFilter.simpleFilter = simpleFilter
        #vsIpAddress = vip.get('vip_address')
        #vsName = vip.get('name')
        #if vsName is None or vsName == '':
        #    vsName = vsIpAddress
        try:
            #server = self._adx_server(vsIpAddress, vsName)
            reply = (self.slb_service
                     .getAllVirtualServerSummary(1, 15,
                     virtualServerSummaryFilter))
            vsList = reply.virtualServerSummary.VirtualServerSummarySequence
            for vs in vsList:
                bytes_in = vs.rxBytes
                bytes_out = vs.txBytes
                active_connections = vs.currentConnections
                total_connections = vs.totalConn
        except suds.WebFault:
            pass
        except Exception as e:
            LOG.debug(_('Exception %s'), e)

        return {constants.STATS_IN_BYTES: bytes_in,
                constants.STATS_OUT_BYTES: bytes_out,
                constants.STATS_ACTIVE_CONNECTIONS: active_connections,
                constants.STATS_TOTAL_CONNECTIONS: total_connections}

    @log.log
    def _create_port_profile(self, port_profile):
        protocol_port = port_profile['protocol_port']
        try:
            portProfile = self.slb_factory.create('PortProfile')
            l4Port = self.slb_factory.create('L4Port')
            l4Port.NameOrNumber = protocol_port
            portProfile.port = l4Port
            portProfile.portType = 'TCP'
            portProfile.status = True

            self.slb_service.createPortProfile(portProfile)
        except suds.WebFault as e:
            # Ignore exception.
            # May be port profile already exists for the given port
            LOG.debug(_('Exception in create port profile %s'), e)

    @log.log
    def _delete_port_profile(self, port_profile):
        protocol_port = port_profile['protocol_port']
        try:
            l4Port = self.slb_factory.create('L4Port')
            l4Port.NameOrNumber = protocol_port
            self.slb_service.deletePortProfile(l4Port)
        except suds.WebFault as e:
            LOG.debug(_('Exception in Delete Port Profile %s'), e)
            raise adx_exception.ConfigError(msg=e.message)
