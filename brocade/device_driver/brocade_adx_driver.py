# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 Brocade Communications Systems, Inc.  All rights reserved.
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

from neutron.common import log
from neutron.openstack.common import log as logging
from neutron.services.loadbalancer.drivers.brocade.device_driver import (
    brocade_adx_driver_impl as driver_impl,
    brocade_adx_device_inventory as device_inventory,
    brocade_adx_service as adx_service,
)

LOG = logging.getLogger(__name__)

class BrocadeAdxDeviceDriver():
    def __init__(self, plugin):
        self.plugin = plugin
        self.device_inventory_manager = (device_inventory
                                         .BrocadeAdxDeviceInventoryManager(self))

    def _get_device(self, subnet_id=None):
        devices = self.device_inventory_manager.get_devices()
        if len(devices) == 0:
            raise device_inventory.NoValidDevice()

        # filter by subnet_id
        filtered = [device for device in devices
                   if subnet_id or 'ALL' in device['subnet_id']]

        if not filtered:
            raise device_inventory.NoValidDevice()

        device = filtered[0]
        return device

    def _fetch_device(self, loadbalancer):
        subnet_id = loadbalancer.vip_subnet_id
        self.device_inventory_manager.load_devices()
        device = self._get_device(subnet_id)
        return device

    @log.log
    def create_loadbalancer(self, obj):
        device = self._fetch_device(obj)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.create_virtual_server(obj)

    @log.log
    def update_loadbalancer(self, obj, old_obj):
        device = self._fetch_device(obj)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.update_virtual_server(obj, old_obj)

    @log.log
    def delete_loadbalancer(self, obj):
        device = self._fetch_device(obj)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.delete_virtual_server(obj)

    @log.log
    def stats(self, obj):
        device = self._fetch_device(obj)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        return impl.stats(obj)

    @log.log
    def create_listener(self, obj):
        device = self._fetch_device(obj.loadbalancer)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.create_virtual_server_port(obj)

        if obj.default_pool_id:
            self.create_pool(obj.default_pool)

    @log.log
    def update_listener(self, obj, old_obj):
        device = self._fetch_device(obj.loadbalancer)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        if old_obj.loadbalancer is None:
            impl.create_virtual_server_port(obj)
        else:
            impl.update_virtual_server_port(obj, old_obj)

        if old_obj.default_pool is None and obj.default_pool:
            self.create_pool(obj.default_pool)
        elif old_obj.default_pool and obj.default_pool is None:
            self._delete_pool(old_obj.default_pool, device)

    @log.log
    def delete_listener(self, obj):
        device = self._fetch_device(obj.loadbalancer)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.delete_virtual_server_port(obj)

        # delete pool
        if obj.default_pool:
            self.delete_pool(obj.default_pool)

    @log.log
    def create_pool(self, obj):
        device = self._fetch_device(obj.listener.loadbalancer)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.create_pool(obj)

        loadbalancer = obj.listener.loadbalancer
        lb_algorithm = obj['lb_algorithm']
        impl.set_predictor_on_virtual_server(loadbalancer, lb_algorithm)

        if obj.healthmonitor:
            self.create_healthmonitor(obj.healthmonitor)

        members = obj.members
        for member in members:
            self.create_member(member)

    @log.log
    def update_pool(self, obj, old_obj):
        device = self._fetch_device(obj.listener.loadbalancer)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)

        loadbalancer = obj.listener.loadbalancer
        lb_algorithm = obj['lb_algorithm']
        old_lb_algorithm = old_obj['lb_algorithm']
        if lb_algorithm != old_lb_algorithm:
            impl.set_predictor_on_virtual_server(loadbalancer, lb_algorithm)

        # create health monitor if present
        if old_obj.healthmonitor is None and obj.healthmonitor:
            self.create_healthmonitor(obj.healthmonitor)
            for member in obj.members:
               impl.bind_monitor_to_member(obj.healthmonitor, member)
        elif old_obj.healthmonitor and obj.healthmonitor is None:
            for member in obj.members:
                impl.unbind_monitor_from_member(old_obj.healthmonitor, member)
            impl.delete_healthmonitor(pool.healthmonitor)


    @log.log
    def _delete_pool(self, obj, device):
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.delete_pool(obj)

        if obj['healthmonitor_id']:
            for member in obj.members:
                impl.unbind_monitor_from_member(obj, member)

            impl.delete_healthmonitor(obj.healthmonitor)

        # delete members
        for member in obj.members:
            impl.delete_member(member)

    @log.log
    def delete_pool(self, obj):
        device = self._fetch_device(obj.listener.loadbalancer)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.delete_pool(obj)

        # delete health monitor
        if obj.healthmonitor:
            self.delete_healthmonitor(obj.healthmonitor)

        # delete members
        members = obj.members
        for member in members:
            self.delete_member(member)


    def _vip_dict(self, listener):
        vip = {}
        loadbalancer = listener.loadbalancer
        vip['vip_address'] = loadbalancer.vip_address
        vip['protocol_port'] = listener['protocol_port']
        vip['name'] = loadbalancer.name
        if vip['name'] is None or vip['name'] == '':
            vip['name'] = loadbalancer.vip_address
        return vip

    @log.log
    def create_member(self, obj):
        device = self._fetch_device(obj.pool.listener.loadbalancer)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.create_member(obj)

        listener = obj.pool.listener
        vip = self._vip_dict(listener)
        impl.bind_member_to_vip(obj, vip)

        if obj.pool.healthmonitor:
            healthmonitor = obj.pool.healthmonitor
            impl.bind_monitor_to_member(healthmonitor, obj)

    @log.log
    def update_member(self, obj, old_obj):
        device = self._fetch_device(obj.pool.listener.loadbalancer)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.update_member(obj, old_obj)

    @log.log
    def delete_member(self, obj):
        device = self._fetch_device(obj.pool.listener.loadbalancer)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.delete_member(obj)

    @log.log
    def create_healthmonitor(self, obj):
        device = self._fetch_device(obj.pool.listener.loadbalancer)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.create_healthmonitor(obj)

    @log.log
    def delete_healthmonitor(self, obj):
        device = self._fetch_device(obj.pool.listener.loadbalancer)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        members = obj.pool.members
        for member in members:
            impl.unbind_monitor_from_member(obj, member)

        impl.delete_healthmonitor(obj)

    @log.log
    def update_healthmonitor(self, obj, old_obj):
        device = self._fetch_device(obj.pool.listener.loadbalancer)
        impl = driver_impl.BrocadeAdxDeviceDriverImpl(self.plugin, device)
        impl.update_healthmonitor(obj, old_obj)
