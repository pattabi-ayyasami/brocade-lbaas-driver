# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 Brocade Communications Systems, Inc.
# All Rights Reserved.
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
# @author: Pattabi Ayyasami, Brocade Communication Systems, Inc.
#
import json
from oslo.config import cfg

from neutron.common import exceptions as q_exc
from neutron.services.loadbalancer.drivers.brocade.device_driver import (
    brocade_adx_service as adx_service
)


class NoValidDevice(q_exc.NotFound):
    message = _("No valid device found")


class NoValidDeviceFile(q_exc.NotFound):
    message = _("Device Inventory File %(name)s either not found or invalid")

brocade_device_driver_opts = [
    cfg.StrOpt('devices_file_name',
               default='/etc/neutron/services/loadbalancer/'
                       'brocade/devices.json',
               help=_('file containing the brocade load balancer devices'))]
cfg.CONF.register_opts(brocade_device_driver_opts, "brocade")


class BrocadeAdxDeviceInventoryManager(object):
    def __init__(self, device_driver):
        self.device_driver = device_driver
        self.devices_file_name = cfg.CONF.brocade.devices_file_name
        self._ADX_DEVICES = dict()

    def _is_device_updated(self, device):
        ip = device['ip']
        user = device['user']
        password = device['password']
        device_in_cache = self._ADX_DEVICES[ip]
        if (user != device_in_cache['user'] or
            password != device_in_cache['password']):
            return True
        return False

    def load_devices(self):
        if not self.devices_file_name:
            raise NoValidDeviceFile(name=self.devices_file_name)

        try:
            with open(self.devices_file_name) as data_file:
                data = json.load(data_file)
        except IOError:
            raise NoValidDeviceFile(name=self.devices_file_name)
        except Exception:
            raise NoValidDeviceFile(name=self.devices_file_name)

        for device in data:
            ip = device['ip']
            if ip in self._ADX_DEVICES:
                if self._is_device_updated(device):
                    self._ADX_DEVICES[ip] = device
                    # Update Client Cache
                    adx_service.ClientCache.delete_adx_service_client(device)
                    adx_service.ClientCache.add_adx_service_client(device)
            else:
                self._ADX_DEVICES[ip] = device
                adx_service.ClientCache.add_adx_service_client(device)

    def get_devices(self):
        return self._ADX_DEVICES.values()
