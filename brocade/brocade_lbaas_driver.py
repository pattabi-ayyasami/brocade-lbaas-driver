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
from neutron.services.loadbalancer.drivers import driver_base

LOG = logging.getLogger(__name__)


class BrocadeLoadBalancerDriver(driver_base.LoadBalancerBaseDriver):

    def __init__(self, plugin):
        super(BrocadeLoadBalancerDriver, self).__init__(plugin)
        self.plugin = plugin
        # Each of the major LBaaS objects in the neutron database
        # need a corresponding manager/handler class.
        #
        # Put common things that are shared across the entire driver, like
        # config or a rest client handle, here.
        #
        # This function is executed when neutron-server starts.

        self.load_balancer = BrocadeLoadBalancerManager(self)
        self.listener = BrocadeListenerManager(self)
        self.pool = BrocadePoolManager(self)
        self.member = BrocadeMemberManager(self)
        self.healthmonitor = BrocadeHealthMonitorManager(self)

        self.brocade_device_driver = None
        try:
            import neutron.services \
                   .loadbalancer.drivers.brocade \
                   .device_driver.brocade_adx_driver as device_driver

            self.brocade_device_driver = device_driver.BrocadeAdxDeviceDriver(plugin)
        except ImportError:
            pass

        if self.brocade_device_driver is None:
            LOG.error(_("Please install brocade adx device driver "
                        "and restart neutron"))


class BrocadeCommonManager(object):
    def _create(self, context, driver_method, obj):
        try:
            driver_method(obj)
            self.active(context, obj.id)
        except Exception as device_driver_exception:
            LOG.error(_("device driver exception : %s"), device_driver_exception)
            self.failed(context, obj.id)

    def _update(self, context, driver_method, obj, old_obj):
        try:
            driver_method(obj, old_obj)
            self.active(context, obj.id)
        except Exception as device_driver_exception:
            LOG.error(_("device driver exception : %s"), device_driver_exception)
            self.failed(context, obj.id)

    def _delete(self, context, driver_method, obj):
        try:
            driver_method(obj)
            self.db_delete(context, obj.id)
        except Exception as device_driver_exception:
            LOG.error(_("device driver exception : %s"), device_driver_exception)
            self.db_delete(context, obj.id)


class BrocadeLoadBalancerManager(BrocadeCommonManager,
                                     driver_base.BaseLoadBalancerManager):
    @log.log
    def create(self, context, obj):
        self._create(context,
                     self.driver.brocade_device_driver.create_loadbalancer,
                     obj)

    @log.log
    def update(self, context, old_obj, obj):
        self._update(context,
                     self.driver.brocade_device_driver.update_loadbalancer,
                     obj, old_obj)

    @log.log
    def delete(self, context, obj):
        self._delete(context,
                     self.driver.brocade_device_driver.delete_loadbalancer,
                     obj)

    @log.log
    def refresh(self, context, lb_obj, force=False):
        # This is intended to trigger the backend to check and repair
        # the state of this load balancer and all of its dependent objects
        LOG.debug("LB pool refresh %s, force=%s", lb_obj.id, force)

    @log.log
    def stats(self, context, lb_obj):
        try:
            return self.driver.brocade_device_driver.stats(lb_obj)
        except Exception as device_driver_exception:
            pass

        return None


class BrocadeListenerManager(BrocadeCommonManager,
                             driver_base.BaseListenerManager):

    @log.log
    def create(self, context, obj):
        self._create(context,
                     self.driver.brocade_device_driver.create_listener,
                     obj)

    @log.log
    def update(self, context, old_obj, obj):
        self._update(context,
                     self.driver.brocade_device_driver.update_listener,
                     obj, old_obj)


    @log.log
    def delete(self, context, obj):
        self._delete(context,
                     self.driver.brocade_device_driver.delete_listener,
                     obj)


class BrocadePoolManager(BrocadeCommonManager,
                         driver_base.BasePoolManager):

    @log.log
    def create(self, context, obj):
        pass

    @log.log
    def update(self, context, old_obj, obj):
        self._update(context,
                     self.driver.brocade_device_driver.update_pool,
                     obj, old_obj)

    @log.log
    def delete(self, context, obj):
        self._delete(context,
                     self.driver.brocade_device_driver.delete_pool,
                     obj)


class BrocadeMemberManager(BrocadeCommonManager,
                               driver_base.BaseMemberManager):
    @log.log
    def create(self, context, obj):
        self._create(context,
                     self.driver.brocade_device_driver.create_member,
                     obj)

    @log.log
    def update(self, context, old_obj, obj):
        self._update(context,
                     self.driver.brocade_device_driver.update_member,
                     obj, old_obj)

    @log.log
    def delete(self, context, obj):
        self._delete(context,
                     self.driver.brocade_device_driver.delete_member,
                     obj)



class BrocadeHealthMonitorManager(BrocadeCommonManager,
                                      driver_base.BaseHealthMonitorManager):
    @log.log
    def create(self, context, obj):
        pass

    @log.log
    def update(self, context, old_obj, obj):
        self._update(context,
                     self.driver.brocade_device_driver.update_healthmonitor,
                     obj, old_obj)

    @log.log
    def delete(self, context, obj):
        self._delete(context,
                     self.driver.brocade_device_driver.delete_healthmonitor,
                     obj)
