/*
Copyright 2014 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package common

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/docker/distribution/uuid"
	"time"

	"code.google.com/p/gcfg"
	"github.com/hyperhq/kubestack/pkg/plugins"
	"github.com/rackspace/gophercloud"
	"github.com/rackspace/gophercloud/openstack"
	"github.com/rackspace/gophercloud/openstack/identity/v2/tenants"
	"github.com/rackspace/gophercloud/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/rackspace/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/rackspace/gophercloud/openstack/networking/v2/extensions/lbaas/members"
	"github.com/rackspace/gophercloud/openstack/networking/v2/extensions/lbaas/monitors"
	"github.com/rackspace/gophercloud/openstack/networking/v2/extensions/lbaas/pools"
	"github.com/rackspace/gophercloud/openstack/networking/v2/extensions/lbaas/vips"
	"github.com/rackspace/gophercloud/openstack/networking/v2/extensions/security/groups"
	"github.com/rackspace/gophercloud/openstack/networking/v2/extensions/security/rules"
	"github.com/rackspace/gophercloud/openstack/networking/v2/networks"
	"github.com/rackspace/gophercloud/openstack/networking/v2/ports"
	"github.com/rackspace/gophercloud/openstack/networking/v2/subnets"
	"github.com/rackspace/gophercloud/pagination"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/networkprovider"

	// import plugins
	_ "github.com/hyperhq/kubestack/pkg/plugins/openvswitch"
	"net"
)

const (
	podNamePrefix     = "kube"
	securitygroupName = "kube-securitygroup-default"

	// Service affinities
	ServiceAffinityNone     = "None"
	ServiceAffinityClientIP = "ClientIP"
)

// encoding.TextUnmarshaler interface for time.Duration
type MyDuration struct {
	time.Duration
}

func (d *MyDuration) UnmarshalText(text []byte) error {
	res, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	d.Duration = res
	return nil
}

type LoadBalancerOpts struct {
	LBMethod          string     `gcfg:"lb-method"`
	CreateMonitor     bool       `gcfg:"create-monitor"`
	MonitorDelay      MyDuration `gcfg:"monitor-delay"`
	MonitorTimeout    MyDuration `gcfg:"monitor-timeout"`
	MonitorMaxRetries uint       `gcfg:"monitor-max-retries"`
}

type PluginOpts struct {
	PluginName        string `gcfg:"plugin-name"`
	IntegrationBridge string `gcfg:"integration-bridge"`
}

// OpenStack is an implementation of network provider Interface for OpenStack.
type OpenStack struct {
	network    *gophercloud.ServiceClient
	identity   *gophercloud.ServiceClient
	provider   *gophercloud.ProviderClient
	region     string
	lbOpts     LoadBalancerOpts
	pluginOpts PluginOpts
	ExtNetID   string
	Plugin     plugins.PluginInterface
}

type Config struct {
	Global struct {
		AuthUrl    string `gcfg:"auth-url"`
		Username   string `gcfg:"username"`
		UserId     string `gcfg:"user-id"`
		Password   string `gcfg: "password"`
		ApiKey     string `gcfg:"api-key"`
		TenantId   string `gcfg:"tenant-id"`
		TenantName string `gcfg:"tenant-name"`
		DomainId   string `gcfg:"domain-id"`
		DomainName string `gcfg:"domain-name"`
		Region     string `gcfg:"region"`
		ExtNetID   string `gcfg:"ext-net-id"`
	}
	LoadBalancer LoadBalancerOpts
	Plugin       PluginOpts
}

func (cfg Config) toAuthOptions() gophercloud.AuthOptions {
	return gophercloud.AuthOptions{
		IdentityEndpoint: cfg.Global.AuthUrl,
		Username:         cfg.Global.Username,
		UserID:           cfg.Global.UserId,
		Password:         cfg.Global.Password,
		APIKey:           cfg.Global.ApiKey,
		TenantID:         cfg.Global.TenantId,
		TenantName:       cfg.Global.TenantName,

		// Persistent service, so we need to be able to renew tokens.
		AllowReauth: true,
	}
}

func NewOpenStack(config io.Reader) (*OpenStack, error) {
	var cfg Config
	err := gcfg.ReadInto(&cfg, config)
	if err != nil {
		glog.Warning("Failed to parse openstack configure file: %v", err)
		return nil, err
	}

	provider, err := openstack.AuthenticatedClient(cfg.toAuthOptions())
	if err != nil {
		glog.Warning("Failed to auth openstack: %v", err)
		return nil, err
	}

	identity, err := openstack.NewIdentityAdmin(provider)
	if err != nil {
		glog.Warning("Failed to find identity endpoint")
		return nil, err
	}

	network, err := openstack.NewNetworkV2(provider, gophercloud.EndpointOpts{
		Region: cfg.Global.Region,
	})
	if err != nil {
		glog.Warning("Failed to find neutron endpoint: %v", err)
		return nil, err
	}

	os := OpenStack{
		identity:   identity,
		network:    network,
		provider:   provider,
		region:     cfg.Global.Region,
		lbOpts:     cfg.LoadBalancer,
		pluginOpts: cfg.Plugin,
		ExtNetID:   cfg.Global.ExtNetID,
	}

	// init plugin
	if cfg.Plugin.PluginName != "" {
		integrationBriage := "br-int"
		if cfg.Plugin.IntegrationBridge != "" {
			integrationBriage = cfg.Plugin.IntegrationBridge
		}

		plugin, _ := plugins.GetNetworkPlugin(cfg.Plugin.PluginName)
		if plugin != nil {
			plugin.Init(integrationBriage)
			os.Plugin = plugin
		}
	}

	return &os, nil
}

func getHostName() string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}

	return host
}

// Get openstack network by id
func (os *OpenStack) getOpenStackNetworkByID(id string) (*networks.Network, error) {
	opts := networks.ListOpts{ID: id}
	return os.getOpenStackNetwork(&opts)
}

// Get openstack network by name
func (os *OpenStack) getOpenStackNetworkByName(name string) (*networks.Network, error) {
	opts := networks.ListOpts{Name: name}
	return os.getOpenStackNetwork(&opts)
}

// Get openstack network
func (os *OpenStack) getOpenStackNetwork(opts *networks.ListOpts) (*networks.Network, error) {
	var osNetwork *networks.Network
	pager := networks.List(os.network, *opts)
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		networkList, e := networks.ExtractNetworks(page)
		if len(networkList) > 1 {
			return false, networkprovider.ErrMultipleResults
		}

		if len(networkList) == 1 {
			osNetwork = &networkList[0]
		}

		return true, e
	})

	if err == nil && osNetwork == nil {
		return nil, networkprovider.ErrNotFound
	}

	return osNetwork, err
}

// Get provider subnet by id
func (os *OpenStack) getProviderSubnet(osSubnetID string) (*networkprovider.Subnet, error) {
	s, err := subnets.Get(os.network, osSubnetID).Extract()
	if err != nil {
		glog.Errorf("Get openstack subnet failed: %v", err)
		return nil, err
	}

	var routes []*networkprovider.Route
	for _, r := range s.HostRoutes {
		route := networkprovider.Route{
			Nexthop:         r.NextHop,
			DestinationCIDR: r.DestinationCIDR,
		}
		routes = append(routes, &route)
	}

	providerSubnet := networkprovider.Subnet{
		UID:           s.ID,
		CIDR:          s.CIDR,
		Gateway:       s.GatewayIP,
		Name:          s.Name,
		DNSNameServer: s.DNSNameservers,
		Routes:        routes,
	}

	return &providerSubnet, nil
}

// Get network by networkID
func (os *OpenStack) GetNetworkByID(networkID string) (*networkprovider.Network, error) {
	osNetwork, err := os.getOpenStackNetworkByID(networkID)
	if err != nil {
		glog.Errorf("Get openstack network failed: %v", err)
		return nil, err
	}

	return os.OSNetworktoProviderNetwork(osNetwork)
}

// Get network by networkName
func (os *OpenStack) GetNetwork(networkName string) (*networkprovider.Network, error) {
	osNetwork, err := os.getOpenStackNetworkByName(networkName)
	if err != nil {
		glog.Errorf("Get openstack network failed: %v", err)
		return nil, err
	}

	return os.OSNetworktoProviderNetwork(osNetwork)
}

func (os *OpenStack) OSNetworktoProviderNetwork(osNetwork *networks.Network) (*networkprovider.Network, error) {
	var providerNetwork networkprovider.Network
	var providerSubnets []*networkprovider.Subnet
	providerNetwork.Name = osNetwork.Name
	providerNetwork.UID = osNetwork.ID
	providerNetwork.Status = os.ToProviderStatus(osNetwork.Status)
	providerNetwork.TenantID = osNetwork.TenantID

	for _, subnetID := range osNetwork.Subnets {
		s, err := os.getProviderSubnet(subnetID)
		if err != nil {
			return nil, err
		}
		providerSubnets = append(providerSubnets, s)
	}

	providerNetwork.Subnets = providerSubnets

	return &providerNetwork, nil
}

func (os *OpenStack) ToProviderStatus(status string) networkprovider.NetworkStatus {
	switch status {
	case "ACTIVE":
		return networkprovider.NetworkActive
	case "BUILD":
		return networkprovider.NetworkPending
	case "DOWN", "ERROR":
		return networkprovider.NetworkFailed
	default:
		return networkprovider.NetworkFailed
	}

	return networkprovider.NetworkFailed
}

// Create network
func (os *OpenStack) CreateNetwork(network *networkprovider.Network) error {
	if len(network.Subnets) == 0 {
		return errors.New("Subnets is null")
	}

	// create network
	opts := networks.CreateOpts{
		Name:         network.Name,
		AdminStateUp: networks.Up,
		TenantID:     network.TenantID,
	}
	osNet, err := networks.Create(os.network, opts).Extract()
	if err != nil {
		glog.Errorf("Create openstack network %s failed: %v", network.Name, err)
		return err
	}

	// create router
	routerOpts := routers.CreateOpts{
		Name:        network.Name,
		TenantID:    network.TenantID,
		GatewayInfo: &routers.GatewayInfo{NetworkID: os.ExtNetID},
	}
	osRouter, err := routers.Create(os.network, routerOpts).Extract()
	if err != nil {
		glog.Errorf("Create openstack router %s failed: %v", network.Name, err)
		delErr := os.DeleteNetwork(network.Name)
		if delErr != nil {
			glog.Errorf("Delete openstack network %s failed: %v", network.Name, delErr)
		}
		return err
	}

	// create subnets and connect them to router
	networkID := osNet.ID
	network.Status = os.ToProviderStatus(osNet.Status)
	network.UID = osNet.ID
	for _, sub := range network.Subnets {
		// create subnet
		subnetOpts := subnets.CreateOpts{
			NetworkID:      networkID,
			CIDR:           sub.CIDR,
			Name:           sub.Name,
			IPVersion:      subnets.IPv4,
			TenantID:       network.TenantID,
			GatewayIP:      sub.Gateway,
			DNSNameservers: sub.DNSNameServer,
		}
		s, err := subnets.Create(os.network, subnetOpts).Extract()
		if err != nil {
			glog.Errorf("Create openstack subnet %s failed: %v", sub.Name, err)
			delErr := os.DeleteNetwork(network.Name)
			if delErr != nil {
				glog.Errorf("Delete openstack network %s failed: %v", network.Name, delErr)
			}
			return err
		}

		// add subnet to router
		opts := routers.InterfaceOpts{
			SubnetID: s.ID,
		}
		_, err = routers.AddInterface(os.network, osRouter.ID, opts).Extract()
		if err != nil {
			glog.Errorf("Create openstack subnet %s failed: %v", sub.Name, err)
			delErr := os.DeleteNetwork(network.Name)
			if delErr != nil {
				glog.Errorf("Delete openstack network %s failed: %v", network.Name, delErr)
			}
			return err
		}
	}

	return nil
}

// Update network
func (os *OpenStack) UpdateNetwork(network *networkprovider.Network) error {
	// TODO: update network subnets
	return nil
}

func (os *OpenStack) getRouterByName(name string) (*routers.Router, error) {
	var result *routers.Router

	opts := routers.ListOpts{Name: name}
	pager := routers.List(os.network, opts)
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		routerList, e := routers.ExtractRouters(page)
		if len(routerList) > 1 {
			return false, networkprovider.ErrMultipleResults
		} else if len(routerList) == 1 {
			result = &routerList[0]
		}

		return true, e
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Delete network by networkName
func (os *OpenStack) DeleteNetwork(networkName string) error {
	osNetwork, err := os.getOpenStackNetworkByName(networkName)
	if err != nil {
		glog.Errorf("Get openstack network failed: %v", err)
		return err
	}

	if osNetwork != nil {
		// Delete ports
		opts := ports.ListOpts{NetworkID: osNetwork.ID}
		pager := ports.List(os.network, opts)
		err := pager.EachPage(func(page pagination.Page) (bool, error) {
			portList, err := ports.ExtractPorts(page)
			if err != nil {
				glog.Errorf("Get openstack ports error: %v", err)
				return false, err
			}

			for _, port := range portList {
				if port.DeviceOwner == "network:router_interface" {
					continue
				}

				err = ports.Delete(os.network, port.ID).ExtractErr()
				if err != nil {
					glog.Warningf("Delete port %v failed: %v", port.ID, err)
				}
			}

			return true, nil
		})
		if err != nil {
			glog.Errorf("Delete ports error: %v", err)
		}

		router, err := os.getRouterByName(networkName)
		if err != nil {
			glog.Errorf("Get openstack router %s error: %v", networkName, err)
			return err
		}

		// delete all subnets
		for _, subnet := range osNetwork.Subnets {
			opts := routers.InterfaceOpts{SubnetID: subnet}
			_, err := routers.RemoveInterface(os.network, router.ID, opts).Extract()
			if err != nil {
				glog.Errorf("Get openstack router %s error: %v", networkName, err)
				return err
			}

			err = subnets.Delete(os.network, subnet).ExtractErr()
			if err != nil {
				glog.Errorf("Delete openstack subnet %s error: %v", subnet, err)
				return err
			}
		}

		// delete router
		err = routers.Delete(os.network, router.ID).ExtractErr()
		if err != nil {
			glog.Errorf("Delete openstack router %s error: %v", router.ID, err)
			return err
		}

		// delete network
		err = networks.Delete(os.network, osNetwork.ID).ExtractErr()
		if err != nil {
			glog.Errorf("Delete openstack network %s error: %v", osNetwork.ID, err)
			return err
		}
	}

	return nil
}

// List all ports in the network
func (os *OpenStack) ListPorts(networkName string) ([]*ports.Port, error) {
	osNetwork, err := os.getOpenStackNetworkByName(networkName)
	if err != nil {
		glog.Errorf("Get openstack network failed: %v", err)
		return nil, err
	}

	var results []*ports.Port
	opts := ports.ListOpts{NetworkID: osNetwork.ID}
	pager := ports.List(os.network, opts)
	err = pager.EachPage(func(page pagination.Page) (bool, error) {
		portList, err := ports.ExtractPorts(page)
		if err != nil {
			glog.Errorf("Get openstack ports error: %v", err)
			return false, err
		}

		for _, port := range portList {
			results = append(results, &port)
		}

		return true, err
	})

	return results, nil
}

func (os *OpenStack) ensureSecurityGroup(tenantID string) (string, error) {
	var securitygroup *groups.SecGroup

	opts := groups.ListOpts{
		TenantID: tenantID,
		Name:     securitygroupName,
	}
	pager := groups.List(os.network, opts)
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		sg, err := groups.ExtractGroups(page)
		if err != nil {
			glog.Errorf("Get openstack securitygroups error: %v", err)
			return false, err
		}

		if len(sg) > 0 {
			securitygroup = &sg[0]
		}

		return true, err
	})
	if err != nil {
		return "", err
	}

	// If securitygroup doesn't exist, create a new one
	if securitygroup == nil {
		securitygroup, err = groups.Create(os.network, groups.CreateOpts{
			Name:     securitygroupName,
			TenantID: tenantID,
		}).Extract()

		if err != nil {
			return "", err
		}
	}

	var secGroupsRules int
	listopts := rules.ListOpts{
		TenantID:   tenantID,
		Direction:  rules.DirIngress,
		SecGroupID: securitygroup.ID,
	}
	rulesPager := rules.List(os.network, listopts)
	err = rulesPager.EachPage(func(page pagination.Page) (bool, error) {
		r, err := rules.ExtractRules(page)
		if err != nil {
			glog.Errorf("Get openstack securitygroup rules error: %v", err)
			return false, err
		}

		secGroupsRules = len(r)

		return true, err
	})
	if err != nil {
		return "", err
	}

	// create new rules
	if secGroupsRules == 0 {
		// create egress rule
		_, err = rules.Create(os.network, rules.CreateOpts{
			TenantID:   tenantID,
			SecGroupID: securitygroup.ID,
			Direction:  rules.DirEgress,
			EtherType:  rules.Ether4,
		}).Extract()

		// create ingress rule
		_, err := rules.Create(os.network, rules.CreateOpts{
			TenantID:   tenantID,
			SecGroupID: securitygroup.ID,
			Direction:  rules.DirIngress,
			EtherType:  rules.Ether4,
		}).Extract()
		if err != nil {
			return "", err
		}
	}

	return securitygroup.ID, nil
}

// Create an port
func (os *OpenStack) CreatePort(networkID, tenantID, portName string) (*ports.Port, error) {
	securitygroup, err := os.ensureSecurityGroup(tenantID)
	if err != nil {
		glog.Errorf("EnsureSecurityGroup failed: %v", err)
		return nil, err
	}

	opts := ports.CreateOpts{
		NetworkID:      networkID,
		Name:           portName,
		AdminStateUp:   ports.Up,
		TenantID:       tenantID,
		HostID:         getHostName(),
		DeviceID:       uuid.Generate().String(),
		DeviceOwner:    fmt.Sprintf("container:%s", getHostName()),
		SecurityGroups: []string{securitygroup},
	}

	port, err := ports.Create(os.network, opts).Extract()
	if err != nil {
		glog.Errorf("Create port %s failed: %v", portName, err)
		return nil, err
	}

	return port, nil
}

// Bind an port to external network, return error
func (os *OpenStack) BindPortToFloatingip(portID, floatingIPAddress, tenantID string) error {
	opts := floatingips.CreateOpts{
		FloatingNetworkID: os.ExtNetID,
		TenantID:          tenantID,
		FloatingIP:        floatingIPAddress,
		PortID:            portID,
	}
	_, err := floatingips.Create(os.network, opts).Extract()
	if err != nil {
		glog.Errorf("Create openstack flaotingip failed: %v", err)
		return err
	}

	return nil
}

// Bind an port to external network, return floatingip binded
func (os *OpenStack) BindPortToExternal(portName, tenantID string) (string, error) {
	port, err := os.GetPort(portName)
	if err != nil {
		glog.Errorf("Get openstack port failed: %v", err)
		return "", err
	}

	opts := floatingips.CreateOpts{
		FloatingNetworkID: os.ExtNetID,
		TenantID:          tenantID,
	}
	ip, err := floatingips.Create(os.network, opts).Extract()
	if err != nil {
		glog.Errorf("Create openstack flaotingip failed: %v", err)
		return "", err
	}

	floatOpts := floatingips.UpdateOpts{PortID: port.ID}
	_, err = floatingips.Update(os.network, ip.ID, floatOpts).Extract()
	if err != nil {
		glog.Errorf("Associate floatingip failed: %v", err)
		e := floatingips.Delete(os.network, ip.ID).ExtractErr()
		if e != nil {
			glog.Errorf("Delete floatingip error: %v", e)
		}
		return "", err
	}

	return ip.FloatingIP, nil
}

func (os *OpenStack) getFloatingIPByPort(portID string) (*floatingips.FloatingIP, error) {
	var result *floatingips.FloatingIP

	opts := floatingips.ListOpts{
		PortID: portID,
	}
	pager := floatingips.List(os.network, opts)
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		floatingipList, err := floatingips.ExtractFloatingIPs(page)
		if err != nil {
			glog.Errorf("Get openstack floatingips error: %v", err)
			return false, err
		}

		if len(floatingipList) > 0 {
			result = &floatingipList[0]
		}

		return true, err
	})

	return result, err
}

// Unbind an port from external
func (os *OpenStack) UnbindPortFromExternal(portName string) error {
	port, err := os.GetPort(portName)
	if err != nil {
		glog.Errorf("get port failed: %v", err)
		return err
	}

	fip, err := os.getFloatingIPByPort(port.ID)
	if err != nil {
		glog.Errorf("get floatingip failed: %v", err)
		return err
	}

	if fip != nil {
		err = floatingips.Delete(os.network, fip.ID).ExtractErr()
		if err != nil {
			glog.Errorf("delete floatingip failed: %v", err)
			return err
		}
	}

	err = ports.Delete(os.network, port.ID).ExtractErr()
	if err != nil {
		glog.Errorf("delete port failed: %v", err)
		return err
	}

	return nil
}

func (os *OpenStack) GetPort(name string) (*ports.Port, error) {
	opts := ports.ListOpts{Name: name}
	pager := ports.List(os.network, opts)

	var port *ports.Port
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		portList, err := ports.ExtractPorts(page)
		if err != nil {
			glog.Errorf("Get openstack ports error: %v", err)
			return false, err
		}

		if len(portList) > 1 {
			return false, networkprovider.ErrMultipleResults
		}

		if len(portList) == 0 {
			return false, networkprovider.ErrNotFound
		}

		port = &portList[0]

		return true, err
	})

	return port, err
}

// Delete port by portName
func (os *OpenStack) DeletePort(portName string) error {
	port, err := os.GetPort(portName)
	if err == networkprovider.ErrNotFound {
		glog.V(4).Infof("Port %s already deleted", portName)
		return nil
	} else if err != nil {
		glog.Errorf("Get openstack port %s failed: %v", portName, err)
		return err
	}

	if port != nil {
		err := ports.Delete(os.network, port.ID).ExtractErr()
		if err != nil {
			glog.Errorf("Delete openstack port %s failed: %v", portName, err)
			return err
		}
	}

	return nil
}

func isNotFound(err error) bool {
	e, ok := err.(*gophercloud.UnexpectedResponseCodeError)
	return ok && e.Actual == http.StatusNotFound
}

// Get OpenStack LBAAS pool by name
func (os *OpenStack) getPoolByName(name string) (*pools.Pool, error) {
	opts := pools.ListOpts{
		Name: name,
	}
	pager := pools.List(os.network, opts)

	poolList := make([]pools.Pool, 0, 1)

	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		p, err := pools.ExtractPools(page)
		if err != nil {
			return false, err
		}
		poolList = append(poolList, p...)
		if len(poolList) > 1 {
			return false, networkprovider.ErrMultipleResults
		}
		return true, nil
	})
	if err != nil {
		if isNotFound(err) {
			return nil, networkprovider.ErrNotFound
		}
		return nil, err
	}

	if len(poolList) == 0 {
		return nil, networkprovider.ErrNotFound
	} else if len(poolList) > 1 {
		return nil, networkprovider.ErrMultipleResults
	}

	return &poolList[0], nil
}

// Get OpenStack LBAAS vip by ID
func (os *OpenStack) getVipByID(id string) (*vips.VirtualIP, error) {
	opts := vips.ListOpts{
		ID: id,
	}
	return os.getVipByOpts(opts)
}

// Get OpenStack LBAAS vip by name
func (os *OpenStack) getVipByName(name string) (*vips.VirtualIP, error) {
	opts := vips.ListOpts{
		Name: name,
	}
	return os.getVipByOpts(opts)
}

// Get OpenStack LBAAS vip by opts
func (os *OpenStack) getVipByOpts(opts vips.ListOpts) (*vips.VirtualIP, error) {
	pager := vips.List(os.network, opts)

	vipList := make([]vips.VirtualIP, 0, 1)

	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		v, err := vips.ExtractVIPs(page)
		if err != nil {
			return false, err
		}
		vipList = append(vipList, v...)
		if len(vipList) > 1 {
			return false, networkprovider.ErrMultipleResults
		}
		return true, nil
	})
	if err != nil {
		if isNotFound(err) {
			return nil, networkprovider.ErrNotFound
		}
		return nil, err
	}

	if len(vipList) == 0 {
		return nil, networkprovider.ErrNotFound
	} else if len(vipList) > 1 {
		return nil, networkprovider.ErrMultipleResults
	}

	return &vipList[0], nil
}

// Get load balancer by name
func (os *OpenStack) GetLoadBalancer(name string) (*networkprovider.LoadBalancer, error) {
	pool, err := os.getPoolByName(name)
	if err != nil {
		return nil, err
	}

	vip, err := os.getVipByID(pool.VIPID)
	if err != nil {
		return nil, err
	}

	var lb networkprovider.LoadBalancer
	lb.UID = pool.ID
	lb.Name = pool.Name
	lb.Status = pool.Status
	lb.Type = networkprovider.LoadBalancerTypeTCP
	lb.Vip = vip.Address
	lb.Subnets = []*networkprovider.Subnet{{UID: vip.SubnetID}}
	lb.Hosts = make([]*networkprovider.HostPort, 0, 1)

	pager := members.List(os.network, members.ListOpts{PoolID: pool.ID})
	err = pager.EachPage(func(page pagination.Page) (bool, error) {
		memList, err := members.ExtractMembers(page)
		if err != nil {
			return false, err
		}

		for _, member := range memList {
			host := networkprovider.HostPort{
				IPAddress:   member.Address,
				TargetPort:  member.ProtocolPort,
				ServicePort: vip.ProtocolPort,
			}
			lb.Hosts = append(lb.Hosts, &host)
		}

		return true, nil
	})
	if err != nil {
		return nil, err
	}

	return &lb, nil
}

// Create load balancer
func (os *OpenStack) CreateLoadBalancer(loadBalancer *networkprovider.LoadBalancer, affinity string) (string, error) {
	if len(loadBalancer.ExternalIPs) > 1 {
		return "", fmt.Errorf("multiple floatingips are not yet supported by openstack")
	}

	servicePort := 0
	for _, p := range loadBalancer.Hosts {
		if servicePort == 0 {
			servicePort = p.ServicePort
		} else if p.ServicePort != servicePort {
			return "", fmt.Errorf("multiple ports are not yet supported in openstack load balancers")
		}
	}

	var persistence *vips.SessionPersistence
	switch affinity {
	case ServiceAffinityNone:
		persistence = nil
	case ServiceAffinityClientIP:
		persistence = &vips.SessionPersistence{Type: "SOURCE_IP"}
	default:
		return "", fmt.Errorf("unsupported load balancer affinity: %v", affinity)
	}

	glog.V(2).Info("Checking if openstack load balancer already exists: ", loadBalancer.Name)
	_, err := os.getPoolByName(loadBalancer.Name)
	if err != nil && err != networkprovider.ErrNotFound {
		return "", fmt.Errorf("error checking if openstack load balancer already exists: %v", err)
	}

	if err == nil {
		err := os.DeleteLoadBalancer(loadBalancer.Name)
		if err != nil {
			return "", fmt.Errorf("error deleting existing openstack load balancer: %v", err)
		}
	}

	lbmethod := os.lbOpts.LBMethod
	if lbmethod == "" {
		lbmethod = pools.LBMethodRoundRobin
	}
	pool, err := pools.Create(os.network, pools.CreateOpts{
		Name:     loadBalancer.Name,
		Protocol: pools.ProtocolTCP,
		SubnetID: loadBalancer.Subnets[0].UID,
		LBMethod: lbmethod,
		TenantID: loadBalancer.TenantID,
	}).Extract()
	if err != nil {
		return "", err
	}

	for _, host := range loadBalancer.Hosts {
		_, err = members.Create(os.network, members.CreateOpts{
			PoolID:       pool.ID,
			ProtocolPort: host.TargetPort,
			Address:      host.IPAddress,
			TenantID:     loadBalancer.TenantID,
		}).Extract()
		if err != nil {
			pools.Delete(os.network, pool.ID)
			return "", err
		}
	}

	var mon *monitors.Monitor
	if os.lbOpts.CreateMonitor {
		mon, err = monitors.Create(os.network, monitors.CreateOpts{
			Type:       monitors.TypeTCP,
			TenantID:   loadBalancer.TenantID,
			Delay:      int(os.lbOpts.MonitorDelay.Duration.Seconds()),
			Timeout:    int(os.lbOpts.MonitorTimeout.Duration.Seconds()),
			MaxRetries: int(os.lbOpts.MonitorMaxRetries),
		}).Extract()
		if err != nil {
			pools.Delete(os.network, pool.ID)
			return "", err
		}

		_, err = pools.AssociateMonitor(os.network, pool.ID, mon.ID).Extract()
		if err != nil {
			monitors.Delete(os.network, mon.ID)
			pools.Delete(os.network, pool.ID)
			return "", err
		}
	}

	createOpts := vips.CreateOpts{
		Name:         loadBalancer.Name,
		Description:  fmt.Sprintf("Kubernetes service %s", loadBalancer.Name),
		Protocol:     "TCP",
		ProtocolPort: servicePort,
		PoolID:       pool.ID,
		SubnetID:     loadBalancer.Subnets[0].UID,
		Persistence:  persistence,
		TenantID:     loadBalancer.TenantID,
	}
	//if loadBalancer.Vip != "" {
	//	createOpts.Address = loadBalancer.Vip
	//}

	vip, err := vips.Create(os.network, createOpts).Extract()
	if err != nil {
		if mon != nil {
			monitors.Delete(os.network, mon.ID)
		}
		pools.Delete(os.network, pool.ID)
		return "", err
	}

	// bind external ip
	if len(loadBalancer.ExternalIPs) > 0 {
		err := os.BindPortToFloatingip(vip.PortID, loadBalancer.ExternalIPs[0], vip.TenantID)
		if err != nil {
			vips.Delete(os.network, vip.ID)
			if mon != nil {
				monitors.Delete(os.network, mon.ID)
			}
			pools.Delete(os.network, pool.ID)
			return "", err
		}
	}

	return vip.Address, nil
}

// Update load balancer
func (os *OpenStack) UpdateLoadBalancer(name string, hosts []*networkprovider.HostPort, externalIPs []string) (string, error) {
	if len(externalIPs) > 1 {
		return "", fmt.Errorf("multiple floatingips are not yet supported by openstack")
	}

	vip, err := os.getVipByName(name)
	if err != nil {
		return "", err
	}

	lb, err := os.GetLoadBalancer(name)
	if err != nil {
		return "", err
	}

	// Set of member (addresses) that _should_ exist
	addrs := make(map[string]*networkprovider.HostPort)
	for _, host := range hosts {
		addrs[host.IPAddress] = host
	}

	// Iterate over members that _do_ exist
	pager := members.List(os.network, members.ListOpts{PoolID: vip.PoolID})
	err = pager.EachPage(func(page pagination.Page) (bool, error) {
		memList, err := members.ExtractMembers(page)
		if err != nil {
			return false, err
		}

		for _, member := range memList {
			if _, found := addrs[member.Address]; found {
				// Member already exists
				delete(addrs, member.Address)
			} else {
				// Member needs to be deleted
				err = members.Delete(os.network, member.ID).ExtractErr()
				if err != nil {
					return false, err
				}
			}
		}

		return true, nil
	})
	if err != nil {
		return "", err
	}

	// Anything left in addrs is a new member that needs to be added
	for _, addr := range addrs {
		_, err := members.Create(os.network, members.CreateOpts{
			TenantID:     lb.TenantID,
			PoolID:       vip.PoolID,
			Address:      addr.IPAddress,
			ProtocolPort: addr.TargetPort,
		}).Extract()
		if err != nil {
			return "", err
		}
	}

	// bind to external ip
	if len(externalIPs) > 0 {
		err := os.BindPortToFloatingip(vip.PortID, externalIPs[0], vip.TenantID)
		if err != nil {
			return "", err
		}
	}

	return lb.Vip, nil
}

// Delete load balancer
func (os *OpenStack) DeleteLoadBalancer(name string) error {
	vip, err := os.getVipByName(name)
	if err != nil && err != networkprovider.ErrNotFound {
		return err
	}

	// We have to delete the VIP before the pool can be deleted,
	// so no point continuing if this fails.
	if vip != nil {
		fip, err := os.getFloatingIPByPort(vip.PortID)
		if err == nil && fip != nil {
			err = floatingips.Delete(os.network, fip.ID).ExtractErr()
			if err != nil && !isNotFound(err) {
				glog.Errorf("delete floatingip failed: %v", err)
				return err
			}
		}

		err = vips.Delete(os.network, vip.ID).ExtractErr()
		if err != nil && !isNotFound(err) {
			return err
		}
	}

	var pool *pools.Pool
	if vip != nil {
		pool, err = pools.Get(os.network, vip.PoolID).Extract()
		if err != nil && !isNotFound(err) {
			return err
		}
	} else {
		// The VIP is gone, but it is conceivable that a Pool
		// still exists that we failed to delete on some
		// previous occasion.  Make a best effort attempt to
		// cleanup any pools with the same name as the VIP.
		pool, err = os.getPoolByName(name)
		if err != nil && err != networkprovider.ErrNotFound {
			return err
		}
	}

	if pool != nil {
		for _, monId := range pool.MonitorIDs {
			_, err = pools.DisassociateMonitor(os.network, pool.ID, monId).Extract()
			if err != nil {
				return err
			}

			err = monitors.Delete(os.network, monId).ExtractErr()
			if err != nil && !isNotFound(err) {
				return err
			}
		}
		err = pools.Delete(os.network, pool.ID).ExtractErr()
		if err != nil && !isNotFound(err) {
			return err
		}
	}

	return nil
}

// Convert tenantID to tenantName
func (os *OpenStack) ToTenantName(tenant string) string {
	opts := tenants.ListOpts{}
	pager := tenants.List(os.identity, &opts)
	result := tenant

	pager.EachPage(func(page pagination.Page) (bool, error) {
		tenantList, err := tenants.ExtractTenants(page)
		if err != nil {
			return false, err
		}

		for _, t := range tenantList {
			if t.ID == tenant {
				result = t.Name
			}
		}

		return true, nil
	})

	return result
}

// Convert tenantName to tenantID
func (os *OpenStack) ToTenantID(tenant string) string {
	opts := tenants.ListOpts{}
	pager := tenants.List(os.identity, &opts)
	result := tenant

	pager.EachPage(func(page pagination.Page) (bool, error) {
		tenantList, err := tenants.ExtractTenants(page)
		if err != nil {
			return false, err
		}

		for _, t := range tenantList {
			if t.Name == tenant {
				result = t.ID
			}
		}

		return true, nil
	})

	return result
}

// Check the tenant id exist
func (os *OpenStack) CheckTenantID(tenantID string) (bool, error) {
	opts := tenants.ListOpts{}
	pager := tenants.List(os.identity, &opts)

	var found bool
	err := pager.EachPage(func(page pagination.Page) (bool, error) {

		tenantList, err := tenants.ExtractTenants(page)
		if err != nil {
			return false, err
		}

		if len(tenantList) == 0 {
			return false, networkprovider.ErrNotFound
		}

		for _, t := range tenantList {
			if t.ID == tenantID || t.Name == tenantID {
				found = true
			}
		}

		return true, nil
	})

	return found, err
}

func (os *OpenStack) BuildPortName(podName, namespace, networkID string) string {
	return podNamePrefix + "_" + podName + "_" + namespace + "_" + networkID
}

// Setup pod
func (os *OpenStack) SetupPod(podName, namespace, podInfraContainerID string, network *networkprovider.Network, containerRuntime string) error {
	portName := os.BuildPortName(podName, namespace, network.UID)

	// get port from openstack; if port doesn't exist, create a new one
	port, err := os.GetPort(portName)
	if err == networkprovider.ErrNotFound || port == nil {
		// Port not found, create one
		port, err = os.CreatePort(network.UID, network.TenantID, portName)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	glog.V(4).Infof("Pod %s's port is %v", podName, port)

	// get subnet and gateway
	subnet, err := os.getProviderSubnet(port.FixedIPs[0].SubnetID)
	if err != nil {
		glog.Errorf("Get info of subnet %s failed: %v", port.FixedIPs[0].SubnetID, err)
		if nil != ports.Delete(os.network, port.ID).ExtractErr() {
			glog.Warningf("Delete port %s failed", port.ID)
		}
		return err
	}

	// setup interface for docker
	_, cidr, _ := net.ParseCIDR(subnet.CIDR)
	prefixSize, _ := cidr.Mask.Size()
	err = os.Plugin.SetupInterface(podName, podInfraContainerID, port,
		fmt.Sprintf("%s/%d", port.FixedIPs[0].IPAddress, prefixSize), subnet.Gateway, containerRuntime)
	if err != nil {
		glog.Errorf("SetupInterface failed: %v", err)
		if nil != ports.Delete(os.network, port.ID).ExtractErr() {
			glog.Warningf("Delete port %s failed", port.ID)
		}
		return err
	}

	return nil
}

// Teardown pod
func (os *OpenStack) TeardownPod(podName, namespace, podInfraContainerID string, network *networkprovider.Network, containerRuntime string) error {
	portName := os.BuildPortName(podName, namespace, network.UID)

	// get port from openstack
	port, err := os.GetPort(portName)
	if err != nil {
		glog.Errorf("GetPort %s failed: %v", portName, err)
		return err
	}

	if port == nil {
		glog.Warningf("Port %s already deleted", portName)
		return nil
	}

	glog.V(4).Infof("Pod %s's port is %v", podName, port)

	// delete interface for docker
	err = os.Plugin.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
	if err != nil {
		glog.Errorf("DestroyInterface for pod %s failed: %v", podName, err)
		return err
	}

	// delete port from openstack
	err = os.DeletePort(portName)
	if err != nil {
		glog.Errorf("DeletePort %s failed: %v", portName, err)
		return err
	}

	return nil
}

// Status of pod
func (os *OpenStack) PodStatus(podName, namespace, podInfraContainerID string, network *networkprovider.Network, containerRuntime string) (string, error) {
	ipAddress := ""
	portName := os.BuildPortName(podName, namespace, network.UID)
	port, err := os.GetPort(portName)
	if err != nil {
		return ipAddress, err
	}

	glog.V(4).Infof("Pod %s's port is %v", podName, port)

	if port != nil {
		ipAddress = port.FixedIPs[0].IPAddress
	}

	return ipAddress, nil
}
