/*
Copyright 2015 The Kubernetes Authors All rights reserved.

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

package kubestack

import (
	"net"

	"github.com/golang/glog"
	"github.com/hyperhq/kubestack/pkg/common"
	provider "github.com/hyperhq/kubestack/pkg/types"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

// KubeHandler forwards requests and responses between the docker daemon and the plugin.
type KubeHandler struct {
	driver *common.OpenStack
	server *grpc.Server
}

// NewKubeHandler initializes the request handler with a driver implementation.
func NewKubeHandler(driver *common.OpenStack) *KubeHandler {
	h := &KubeHandler{
		driver: driver,
		server: grpc.NewServer(),
	}
	h.registerServer()
	return h
}

func (h *KubeHandler) Serve(addr string) error {
	glog.V(1).Infof("Starting kubestack at %s", addr)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		glog.Fatalf("Failed to listen: %s", addr)
		return err
	}
	return h.server.Serve(l)
}

func (h *KubeHandler) registerServer() {
	provider.RegisterLoadBalancersServer(h.server, h)
	provider.RegisterNetworksServer(h.server, h)
	provider.RegisterPodsServer(h.server, h)
}

func (h *KubeHandler) Active(c context.Context, req *provider.ActiveRequest) (*provider.ActivateResponse, error) {
	glog.V(3).Infof("Activating called")

	resp := provider.ActivateResponse{
		Result: true,
	}

	return &resp, nil
}

func (h *KubeHandler) CheckTenantID(c context.Context, req *provider.CheckTenantIDRequest) (*provider.CheckTenantIDResponse, error) {
	glog.V(4).Infof("CheckTenantID with request %v", req.TenantID)

	resp := provider.CheckTenantIDResponse{}
	checkResult, err := h.driver.CheckTenantID(req.TenantID)
	if err != nil {
		resp.Error = err.Error()
	} else {
		resp.Result = checkResult
	}

	glog.V(4).Infof("CheckTenantID result %v", resp)
	return &resp, nil
}

func (h *KubeHandler) GetNetwork(c context.Context, req *provider.GetNetworkRequest) (*provider.GetNetworkResponse, error) {
	glog.V(4).Infof("GetNetwork with request %v", req.String())

	resp := provider.GetNetworkResponse{}
	var result *provider.Network
	var err error
	if req.Id != "" {
		result, err = h.driver.GetNetworkByID(req.Id)
	} else if req.Name != "" {
		result, err = h.driver.GetNetwork(req.Name)
	}

	if err != nil {
		resp.Error = err.Error()
	} else {
		resp.Network = result
	}

	glog.V(4).Infof("GetNetwork result %v", resp)
	return &resp, nil
}

func (h *KubeHandler) CreateNetwork(c context.Context, req *provider.CreateNetworkRequest) (*provider.CommonResponse, error) {
	glog.V(4).Infof("CreateNetwork with request %v", req)

	resp := provider.CommonResponse{}
	req.Network.TenantID = h.driver.ToTenantID(req.Network.TenantID)
	err := h.driver.CreateNetwork(req.Network)
	if err != nil {
		resp.Error = err.Error()
	}

	glog.V(4).Infof("CreateNetwork result %v", resp)
	return &resp, nil
}

func (h *KubeHandler) UpdateNetwork(c context.Context, req *provider.UpdateNetworkRequest) (*provider.CommonResponse, error) {
	glog.V(4).Infof("UpdateNetwork with request %v", req.String())

	resp := provider.CommonResponse{}
	req.Network.TenantID = h.driver.ToTenantID(req.Network.TenantID)
	err := h.driver.UpdateNetwork(req.Network)
	if err != nil {
		resp.Error = err.Error()
	}

	glog.V(4).Infof("UpdateNetwork result %v", resp)
	return &resp, nil
}

func (h *KubeHandler) DeleteNetwork(c context.Context, req *provider.DeleteNetworkRequest) (*provider.CommonResponse, error) {
	glog.V(4).Infof("DeleteNetwork with request %v", req.String())

	resp := provider.CommonResponse{}
	err := h.driver.DeleteNetwork(req.NetworkName)
	if err != nil {
		resp.Error = err.Error()
	}

	glog.V(4).Infof("DeleteNetwork result %v", resp)
	return &resp, nil
}

func (h *KubeHandler) GetLoadBalancer(c context.Context, req *provider.GetLoadBalancerRequest) (*provider.GetLoadBalancerResponse, error) {
	resp := provider.GetLoadBalancerResponse{}
	lb, err := h.driver.GetLoadBalancer(req.Name)
	if err != nil {
		resp.Error = err.Error()
	} else {
		resp.LoadBalancer = lb
	}

	return &resp, nil
}

func (h *KubeHandler) CreateLoadBalancer(c context.Context, req *provider.CreateLoadBalancerRequest) (*provider.CreateLoadBalancerResponse, error) {
	glog.V(4).Infof("CreateLoadBalancer with request %v", req.String())

	resp := provider.CreateLoadBalancerResponse{}
	req.LoadBalancer.TenantID = h.driver.ToTenantID(req.LoadBalancer.TenantID)
	vip, err := h.driver.CreateLoadBalancer(req.LoadBalancer, string(req.Affinity))
	if err != nil {
		resp.Error = err.Error()
	} else {
		resp.Vip = vip
	}

	glog.V(4).Infof("CreateLoadBalancer result %v", resp)
	return &resp, nil
}

func (h *KubeHandler) UpdateLoadBalancer(c context.Context, req *provider.UpdateLoadBalancerRequest) (*provider.UpdateLoadBalancerResponse, error) {
	glog.V(4).Infof("UpdateLoadBalancer with request %v", req.String())

	resp := provider.UpdateLoadBalancerResponse{}
	vip, err := h.driver.UpdateLoadBalancer(req.Name, req.Hosts, req.ExternalIPs)
	if err != nil {
		resp.Error = err.Error()
	} else {
		resp.Vip = vip
	}

	glog.V(4).Infof("UpdateLoadBalancer result %v", resp)

	return &resp, nil
}

func (h *KubeHandler) DeleteLoadBalancer(c context.Context, req *provider.DeleteLoadBalancerRequest) (*provider.CommonResponse, error) {
	glog.V(4).Infof("DeleteLoadBalancer with request %v", req.String())

	resp := provider.CommonResponse{}
	err := h.driver.DeleteLoadBalancer(req.Name)
	if err != nil {
		resp.Error = err.Error()
	}

	glog.V(4).Infof("DeleteLoadBalancer result %v", resp)
	return &resp, nil
}

func (h *KubeHandler) SetupPod(c context.Context, req *provider.SetupPodRequest) (*provider.CommonResponse, error) {
	glog.V(4).Infof("SetupPod with request %v", req.String())

	resp := provider.CommonResponse{}
	// TODO: Add hostname in SetupPod Interface
	_, err := h.driver.SetupPod(req.PodName, req.Namespace, req.PodInfraContainerID, req.Network, req.ContainerRuntime)
	if err != nil {
		glog.Errorf("SetupPod failed: %v", err)
		resp.Error = err.Error()
	}

	return &resp, nil
}

func (h *KubeHandler) TeardownPod(c context.Context, req *provider.TeardownPodRequest) (*provider.CommonResponse, error) {
	glog.V(4).Infof("TeardownPod with request %v", req.String())

	resp := provider.CommonResponse{}
	err := h.driver.TeardownPod(req.PodName, req.Namespace, req.PodInfraContainerID, req.Network, req.ContainerRuntime)
	if err != nil {
		glog.Errorf("TeardownPod failed: %v", err)
		resp.Error = err.Error()
	}

	return &resp, nil
}

func (h *KubeHandler) PodStatus(c context.Context, req *provider.PodStatusRequest) (*provider.PodStatusResponse, error) {
	glog.V(4).Infof("PodStatus with request %v", req.String())

	resp := provider.PodStatusResponse{}
	ip, err := h.driver.PodStatus(req.PodName, req.Namespace, req.PodInfraContainerID, req.Network, req.ContainerRuntime)
	if err != nil {
		glog.Errorf("PodStatus failed: %v", err)
		resp.Error = err.Error()
	} else {
		resp.Ip = ip
	}

	return &resp, nil
}
