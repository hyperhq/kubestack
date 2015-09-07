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
	"net/http"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/networkprovider"
	"k8s.io/kubernetes/pkg/networkprovider/providers/remote"
	"kubestack/pkg/common"
)

// KubeHandler forwards requests and responses between the docker daemon and the plugin.
type KubeHandler struct {
	driver *common.OpenStack
	mux    *http.ServeMux
}

// NewKubeHandler initializes the request handler with a driver implementation.
func NewKubeHandler(driver *common.OpenStack) *KubeHandler {
	h := &KubeHandler{driver, http.NewServeMux()}
	h.initMux()
	return h
}

func (h *KubeHandler) initMux() {
	h.mux.HandleFunc("/"+remote.ActivateMethod, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", common.DefaultContentType)
		res := common.Response{Result: true}
		common.EncodeResponse(w, res)
	})

	h.mux.HandleFunc("/"+remote.GetNetworkMethod, func(w http.ResponseWriter, r *http.Request) {
		var req remote.GetNetworkRequest
		err := common.DecodeRequest(w, r, &req)
		if err != nil {
			common.ErrorResponse(w, err)
			return
		}

		res := h.GetNetwork(&req)
		common.EncodeResponse(w, res)
	})

	h.mux.HandleFunc("/"+remote.CheckTenantIDMethod, func(w http.ResponseWriter, r *http.Request) {
		var req remote.CheckTenantIDRequest
		err := common.DecodeRequest(w, r, &req)
		if err != nil {
			common.ErrorResponse(w, err)
			return
		}

		res := h.CheckTenantID(&req)
		common.EncodeResponse(w, res)
	})

	h.mux.HandleFunc("/"+remote.CreateNetworkMethod, func(w http.ResponseWriter, r *http.Request) {
		var req remote.CreateNetworkRequest
		err := common.DecodeRequest(w, r, &req)
		if err != nil {
			common.ErrorResponse(w, err)
			return
		}

		res := h.CreateNetwork(&req)
		common.EncodeResponse(w, res)
	})

	h.mux.HandleFunc("/"+remote.UpdateNetworkMethod, func(w http.ResponseWriter, r *http.Request) {
		var req remote.UpdateNetworkRequest
		err := common.DecodeRequest(w, r, &req)
		if err != nil {
			common.ErrorResponse(w, err)
			return
		}

		res := h.UpdateNetwork(&req)
		common.EncodeResponse(w, res)
	})

	h.mux.HandleFunc("/"+remote.DeleteNetworkMethod, func(w http.ResponseWriter, r *http.Request) {
		var req remote.DeleteNetworkRequest
		err := common.DecodeRequest(w, r, &req)
		if err != nil {
			common.ErrorResponse(w, err)
			return
		}

		res := h.DeleteNetwork(&req)
		common.EncodeResponse(w, res)
	})

	h.mux.HandleFunc("/"+remote.GetLoadBalancerMethod, func(w http.ResponseWriter, r *http.Request) {
		var req remote.GetLoadBalancerRequest
		err := common.DecodeRequest(w, r, &req)
		if err != nil {
			common.ErrorResponse(w, err)
			return
		}

		res := h.GetLoadBalancer(&req)
		common.EncodeResponse(w, res)
	})

	h.mux.HandleFunc("/"+remote.CreateLoadBalancerMethod, func(w http.ResponseWriter, r *http.Request) {
		var req remote.CreateLoadBalancerRequest
		err := common.DecodeRequest(w, r, &req)
		if err != nil {
			common.ErrorResponse(w, err)
			return
		}

		res := h.CreateLoadBalancer(&req)
		common.EncodeResponse(w, res)
	})

	h.mux.HandleFunc("/"+remote.UpdateLoadBalancerMethod, func(w http.ResponseWriter, r *http.Request) {
		var req remote.UpdateLoadBalancerRequest
		err := common.DecodeRequest(w, r, &req)
		if err != nil {
			common.ErrorResponse(w, err)
			return
		}

		res := h.UpdateLoadBalancer(&req)
		common.EncodeResponse(w, res)
	})

	h.mux.HandleFunc("/"+remote.DeleteLoadBalancerMethod, func(w http.ResponseWriter, r *http.Request) {
		var req remote.DeleteLoadBalancerRequest
		err := common.DecodeRequest(w, r, &req)
		if err != nil {
			common.ErrorResponse(w, err)
			return
		}

		res := h.DeleteLoadBalancer(&req)
		common.EncodeResponse(w, res)
	})

	// kubelet methods
	h.mux.HandleFunc("/"+remote.SetupPodMethod, func(w http.ResponseWriter, r *http.Request) {
		var req remote.SetupPodRequest
		err := common.DecodeRequest(w, r, &req)
		if err != nil {
			common.ErrorResponse(w, err)
			return
		}

		res := h.SetupPod(&req)
		common.EncodeResponse(w, res)
	})

	h.mux.HandleFunc("/"+remote.TeardownPodMethod, func(w http.ResponseWriter, r *http.Request) {
		var req remote.TeardownPodRequest
		err := common.DecodeRequest(w, r, &req)
		if err != nil {
			common.ErrorResponse(w, err)
			return
		}

		res := h.TeardownPod(&req)
		common.EncodeResponse(w, res)
	})

	h.mux.HandleFunc("/"+remote.PodStatudMethod, func(w http.ResponseWriter, r *http.Request) {
		var req remote.PodStatusRequest
		err := common.DecodeRequest(w, r, &req)
		if err != nil {
			common.ErrorResponse(w, err)
			return
		}

		res := h.PodStatus(&req)
		common.EncodeResponse(w, res)
	})
}

func (h *KubeHandler) CheckTenantID(req *remote.CheckTenantIDRequest) common.Response {
	glog.V(4).Infof("CheckTenantID with request %v", req)

	var resp common.Response
	checkResult, err := h.driver.CheckTenantID(req.TenantID)
	if err != nil {
		resp.Err = err.Error()
	} else {
		resp.Result = checkResult
		resp.Err = ""
	}

	glog.V(4).Infof("CheckTenantID result %v", resp)
	return resp
}

func (h *KubeHandler) GetNetwork(req *remote.GetNetworkRequest) common.Response {
	glog.V(4).Infof("GetNetwork with request %v", req)

	var resp common.Response
	var result *networkprovider.Network
	var err error
	if req.ID != "" {
		result, err = h.driver.GetNetworkByID(req.ID)
	} else if req.Name != "" {
		result, err = h.driver.GetNetwork(req.Name)
	}

	if err != nil {
		resp.Err = err.Error()
	} else {
		resp.Result = result
	}

	glog.V(4).Infof("GetNetwork result %v", resp)
	return resp
}

func (h *KubeHandler) CreateNetwork(req *remote.CreateNetworkRequest) common.Response {
	glog.V(4).Infof("CreateNetwork with request %v", req)

	var resp common.Response
	err := h.driver.CreateNetwork(req.Network)
	if err != nil {
		resp.Err = err.Error()
	}

	glog.V(4).Infof("CreateNetwork result %v", resp)
	return resp
}

func (h *KubeHandler) UpdateNetwork(req *remote.UpdateNetworkRequest) common.Response {
	glog.V(4).Infof("UpdateNetwork with request %v", req)

	var resp common.Response
	err := h.driver.UpdateNetwork(req.Network)
	if err != nil {
		resp.Err = err.Error()
	}

	glog.V(4).Infof("UpdateNetwork result %v", resp)
	return resp
}

func (h *KubeHandler) DeleteNetwork(req *remote.DeleteNetworkRequest) common.Response {
	glog.V(4).Infof("DeleteNetwork with request %v", req)

	var resp common.Response
	err := h.driver.DeleteNetwork(req.Name)
	if err != nil {
		resp.Err = err.Error()
	}

	glog.V(4).Infof("DeleteNetwork result %v", resp)
	return resp
}

func (h *KubeHandler) GetLoadBalancer(req *remote.GetLoadBalancerRequest) common.Response {
	var resp common.Response
	lb, err := h.driver.GetLoadBalancer(req.Name)
	if err != nil {
		resp.Err = err.Error()
	} else {
		resp.Result = lb
	}

	return resp
}

func (h *KubeHandler) CreateLoadBalancer(req *remote.CreateLoadBalancerRequest) common.Response {
	glog.V(4).Infof("CreateLoadBalancer with request %v", req)

	var resp common.Response
	vip, err := h.driver.CreateLoadBalancer(req.LoadBalancer, string(req.Affinity))
	if err != nil {
		resp.Err = err.Error()
	}

	result := make(map[string]string)
	if vip != "" {
		result["VIP"] = vip
	}
	resp.Result = result

	glog.V(4).Infof("CreateLoadBalancer result %v", resp)
	return resp
}

func (h *KubeHandler) UpdateLoadBalancer(req *remote.UpdateLoadBalancerRequest) common.Response {
	glog.V(4).Infof("UpdateLoadBalancer with request %v", req)

	var resp common.Response
	vip, err := h.driver.UpdateLoadBalancer(req.Name, req.Hosts, req.ExternalIPs)
	if err != nil {
		resp.Err = err.Error()
	}

	result := make(map[string]string)
	if vip != "" {
		result["VIP"] = vip
	}
	resp.Result = result

	glog.V(4).Infof("UpdateLoadBalancer result %v", resp)
	return resp
}

func (h *KubeHandler) DeleteLoadBalancer(req *remote.DeleteLoadBalancerRequest) common.Response {
	glog.V(4).Infof("DeleteLoadBalancer with request %v", req)

	var resp common.Response
	err := h.driver.DeleteLoadBalancer(req.Name)
	if err != nil {
		resp.Err = err.Error()
	}

	glog.V(4).Infof("DeleteLoadBalancer result %v", resp)
	return resp
}

// ServeTCP makes the handler to listen for request in a given TCP address.
// It also writes the spec file on the right directory for docker to read.
func (h *KubeHandler) ServeTCP(pluginName, addr string) error {
	return h.listenAndServe("tcp", addr, pluginName)
}

// ServeUnix makes the handler to listen for requests in a unix socket.
// It also creates the socket file on the right directory for docker to read.
func (h *KubeHandler) ServeUnix(systemGroup, addr string) error {
	return h.listenAndServe("unix", addr, systemGroup)
}

func (h *KubeHandler) listenAndServe(proto, addr, group string) error {
	server := http.Server{
		Addr:    addr,
		Handler: h.mux,
	}

	start := make(chan struct{})

	var l net.Listener
	var err error
	switch proto {
	case "tcp":
		l, err = common.NewTCPSocket(addr, nil, start)
		if err == nil {
			err = common.WriteSpec(group, l.Addr().String(), common.KubestackSpecDir)
		}
	case "unix":
		var s string
		s, err = common.FullSocketAddr(addr, common.KubestackSockDir)
		if err == nil {
			l, err = common.NewUnixSocket(s, group, start)
		}
	}
	if err != nil {
		return err
	}

	close(start)
	return server.Serve(l)
}

func (h *KubeHandler) SetupPod(req *remote.SetupPodRequest) common.Response {
	glog.V(4).Infof("SetupPod with request %v", req)

	var resp common.Response
	err := h.driver.SetupPod(req.PodName, req.Namespace, req.PodInfraContainerID, req.Network, req.ContainerRuntime)
	if err != nil {
		glog.Errorf("SetupPod failed: %v", err)
		resp.Err = err.Error()
	}

	return resp
}

func (h *KubeHandler) TeardownPod(req *remote.TeardownPodRequest) common.Response {
	glog.V(4).Infof("TeardownPod with request %v", req)

	var resp common.Response
	err := h.driver.TeardownPod(req.PodName, req.Namespace, req.PodInfraContainerID, req.Network, req.ContainerRuntime)
	if err != nil {
		glog.Errorf("TeardownPod failed: %v", err)
		resp.Err = err.Error()
	}

	return resp
}

func (h *KubeHandler) PodStatus(req *remote.PodStatusRequest) common.Response {
	glog.V(4).Infof("PodStatus with request %v", req)

	var resp common.Response
	ip, err := h.driver.PodStatus(req.PodName, req.Namespace, req.PodInfraContainerID, req.Network, req.ContainerRuntime)
	if err != nil {
		glog.Errorf("PodStatus failed: %v", err)
		resp.Err = err.Error()
	} else {
		resp.Result = &remote.PodStatusResult{IP: ip}
	}

	return resp
}
