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

package openvswitch

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strings"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/golang/glog"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/hyperhq/kubestack/pkg/exec"
	"github.com/hyperhq/kubestack/pkg/plugins"
)

const (
	pluginName = "ovs"

	runtimeTypeDocker = "docker"
	runtimeTypeRkt    = "rkt"
	runtimeTypeHyper  = "hyper"

	hyperPodSpecDir = "/var/lib/kubelet/hyper"
)

type OVSPlugin struct {
	IntegrationBridage string
}

func init() {
	plugins.RegisterNetworkPlugin(pluginName, func() (plugins.PluginInterface, error) {
		return NewOVSPlugin(), nil
	})
}

func NewOVSPlugin() *OVSPlugin {
	return &OVSPlugin{}
}

func (p *OVSPlugin) Name() string {
	return pluginName
}

func (p *OVSPlugin) Init(integrationBridge string) error {
	p.IntegrationBridage = integrationBridge
	return nil
}

func (p *OVSPlugin) buildBridgeName(portID string) string {
	return ("qbr" + portID)[:14]
}

func (p *OVSPlugin) buildTapName(portID string) (string, string) {
	return ("tap" + portID)[:14], ("vif" + portID)[:14]
}

func (p *OVSPlugin) buildVethName(portID string) (string, string) {
	return ("qvb" + portID)[:14], ("qvo" + portID)[:14]
}

func (p *OVSPlugin) SetupDockerInterface(podName, podInfraContainerID string, port *ports.Port, ipcidr, gateway string) error {
	tapName, vifName := p.buildTapName(port.ID)
	ret, err := exec.RunCommand("ip", "link", "add", tapName, "type", "veth", "peer", "name", vifName)
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return err
	}

	bridge := p.buildBridgeName(port.ID)
	ret, err = exec.RunCommand("brctl", "addif", bridge, tapName)
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return err
	}

	ret, err = exec.RunCommand("ip", "link", "set", "dev", vifName, "address", port.MACAddress)
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return err
	}

	pid, err := exec.RunCommand("docker", "inspect", "-f", "'{{.State.Pid}}'", podInfraContainerID)
	if err != nil {
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return err
	}

	netns := strings.Trim(pid[0], "'")
	ret, err = exec.RunCommand("ln", "-s", fmt.Sprintf("/proc/%s/ns/net", netns),
		fmt.Sprintf("/var/run/netns/%s", netns))
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return err
	}

	ret, err = exec.RunCommand("ip", "link", "set", vifName, "netns", netns)
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return err
	}

	ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "link", "delete", "eth0")
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return err
	}

	ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "link", "set", vifName, "down")
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return err
	}

	ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "link", "set", vifName, "name", "eth0")
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return err
	}

	ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "link", "set", "eth0", "up")
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return err
	}

	ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "addr", "add", "dev", "eth0", ipcidr)
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return err
	}

	ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "route", "add", "default", "via", gateway)
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return err
	}

	ret, err = exec.RunCommand("ip", "link", "set", "dev", tapName, "up")
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return err
	}

	_, err = exec.RunCommand("rm", "-f", fmt.Sprintf("/var/run/netns/%s", netns))
	if err != nil {
		glog.V(5).Infof("Warning: remove netns symlink failed: %v", err)
	}

	return nil
}

func (p *OVSPlugin) getHyperPodSpec(podFullName string) (string, error) {
	specFileName := path.Join(hyperPodSpecDir, podFullName)
	_, err := os.Stat(specFileName)
	if err != nil {
		return "", err
	}

	spec, err := ioutil.ReadFile(specFileName)
	if err != nil {
		return "", err
	}

	return string(spec), nil
}

func (p *OVSPlugin) saveHyperPodSpec(spec, podFullName string) error {
	// save spec to file
	specFileName := path.Join(hyperPodSpecDir, podFullName)
	err := ioutil.WriteFile(specFileName, []byte(spec), 0664)
	if err != nil {
		glog.Errorf("SaveHyperPodSpec failed: %v", err)
		return err
	}

	return nil
}

func (p *OVSPlugin) SetupHyperInterface(podName, podInfraContainerID string, port *ports.Port, ipcidr, gateway string, dnsServers []string) error {
	// Generate interfaces configure
	bridge := p.buildBridgeName(port.ID)
	tapName, _ := p.buildTapName(port.ID)
	interfaceSpec := map[string]string{
		"bridge":  bridge,
		"ifname":  tapName,
		"mac":     port.MACAddress,
		"ip":      ipcidr,
		"gateway": gateway,
	}

	// Get original hyper spec
	podSpec, err := p.getHyperPodSpec(podName)
	if err != nil {
		glog.Errorf("getHyperPodSpec failed: %v", err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeHyper)
		return err
	}

	// Add interfaces to hyper spec
	specData := make(map[string]interface{})
	err = json.Unmarshal([]byte(podSpec), &specData)
	if err != nil {
		glog.Errorf("Unmarshal %s failed: %v", podSpec, err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeHyper)
		return err
	}
	specData["interfaces"] = []map[string]string{interfaceSpec}

	// Setup dns servers
	if dns, ok := specData["dns"]; ok {
		if hosts, ok := dns.([]interface{}); ok {
			for _, host := range hosts {
				dnsServers = append(dnsServers, host.(string))
			}
			specData["dns"] = dnsServers
		}
	} else {
		specData["dns"] = dnsServers
	}

	// save spec back
	newPodSpec, err := json.Marshal(specData)
	if err != nil {
		glog.Errorf("Marshal %s failed: %v", specData, err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeHyper)
		return err
	}
	err = p.saveHyperPodSpec(string(newPodSpec), podName)
	if err != nil {
		glog.Errorf("saveHyperPodSpec failed: %v", err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeHyper)
		return err
	}

	return nil
}

func (p *OVSPlugin) SetupOVSInterface(podName, podInfraContainerID string, port *ports.Port, ipcidr, gateway string, containerRuntime string) error {
	qvb, qvo := p.buildVethName(port.ID)
	ret, err := exec.RunCommand("ip", "link", "add", qvb, "type", "veth", "peer", "name", qvo)
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
		return err
	}

	bridge := p.buildBridgeName(port.ID)
	ret, err = exec.RunCommand("brctl", "addbr", bridge)
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
		return err
	}

	ret, err = exec.RunCommand("ip", "link", "set", qvb, "up")
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
		return err
	}

	ret, err = exec.RunCommand("ip", "link", "set", qvo, "up")
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
		return err
	}

	ret, err = exec.RunCommand("ip", "link", "set", bridge, "up")
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
		return err
	}

	ret, err = exec.RunCommand("brctl", "addif", bridge, qvb)
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
		return err
	}

	ret, err = exec.RunCommand("ovs-vsctl", "-vconsole:off", "--", "--if-exists", "del-port",
		qvo, "--", "add-port", p.IntegrationBridage, qvo, "--", "set", "Interface", qvo,
		fmt.Sprintf("external_ids:attached-mac=%s", port.MACAddress),
		fmt.Sprintf("external_ids:iface-id=%s", port.ID),
		fmt.Sprintf("external_ids:vm-id=%s", podName),
		"external_ids:iface-status=active")
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
		return err
	}

	return nil
}

func (p *OVSPlugin) SetupInterface(podName, netns, podInfraContainerID string, port *ports.Port, ipcidr, gateway string, dnsServers []string, containerRuntime string) (*current.Result, error) {
	err := p.SetupOVSInterface(podName, podInfraContainerID, port, ipcidr, gateway, containerRuntime)
	if err != nil {
		glog.Errorf("SetupOVSInterface failed: %v", err)
		return nil, err
	}

	/*	switch containerRuntime {
		case runtimeTypeDocker:
			err := p.SetupDockerInterface(podName, podInfraContainerID, port, ipcidr, gateway)
			if err != nil {
				glog.Errorf("SetupDockerInterface failed: %v", err)
				return err
			}
		case runtimeTypeHyper:
			err := p.SetupHyperInterface(podName, podInfraContainerID, port, ipcidr, gateway, dnsServers)
			if err != nil {
				glog.Errorf("SetupHyperInterface failed: %v", err)
				return err
			}
		default:
			glog.V(4).Infof("SetupInterface for %s done", containerRuntime)
		}*/
	// build veth pair
	tapName, vifName := p.buildTapName(port.ID)
	ret, err := exec.RunCommand("ip", "link", "add", tapName, "type", "veth", "peer", "name", vifName)
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return nil, err
	}

	// add one veth device to bridge
	bridge := p.buildBridgeName(port.ID)
	ret, err = exec.RunCommand("brctl", "addif", bridge, tapName)
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return nil, err
	}

	ret, err = exec.RunCommand("ip", "link", "set", "dev", vifName, "address", port.MACAddress)
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return nil, err
	}

	// put another veth device into net ns
	ret, err = exec.RunCommand("ip", "link", "set", vifName, "netns", netns)
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return nil, err
	}

	ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "link", "set", vifName, "down")
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return nil, err
	}

	ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "link", "set", vifName, "name", "eth0")
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return nil, err
	}

	ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "link", "set", "eth0", "up")
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return nil, err
	}

	ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "addr", "add", "dev", "eth0", ipcidr)
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return nil, err
	}

	ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "route", "add", "default", "via", gateway)
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return nil, err
	}

	ret, err = exec.RunCommand("ip", "link", "set", "dev", tapName, "up")
	if err != nil {
		glog.Warningf("SetupInterface failed, ret:%s, error:%v", strings.Join(ret, "\n"), err)
		p.DestroyInterface(podName, podInfraContainerID, port, runtimeTypeDocker)
		return nil, err
	}

	brInterface := &current.Interface{
		Name: bridge,
		//Mac:
	}
	hostInterface := &current.Interface{
		Name: tapName,
		//Mac:
	}
	containerInterface := &current.Interface{
		Name:    "eth0",
		Mac:     port.MACAddress,
		Sandbox: netns,
	}

	_, ipnet, err := net.ParseCIDR(ipcidr)
	if err != nil {
		return nil, err
	}

	ipConfig := &current.IPConfig{
		Version: "4",
		Address: *ipnet,
		Gateway: net.ParseIP(gateway),
	}

	result := &current.Result{}
	result.Interfaces = []*current.Interface{brInterface, hostInterface, containerInterface}
	result.IPs = []*current.IPConfig{ipConfig}

	return result, nil
}

func (p *OVSPlugin) destroyOVSInterface(podName, podInfraContainerID, portID string) error {
	qvb, qvo := p.buildVethName(portID)
	bridge := p.buildBridgeName(portID)

	output, err := exec.RunCommand("brctl", "delif", bridge, qvb)
	if err != nil {
		glog.Warningf("Warning: brctl delif %s failed: %v, %v", qvb, output, err)
	}

	output, err = exec.RunCommand("ip", "link", "set", "dev", bridge, "down")
	if err != nil {
		glog.Warningf("Warning: set bridge %s down failed: %v, %v", bridge, output, err)
	}

	output, err = exec.RunCommand("brctl", "delbr", bridge)
	if err != nil {
		glog.Warningf("Warning: delete bridge %s failed: %v, %v", bridge, output, err)
	}

	output, err = exec.RunCommand("ovs-vsctl", "-vconsole:off", "--if-exists", "del-port", qvo)
	if err != nil {
		glog.Warningf("Warning: ovs del-port %s failed: %v, %v", qvo, output, err)
	}

	output, err = exec.RunCommand("ip", "link", "set", "dev", qvo, "down")
	if err != nil {
		glog.Warningf("Warning: set dev %s down failed: %v, %v", qvo, output, err)
	}

	output, err = exec.RunCommand("ip", "link", "delete", "dev", qvo)
	if err != nil {
		glog.Warningf("Warning: delete dev %s failed: %v, %v", qvo, output, err)
	}

	return nil
}

func (p *OVSPlugin) destroyDockerInterface(podName, podInfraContainerID, portID string) error {
	tapName, _ := p.buildTapName(portID)
	_, err := exec.RunCommand("ip", "link", "delete", tapName)
	if err != nil {
		glog.V(5).Infof("Warning: DestroyInterface failed: %v", err)
	}

	pid, err := exec.RunCommand("docker", "inspect", "-f", "'{{.State.Pid}}'", podInfraContainerID)
	if err != nil {
		glog.V(5).Infof("Warning: DestroyInterface failed: %v", err)
	}

	if pid != nil && len(pid) > 0 {
		netns := strings.Trim(pid[0], "'")
		_, err = exec.RunCommand("rm", "-f", fmt.Sprintf("/var/run/netns/%s", netns))
		if err != nil {
			glog.V(5).Infof("Warning: DestroyInterface failed: %v", err)
		}
	}

	return nil
}

func (p *OVSPlugin) DestroyInterface(podName, podInfraContainerID string, port *ports.Port, containerRuntime string) error {
	p.destroyOVSInterface(podName, podInfraContainerID, port.ID)

	switch containerRuntime {
	case runtimeTypeDocker:
		p.destroyDockerInterface(podName, podInfraContainerID, port.ID)
	default:
		glog.V(4).Infof("DestroyInterface for %s done", containerRuntime)
	}

	return nil
}
