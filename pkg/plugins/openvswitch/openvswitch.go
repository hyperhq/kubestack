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
    "kubestack/pkg/plugins"
	"github.com/golang/glog"
    "kubestack/pkg/exec"
	"github.com/rackspace/gophercloud/openstack/networking/v2/ports"
    "fmt"
    "strings"
)

const (
    pluginName = "ovs"
)

type OVSPlugin struct {
	IntegrationBridage string
}

func init() {
    plugins.RegisterNetworkPlugin(pluginName, func() (plugins.PluginInterface, error){
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

func (p *OVSPlugin) SetupInterface(podName, podInfraContainerID string, port *ports.Port, ipcidr, gateway string, containerRuntime string) error {
    qvb, qvo := p.buildVethName(port.ID)
    ret, err := exec.RunCommand("ip", "link", "add", qvb, "type", "veth", "peer", "name", qvo)
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    bridge := p.buildBridgeName(port.ID)
    ret, err = exec.RunCommand("brctl", "addbr", bridge)
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    ret, err = exec.RunCommand("ip", "link", "set", qvb, "up")
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    ret, err = exec.RunCommand("ip", "link", "set", qvo, "up")
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    ret, err = exec.RunCommand("ip", "link", "set", bridge, "up")
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    ret, err = exec.RunCommand("brctl", "addif", bridge, qvb)
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    tapName, vifName := p.buildTapName(port.ID)
    ret, err = exec.RunCommand("ip", "link", "add", tapName, "type", "veth", "peer", "name", vifName)
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    ret, err = exec.RunCommand("brctl", "addif", bridge, tapName)
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    ret, err = exec.RunCommand("ip", "link", "set", "dev", vifName, "address", port.MACAddress)
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
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
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    pid, err := exec.RunCommand("docker", "inspect", "-f", "'{{.State.Pid}}'", podInfraContainerID)
    if err != nil {
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    netns := strings.Trim(pid[0], "'")
    ret, err = exec.RunCommand("ln", "-s", fmt.Sprintf("/proc/%s/ns/net", netns),
        fmt.Sprintf("/var/run/netns/%s", netns))
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    ret, err = exec.RunCommand("ip", "link", "set", vifName, "netns", netns)
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "link", "delete", "eth0")
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "link", "set", vifName, "down")
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "link", "set", vifName, "name", "eth0")
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "link", "set", "eth0", "up")
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "addr", "add", "dev", "eth0", ipcidr)
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    ret, err = exec.RunCommand("ip", "netns", "exec", netns, "ip", "route", "add", "default", "via", gateway)
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    ret, err = exec.RunCommand("ip", "link", "set", "dev", tapName, "up")
    if err != nil {
        glog.Warningf("SetupInterface failed: %s", strings.Join(ret, "\n"))
        p.DestroyInterface(podName, podInfraContainerID, port, containerRuntime)
        return err
    }

    return nil
}

func (p *OVSPlugin) DestroyInterface(podName, podInfraContainerID string, port *ports.Port, containerRuntime string) error {
    _, qvo := p.buildVethName(port.ID)
    _, err := exec.RunCommand("ip", "link", "delete", qvo)
    if err != nil {
        glog.V(5).Infof("Warning: DestroyInterface failed: %v", err)
    }

    tapName, _ := p.buildTapName(port.ID)
    _, err = exec.RunCommand("ip", "link", "delete", tapName)
    if err != nil {
        glog.V(5).Infof("Warning: DestroyInterface failed: %v", err)
    }

    _, err = exec.RunCommand("ovs-vsctl", "-vconsole:off", "--if-exists", "del-port", qvo)
    if err != nil {
        glog.V(5).Infof("Warning: DestroyInterface failed: %v", err)
    }

    bridge := p.buildBridgeName(port.ID)
    _, err = exec.RunCommand("ip", "link", "set", bridge, "down")
    if err != nil {
        glog.V(5).Infof("Warning: DestroyInterface failed: %v", err)
    }

    _, err = exec.RunCommand("brctl", "delbr", bridge)
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
