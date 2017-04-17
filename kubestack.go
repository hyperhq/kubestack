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

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/hyperhq/kubestack/pkg/common"
	"github.com/hyperhq/kubestack/pkg/types"
)

const (
	VERSION    = "0.5"
	CONFIGFILE = "/etc/kubestack/kubestack.conf"
)

/*
func main() {
	var (
		version    bool
		configFile string
		port       string
	)

	flag.BoolVar(&version, "version", false, "print version and exit")
	flag.StringVar(&configFile, "conf", "/etc/kubestack.conf",
		"openstack network controller configure file")
	flag.StringVar(&port, "port", ":4237", "which port to listen on, e.g. 127.0.0.1:4237")

	flag.Parse()

	if version {
		fmt.Printf("kubestack version: %s\n", VERSION)
		os.Exit(0)
	}

	config, err := os.Open(configFile)
	if err != nil {
		fmt.Printf("Couldn't open configuration file %s: %#v", configFile, err)
		os.Exit(1)
	}
	defer config.Close()

	openstack, err := common.NewOpenStack(config)
	if err != nil {
		fmt.Printf("Couldn't initialize openstack: %#v", err)
		os.Exit(1)
	}

	server := kubestack.NewKubeHandler(openstack)
	fmt.Println(server.Serve(port))
}
*/

func loadNetConf(bytes []byte) (*types.NetConf, string, error) {
	n := &types.NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, n.CNIVersion, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	config, err := os.Open(CONFIGFILE)
	if err != nil {
		return fmt.Errorf("Couldn't open configuration file %s: %#v", CONFIGFILE, err)
	}
	defer config.Close()

	openstack, err := common.NewOpenStack(config)
	if err != nil {
		return fmt.Errorf("Couldn't initialize openstack: %#v", err)
	}

	n, cniVersion, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	n.TenantID = openstack.ToTenantID(n.TenantName)
	if err := openstack.CreateNetworkCNI(n); err != nil {
		return err
	}

	result, err := openstack.SetupPodCNI(args.ContainerID, args.Netns, args.ContainerID, n)

	return cnitypes.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
