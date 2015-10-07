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
	"flag"
	"fmt"
	"os"

	"github.com/hyperhq/kubestack/pkg/common"
	"github.com/hyperhq/kubestack/pkg/kubestack"
)

const (
	VERSION = "0.1"
)

func main() {
	var (
		version     bool
		configFile  string
		systemGroup string
	)

	flag.BoolVar(&version, "version", false, "print version and exit")
	flag.StringVar(&configFile, "conf", "/etc/kubestack.conf",
		"openstack network controller configure file")
	flag.StringVar(&systemGroup, "group", "root", "system group this process will run as")

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
	fmt.Println(server.ServeUnix(systemGroup, "openstack"))
}
