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

package common

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

const (
	DefaultContentType = "appplication/json"
	KubestackSpecDir   = "/usr/lib/kubernetes/plugins"
	KubestackSockDir   = "/usr/lib/kubernetes/plugins"
)

type Request interface{}

type Response struct {
	Result interface{} `json:"Result"`
	Err    string      `json:"Err"`
}

type actionKubeHandler func(interface{}) Response

func DecodeRequest(w http.ResponseWriter, r *http.Request, req interface{}) (err error) {
	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	return
}

func EncodeResponse(w http.ResponseWriter, res Response) {
	w.Header().Set("Content-Type", DefaultContentType)
	json.NewEncoder(w).Encode(res)
}

func ErrorResponse(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", DefaultContentType)
	res := Response{Err: err.Error()}
	json.NewEncoder(w).Encode(res)
}

func WriteSpec(name, addr, dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	spec := filepath.Join(dir, name+".spec")
	url := "tcp://" + addr
	return ioutil.WriteFile(spec, []byte(url), 0644)
}

func FullSocketAddr(addr, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	if filepath.IsAbs(addr) {
		return addr, nil
	}

	return filepath.Join(dir, addr+".sock"), nil
}
