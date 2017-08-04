// Copyright 2017 OpenConfigd Project.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/clientv3/concurrency"
	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

type JsonBody struct {
	Value   string
	Body    string `mapstructure:"body"`
	Version int    `mapstructure:"version"`
}

var (
	// `etcd' endpoints as described in etcdctl help: --endpoints value a
	// comma-delimited list of machine addresses in the cluster (default:
	// "http://127.0.0.1:2379,http://127.0.0.1:4001")
	etcdEndpoints []string

	// etcd watch path.
	etcdPath string

	// Exit function.
	etcdExitFunc func()

	// Wait group for etcd wathcer.
	etcdWaitGroup sync.WaitGroup

	// Timer for reconnect.
	etcdTimer *time.Timer

	// Last etcd value.
	etcdLastValue string

	// Last etcd value as JSON.
	etcdLastJson    JsonBody
	etcdLastVrfJson JsonBody
	etcdBgpWanJson  JsonBody

	// Value map.
	etcdKeyValueMap = map[string]*JsonBody{}

	// Callback.
	etcdCallbackRegistered bool
)

func EtcdPathApi(set bool, Args []interface{}) {
	if len(Args) != 1 {
		return
	}
	path := Args[0].(string)
	if set {
		etcdPath = path
	} else {
		etcdPath = ""
	}
	EtcdWatchUpdate()
}

func EtcdEndpointsApi(set bool, Args []interface{}) {
	if len(Args) != 1 {
		return
	}
	endPoint := Args[0].(string)
	if set {
		EtcdEndpointsAdd(endPoint)
	} else {
		EtcdEndpointsDelete(endPoint)
	}
}

func EtcdRegisterCallback(callback chan bool, exiting chan struct{}) {
	if !etcdCallbackRegistered {
		etcdCallbackRegistered = true
		go func() {
			timer := time.NewTimer(time.Second * 1)
			select {
			case <-exiting:
				fmt.Println("EtcdRegisterCallback is canceled")
				timer.Stop()
			case <-timer.C:
				callback <- true
			}
		}()
	}
}

func EtcdKeepWatch(cli *clientv3.Client, ctx context.Context, ctxS context.Context, watchPoint string, exiting chan struct{}, callback chan bool) {
	// Get
	resp, err := cli.Get(ctx, watchPoint, clientv3.WithPrefix())
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("EtcdWatchStart:cli.Get()")
	}
	for _, ev := range resp.Kvs {
		EtcdKeyValueParse(ev.Key, ev.Value, true)
		EtcdRegisterCallback(callback, exiting)
	}

	fmt.Println("EtcdKeepWatch started")
	session, err := concurrency.NewSession(cli, concurrency.WithContext(ctxS), concurrency.WithTTL(3))
	fmt.Println("EtcdKeepWatch session created", session)
	if err != nil {
		return
	}

	// Watch
	rch := cli.Watch(ctx, watchPoint, clientv3.WithPrefix())
	fmt.Println("[etcd]watching")
	for {
		select {
		case wresp := <-rch:
			fmt.Println("[etcd]watch chan returns")
			err = wresp.Err()
			if err != nil {
				fmt.Println("err", err)
			}
			for _, ev := range wresp.Events {
				switch ev.Type {
				case clientv3.EventTypePut:
					fmt.Println("[etcd]watch EventTypePut")
					EtcdKeyValueParse(ev.Kv.Key, ev.Kv.Value, false)
					EtcdRegisterCallback(callback, exiting)
				case clientv3.EventTypeDelete:
					fmt.Println("[etcd]watch EventTypeDelete")
					EtcdKeyDelete(ev.Kv.Key)
					EtcdRegisterCallback(callback, exiting)
				default:
				}
			}
		case <-exiting:
			fmt.Println("[eccd]exit called")
			return
		case run := <-callback:
			// fmt.Println("callback is called", run)
			etcdCallbackRegistered = false
			if run {
				// fmt.Println("call callback function here")
			}
		case <-session.Done():
			fmt.Println("[etcd]Session timeout")
			return
		}
	}

}

func EtcdWatchStart(cfg clientv3.Config, watchPoint string) func() {
	ctx, cancel := context.WithCancel(context.Background())
	ctxS, cancelS := context.WithCancel(context.Background())
	exiting := make(chan struct{})
	callback := make(chan bool)

	etcdWaitGroup.Add(1)
	go func() {
		defer etcdWaitGroup.Done()

		var cli *clientv3.Client
		var err error

		for {
			cli, err = clientv3.New(cfg)
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("EtcdWatchStart:clientv3.New()")
				etcdTimer = time.NewTimer(time.Second * 3)
				select {
				case <-etcdTimer.C:
					etcdTimer = nil
					continue
				case <-exiting:
					etcdTimer.Stop()
					etcdTimer = nil
					return
				}
			}
			defer func(c *clientv3.Client) { c.Close() }(cli)
			break
		}

		for {
			fmt.Println("[etcd]Start of EtcdKeepWatch")
			EtcdKeepWatch(cli, ctx, ctxS, watchPoint, exiting, callback)
			select {
			case <-exiting:
				return
			default:
				fmt.Println("[etcd]EtcdKeepWatch failed start timer")
				etcdTimer = time.NewTimer(time.Second * 3)
				select {
				case <-exiting:
					fmt.Println("[etcd]EtcdKeepWatch exiting last")
					etcdTimer.Stop()
					etcdTimer = nil
					return
				case <-etcdTimer.C:
					fmt.Println("[etcd]EtcdKeepWatch timer expired")
					etcdTimer = nil
				}
			}
		}
	}()

	return func() {
		cancelS()
		cancel()
		close(exiting)
		close(callback)
	}
}

func EtcdWatchStop() {
	if etcdExitFunc != nil {
		etcdExitFunc()
		etcdExitFunc = nil
		etcdWaitGroup.Wait()
	}
}

// Update etcd endpoints.
func EtcdWatchUpdate() {
	// Stop current etcd watch.
	EtcdWatchStop()

	// No path is specivied.
	if etcdPath == "" {
		return
	}

	// No endpoints just return.
	if len(etcdEndpoints) == 0 {
		return
	}

	cfg := clientv3.Config{
		Endpoints:   etcdEndpoints,
		DialTimeout: 3 * time.Second,
	}

	etcdExitFunc = EtcdWatchStart(cfg, etcdPath)
}

// Add etcd endpoint.
func EtcdEndpointsAdd(endPoint string) {
	etcdEndpoints = append(etcdEndpoints, endPoint)
	EtcdWatchUpdate()
}

// Delete etcd endpoint.
func EtcdEndpointsDelete(endPoint string) {
	EndPoints := []string{}
	for _, ep := range etcdEndpoints {
		if ep != endPoint {
			EndPoints = append(EndPoints, ep)
		}
	}
	etcdEndpoints = EndPoints
	EtcdWatchUpdate()
}

func EtcdEndpointsShow() (str string) {
	str = "Etcd Path Config: " + etcdPath + "\n"
	if etcdExitFunc == nil {
		if etcdPath == "" {
			str += "Etcd Status: etcd path is not configured\n"
		}
		if len(etcdEndpoints) == 0 {
			str += "Etcd Status: etcd endpoint is not configured\n"
		}
		return
	}
	if etcdTimer != nil {
		str += "Etcd Status: not connected (retrying)\n"
	} else {
		str += "Etcd Status: connected (watching)\n"
	}
	for _, endPoint := range etcdEndpoints {
		str += "Etcd Endpoints: " + endPoint + "\n"
	}
	if etcdPath != "" {
		str += "Etcd Watch Path: " + etcdPath + "\n"
	}
	return
}

func EtcdTrimServicesPrefix(keyStr string) []string {
	path := strings.Split(keyStr, "/")
	// First path would be "/config" or "/local".
	if len(path) > 2 {
		if path[1] == "config" || path[1] == "local" {
			for pos, p := range path {
				if p == "services" {
					path = path[pos+1:]
					return path
				}
			}
		}
	}
	return []string{}
}

func EtcdKeyValueParse(key, value []byte, get bool) {
	var jsonIntf interface{}
	err := json.Unmarshal(value, &jsonIntf)
	if err != nil {
		log.WithFields(log.Fields{
			"json":  string(value),
			"error": err,
		}).Error("EtcdKeyValueParse:json.Unmarshal()")
		return
	}

	jsonBody := &JsonBody{}
	err = mapstructure.Decode(jsonIntf, jsonBody)
	if err != nil {
		log.WithFields(log.Fields{
			"json-intf": jsonIntf,
			"error":     err,
		}).Error("EtcdKeyValueParse:mapstructure.Decode()")
		return
	}

	// Store etcd value to map.
	keyStr := string(key)
	etcdKeyValueMap[keyStr] = jsonBody

	// Path of subscription.
	path := EtcdTrimServicesPrefix(keyStr)
	if len(path) < 1 {
		log.WithFields(log.Fields{
			"path":  keyStr,
			"error": "path length is smaller than 1 after trimming services prefix",
		}).Error("EtcdKeyValueParse:EtcdTrimServicesPrefix()")
		return
	}

	fmt.Println("[etcd]Path Put:", path)

	switch path[0] {
	case "bgp":
		etcdLastValue = string(value)
		etcdLastJson = *jsonBody
		GobgpParse(jsonBody.Body)
	case "vrf":
		etcdLastVrfJson = *jsonBody
		vrfId := 0
		if len(path) > 1 {
			vrfId, _ = strconv.Atoi(path[1])
		}
		if vrfId == 0 {
			return
		}
		VrfParse(vrfId, jsonBody.Body)
	case "bgp_wan":
		etcdBgpWanJson = *jsonBody
		GobgpWanParse(jsonBody.Body)
	case "command":
		if get {
			return
		}
		switch path[1] {
		case "dhcp":
			DhcpStatusUpdate()
		case "bgp_lan":
			QuaggaStatusUpdate()
		case "bgp_wan":
			GobgpStatusUpdate()
		}
	}
}

func EtcdKeyDelete(key []byte) {
	// Delete etcd value from map.
	keyStr := string(key)
	delete(etcdKeyValueMap, keyStr)

	// Path of subscription.
	path := EtcdTrimServicesPrefix(keyStr)
	if len(path) < 1 {
		log.WithFields(log.Fields{
			"path":  keyStr,
			"error": "path length is smaller than 1 after trimming services prefix",
		}).Error("EtcdKeyValueParse:EtcdTrimServicesPrefix()")
		return
	}

	fmt.Println("Path Delete:", path)

	switch path[0] {
	case "bgp":
		// etcdLastValue = string(value)
		// etcdLastJson = *jsonBody
		// GobgpParse(jsonBody.Body)
	case "vrf":
		vrfId := 0
		if len(path) > 1 {
			vrfId, _ = strconv.Atoi(path[1])
		}
		if vrfId == 0 {
			return
		}
		if len(path) > 2 && path[2] == "bgp" {
			QuaggaDelete(vrfId)
		} else {
			VrfDelete(vrfId)
		}
	case "bgp_wan":
		GobgpWanStop()
	}
}

// Show function
func showSystemEtcd(Args []string) (inst int, instStr string) {
	inst = CliSuccessShow
	instStr = EtcdEndpointsShow()
	return
}

// configure# etcd json
// configure# etcd body
// configure" etcd version
func configureEtcdJsonFunc(Args []string) (inst int, instStr string) {
	inst = CliSuccessShow
	instStr = etcdLastValue
	return
}

func configureEtcdBodyFunc(Args []string) (inst int, instStr string) {
	inst = CliSuccessShow
	instStr = etcdLastJson.Body
	return
}

func configureEtcdVersionFunc(Args []string) (inst int, instStr string) {
	inst = CliSuccessShow
	instStr = strconv.Itoa(etcdLastJson.Version)
	return
}

func configureEtcdBodyFunc2(Args []string) (inst int, instStr string) {
	inst = CliSuccessShow
	instStr = etcdLastVrfJson.Body
	return
}

func configureEtcdVersionFunc2(Args []string) (inst int, instStr string) {
	inst = CliSuccessShow
	instStr = strconv.Itoa(etcdLastVrfJson.Version)
	return
}

func configureEtcdBgpWanBodyFunc(Args []string) (inst int, instStr string) {
	inst = CliSuccessShow
	instStr = etcdBgpWanJson.Body
	return
}
