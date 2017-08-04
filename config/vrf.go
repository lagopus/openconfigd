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
	"strings"
	"time"
	//"net"

	log "github.com/sirupsen/logrus"
	//"github.com/coreswitch/netutil"
	"github.com/mitchellh/mapstructure"
)

type IPv4Addr struct {
	Ip string `mapstructure:"ip" json:"ip,omitempty"`
}

type IPv4 struct {
	Address []IPv4Addr `mapstructure:"address" json:"address,omitempty"`
}

type Vlan struct {
	VlanId int `mapstructure:"vlan-id" json:"vlan-id,omitempty"`
}

type Hub struct {
	Address string `mapstructure:"address" json:"address,omitempty"`
}

type Interface struct {
	IPv4           IPv4   `mapstructure:"ipv4" json:"ipv4,omitempty"`
	Vlans          []Vlan `mapstructure:"vlans" json:"vlans,omitempty"`
	Name           string `mapstructure:"name" json:"name,omitempty"`
	DhcpRelayGroup string `mapstructure:"dhcp-relay-group" json:"dhcp-relay-group,omitempty"`
}

type Interfaces struct {
	Interface []Interface `mapstructure:"interface" json:"interface,omitempty"`
}

type Static struct {
	Route Route `mapstructure:"route" json:"route,omitempty"`
}

type QuaggaBgp struct {
	CiscoConfig string `mapstructure:"cisco-config" json:"cisco-config,omitempty"`
	Interface   string `mapstructure:"interface" json:"interface,omitempty"`
}

type VrfsConfig struct {
	Name       string      `mapstructure:"name" json:"name,omitempty"`
	Id         int         `mapstructure:"vrf_id" json:"vrf_id,omitempty"`
	Rd         string      `mapstructure:"rd" json:"rd,omitempty"`
	RtImport   string      `mapstructure:"rt_import" json:"rt_import,omitempty"`
	RtExport   string      `mapstructure:"rt_export" json:"rt_export,omitempty"`
	RtBoth     string      `mapstructure:"rt_both" json:"rt_both,omitempty"`
	VrfRibs    []VrfRib    `mapstructure:"ribs" json:"ribs,omitempty"`
	Hubs       []Hub       `mapstructure:"hubs" json:"hubs,omitempty"`
	Interfaces Interfaces  `mapstructure:"interfaces" json:"interfaces,omitempty"`
	Vrrp       []Vrrp      `mapstructure:"vrrp" json:"vrrp,omitempty"`
	Dhcp       Dhcp        `mapstructure:"dhcp" json:"dhcp,omitempty"`
	Static     Static      `mapstructure:"static" json:"static,omitempty"`
	Bgp        []QuaggaBgp `mapstructure:"bgp" json:"bgp,omitempty"`
}

func EtcdVrfVlanSubinterfacesDelete(vrf *VrfsConfig) {
	for _, ifp := range vrf.Interfaces.Interface {
		for _, Vlan := range ifp.Vlans {
			ExecLine(fmt.Sprintf("delete interfaces interface %s vlans %d", ifp.Name, Vlan.VlanId))
		}
	}
	Commit()
}

func EtcdVrfAddressClear(vrfId int, vrf *VrfsConfig) {
	for _, ifp := range vrf.Interfaces.Interface {
		ExecLine(fmt.Sprintf("delete interfaces interface %s ipv4", ifp.Name))
		Commit()
		ExecLine(fmt.Sprintf("delete interfaces interface %s vrf vrf%d", ifp.Name, vrfId))
		if ifp.DhcpRelayGroup != "" {
			ExecLine(fmt.Sprintf("delete interfaces interface %s dhcp-relay-group %s", ifp.Name, ifp.DhcpRelayGroup))
		}
	}
}

func EtcdVrfVlanSubinterfacesAdd(vrf *VrfsConfig) {
	for _, ifp := range vrf.Interfaces.Interface {
		for _, Vlan := range ifp.Vlans {
			ExecLine(fmt.Sprintf("set interfaces interface %s vlans %d", ifp.Name, Vlan.VlanId))
		}
	}

	Commit()
}

// TODO: Return failure if we finally fail.
// TODO: Generic failure recovery mechanism for any configuration set
func ExecLineWaitIfNoMatch(command string) {
	loopCount := 0
	for {
		result := ExecLine(command)
		if strings.TrimRight(result, "\n") != "NoMatch" {
			break
		} else {
			if loopCount == 10 {
				fmt.Println("Execution of command failed", command)
			}
			loopCount++
			time.Sleep(1 * time.Second)
		}
	}
}

func EtcdVrfAddressAdd(vrfId int, vrf *VrfsConfig) {
	for _, ifp := range vrf.Interfaces.Interface {
		// Wait for Ribd to create the interface in case we get NoMatch
		ExecLineWaitIfNoMatch(fmt.Sprintf("set interfaces interface %s", ifp.Name))
		ExecLine(fmt.Sprintf("set interfaces interface %s vrf vrf%d", ifp.Name, vrfId))
		for _, addr := range ifp.IPv4.Address {
			ExecLine(fmt.Sprintf("set interfaces interface %s ipv4 address %s", ifp.Name, addr.Ip))
		}
		if ifp.DhcpRelayGroup != "" {
			ExecLine(fmt.Sprintf("set interfaces interface %s dhcp-relay-group %s", ifp.Name, ifp.DhcpRelayGroup))
		}
	}
}

func EtcdVrfSync(vrfId int, vrf *VrfsConfig) {
	ExecLine(fmt.Sprintf("set vrf name vrf%d", vrfId))
	if vrfConfig, ok := EtcdVrfMap[vrfId]; ok {
		EtcdVrfAddressClear(vrfId, &vrfConfig)
		EtcdVrfVlanSubinterfacesDelete(&vrfConfig)
	}
	EtcdVrfVlanSubinterfacesAdd(vrf)
	EtcdVrfAddressAdd(vrfId, vrf)
	Commit()
}

func EtcdVrfDelete(vrfId int) {
	fmt.Println("EtcdVrfDelete:", vrfId)
	if vrfConfig, ok := EtcdVrfMap[vrfId]; ok {
		EtcdVrfAddressClear(vrfId, &vrfConfig)
		EtcdVrfVlanSubinterfacesDelete(&vrfConfig)
		// ExecLine(fmt.Sprintf("delete vrf name vrf%d", vrfId))
		Commit()
	} else {
		fmt.Println("EtcdVrfDelete: can't find vrf cache for", vrfId)
	}
}

func (vrf *VrfsConfig) Copy() VrfConfig {
	var vrfConfig VrfConfig
	vrfConfig.Name = vrf.Name
	vrfConfig.VrfId = vrf.Id
	vrfConfig.Rd = vrf.Rd
	vrfConfig.RtImport = vrf.RtImport
	vrfConfig.RtExport = vrf.RtExport
	vrfConfig.RtBoth = vrf.RtBoth
	for _, rib := range vrf.VrfRibs {
		vrfConfig.VrfRibs = append(vrfConfig.VrfRibs, rib)
	}
	for _, hub := range vrf.Hubs {
		vrfConfig.Hubs = append(vrfConfig.Hubs, hub)
	}
	return vrfConfig
}

var EtcdVrfMap = map[int]VrfsConfig{}

func VrfParse(vrfId int, jsonStr string) {
	var jsonIntf interface{}
	err := json.Unmarshal([]byte(jsonStr), &jsonIntf)
	if err != nil {
		log.WithFields(log.Fields{
			"json":  jsonStr,
			"error": err,
		}).Error("VrfParse:json.Unmarshal()")
		return
	}

	var vrf VrfsConfig
	err = mapstructure.Decode(jsonIntf, &vrf)
	if err != nil {
		log.WithFields(log.Fields{
			"json-intf": jsonIntf,
			"error":     err,
		}).Error("VrfParse:mapstructure.Decode()")
		return
	}

	// Vrf Sync.
	EtcdVrfSync(vrfId, &vrf)
	DhcpVrfSync(vrfId, &vrf)
	VrrpVrfSync(vrfId, &vrf)
	QuaggaVrfSync(vrfId, &vrf)

	// GoBGP VrfConfig
	vrfConfig := vrf.Copy()
	GobgpVrfUpdate(vrfConfig)
	GobgpHubUpdate(vrfConfig)

	EtcdVrfMap[vrfId] = vrf

	fmt.Println("VrfParse ends here")
}

func VrfDelete(vrfId int) {
	// GoBGP VRF
	GobgpVrfDelete(vrfId)
	GobgpHubDelete(vrfId)

	// Vrf Sync.
	DhcpVrfDelete(vrfId)
	VrrpVrfDelete(vrfId)
	QuaggaVrfDelete(vrfId)
	EtcdVrfDelete(vrfId)

	delete(EtcdVrfMap, vrfId)

	fmt.Println("VrfDelete ends here")
}
