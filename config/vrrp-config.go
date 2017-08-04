// Generated by pyang using OpenConfig https://github.com/openconfig/public.

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
	"fmt"
)

// typedef for identity vrrp:state
type State string

const (
	STATE_MASTER State = "master"
	STATE_BACKUP State = "backup"
)

var StateToIntMap = map[State]int{
	STATE_MASTER: 0,
	STATE_BACKUP: 1,
}

func (v State) ToInt() int {
	i, ok := StateToIntMap[v]
	if !ok {
		return -1
	}
	return i
}

var IntToStateMap = map[int]State{
	0: STATE_MASTER,
	1: STATE_BACKUP,
}

func (v State) Validate() error {
	if _, ok := StateToIntMap[v]; !ok {
		return fmt.Errorf("invalid State: %s", v)
	}
	return nil
}

//struct for container vrrp:unicast-peer
type UnicastPeer struct {
	// original -> vrrp:address
	//vrrp:address's original type is inet:ipv4-address
	Address string `mapstructure:"address" json:"address,omitempty"`
}

func (lhs *UnicastPeer) Equal(rhs *UnicastPeer) bool {
	if lhs == nil || rhs == nil {
		return false
	}
	if lhs.Address != rhs.Address {
		return false
	}
	return true
}

//struct for container vrrp:vrrp
type Vrrp struct {
	// original -> vrrp:vrid
	Vrid uint8 `mapstructure:"vrid" json:"vrid,omitempty"`
	// original -> vrrp:interface
	Interface string `mapstructure:"interface" json:"interface,omitempty"`
	// original -> vrrp:vrrp-state
	State State `mapstructure:"state" json:"state,omitempty"`
	// original -> vrrp:virtual-address
	//vrrp:virtual-address's original type is inet:ipv4-address
	VirtualAddress string `mapstructure:"virtual-address" json:"virtual-address,omitempty"`
	// original -> vrrp:priority
	Priority uint8 `mapstructure:"priority" json:"priority,omitempty"`
	// original -> vrrp:advertisement-interval
	AdvertisementInterval uint8 `mapstructure:"advertisement-interval" json:"advertisement-interval,omitempty"`
	// original -> vrrp:unicast-peer
	UnicastPeerList []UnicastPeer `mapstructure:"unicast-peer" json:"unicast-peer,omitempty"`
	// original -> vrrp:authentication-key
	AuthenticationKey string `mapstructure:"authentication-key" json:"authentication-key,omitempty"`
	// original -> vrrp:preempt
	//vrrp:preempt's original type is empty
	Preempt bool `mapstructure:"preempt" json:"preempt,omitempty"`
	// manual addition.
	Vrf string `mapstructure:"vrf" json:"vrf,omitempty"`
}

func (lhs *Vrrp) Equal(rhs *Vrrp) bool {
	if lhs == nil || rhs == nil {
		return false
	}
	if lhs.Vrid != rhs.Vrid {
		return false
	}
	if lhs.Interface != rhs.Interface {
		return false
	}
	if lhs.VirtualAddress != rhs.VirtualAddress {
		return false
	}
	if lhs.Priority != rhs.Priority {
		return false
	}
	if lhs.AdvertisementInterval != rhs.AdvertisementInterval {
		return false
	}
	if len(lhs.UnicastPeerList) != len(rhs.UnicastPeerList) {
		return false
	}
	{
		lmap := make(map[string]*UnicastPeer)
		for i, l := range lhs.UnicastPeerList {
			lmap[mapkey(i, string(l.Address))] = &lhs.UnicastPeerList[i]
		}
		for i, r := range rhs.UnicastPeerList {
			if l, y := lmap[mapkey(i, string(r.Address))]; !y {
				return false
			} else if !r.Equal(l) {
				return false
			}
		}
	}
	if lhs.AuthenticationKey != rhs.AuthenticationKey {
		return false
	}
	if lhs.Preempt != rhs.Preempt {
		return false
	}
	return true
}
