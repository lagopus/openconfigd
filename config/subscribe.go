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
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"sync"
	"time"

	rpc "github.com/lagopus/openconfigd/proto"
)

var (
	RootPath       = &Path{Map: PathMap{}}
	SubscribeMap   = map[*Subscriber]struct{}{}
	SubscribeWg    sync.WaitGroup
	SubscribeMutex sync.RWMutex
	ValidateCount  int
)

type Path struct {
	Name    string
	Parent  *Path
	Map     PathMap
	Refcnt  uint32
	SubPath []SubPath
}

type PathMap map[string]*Path

type SubPath interface {
	Len() int
	Append([]string, *Command)
	RegisterPath([]string)
	Commit()
	Path() *Path
	Sync() bool
	CommandClear()
}

type SubPathBase struct {
	path *Path
	//cmd  []*Command
	pathcmd map[string][]*Command
	sync    bool
	json    bool
}

type SubPathJsonCallback func([]string, string) error

type SubPathLocal struct {
	SubPathBase
	json SubPathJsonCallback
}

type SubPathRemote struct {
	SubPathBase
	sub *Subscriber
}

func (subPath *SubPathBase) Len() int {
	num := 0
	for _, cmd := range subPath.pathcmd {
		num += len(cmd)
	}
	return num
}

func (subPath *SubPathBase) Sync() bool {
	return subPath.sync
}

func (subPath *SubPathBase) Append(path []string, cmd *Command) {
	pathStr := strings.Join(path, "|")
	subPath.pathcmd[pathStr] = append(subPath.pathcmd[pathStr], cmd)
	//subPath.cmd = append(subPath.cmd, cmd)
}

func (subPath *SubPathBase) Commit() {
}

func (subPath *SubPathBase) Path() *Path {
	return subPath.path
}

func (subPath *SubPathBase) CommandClear() {
	//subPath.cmd = subPath.cmd[:0]
	subPath.pathcmd = map[string][]*Command{}
}

func (subPath *SubPathRemote) Commit() {
	//fmt.Println("[cmd]SubPathRemote:Commit() Start", subPath.path.Name)
	for _, pathcmd := range subPath.pathcmd {
		for _, cmd := range pathcmd {
			subPath.sub.SendCommand(cmd)
		}
	}
	//fmt.Println("[cmd]SubPathRemote:Commit() End", subPath.path.Name)
}

func (subPath *SubPathLocal) Commit() {
	if subPath.Len() == 0 {
		return
	}
	for pathstr, pathcmd := range subPath.pathcmd {
		if subPath.json != nil {
			path := strings.Split(pathstr, "|")
			config := configCandidate.LookupByPath(path)
			json := "{}"
			if config != nil {
				json = config.JsonMarshal()
			} else {
				fmt.Println("XXXX empty JSON", path)
			}
			subPath.json(path, json)
		} else {
			for _, cmd := range pathcmd {
				ExecCmd(cmd)
			}
		}
	}
}

type Subscriber struct {
	Type    int
	Module  string
	Port    uint32
	stream  rpc.Config_DoConfigServer
	done    chan rpc.ConfigType
	SubPath []SubPath
}

func (sub *Subscriber) SendMessage(typ rpc.ConfigType, path []string) {
	if sub.stream == nil {
		fmt.Println("[cmd]SendMessage: sub.stream is nil")
		return
	}
	msg := &rpc.ConfigReply{
		Type: typ,
		Path: path,
	}
	sub.stream.Send(msg)
}

func (sub *Subscriber) SendCommand(cmd *Command) {
	if cmd.set {
		//fmt.Println("[cmd]SendCommand set:", cmd.cmds)
		sub.SendMessage(rpc.ConfigType_SET, cmd.cmds)
	} else {
		//fmt.Println("[cmd]SendCommand del:", cmd.cmds)
		sub.SendMessage(rpc.ConfigType_DELETE, cmd.cmds)
	}
}

func (sub *Subscriber) CommitStart() {
	sub.SendMessage(rpc.ConfigType_COMMIT_START, nil)
}

func (sub *Subscriber) CommitEnd() {
	sub.SendMessage(rpc.ConfigType_COMMIT_END, nil)
}

func (sub *Subscriber) ValidateStart() {
	sub.SendMessage(rpc.ConfigType_VALIDATE_START, nil)
}

func (sub *Subscriber) ValidateEnd() {
	sub.SendMessage(rpc.ConfigType_VALIDATE_END, nil)
}

func PathRegisterCommand(p *Path, c *Command, sync bool) {
	var lastMatch *Path
	var path []string
Loop:
	for _, lit := range c.cmds {
		match := p.Map[lit]
		if match == nil {
			match = p.Map["*"]
			if match == nil {
				break Loop
			}
		}
		path = append(path, lit)

		if len(match.SubPath) > 0 {
			lastMatch = match
		}
		p = match
	}

	if lastMatch != nil {
		//fmt.Println("[cmd]PathRegister", c.cmds)
		for _, subPath := range lastMatch.SubPath {
			if sync {
				if subPath.Sync() {
					subPath.Append(path, c)
				}
			} else {
				subPath.Append(path, c)
			}
		}
	}
}

func (sub *Subscriber) HasCommand() bool {
	num := 0
	for _, subPath := range sub.SubPath {
		num += subPath.Len()
	}
	return num != 0
}

func (sub *Subscriber) Commit() {
	if !sub.HasCommand() {
		return
	}
	sub.CommitStart()
	for _, subPath := range sub.SubPath {
		subPath.Commit()
		subPath.CommandClear()
	}
	sub.CommitEnd()
}

func (sub *Subscriber) CommandClear() {
	for _, subPath := range sub.SubPath {
		subPath.CommandClear()
	}
}

func (sub *Subscriber) Validate() {
	if sub.stream == nil {
		return
	}
	if !sub.HasCommand() {
		return
	}
	SubscribeWg.Add(1)
	ValidateCount++
	go func() {
		defer func() {
			SubscribeWg.Done()
			close(sub.done)
			sub.done = nil
		}()

		sub.done = make(chan rpc.ConfigType)

		sub.ValidateStart()
		for _, subPath := range sub.SubPath {
			subPath.Commit()
		}
		sub.ValidateEnd()

		// Wait for the result.
		timer := time.NewTimer(time.Second * 3)
		select {
		case <-timer.C:
			//fmt.Println("Timeout...")
			sub.CommandClear()
		case done := <-sub.done:
			timer.Stop()
			if done == rpc.ConfigType_VALIDATE_SUCCESS {
				ValidateCount--
			} else {
				sub.CommandClear()
			}
		}
	}()
}

func SubscribeLookup(stream rpc.Config_DoConfigServer) *Subscriber {
	for sub := range SubscribeMap {
		if sub.stream == stream {
			return sub
		}
	}
	return nil
}

func SubscribeValidateProcess(stream rpc.Config_DoConfigServer, typ rpc.ConfigType) {
	sub := SubscribeLookup(stream)
	if sub == nil {
		return
	}
	if sub.done != nil {
		sub.done <- typ
	}
}

func SubscribeValidateResult() bool {
	SubscribeWg.Wait()
	return ValidateCount == 0
}

func Validate() bool {
	if twoPhaseCommit {
		ValidateCount = 0
		for sub := range SubscribeMap {
			sub.Validate()
		}
		if !SubscribeValidateResult() {
			return false
		}
	}
	return true
}

func Commit() bool {
	//fmt.Println("[cmd]Commit(): Start")

	//fmt.Println("Lock:Commit")
	SubscribeMutex.Lock()
	defer SubscribeMutex.Unlock()

	var entry bool
	scanner := bufio.NewScanner(bytes.NewBufferString(CompareCommand()))
	for scanner.Scan() {
		c := NewCommand(scanner.Text())
		if c != nil {
			//fmt.Println("[cmd]Regsitering:", c.cmds)
			entry = true
			PathRegisterCommand(RootPath, c, false)
		}
	}
	if !entry {
		//fmt.Println("[cmd]Commit(): End (not sync entry)")
		return true
	}

	if !Validate() {
		//fmt.Println("[cmd]Commit(): End (validation failure)")
		return false
	}

	for sub := range SubscribeMap {
		sub.Commit()
	}

	copy := configCandidate.Copy(nil)
	configActive = copy

	if !zeroConfig {
		RollbackRevisionIncrement()
		configActive.WriteTo(configActiveFile+".0", "cli")
	}

	//fmt.Println("[cmd]Commit(): Done")

	return true
}

func SubscribeSync() bool {
	// Itegate command and register command.
	for _, line := range configActive.CommandList(nil) {
		PathRegisterCommand(RootPath, line.Command(), true)
	}

	// if !Validate() {
	// 	return false
	// }

	for sub := range SubscribeMap {
		sub.Commit()
	}
	return true
}

func SubscribePortLookup(name string) uint32 {
	for sub := range SubscribeMap {
		if sub.Module == name {
			return sub.Port
		}
	}
	return 0
}

func NewPath(name string, parent *Path) *Path {
	return &Path{Name: name, Parent: parent, Map: PathMap{}}
}

func (subPath *SubPathBase) RegisterPath(paths []string) {
	path := RootPath
	for _, p := range paths {
		next := path.Map[p]
		if next == nil {
			next = NewPath(p, path)
			path.Map[p] = next
		}
		path = next
		path.Refcnt++
	}
	path.SubPath = append(path.SubPath, subPath)
	subPath.path = path
}

func UnregisterPath(p *Path) {
	parent := p.Parent
	if parent != nil {
		p.Refcnt--
		if p.Refcnt == 0 {
			delete(parent.Map, p.Name)
		}
		UnregisterPath(p.Parent)
	}
}

func SubscribeLocalAdd(path []string, json SubPathJsonCallback) {
	// fmt.Println("Lock:SubscribeLocalAdd")
	SubscribeMutex.Lock()
	defer SubscribeMutex.Unlock()

	sub := SubscribeLookup(nil)
	if sub == nil {
		sub = &Subscriber{Module: "local"}
		SubscribeMap[sub] = struct{}{}
	}
	subPath := &SubPathLocal{}
	subPath.pathcmd = map[string][]*Command{}
	if json != nil {
		subPath.json = json
	}
	subPath.RegisterPath(path)
	sub.SubPath = append(sub.SubPath, subPath)

	//SubscribeDump()
}

func SubscribeRemoteAdd(stream rpc.Config_DoConfigServer, req *rpc.ConfigRequest) {
	//fmt.Println("[sub]SubscribeRemoteAdd:", req.Module)
	//fmt.Println("Lock:SubscribeRemoteAdd")
	SubscribeMutex.Lock()
	defer SubscribeMutex.Unlock()

	if req.Module == "ribd" {
		RIBD_SYNCHRONIZED = true
	}

	sub := SubscribeLookup(stream)
	if sub == nil {
		sub = &Subscriber{Module: req.Module, Port: req.Port, stream: stream}
		SubscribeMap[sub] = struct{}{}
	}

	// Registration
	subPath := &SubPathRemote{sub: sub}
	subPath.pathcmd = map[string][]*Command{}
	subPath.sync = true
	subPath.RegisterPath(req.Path)
	sub.SubPath = append(sub.SubPath, subPath)

	// Sync
	SubscribeSync()

	// Clear sync flag.
	subPath.sync = false

	//SubscribeDump()
}

func SubscribeRemoteAddMulti(stream rpc.Config_DoConfigServer, req *rpc.ConfigRequest) {
	//fmt.Println("[sub]SubscribeRemoteAddMulti:", req.Module)
	//fmt.Println("Lock:SubscribeRemoteAddMulti")
	SubscribeMutex.Lock()
	defer SubscribeMutex.Unlock()

	if req.Module == "ribd" {
		RIBD_SYNCHRONIZED = true
	}

	sub := SubscribeLookup(stream)
	if sub == nil {
		sub = &Subscriber{Module: req.Module, Port: req.Port, stream: stream}
		SubscribeMap[sub] = struct{}{}
	}

	// Registration
	subPathList := []*SubPathRemote{}
	for _, path := range req.Path {
		subPath := &SubPathRemote{sub: sub}
		subPath.pathcmd = map[string][]*Command{}
		subPath.sync = true
		subPath.RegisterPath([]string{path})
		sub.SubPath = append(sub.SubPath, subPath)
		subPathList = append(subPathList, subPath)
	}

	// Sync
	SubscribeSync()

	// Clear sync flag.
	for _, subPath := range subPathList {
		subPath.sync = false
	}

	//SubscribeDump()
}

func SubscribeDelete(stream rpc.Config_DoConfigServer) error {
	//fmt.Println("Lock:SubscribeDelete")
	SubscribeMutex.Lock()
	defer SubscribeMutex.Unlock()

	// Lookup and delete from SubscribeMap.
	sub := SubscribeLookup(stream)
	if sub == nil {
		return fmt.Errorf("Can't find Subscribe for DoConfigServer %v", stream)
	}

	// Delete each SubPath entry of the Subscriber.
	for _, subPath := range sub.SubPath {
		UnregisterPath(subPath.Path())
	}
	sub.SubPath = sub.SubPath[:0]

	if sub.done != nil {
		sub.done <- rpc.ConfigType_VALIDATE_FAILED
	}
	delete(SubscribeMap, sub)

	//SubscribeDump()
	return nil
}

func PathDump(path *Path, depth int) {
	if path.Name != "" {
		fmt.Println("+", path.Name)
	}
	for _, p := range path.Map {
		PathDump(p, depth+1)
	}
}

func SubscribeDump() {
	for sub := range SubscribeMap {
		fmt.Println("Module:", sub.Module)
	}
	fmt.Println("---")
	PathDump(RootPath, 0)
	fmt.Println("---")
}
