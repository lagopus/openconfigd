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
	"os"
	"regexp"
	"strings"

	"github.com/coreswitch/cmd"
	"github.com/coreswitch/component"
	"github.com/coreswitch/goyang/pkg/yang"
)

type yangEntry struct {
	*yang.Entry
}

var (
	rootEntry *yang.Entry
)

type stateType int

const (
	DirState stateType = iota
	DirKeyState
	DirKeyMatched
	LeafState
	LeafMatched
	UnknownState
)

// need a better name
type stateValue struct {
	typ      stateType
	keyIndex int
}

var StateToString = map[stateType]string{
	DirState:      "DirState",
	DirKeyState:   "DirKeyState",
	DirKeyMatched: "DirKeyMatched",
	LeafState:     "LeafState",
	LeafMatched:   "LeafMatched",
	UnknownState:  "UnknownState",
}

func (e yangEntry) matchDir(s string) *yang.Entry {
	for _, ent := range e.Dir {
		//fmt.Println("s", "<->", ent.Name)
		if s == ent.Name {
			return ent
		}
	}
	return nil
}

func (e yangEntry) matchLeaf(s string) bool {
	if e.Type == nil {
		return false
	}

	if e.Type.Kind == yang.Yleafref {
		e.Entry = e.Find(e.Type.Path)
		if e.Entry == nil {
			return false
		}
	}

	switch e.Type.Kind {
	case yang.Yint8, yang.Yint16, yang.Yint32, yang.Yint64,
		yang.Yuint8, yang.Yuint16, yang.Yuint32, yang.Yuint64:
		num, err := yang.ParseNumber(s)
		if err != nil {
			fmt.Println(err)
			return false
		}
		for _, r := range e.Type.Range {
			if num.Less(r.Min) || r.Max.Less(num) {
				return false
			}
		}
		return true
	case yang.Ybool:
		if s == "true" || s == "false" {
			return true
		}
		return false
	case yang.Ystring:
		if len(e.Type.Pattern) > 0 {
			//fmt.Println(s, e.Type.Pattern[0])
			regex, err := regexp.Compile("^" + e.Type.Pattern[0] + "$")
			if err != nil {
				return false
			}
			//fmt.Println(regex.MatchString(s))
			return regex.MatchString(s)
		}
		return true
	case yang.Yenum:
		if _, ok := e.Type.Enum.NameMap()[s]; ok {
			return true
		}
		return false
	}
	return false
}

func (e yangEntry) hasEmptyLeaf() bool {
	if e.isLeaf() && e.Type != nil && e.Type.Kind == yang.Yempty {
		return true
	}
	return false
}

func (e yangEntry) keys() []string {
	if e.Entry == nil {
		return nil
	}
	return strings.Split(e.Key, " ")
}

func (e yangEntry) keysInclude(s string) bool {
	for _, v := range e.keys() {
		if v == s {
			return true
		}
	}

	return false
}

func (e yangEntry) keyIndexedBy(i int) string {
	ks := e.keys()
	if i < len(ks) {
		return ks[i]
	}

	return ""
}

func (e yangEntry) dir(key string) *yang.Entry {
	if !e.keysInclude(key) {
		return nil
	}

	return e.Dir[key]
}

func (e yangEntry) isDir() bool {
	if e.Kind == yang.DirectoryEntry {
		return true
	}

	return false
}

func (e yangEntry) hasKey() bool {
	if e.Key == "" {
		return false
	}

	return true
}

func (e yangEntry) isLeaf() bool {
	if e.Kind == yang.LeafEntry {
		return true
	}

	return false
}

func (e yangEntry) maxKeyIndex() int {
	len := len(e.keys())
	if len > 0 {
		return len - 1
	} else {
		return 0
	}
}

func (state stateValue) next(ent yangEntry, e yangEntry) stateValue {
	switch state.typ {
	case DirState, DirKeyMatched:
		if e.isDir() {
			if !e.hasKey() {
				return stateValue{}
			} else {
				return stateValue{typ: DirKeyState}
			}
		}
		if e.isLeaf() {
			if e.hasEmptyLeaf() {
				return stateValue{typ: LeafMatched}
			} else {
				return stateValue{typ: LeafState}
			}
		}
	case DirKeyState:
		if ent.Entry != nil && state.keyIndex < ent.maxKeyIndex() {
			return stateValue{typ: DirKeyState, keyIndex: state.keyIndex + 1}
		} else {
			return stateValue{typ: DirKeyMatched}
		}
	case LeafState:
		return stateValue{typ: LeafMatched}
	}
	return stateValue{}
}

// Next state retrieval function used only when config deletion
func (state stateValue) next2(e yangEntry) stateValue {
	switch state.typ {
	case DirState, DirKeyMatched:
		if e.isDir() {
			if !e.hasKey() {
				return stateValue{}
			} else {
				if e.Entry != nil && e.maxKeyIndex() == 0 {
					return stateValue{typ: DirKeyMatched}
				} else {
					return stateValue{typ: DirKeyState}
				}
			}
		}
		if e.isLeaf() {
			if len(e.Parent.Dir) > 1 {
				if !e.hasKey() {
					return stateValue{typ: DirState}
				} else {
					if e.Entry != nil && e.maxKeyIndex() == 0 {
						return stateValue{typ: DirKeyMatched}
					} else {
						return stateValue{typ: DirKeyState}
					}
				}
			} else {
				if e.hasEmptyLeaf() {
					return stateValue{typ: LeafMatched}
				} else {
					return stateValue{typ: LeafState}
				}
			}
		}
	case DirKeyState:
		if e.Entry != nil && state.keyIndex < e.maxKeyIndex() {
			return stateValue{typ: DirKeyState, keyIndex: state.keyIndex + 1}
		} else {
			return stateValue{typ: DirKeyMatched}
		}
	case LeafState:
		return stateValue{typ: LeafMatched}
	}
	return stateValue{}
}

func YangSet(Args []string) (inst int, instStr string) {
	SubscribeMutex.Lock()
	defer SubscribeMutex.Unlock()
	Process(Args, rootEntry, configCandidate)
	return CliSuccess, ""
}

func YangConfigPush(Args []string) {
	SubscribeMutex.Lock()
	defer SubscribeMutex.Unlock()
	//fmt.Println("Lock: YangConfigPush")
	Process(Args, rootEntry, configActive)
	Process(Args, rootEntry, configCandidate)
}

func YangDelete(Args []string) (inst int, instStr string) {
	return CliSuccess, ""
}

func (e yangEntry) isExpandable() bool {
	if e.Type.Kind == yang.Ybool || e.Type.Kind == yang.Yenum {
		return true
	} else {
		return false
	}
}

func (e yangEntry) expand() []string {
	if e.Type.Kind == yang.Ybool {
		return []string{"false", "true"}
	}
	if e.Type.Kind == yang.Yenum {
		comp := []string{}
		for key := range e.Type.Enum.NameMap() {
			comp = append(comp, key)
		}
		return comp
	}
	return nil
}

type YMatchState struct {
	match cmd.MatchType
	count int
	entry *yang.Entry
	comps cmd.CompSlice
}

type yMatchType int

const (
	YMatchTypeKeyword yMatchType = iota
	YMatchTypeNumber
	YMatchTypeString
)

func YEntryJson(e *yang.Entry) string {
	if e.Type == nil {
		return ""
	}
	if e.Type.Kind == yang.Yempty {
		return "true"
	}
	return ""
}

func YMatchNumber(e *yang.Entry, str string) (pos int, match cmd.MatchType) {
	num, err := yang.ParseNumber(str)
	if err != nil {
		return 0, cmd.MatchTypeNone
	}

	for _, r := range e.Type.Range {
		if num.Less(r.Min) || r.Max.Less(num) {
			return 0, cmd.MatchTypeNone
		}
	}

	return len(str), cmd.MatchTypeRange
}

func YMatchString(e *yang.Entry, str string) (pos int, match cmd.MatchType) {
	if len(e.Type.Pattern) == 0 {
		return 0, cmd.MatchTypeExact
	}

	regex, err := regexp.Compile("^" + e.Type.Pattern[0] + "$")
	if err != nil {
		return 0, cmd.MatchTypeNone
	}

	if !regex.MatchString(str) {
		return 0, cmd.MatchTypeNone
	}

	return 0, cmd.MatchTypeExact
}

func YMatchKeyword(e *yang.Entry, str string, name string, complete bool, state *YMatchState) {
	_, match := cmd.MatchKeyword(str, name)
	if match == cmd.MatchTypeNone {
		return
	}

	if complete {
		state.comps = append(state.comps, &cmd.Comp{Name: name})
	}
	if match > state.match {
		state.match = match
		state.entry = e
		state.count = 1
	} else if match == state.match {
		state.count++
	}
}

func yMatchNumber(e *yang.Entry, str string, complete bool) *YMatchState {
	_, match := YMatchNumber(e, str)
	if match == cmd.MatchTypeNone {
		return &YMatchState{}
	}

	state := &YMatchState{
		match: match,
		entry: e,
		count: 1,
	}

	if complete {
		state.comps = append(state.comps, &cmd.Comp{Name: "<" + e.Name + ">"})
	}

	return state
}

func yMatchString(e *yang.Entry, str string, complete bool) *YMatchState {
	_, match := YMatchString(e, str)
	if match == cmd.MatchTypeNone {
		return &YMatchState{}
	}

	state := &YMatchState{
		match: match,
		entry: e,
		count: 1,
	}

	if complete {
		state.comps = append(state.comps, &cmd.Comp{Name: "<" + e.Name + ">"})
	}

	return state
}

func yMatchBool(e *yang.Entry, str string, boolean string, complete bool) *YMatchState {
	_, match := cmd.MatchKeyword(str, boolean)
	if match == cmd.MatchTypeNone {
		return &YMatchState{}
	}

	state := &YMatchState{
		match: match,
		entry: e,
		count: 1,
	}

	if complete {
		state.comps = append(state.comps, &cmd.Comp{Name: boolean})
	}

	return state
}

// getPrefix returns the prefix and base name of s.  If s has no prefix
// then the returned prefix is "".
func getPrefix(s string) (string, string) {
	f := strings.SplitN(s, ":", 2)
	if len(f) == 1 {
		return "", s
	}
	return f[0], f[1]
}

func YMatchLeaf(e *yang.Entry, str string, complete bool) *YMatchState {
	if e.Type == nil {
		return &YMatchState{}
	}
	if e.Type.Kind == yang.Yleafref {
		e = e.Find(e.Type.Path)
		if e == nil {
			return &YMatchState{}
		}
	}

	state := &YMatchState{}
	switch e.Type.Kind {
	case yang.Yint8, yang.Yint16, yang.Yint32, yang.Yint64,
		yang.Yuint8, yang.Yuint16, yang.Yuint32, yang.Yuint64:
		return yMatchNumber(e, str, complete)
	case yang.Ystring:
		return yMatchString(e, str, complete)
	case yang.Ybool:
		state = yMatchBool(e, str, "true", complete)
		if state.match != cmd.MatchTypeNone {
			return state
		}
		return yMatchBool(e, str, "false", complete)
	case yang.Yenum:
		for name := range e.Type.Enum.NameMap() {
			YMatchKeyword(e, str, name, complete, state)
		}
	}

	return state
}

func YParseSet(param *cmd.Param) (int, cmd.Callback, []interface{}, cmd.CompSlice) {
	ent := yangEntry{rootEntry}
	comps := cmd.CompSlice{}

	// Trim "set" or "delete"
	if len(param.Command) > 0 {
		param.Command = param.Command[1:]
	}

	// When no arguments are given, fill in completion information and return.
	if param.Complete && len(param.Command) == 0 {
		for _, e := range ent.Dir {
			comps = append(comps, &cmd.Comp{Name: e.Name})
		}
		return cmd.ParseIncomplete, nil, nil, comps
	}

	var state stateValue
	var key yangEntry
	var matched yangEntry

	for _, p := range param.Command {
		status := &YMatchState{}
		switch state.typ {
		case DirState:
			for _, e := range ent.Dir {
				YMatchKeyword(e, p, e.Name, param.Complete, status)
			}
		case DirKeyMatched:
			for _, e := range ent.Dir {
				if !(ent.keysInclude(e.Name)) {
					YMatchKeyword(e, p, e.Name, param.Complete, status)
				}
			}
		case LeafState:
			status = YMatchLeaf(ent.Entry, p, param.Complete)
		case DirKeyState:
			status = YMatchLeaf(key.Entry, p, param.Complete)
		}
		comps = status.comps

		// Sync status candidates to Param's candidate
		if status.count == 0 {
			return cmd.ParseNoMatch, nil, nil, comps
		}
		if status.count > 1 {
			return cmd.ParseAmbiguous, nil, nil, comps
		}

		matched.Entry = status.entry

		//fmt.Print(p, " ", StateToString[state], "-> ")
		state = state.next(ent, matched)
		//fmt.Println(StateToString[state])

		switch state.typ {
		case DirState, LeafState:
			ent = matched
		case DirKeyState:
			if state.keyIndex == 0 {
				ent = matched
			}
			key.Entry = ent.Dir[ent.keyIndexedBy(state.keyIndex)]
			if key.Entry == nil {
				return cmd.ParseNoMatch, nil, nil, comps
			}
		case DirKeyMatched:
		case LeafMatched:
		}
	}

	if param.Complete && param.TrailingSpace {
		comps = comps[:0]
		switch state.typ {
		case DirState:
			for _, e := range ent.Dir {
				comps = append(comps, &cmd.Comp{Name: e.Name})
			}
		case LeafState:
			if ent.isExpandable() {
				for _, name := range ent.expand() {
					comps = append(comps, &cmd.Comp{Name: name})
				}
			} else {
				comps = append(comps, &cmd.Comp{Name: "<" + ent.Name + ">"})
			}
		case DirKeyState:
			comps = append(comps, &cmd.Comp{Name: "<" + key.Name + ">"})
		case DirKeyMatched:
			fmt.Println("Here we are")
			if key.Entry != nil {
				for _, e := range ent.Dir {
					if !ent.keysInclude(e.Name) {
						comps = append(comps, &cmd.Comp{Name: e.Name})
					}
				}
			}
		}
	}

	if state.typ != LeafMatched && state.typ != DirKeyMatched {
		return cmd.ParseIncomplete, nil, nil, comps
	} else {
		return cmd.ParseSuccess, YangSet, cmd.String2Interface(param.Command), comps
	}
}

func ProcessDelete(config *Config) {
	fmt.Println("SubscribeMutex.Lock ProcessDelete")
	SubscribeMutex.Lock()
	defer SubscribeMutex.Unlock()

	Delete(config, true)
}

func YParseDelete(param *cmd.Param) (int, cmd.Callback, []interface{}, cmd.CompSlice) {
	config := configCandidate
	comps := cmd.CompSlice{}

	if len(param.Command) > 0 {
		param.Command = param.Command[1:]
	}

	if param.Complete && len(param.Command) == 0 {
		for _, c := range config.Configs {
			comps = append(comps, &cmd.Comp{Name: c.Name})
		}
		return cmd.ParseIncomplete, nil, nil, comps
	}

	var state stateValue
	var latestMatch cmd.MatchType

	for _, p := range param.Command {
		match := cmd.MatchTypeNone
		var matchCount int
		var matched *Config

		latestMatch = cmd.MatchTypeNone

		if param.Complete {
			comps = comps[:0]
		}

		switch state.typ {
		case DirState, DirKeyMatched, DirKeyState:
			var configs []*Config
			if state.typ == DirKeyState || state.typ == DirKeyMatched {
				configs = config.Keys
			} else {
				configs = config.Configs
			}
			for _, c := range configs {
				_, match = cmd.MatchKeyword(p, c.Name)
				if match == cmd.MatchTypeNone {
					continue
				}
				if param.Complete {
					comps = append(comps, &cmd.Comp{Name: c.Name})
				}
				if match > latestMatch {
					latestMatch = match
					matchCount = 1
					matched = c
				} else if match == latestMatch {
					matchCount++
				}
			}
		case LeafState:
			for _, c := range config.Configs {
				_, match = cmd.MatchKeyword(p, c.Name)
				if match == cmd.MatchTypeNone {
					continue
				}
				if param.Complete {
					comps = append(comps, &cmd.Comp{Name: c.Name})
				}
				if match > latestMatch {
					latestMatch = match
					matchCount = 1
					matched = c
				} else if match == latestMatch {
					matchCount++
				}
			}
		}

		if matchCount == 0 {
			return cmd.ParseNoMatch, nil, nil, comps
		}
		if matchCount > 1 {
			return cmd.ParseAmbiguous, nil, nil, comps
		}
		config = matched

		if config.Entry != nil {
			//fmt.Println("Name", config.Name, "Key [", config.Entry.Key, "]")
			//fmt.Print(StateToString[state], "-> ")
			state = state.next2(yangEntry{config.Entry})
			//fmt.Println(StateToString[state])
		} else {
			//fmt.Println("config.Entry is nil")
		}
	}

	if param.Complete && param.TrailingSpace {
		comps = comps[:0]
		switch state.typ {
		case DirState:
			for _, c := range config.Configs {
				comps = append(comps, &cmd.Comp{Name: c.Name})
			}
		case LeafState:
			for _, c := range config.Configs {
				comps = append(comps, &cmd.Comp{Name: c.Name})
			}
		case DirKeyState, DirKeyMatched:
			for _, c := range config.Keys {
				comps = append(comps, &cmd.Comp{Name: c.Name})
			}
		}
	}

	if state.typ == LeafState || state.typ == LeafMatched || state.typ == DirKeyMatched || state.typ == DirState {
		if latestMatch != cmd.MatchTypeExact {
			return cmd.ParseIncomplete, nil, nil, comps
		} else {
			if !param.Complete {
				if config.Entry != nil && config.Entry.ReadOnlyConfig {
					return cmd.ParseNoMatch, nil, nil, nil
				} else {
					ProcessDelete(config)
				}
			}
			return cmd.ParseSuccess, YangDelete, nil, comps
		}
	}

	return cmd.ParseNoMatch, nil, nil, comps
}

func Process(path []string, ent *yang.Entry, config *Config) error {
	if ent.Kind != yang.DirectoryEntry {
		return fmt.Errorf("Top YANG entry must be container or list")
	}

	var state stateValue
	var key *yang.Entry
	var matched *yang.Entry

	for _, p := range path {
		//fmt.Printf("Parsing [%d] %s\n", pos, p)

		switch state.typ {
		case DirState, DirKeyMatched:
			matched = yangEntry{ent}.matchDir(p)
			if matched == nil {
				return fmt.Errorf("No match")
			}
		case LeafState:
			//fmt.Println("LeafState need to match", p, "with", ent.Name)
			if !(yangEntry{ent}).matchLeaf(p) {
				return fmt.Errorf("Leaf match error")
			}
		case DirKeyState:
			//fmt.Println("DirKeyState need to match", p, "with", key.Name)
			if !(yangEntry{key}).matchLeaf(p) {
				return fmt.Errorf("Leaf match error")
			}
		}

		//fmt.Printf("  %s -> ", StateToString[state])
		state = state.next(yangEntry{ent}, yangEntry{matched})
		//fmt.Printf("%s\n", StateToString[state])

		switch state.typ {
		case DirState, LeafState:
			ent = matched
			if config != nil {
				config = config.Set(matched)
			}
		case DirKeyState:
			if state.keyIndex == 0 {
				ent = matched
			}
			if config != nil {
				//config = config.Set(matched)
				if state.keyIndex == 0 {
					config = config.Set(matched)
				} else {
					config = config.SetKey(key, p, ent.Name)
				}
			}
			key = ent.Dir[yangEntry{ent}.keyIndexedBy(state.keyIndex)]
			if key == nil {
				return fmt.Errorf("Can not find key entry")
			}
		case DirKeyMatched:
			if config != nil {
				config = config.SetKey(key, p, ent.Name)
				//fmt.Println("key", p)
			}
		case LeafMatched:
			if config != nil {
				if (yangEntry{matched}).hasEmptyLeaf() {
					config = config.Set(matched)
				} else {
					config = config.SetValue(p)
				}
			}
		}
	}

	if state.typ != LeafMatched && state.typ != DirKeyMatched {
		return fmt.Errorf("Match incomplete")
	}

	return nil
}

// func EntryDump(e *yang.Entry, depth int) {
// 	if depth != 0 {
// 		fmt.Printf("%*s", depth*2, " ")
// 	}
// 	if len(e.Key) != 0 {
// 		fmt.Printf("%s [%s] ", e.Name, e.Key)
// 	} else {
// 		fmt.Printf("%s ", e.Name)
// 	}
// 	fmt.Printf("%s\n", yang.EntryKindToName[e.Kind])

// 	if e.Kind == yang.DirectoryEntry {
// 		for _, ent := range e.Dir {
// 			EntryDump(ent, depth+1)
// 		}
// 	}
// }

func (e yangEntry) lookup(p []string) *yang.Entry {
	for _, path := range p {
		ent := e.matchDir(path)
		if ent == nil {
			return nil
		}
		e = yangEntry{ent}
	}
	return e.Entry
}

// Yang component.
type YangComponent struct {
	YangPaths   string
	YangModules []string
}

// Yang component start method.
func (this *YangComponent) Start() component.Component {
	// Set up Yang file load path. Append GOPATH + openconfigd's source yang
	// directory as well.
	yang.AddPath(this.YangPaths)
	yang.AddPath(Env("GOPATH") + "/src/github.com/lagopus/openconfigd/yang")

	// Initialize YANG modules
	ms := yang.NewModules()

	// Read YANG modules.
	for _, name := range this.YangModules {
		if err := ms.Read(name); err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
	}
	ms.Process()

	// Avoid duplicated module name.
	mods := map[string]*yang.Module{}
	var names []string
	for _, m := range ms.Modules {
		if mods[m.Name] == nil {
			mods[m.Name] = m
			names = append(names, m.Name)
		}
	}

	// Unique list of module names.
	rootEntry = &yang.Entry{
		Kind: yang.DirectoryEntry,
		Dir:  map[string]*yang.Entry{},
	}
	for _, name := range names {
		e := yang.ToEntry(mods[name])
		for key, value := range e.Dir {
			rootEntry.Dir[key] = value
		}
	}

	// Add local subscription.
	SubscribeLocalAdd([]string{"system"}, nil)
	SubscribeLocalAdd([]string{"protocols"}, nil)
	SubscribeLocalAdd([]string{"vrrp"}, VrrpJsonConfig)
	SubscribeLocalAdd([]string{"dhcp"}, DhcpJsonConfig)
	SubscribeLocalAdd([]string{"vrf", "name", "*", "vrrp"}, VrrpJsonConfig)
	SubscribeLocalAdd([]string{"vrf", "name", "*", "dhcp"}, DhcpJsonConfig)
	SubscribeLocalAdd([]string{"interfaces", "interface", "*", "dhcp-relay-group"}, nil)

	// ReadOnlyConfig
	ent := yangEntry{rootEntry}.lookup([]string{"interfaces", "interface", "name"})
	if ent != nil {
		ent.ReadOnlyConfig = true
	}

	// YangJsonParse()

	return this
}

// Yang component stop method.
func (this *YangComponent) Stop() component.Component {
	// Clear YANG file load path.
	//fmt.Println("yang component stop")
	yang.Path = nil
	return this
}

var jsonStr2 = `
{
    "dhcp": {
        "server": {
            "default-lease-time": 600,
            "dhcp-ip-pool": [
                {
                    "default-lease-time": 456,
                    "gateway-ip": "192.168.10.1",
                    "host": [
                        {
                            "host-name": "h0",
                            "ip-address": "192.168.10.23",
                            "mac-address": "00:1c:42:83:e5:ac"
                        }
                    ],
                    "interface": "lan-1",
                    "ip-pool-name": "904cd99a-f447-4bc0-ac6c-d151606be5bd",
                    "max-lease-time": 34567,
                    "option": {
                        "domain-name": "ntti3.com",
                        "domain-name-servers": [
                            {
                                "server": "8.8.8.8"
                            },
                            {
                                "server": "4.4.8.8"
                            }
                        ],
                        "ntp-servers": [
                            {
                                "server": "192.168.10.2"
                            }
                        ]
                    },
                    "range": [
                        {
                            "range-end-ip": "192.168.10.200",
                            "range-index": 1,
                            "range-start-ip": "192.168.10.100"
                        }
                    ],
                    "subnet": "192.168.10.0/24"
                }
            ],
            "max-lease-time": 7200
        }
    }
}
`

var jsonStr = `
{
    "dhcp": {
        "server": {
            "default-lease-time": 600,
            "max-lease-time": 7200
        }
    }
}
`

func parse(path string, v interface{}) {
	switch v := v.(type) {
	case map[string]interface{}:
		for key, elem := range v {
			parse(fmt.Sprintf("%s[%s]", path, key), elem)
		}
	case []interface{}:
		for i, elem := range v {
			parse(fmt.Sprintf("%s[%d]", path, i), elem)
		}
	case bool, float64, string:
		fmt.Printf("%s.value = %s (%T)\n", path, v, v)
	case nil:
		fmt.Printf("%s = nil\n", path)
	default:
		fmt.Printf("%s\n", v)
	}
}

// Yang based json parser.
func YangJsonParse() {
	fmt.Println("YangJsonParse")

	var jsonIntf interface{}
	err := json.Unmarshal([]byte(jsonStr2), &jsonIntf)
	if err != nil {
		fmt.Println("json error:", err)
		return
	}
	parse("", jsonIntf)
}
