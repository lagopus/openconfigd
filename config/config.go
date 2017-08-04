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
	"io"
	"os"
	"os/user"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/coreswitch/component"
	"github.com/coreswitch/goyang/pkg/yang"
)

var (
	configActiveFile   string  // Currently active configuration file name.
	configFileDir      string  // Config save path.
	configActive       *Config // Currently active configuration.
	configCandidate    *Config // Candidate configuration.
	configFileBasename string  // Configuration base filename.
	twoPhaseCommit     bool
	zeroConfig         bool
)

type Config struct {
	Name      string
	Entry     *yang.Entry
	Parent    *Config
	KeyConfig bool
	HasValue  bool
	Configs   ConfigSlice
	Keys      ConfigSlice
	Value     string
	Prefix    string
}

type ConfigSlice []*Config

func (c *Config) lookup(name string) *Config {
	for _, n := range c.Configs {
		if n.Name == name {
			return n
		}
	}
	return nil
}

func (c *Config) lookupKeyShallow(key string) (*Config, *Config) {
	for _, n := range c.Keys {
		if n.Name == key {
			return c, n
		}
	}
	return c, nil
}

func (c *Config) lookupKey(key string) (*Config, *Config) {
	if c.IsKeyConfig() {
		for _, p := range c.Parent.Keys {
			_, n := p.lookupKeyShallow(key)
			if n != nil {
				return p, n
			}
		}
		return c, nil
	}
	return c.lookupKeyShallow(key)
}

func ConfigLookupVrf(ifName string) string {
	vrf := ""
	c := configCandidate.LookupByPath([]string{"interfaces", "interface", ifName, "vrf"})
	if c != nil {
		vrf = c.Value
	}
	return vrf
}

func (c *Config) LookupByPath(path []string) *Config {
	var next *Config
	for _, p := range path {
		// fmt.Println("LookupByPath: ", p)
		next = c.lookup(p)
		if next == nil {
			_, next = c.lookupKey(p)
			if next == nil {
				// fmt.Println("LookupByPath: can't find", p)
				return nil
			}
		}
		c = next
	}
	return c
}

func (c *Config) Empty() bool {
	if len(c.Configs) == 0 && len(c.Keys) == 0 {
		return true
	}
	return false
}

// Static config priority until we add priority to YANG entry.
func (c *Config) Priority() int {
	if c.Entry.Name == "vrf" {
		return 150
	}
	if c.Entry.Name == "vlans" {
		return 100
	}
	if c.Entry.Name == "interfaces" {
		return 50
	}
	if c.Entry.Name == "interface" {
		return 10
	}
	if c.Entry.Name == "subnet" {
		return 5
	}
	if c.Entry.Name == "section-start-ip" {
		return 1
	}
	if c.Entry.Name == "range-start-ip" {
		return 1
	}
	return 0
}

// ConfigSlice sort
func (configs ConfigSlice) Len() int {
	return len(configs)
}

func (configs ConfigSlice) Less(i, j int) bool {
	pi := configs[i].Priority()
	pj := configs[j].Priority()
	if pi != pj {
		return pi > pj
	} else {
		return configs[i].Name < configs[j].Name
	}
}

func (configs ConfigSlice) Swap(i, j int) {
	configs[i], configs[j] = configs[j], configs[i]
}

func (c *Config) Set(e *yang.Entry) *Config {
	n := c.lookup(e.Name)
	if n == nil {
		n = &Config{Name: e.Name, Entry: e}
		n.Parent = c
		c.Configs = append(c.Configs, n)
		sort.Sort(c.Configs)
	}
	return n
}

func (c *Config) SetKey(e *yang.Entry, key string, prefix string) *Config {
	c, n := c.lookupKeyShallow(key)
	if n == nil {
		n = &Config{Name: key, Entry: e, KeyConfig: true, Prefix: prefix, Parent: c}
		c.Keys = append(c.Keys, n)
		sort.Sort(c.Keys)
	}
	return n
}

func (c *Config) SetValue(value string) *Config {
	c.Value = value
	c.HasValue = true
	return c
}

func (c *Config) Delete(n *Config) {
	configs := []*Config{}
	for _, conf := range c.Configs {
		if conf != n {
			configs = append(configs, conf)
		}
	}
	c.Configs = configs
}

func (c *Config) DeleteKey(n *Config) {
	configs := []*Config{}
	for _, conf := range c.Keys {
		if conf != n {
			configs = append(configs, conf)
		}
	}
	c.Keys = configs
}

func Delete(c *Config, leaf bool) {
	//fmt.Println("Deleting: ", c.Name)
	if c.Entry != nil {
		if c.Entry.Kind == yang.LeafEntry {
			//fmt.Println(c.Name, c.Value)
			if leaf {
				if (c.HasValue || yangEntry{c.Entry}.hasEmptyLeaf()) && c.Parent != nil {
					//fmt.Println("Delete laef value")
					c.Parent.Delete(c)
				}
				if c.KeyConfig && c.Parent != nil {
					c.Parent.DeleteKey(c)
				}
			}
		}
		if c.Entry.Kind == yang.DirectoryEntry {
			//fmt.Println("Deleting directory entry:", c.Name)
			if leaf {
				c.Configs = c.Configs[:0]
				c.Keys = c.Keys[:0]
			}
			if len(c.Configs) == 0 && len(c.Keys) == 0 && c.Parent != nil {
				//fmt.Println("Removing directory")
				c.Parent.Delete(c)
			}
		}
	}
	if c.Parent != nil {
		Delete(c.Parent, false)
	}
}

func (c *Config) quote() bool {
	if c.Entry.Type.Kind == yang.Ystring {
		if len(c.Entry.Type.Pattern) == 0 {
			return true
		}
	}
	return false
}

func (c *Config) CommandList(list []*Config) []*Config {
	if c.IsLeaf() {
		list = append(list, c)
	}
	for _, n := range c.Keys {
		list = n.CommandList(list)
	}
	for _, n := range c.Configs {
		list = n.CommandList(list)
	}
	return list
}

func (c *Config) CommandPath() []string {
	if c.Parent != nil {
		ret := append(c.Parent.CommandPath(), c.Name)
		if c.Value != "" {
			ret = append(ret, c.Value)
		}
		return ret
	}
	return []string{}
}

func (c *Config) Command() *Command {
	cmd := &Command{
		set:  true,
		cmds: c.CommandPath(),
	}
	return cmd
}

func (c *Config) CopyShallow() *Config {
	config := &Config{
		Name:      c.Name,
		Entry:     c.Entry,
		Parent:    c.Parent,
		KeyConfig: c.KeyConfig,
		HasValue:  c.HasValue,
		Configs:   make([]*Config, 0),
		Keys:      make([]*Config, 0),
		Value:     c.Value,
		Prefix:    c.Prefix,
	}
	return config
}

func (c *Config) Copy(parent *Config) *Config {
	config := &Config{
		Name:      c.Name,
		Entry:     c.Entry,
		Parent:    parent,
		KeyConfig: c.KeyConfig,
		HasValue:  c.HasValue,
		Configs:   make([]*Config, len(c.Configs)),
		Keys:      make([]*Config, len(c.Keys)),
		Value:     c.Value,
		Prefix:    c.Prefix,
	}
	for pos, subConfig := range c.Configs {
		config.Configs[pos] = subConfig.Copy(config)
	}
	for pos, subKey := range c.Keys {
		config.Keys[pos] = subKey.Copy(config)
	}
	return config
}

func isConfigKeyNode(c *Config) bool {
	if c.Entry.Key == "" {
		return false
	} else {
		return true
	}
}

func (c *Config) CommandLine() []string {
	if c.Parent != nil {
		ret := append(c.Parent.CommandLine(), c.Name)
		if c.Value != "" {
			if c.quote() {
				ret = append(ret, "\""+c.Value+"\"")
			} else {
				ret = append(ret, c.Value)
			}
		}
		return ret
	}
	return []string{}
}

func (c *Config) IsLeaf() bool {
	return (len(c.Keys) == 0 && len(c.Configs) == 0) || (c.Entry != nil && c.Entry.Kind == yang.LeafEntry)
}

func (c *Config) writeCommand(out io.Writer) {
	if c.IsLeaf() && !c.IsKeyConfig() {
		fmt.Fprintf(out, "set "+strings.Join(c.CommandLine(), " ")+"\n")
	}
	for _, n := range c.Keys {
		n.writeCommand(out)
	}
	for _, n := range c.Configs {
		n.writeCommand(out)
	}
}

func (c *Config) CommandString() string {
	buf := new(bytes.Buffer)
	c.writeCommand(buf)
	return buf.String()
}

func (c *Config) WriteCommandTo(path string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Println("File can't be created")
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, config := range c.Configs {
		config.writeCommand(w)
	}
	w.Flush()
}

func (c *Config) IsKeyConfig() bool {
	return len(c.Keys) > 0 && c.KeyConfig
}

func (c *Config) write(out io.Writer, depth int, prefix string) {
	brace := true
	keyFirst := false

	if len(c.Keys) == 0 {
		if len(c.Configs) == 0 {
			brace = false
		} else {
			if c.KeyConfig {
				brace = true
			}
		}
	}
	if len(c.Keys) > 0 && c.KeyConfig {
		keyFirst = true
		brace = false
	}

	if isConfigKeyNode(c) {
		prefix = ""
		for i := 0; i < depth; i++ {
			prefix += "    "
		}
		prefix += c.Name
	} else {
		if c.KeyConfig {
			prefix += " " + c.Name
			if len(c.Keys) == 0 {
				fmt.Fprintf(out, "%s", prefix)
			}
		} else {
			if depth != 0 {
				fmt.Fprintf(out, "%*s", depth*4, " ")
			}
			fmt.Fprintf(out, "%s", c.Name)
			if c.Value != "" {
				if c.quote() {
					fmt.Fprintf(out, " \"%s\"", c.Value)
				} else {
					fmt.Fprintf(out, " %s", c.Value)
				}
			}
		}
		if brace {
			fmt.Fprintf(out, " {\n")
		} else {
			if !keyFirst {
				fmt.Fprintf(out, ";\n")
			}
		}
	}

	for _, n := range c.Keys {
		n.write(out, depth, prefix)
	}
	for _, n := range c.Configs {
		n.write(out, depth+1, prefix)
	}

	if !isConfigKeyNode(c) {
		if brace {
			if depth != 0 {
				fmt.Fprintf(out, "%*s", depth*4, " ")
			}
			fmt.Fprintf(out, "}\n")
		}
	}
}

func (c *Config) hasPrefix() bool {
	return c.Prefix != ""
}

func (c *Config) needQuote() bool {
	if c.Entry != nil && c.Entry.Type != nil {
		switch c.Entry.Type.Kind {
		case yang.Yint8, yang.Yint16, yang.Yint32, yang.Yint64,
			yang.Yuint8, yang.Yuint16, yang.Yuint32, yang.Yuint64,
			yang.Ybool:
			return false
		default:
			return true
		}
	}
	return true
}

func (c *Config) jsonMarshal(pos int, prefix string) string {
	var str string

	if pos != 0 {
		if c.KeyConfig {
			if len(prefix) > 0 && prefix[len(prefix)-1] != ',' { // tricky way
				prefix += ","
			}
		} else {
			str += ","
		}
	}

	if isConfigKeyNode(c) {
		str += "\"" + c.Name + "\": ["
	} else {
		if c.hasPrefix() {
			str_ := ""
			if !c.Parent.hasPrefix() {
				str_ += "{"
			}
			if c.needQuote() {
				str_ += "\"" + c.Entry.Name + "\":" + "\"" + c.Name + "\""
			} else {
				str_ += "\"" + c.Entry.Name + "\":" + c.Name
			}
			if c.KeyConfig {
				prefix += str_
				if len(c.Keys) == 0 {
					str += prefix
					prefix = ""
				}
			} else {
				str += str_
			}
		} else {
			if c.Value == "" {
				str += "\"" + c.Name + "\":" + YEntryJson(c.Entry)
			} else {
				if c.needQuote() {
					str += "\"" + c.Name + "\"" + ":" + "\"" + c.Value + "\""
				} else {
					str += "\"" + c.Name + "\"" + ":" + c.Value
				}
			}
		}
	}

	if len(c.Keys) != 0 {
		for pos_, n := range c.Keys {
			if c.hasPrefix() {
				str += n.jsonMarshal(pos_+1, prefix)
			} else {
				str += n.jsonMarshal(pos_, prefix)
			}
		}
	}

	if len(c.Configs) != 0 {
		if !c.hasPrefix() {
			str += "{"
		}
		for pos_, n := range c.Configs {
			if c.hasPrefix() {
				str += n.jsonMarshal(pos_+1, prefix)
			} else {
				str += n.jsonMarshal(pos_, prefix)
			}
		}
		str = strings.TrimSuffix(str, ",")
		str += "},"
	} else {
		if c.hasPrefix() && len(c.Keys) == 0 {
			str = strings.TrimSuffix(str, ",")
			str += "},"
		}
	}

	if isConfigKeyNode(c) {
		str = strings.TrimSuffix(str, ",")
		str += "]"
	}

	return str
}

func (c *Config) JsonMarshal() string {
	var str string

	if len(c.Keys) > 0 {
		for pos, config := range c.Keys {
			if pos != 0 {
				str += ","
			}
			str += config.jsonMarshal(0, "")
		}
		return "[" + str + "]"
	}
	for _, config := range c.Configs {
		str += config.jsonMarshal(0, "")
	}
	str = strings.TrimSuffix(str, ",")
	return "{" + str + "}"
}

func (c *Config) String() string {
	buf := new(bytes.Buffer)
	for _, config := range c.Configs {
		config.write(buf, 0, "")
	}
	return buf.String()
}

func (c *Config) Signature(out io.Writer, via string) {
	const layout = "2006-01-02 15:04:05 MST"
	username := "anonymous"
	user, _ := user.Current()
	if user != nil {
		username = user.Username
	}
	fmt.Fprintf(out, "# %s by %s via %s\n", time.Now().Format(layout), username, via)
}

func (c *Config) WriteTo(path string, by ...string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Println("File can't be created")
		return
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	if len(by) > 0 {
		c.Signature(w, by[0])
	}
	for _, config := range c.Configs {
		config.write(w, 0, "")
	}
	w.Flush()
}

func ConfigDiscard() bool {
	diff := CompareCommand()
	if diff != "" {
		configCandidate = configActive.Copy(nil)
		return true
	} else {
		return false
	}
}

// Config component.
type ConfigComponent struct {
	ConfigActiveFile string
	ConfigFileDir    string
	TwoPhaseCommit   bool
	ZeroConfig       bool
}

// Config component start method.
func (this *ConfigComponent) Start() component.Component {
	configActive = &Config{}
	configCandidate = &Config{}

	// When active file is absolute path, it overwrite opts.ConfigFileDir.
	if path.IsAbs(this.ConfigActiveFile) {
		this.ConfigFileDir = path.Dir(this.ConfigActiveFile)
	} else {
		this.ConfigActiveFile = this.ConfigFileDir + "/" + this.ConfigActiveFile
	}

	configFileDir = this.ConfigFileDir
	configActiveFile = this.ConfigActiveFile
	configFileBasename = path.Base(configActiveFile)
	twoPhaseCommit = this.TwoPhaseCommit
	zeroConfig = this.ZeroConfig

	// Load saved configuration.
	if zeroConfig {
		err := Load(configActiveFile)
		if err != nil {
			fmt.Println("Can't load config:", err)
			return this
		}
	} else {
		err := Load(configActiveFile + ".0")
		if err != nil {
			err = Load(configActiveFile)
			if err != nil {
				fmt.Println("Can't load config:", err)
				return this
			}
		}
	}

	// Check configCandidate is properly loaded.
	if configCandidate.Empty() {
		fmt.Println("Loaded config is empty")
	} else {
		Commit()
	}

	return this
}

// Config component stop method.
func (this *ConfigComponent) Stop() component.Component {
	fmt.Println("component config: stop")

	// Clean up etcd config.
	//EtcdVrfClean()
	Commit()
	DhcpExitFunc()
	VrrpServerStopAll()
	RelayExitFunc()
	QuaggaExit()

	configActive = nil
	configCandidate = nil
	return this
}
