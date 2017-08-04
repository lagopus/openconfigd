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

	"github.com/coreswitch/goyang/pkg/yang"
)

func JsonFlatten(paths []string, v interface{}, f func([]string)) {
	switch v := v.(type) {
	case bool:
		f(append(paths, strconv.FormatBool(v)))
	case float64:
		f(append(paths, strconv.FormatFloat(v, 'f', -1, 64)))
	case string:
		f(append(paths, v))
	case []interface{}:
		for _, elem := range v {
			JsonFlatten(paths, elem, f)
		}
	case map[string]interface{}:
		for key, elem := range v {
			JsonFlatten(append(paths, key), elem, f)
		}
	default:
	}
}

func processJsonValue(v interface{}) string {
	switch v := v.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

func jsonToFlatConfig(path string, configStr []string, v interface{}, yent *yang.Entry) []string {
	switch v := v.(type) {
	case map[string]interface{}:
		entry := yangEntry{yent}
		// First, process the nodes corresponding to a YANG key
		for key, elem := range v {
			if entry.dir(key) == nil {
				continue
			}

			path += " " + processJsonValue(elem)
		}
		// Then process other nodes (which is NOT corresponding to any YANG keys)
		nodeAvailable := false
		for key, elem := range v {
			// YANG key entries were already processed
			if entry.keysInclude(key) {
				continue
			}

			dir := entry.dir(key)
			if dir == nil {
				continue
			}

			nodeAvailable = true
			if path == "" {
				configStr = jsonToFlatConfig(key, configStr, elem, dir)
			} else {
				configStr = jsonToFlatConfig(path+" "+key, configStr, elem, dir)
			}
		}
		// the case of config which ends with a key
		if !nodeAvailable {
			configStr = append(configStr, path)
		}
	case []interface{}:
		for _, elem := range v {
			configStr = jsonToFlatConfig(path, configStr, elem, yent)
		}
	case string:
		configStr = append(configStr, path+" "+v)
	case bool:
		configStr = append(configStr, path+" "+strconv.FormatBool(v))
	case float64:
		configStr = append(configStr, path+" "+strconv.FormatFloat(v, 'f', -1, 64))
	default:
		// Unknown kind of entry
	}
	return configStr
}

// Import JSON format config and put it into the Config tree according to the YANG tree.
func JsonConfigImport(jsonBuf []byte, yangRoot *yang.Entry, configRoot *Config) error {
	var jsonIntf interface{}

	err := json.Unmarshal(jsonBuf, &jsonIntf)
	if err != nil {
		return err
	}

	configStr := jsonToFlatConfig("", []string{}, jsonIntf, yangRoot)

	if len(configStr) != 0 {
		for _, str := range configStr {
			err = Process(strings.Split(str, " "), yangRoot, configRoot)
			if err != nil {
				fmt.Printf("process failed: '%s' - %s\n", str, err)
			}
		}
	}

	return nil
}

func JsonParse(jsonString string) ([]string, error) {
	var jsonIntf interface{}

	err := json.Unmarshal([]byte(jsonString), &jsonIntf)
	if err != nil {
		return nil, err
	}
	JsonFlatten(nil, jsonIntf,
		func(path []string) {
			fmt.Println("Path:", path)
		},
	)
	fmt.Println()
	return nil, nil
}
