# OpenConfigd

OpenConfigd is software which manages [OpenConfig](http://www.openconfig.net/)
common data models for networking. It handles networking protocol configuration
as well as any generic configuration parameters.


OpenConfigd reads YANG model definition then generate configuration schema from
it.

### Install

Following command build `openconfigd` and `cli_command`.

``` bash
$ go get github.com/lagopus/openconfigd/...
```

CLI command build and set up.

``` bash
$ cd $GOPATH/src/github.com/lagopus/openconfigd/cli
$ ./build.sh
$ sudo make install
```

will install `cli` command to /usr/local/bin.

CLI completion file called `cli` file exists under bash_completion.d as well. On
Ubuntu platform, this file should be installed under `/etc/bach_completion.d`

``` bash
$ cd $GOPATH/src/github.com/lagopus/openconfigd/bash_completion.d
$ sudo cp cli /etc/bash_completion.d/
```

### Quick Start

Invoke openconfigd, then start cli.  "show version" display version information.

``` bash
$ openconfigd &
$ cli
ubuntu>
ubuntu> show version
Developer Preview version of openconfigd
ubuntu>
```

### Options

`openconfigd` takes YANG module names as arguments.  When no YANG module is specified, default `coreswitch.yang` is used.  '.yang' saffix is optional.  Use can specify multiple YANG file.  So

``` bash
$ openconfigd lagopus ietf-ip
```

will load both `lagopus.yang` and `ietf-ip.yang` modules.

There are several other options.

*  -c, --config-file= active config file name (default: coreswitch.conf)
*  -p, --config-dir=  config file directory (default: /usr/local/etc)
*  -y, --yang-paths=  comma separated YANG load path directories
*  -h, --help         Show this help message

`-c` option specify active config file name.  `-p` option specify config file save directory.  When full path is specified to `-c` option's base directory overrides the `-p` option config file directory.

`-y` option specify YANG file load path.  Use can specify multiple YANG load path with colon separated list.

``` bash
$ openconfigd -y /usr/shared/yang:/opt/yang
```

will search both `/usr/shared/yang` and `/opt/yang` directory.  Default YANG laod path `$GOPATH/src/github.com/lagopus/openconfigd/yang` is automatically added.

### OpenConfigd scripting

OpenConfigd support CLI scripting. All operational and configuration mode
commands can run from script.

Here is an example:

``` shell
#! /bin/bash

source /etc/bash_completion.d/cli

configure
set system host-name ubuntu
commit

run show version
```
