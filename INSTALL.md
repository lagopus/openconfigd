# How to INSTALL openconfigd

* [Ubuntu 16.04](#ubuntu-1604)

## Ubuntu 16.04

> Note: You cannot set $GOROOT and $GOPATH same in Ubuntu 16.04.
> Update this doc if you found out it's incorrect or there are better way.

* Set go environment

```
$ vi .bashrc
export GOROOT=/usr/local/go
export GOPATH=/home/$USER/go
export PATH=$PATH:$GOPATH/bin:$GOROOT/bin
```

* Install required Go packages

```
> Installed under $GOPATH/{src|pkg|bin}/
$ go get "github.com/golang/protobuf/proto"
$ go get "golang.org/x/net/context"
$ go get "google.golang.org/grpc"
```

* Download and install hash-set/openconfigd

```
$ cd ${GOPATH}/src/github.com/
$ mkdir hash-set
$ cd hash-set
$ git clone http://github.com/hash-set/openconfigd.git
$ go install github.com/hash-set/openconfigd/openconfigd
$ go install github.com/hash-set/openconfigd/cli_command
```

* Confirm openconfigd is created.

```
ebiken@u1604s:~$ ls -al ${GOPATH}/bin/openconfigd
-rwxrwxr-x 1 ebiken ebiken 11236912 Jul 11 21:47 /home/ebiken/go/bin/openconfigd
```
## Swagger

To define REST API, we use swagger. Please install go-swagger with following
command.

```
go get -u github.com/go-swagger/go-swagger/cmd/swagger
```

This will install command `swagger`.
