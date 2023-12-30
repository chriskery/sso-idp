#!/bin/bash
cp favicon.ico dist
# can't use -o option
go-bindata-assetfs -pkg ui dist/...
mv bindata_assetfs.go ../../ui/bindata.go
