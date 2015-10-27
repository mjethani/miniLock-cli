#!/bin/bash

cd "$(dirname "$0")" || exit 1

if [ $# -lt 1 ]; then
  exit 1
fi

version=$1

date=$(date +'%B %-d, %Y')

cp -f package.json .package.json.tmp
sed -E "s/(\"version\": )\"([^\"]+)\"/\1\"$version\"/" .package.json.tmp \
  > package.json

# vim: et ts=2 sw=2
