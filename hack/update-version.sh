#!/bin/bash

# Check if a Makefile exists in the current directory
if [ ! -f "Makefile" ]; then
	echo "Error: Makefile not found in the current directory."
	exit 1
fi

# Check if the VERSION argument is provided
if [ -z "$1" ]; then
	echo "Usage: $0 VERSION=<value>"
	exit 1
fi

# Extract the VERSION value from the argument
version=$(echo "$1" | sed 's/VERSION=//g')

# Update the VERSION parameter in the Makefile
sed -i "s/^VERSION.*$/VERSION ?= $version/" Makefile
sed -i "s/^CHART_VERSION.*$/CHART_VERSION ?= $version/" Makefile
