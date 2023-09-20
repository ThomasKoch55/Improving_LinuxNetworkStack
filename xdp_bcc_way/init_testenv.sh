#!/bin/bash

sudo testenv/testenv.sh setup --name veth-basic02

testenv/testenv.sh alias

eval $(testenv/testenv.sh alias)

echo "Test environment ready!"
