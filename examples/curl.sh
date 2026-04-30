#!/bin/sh

set -eu

body=${1:-hello}

curl -i -X POST --data-binary "$body" \
    http://127.0.0.1:18080/view

curl -i -X POST --data-binary "$body" \
    http://127.0.0.1:18080/consume_access

curl -i -X POST --data-binary "$body" \
    http://127.0.0.1:18080/consume_content
