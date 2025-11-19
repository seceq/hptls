#!/bin/bash
set -e

# Clone hpcrypt-seceq dependency if not already present
if [ ! -d "../hpcrypt-seceq" ]; then
    echo "Cloning hpcrypt-seceq..."
    cd ..
    git clone https://github.com/seceq/hpcrypt.git hpcrypt-seceq
    cd -
else
    echo "hpcrypt-seceq already exists"
fi
