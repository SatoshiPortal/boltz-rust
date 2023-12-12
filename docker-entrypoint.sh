#!/bin/bash

source $HOME/.bashrc

if (( $EUID == 0 )); then
    bash /stackmate-core/scripts/build.sh
else
    bash $HOME/stackmate-core/scripts/build.sh
fi
# tail -f /dev/null

exec "$@"