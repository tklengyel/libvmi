#!/bin/bash
domid=$(xl domid windows7-test)
count=0

while [ 1 ]; do
    lines=$(timeout 2 ./examples/event-example windows7-test | tail -n 1)

    (( count++ ))

    echo "$count $lines"

    if [ $lines -lt 10 ]; then
        exit 1;
    fi

    #sleep 5
done
