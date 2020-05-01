#!/bin/bash
set -e

go run ../../cmd/gen_keys $1

start() {
    echo $(python -c \
    "from datetime import datetime, timedelta; \
    t = datetime.utcnow() + timedelta(seconds=3); \
    print(t.strftime('%a %b %d %H:%M:%S UTC %Y'))")
}

echo "$(start)"

end=$(($1-1))

for PID in $(seq 0 $end)
do
    go run ../../cmd/tecdsa --pk $PID.pk --keys_addrs keys_addrs -roundDuration $2 --startTime "$(start)" &
done
