. inject-env.sh
export WORKER_DB_ROOT=/tmp
export WORKER_DB_ROOT=/dev/shm
export WORKER_DB_ROOT=/nvme-shared/worker-db-root
#export WORKER_DB_ROOT=/node-shared/worker-db-root
export WEB_DOMAIN=topling.in
#export  ETCD_URL=192.168.100.100:2379

export NFS_DYNAMIC_MOUNT=0
export NFS_MOUNT_ROOT=/nvme-shared
export MAX_PARALLEL_COMPACTIONS=128

# TerarkZipTable_XXX can be override here by env, which will
# override the values defined in db Hoster side's json config.
#
# Hoster side's json config will be passed to compact worker through
# rpc, then it may be override by env defined here!
#
export DictZipBlobStore_zipThreads=16
export TerarkZipTable_nltBuildThreads=16
export TerarkZipTable_localTempDir=/dev/shm
export TerarkZipTable_warmupLevel=kValue

cd /node-shared/leipeng/osc/rocksdb/sideplugin/topling-rocks

#rm -rf $WORKER_DB_ROOT/db1/* # db1 is test db instance_name
rm -rf /dev/shm/Terark-*
ulimit -n 100000
#dbg="strace -e trace=creat,open,openat,close"
#dbg="gdb --args"
#nodeset="0"
nodeset="0 1"

for i in $nodeset; do
    PORT=$((8080+i))
    cmd="env ADVERTISE_ADDR=${SELF_ADDR}:${PORT} \
         numactl --cpunodebind=$i -- $dbg ./dcompact_worker.exe \
         -D listening_ports=${PORT} -D document_root=$WORKER_DB_ROOT"
    if [ "$REDIRECT" = "1" ]; then
        SUFFIX=$USER.$SELF_ADDR.$PORT
        mkdir -p $WORKER_DB_ROOT/{stdout,stderr}
        nohup $cmd > $WORKER_DB_ROOT/stdout/stdout.$SUFFIX 2> $WORKER_DB_ROOT/stderr/stderr.$SUFFIX &
    else
        nohup $cmd &
    fi
done
