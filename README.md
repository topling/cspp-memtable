## CSPP MemTable 仅支持 BytewiseComparator 和 ReverseBytewiseComparator
在 [ToplingDB](https://github.com/topling/toplingdb) 中，CSPP MemTable 在形式上是作为一个 SidePlugin 实现的，也就是说，要使用 CSPP MemTable，用户代码不需要任何修改，只需要改 json/yaml 配置文件。

编译 ToplingDB 时，本模块(CSPP MemTable)由 ToplingDB 的 Makefile 中从 github 自动 clone 下来
## 一、配置方式
cspp-memtable 在 [SidePlugin](https://github.com/topling/rockside/wiki) 中配置，类名是 `cspp`，配置参数：
参数名        | 类型  |默认值| 说明
--------------|:----:|:----:|------
mem_cap       |uint64|2G    |cspp 需要预分配足够的单块内存**地址空间**，这些内存可以只是**保留地址空间，但并未实际分配**。<br/>有效最大值是 16G
use_vm        |bool  |true  |使用 malloc/posix_memalign 时，地址空间可能是已经实际分配的，设置该选项会强制使用 mmap 分配内存，从而保证仅仅是**保留地址空间，但并不实际分配**
use_hugepage  |bool  |false |使用该选项时，linux 下必须保证设置了足够的 `vm.nr_hugepages`
vm_explicit_commit|bool  |false |Windows `VirtualAlloc` 需要显式 commit，linux 不需要，但是如果内存不足，访问虚存时会 SegFault/BusError，linux kernel 5.14+ 的 `MADV_POPULATE_WRITE` 可以起到 Windows 显式 commit 的类似效果
convert_to_sst|enum  |kDontConvert|直接将 MemTable **转化**为 SST，省去 Flush，可选值：<br>`{kDontConvert, kDumpMem, kFileMmap}`
sync_sst_file |bool  |true  |convert_to_sst 为 `kFileMmap` 时，SST 转化完成后是否执行 fsync
token_use_idle|bool  |true  |该选项用来优化 token ring，一般情况下使用默认值即可
accurate_memsize|bool  |false  |仅用于测试，生产环境开启此选项会导致性能问题
<table>
  <tr align="center">
    <td>
<a href="https://github.com/topling/rockside/blob/master/sample-conf/lcompact_csppmemtab.json#L85-L93">json 配置样例</a>
    </td>
    <td>
<a href="https://github.com/topling/rockside/blob/master/sample-conf/lcompact_csppmemtab.yaml#L69-L74">yaml 配置样例</a>
    </td>
  </tr>
  <tr valign="top">
    <td>
<pre>
"MemTableRepFactory": {
   "cspp": {
      "class": "cspp",
      "params": {
         "mem_cap": "2G",
         "use_vm": false,
         "token_use_idle": true
      }
   },
   "skiplist": {
      "class": "SkipList",
      "params": {
         "lookahead": 0
      }
   }
}
</pre>
    </td>
    <td>
<pre>
MemTableRepFactory:
  cspp:
    class: cspp
    params:
      mem_cap: 2G
      use_vm: false
      token_use_idle: true
  skiplist:
    class: SkipList
    params:
      lookahead: 0
</pre>
    </td>
  </tr>
  <tr align="center">
    <td>
      <a href="https://github.com/topling/rockside/blob/master/sample-conf/lcompact_csppmemtab.json#L102">在 json 中引用该 cspp memtable</a>
    </td>
    <td>
      <a href="https://github.com/topling/rockside/blob/master/sample-conf/lcompact_csppmemtab.yaml#L82">在 yaml 中引用该 cspp memtable</a>
    </td>
  </tr>
</table>

## 二、MemTable 直接转化成 SST
MemTable 直接转化成 SST 代替了 MemTable Flush 操作，有巨大的收益，目前只有 CSPP MemTable 支持该功能。CSPP 可以直接在 ReadWrite 的文件 mmap 上操作，这是该功能得以有效实现的基础。

`convert_to_sst` 的三个枚举值：

* **kDontConvert**：禁用该功能，此为默认值。
* **kDumpMem**：转化时将 MemTable 的整块内存写入 SST 文件，避免 CPU 消耗，但未降低内存消耗
* **kFileMmap**：将 MemTable 内容 mmap 到文件，这是关键功能，同时降低 CPU 和内存消耗

CSPPMemTab 创建时预分配的内存可以是文件 mmap，此时文件在创建时 truncate 到 mem_cap 尺寸，
主流的文件系统(ext4,xfs,...)都支持稀疏文件，虽然 truncate 到 mem_cap 尺寸，虚拟内存也分配
了 mem_cap 地址空间，但实际上文件并没占用磁盘空间，虚拟地址空间也并未占用物理内存。

只有在我们实际向虚拟内存地址写入内容时，操作系统才会分配对应的物理内存（以 Page 为单位），
只有当这些内存 Page 变脏（写入了内容）超过一定时间，操作系统才会把这些 Page 写入文件，
此时才会实际分配磁盘空间。
> 用 `ls -l -s -h` 同时查看文件实际占用的空间和文件的名义尺寸。

当 CSPP MemTable 从 Active 转化为 Immutable（被标记为 ReadOnly）时，文件被 truncate 到真实尺寸，
转化 SST 时，只需要在文件后面追加 SST File Footer 即可。为此实现一个包装器，将 CSPP MemTable 包装
成 SST，定义 SST TableFactory:
```json
    "cspp_memtab_sst": {
      "class": "CSPPMemTabTable",
      "params": { }
    }
```
然后，在 DispatchTable 中，将 `cspp_memtab_sst` 放入 `readers` 作为 SST TableFactory 子类 CSPPMemTabTable 的 reader:
> 关键行： `"CSPPMemTabTable": "cspp_memtab_sst",`
```json
    "dispatch": {
      "class": "DispatcherTable",
      "params": {
        "default": "light_dzip",
        "readers": {
          "VecAutoSortTable": "auto_sort",
          "CSPPMemTabTable": "cspp_memtab_sst",
          "BlockBasedTable": "bb",
          "SingleFastTable": "sng",
          "ToplingZipTable": "dzip"
        },
        "level_writers": ["sng", "sng", "dzip", "dzip", "dzip", "dzip", "dzip"]
      }
    }
```
DispatcherTable 从来不会创建 CSPPMemTabTable 的 SST，它只读取这种 SST。

### 最佳实践
* ColumnFamilyOptions::write_buffer_size 配置为较大的值（例如 2G，同时将 CSPPMemTab::mem_cap 设为 3G）
* ColumnFamilyOptions::max_bytes_for_level_base 不要配置（默认 = write_buffer_size）

### 直接转化 SST 的收益
**1. 降低 CPU 用量**：MemTable Flush 过程中要扫描 MemTable 和创建 SST，去掉这些操作，自然也就去掉了相应的 CPU 消耗。

在分布式 Compact 的加持下，DB 结点只需要做 MemTable Flush 和 L0 -> L1 Compact，MemTable Flush 大约占一半，省去一半，
效果是立竿见影的。

**2. 降低内存用量**：MemTable Flush 中必然需要双份内存占用，如果存在 SuperVersion 对 MemTable 的引用，这个双份内存占用要持续很长时间，如果使用的是 BlockBasedTable，还有 BlockCache 中的一份内存占用。

CSPP MemTable 直接转化成 SST，即便 SST 和 MemTable 同时被引用，但两者对应的 PageCache 物理内存只有一份，
不会因为老旧 SuperVersion 的存在而多占内存！

**3. 减少 IO**：如果写得很快，并且脏页留存时间较长，并且我们在转化完 SST 之后不 fsync，并且很快发生了 Compact
导致 MemTable 转化来的 SST 被删除，那么在操作系统内部，因为这些 SST 文件的 mmap 还没来得及写回到磁盘上，该 SST
文件就被删除了，所以操作系统实际上就不再需要把这些内存写回磁盘，从而大幅降低 IO。
> （目前: 2023-08-30）xfs close file 时会顺带执行 fsync，不能发挥此优势；ext4 close file 时不会顺带 fsync，可以发挥此优势

### 关于 Crash Safe
CSPP 为了实现高性能的多线程并发插入，使用了 Copy On Write，由此顺带获得了 Crash Safe 的效果，也就是说进程在任意时刻崩溃时，文件 mmap 上的 CSPP Trie 的状态都是一致的，实现了数据库 ACID 中的 ACD 三项。

不过 MemTable 直接转化 SST 尚未用到 Crash Safe。


### 未来可能更近一步
目前直接将 CSPP MemTable 转化为 SST，并不会大幅减少文件 IO，只是将这些 IO 分散到了写 MemTable 的过程中，
因为写 MemTable 不完全是顺序写，有可能 IO 实际上会更大，这取决于操作系统负载和参数设定等（例如脏页留存时间）。

更好的方案是 MemTable 只存储索引，数据放在 WAL Log 中，参考 [Omit L0 Flush](https://github.com/topling/toplingdb/wiki/Omit-L0-Flush)，但是做到这一点工程量太大，需要修改的代码太多……

## 三、memtablerep_bench
ToplingDB 在 RocksDB 的 memtablerep_bench 中加入了 cspp，以下脚本对比 skiplist 和 cspp（linux 下必须保证设置了足够的 `vm.nr_hugepages`）
> linux kernel 5.14 以上可以自动检测 vm.nr_hugepages 不足导致的失败，旧版内核在 vm.nr_hugepages 不足时会发生 segfault 或 bus error，
> 将 "use_hugepage": `true` 改成 `false` 即可，代价是性能会有少许损失。
```bash
sudo yum -y install git libaio-devel gcc-c++ gflags-devel zlib-devel bzip2-devel libcurl-devel liburing-devel
git clone https://github.com/topling/toplingdb
cd toplingdb
make DEBUG_LEVEL=0 memtablerep_bench -j`nproc`
export LD_LIBRARY_PATH=.:`find sideplugin -name lib_shared`:${LD_LIBRARY_PATH}
./memtablerep_bench -memtablerep=skiplist -huge_page_tlb_size=2097152 \
  -benchmarks=fillrandom,readrandom,readwrite \  
  -write_buffer_size=536870912 -item_size=0 -num_operations=10000000
./memtablerep_bench -memtablerep='cspp:{"mem_cap":"16G","use_hugepage":true}' \
  -benchmarks=fillrandom,readrandom,readwrite \
  -write_buffer_size=536870912 -item_size=0 -num_operations=10000000
```
该测试结果一般可体现出 CSPP 相比 SkipList，**写性能有 6 倍的优势，读性能 有 8 倍的优势**。
* 注意：-item_size=0 表示将 value 的长度设为 0，从而去除 memcpy value 的影响
* 注意：测试结果中最有参考价值的指标是 **write us/op** 和 **read us/op**
* 注意：memtablerep_bench 仅测试 MemTableRep 的性能，调用链的开销很低
  * 如果在 DB 中使用 CSPP，主要耗时在于调用链开销，即便如此，最终的加速比也非常显著
* 注意：memtablerep_bench 不支持多线程并发写，要测试多线程并发写，请使用 db_bench
  * 例如：`db_bench -threads=10 -batch_size=100 -benchmarks=fillrandom`
---
---
---
## **背景**
> 以下文档主要完成于 2018 年，之后进行了小幅修改和添加注解。

在 MyRocks 的一个场景，MyRocks(RocksDB+MySQL) 的表现远不如预期，写入速度甚至只有 InnoDB 的 70%。这是我们万万不能接受的一个结果，经过仔细排查，我们发现，SkipList 相关的时间开销（主要是 Comparator 耗时）占了 60% 以上！

> 现在（2022-10-24），[MyTopling](https://github.com/topling/mytopling) 对 MyRocks 和 RocksDB 的 TransactionDB 进行了重大的优化，完全重写了关键代码，综合性能提升了 5 倍以上，部分场景性能提升 20 倍以上。

在这个场景中，数据条目数量非常大（20 多亿条），但表的结构很简单，类似这样：
```sql
CREATE TABLE Counting(
    name     varchar(100) PRIMARY KEY, # 实际平均长度约 30 字节
    count    INT(10)
);
```
每天会进行一次批量数据更新，大约更新 1亿条 数据，这个更新过程，InnoDB 需要 12分钟，MyRocks 需要 17分钟。

在 MyRocks 中，`Counting` 表对应到存储引擎上：name 字段就是 key，count 字段是 value，对于一般的场景，value 尺寸是远大于 key 的，但在这个场景中，key 的尺寸却远大于 value，一下就命中了 MyRocks 的软肋……

## **RocksDB 的 MemTable**
架构上，RocksDB MemTable 的设计目标是可插拔的不同实现的，在具体实现上，RocksDB 使用 SkipList 作为默认的 MemTable，其最大的优点是可以并发插入。

然而，RocksDB MemTable 的架构设计实际上有诸多的问题：

1. MemTable 不允许插入失败：每个 MemTable 有内存上限（`write_buffer_size`），是否达到内存上限，通过一种很猥琐的方式来判定：
   * MemTable 需要自己实现一个虚函数，用来报告自己的内存用量
   * `管理层`根据 MemTable 报告的内存用量，决定是否冻结当前 MemTable 并创建新的 MemTable
   * 如此，引发了一个很严重的问题：[#4056](https://github.com/facebook/rocksdb/issues/4056)
   * 这个缺陷非常致命，直接导致内存用量无法精确控制，严重阻碍优化方案的实现；更致命的是相关的代码错综复杂，几乎无法修改，我们进行了大量的尝试，最终还是只能放弃，退回到次优化的实现
     * 这个问题我们现在已经解决（规避）了，使用 VirtualAlloc/mmap 分配足够的内存地址空间(例如 16G)，这些地址空间只有用到时才会真正地分配物理内存，从而在事实上不会突破 MemTable 的内存限制
2. MemTable 限死了 KeyValue 的编码方式：都由带 var int 前缀的方式编码，这又带来了至少两个严重的问题：
   <br/>&nbsp;&nbsp;&nbsp;(1) var int 解码需要 CPU 时间，并且 key value 都无法自然对齐（对齐到 4 字节或 8 字节）
   <br/>&nbsp;&nbsp;&nbsp;(2) 新的 MemTable 无法使用别的存储方式，例如基于 Trie 树的 MemTable 不需要保存 Key，而是在搜索/扫描的过程中重建 Key
   * 这个缺陷可以通过重构来解决，我们曾向 RocksDB 提交过相关的 Pull Request 但未被接受（这类问题是 ToplingDB 必须独立存在的一个重要原因）
3. 工厂机制形同摆设，新的 MemTable 不能无缝 plugin，这个缺陷我们也曾经提交过相关的 Pull Request（也未被接受）

经过这些重构，其结果就是 ToplingDB 的通用 MemTable 接口，这个接口，放进 SidePlugin 体系，就实现了 MemTable 的无缝插件化。

架构上的改进，如果没有高效的实现来验证，总是缺乏一些说服力，我们经过不懈的努力，在算法层面获得了 8 倍以上的性能提升，同时 MemTable 的内存用量还大大降低。当然，这个提升，在整个系统层面会被其它部分拖后腿，最终效果是：在 MyRocks 中的一些场景下，我们可以获得 70% 以上的性能提升。

## 所以我们从头实现了一个 [CSPP](https://github.com/topling/rockside/wiki/Crash-Safe-Parallel-Patricia)
基于 CSPP，我们实现了 CSPPMemTab，设计上，CSPP 是 DFA 体系的一员，和 RocksDB 完全独立，也就是说，CSPPMemTab 把 [CSPP](https://github.com/topling/rockside/wiki/Crash-Safe-Parallel-Patricia) 作为一个基本构造块，CSPPMemTab 是 [CSPP](https://github.com/topling/rockside/wiki/Crash-Safe-Parallel-Patricia) 到 RocksDB MemTable 的适配层。

## [Comparator 问题](https://github.com/krareT/trkdb/wiki/Key-Comparator)
作为一个 Trie，它里面的 Key 对外部观察者而言只能是字典序，自然，CSPPMemTab 也只能支持 BytewiseComparator（和 Reverse Bytewise）。
