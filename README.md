## CSPP MemTable 仅支持 BytewiseComparator 和 ReverseBytewiseComparator
在 [ToplingDB](https://github.com/topling/toplingdb) 中，CSPP MemTable 在形式上是作为一个 SidePlugin 实现的，也就是说，要使用 CSPP MemTable，用户代码不需要任何修改，只需要改 json/yaml 配置文件。

编译 ToplingDB 时，本模块(CSPP MemTable)由 ToplingDB 的 Makefile 中从 github 自动 clone 下来
## **配置方式**
cspp-memtable 在 [SidePlugin](https://github.com/topling/rockside/wiki) 中配置，类名是 `cspp`，配置参数：
参数名        | 类型  |默认值| 说明
--------------|------|------|------
mem_cap       |uint64|2G    |cspp 需要预分配足够的单块内存**地址空间**，这些内存可以只是**保留地址空间，但并未实际分配**。<br/>有效最大值是 16G
use_vm        |bool  |true  |使用 malloc/posix_memalign 时，地址空间可能是已经实际分配的，设置该选项会强制使用 mmap 分配内存，从而保证仅仅是**保留地址空间，但并不实际分配**
use_hugepage  |bool  |false |使用该选项时，linux 下必须保证设置了足够的 `vm.nr_hugepages`
token_use_idle|bool  |true  |该选项用来优化 token ring，一般情况下使用默认值即可
### **[配置样例：使用 yaml](https://github.com/topling/rockside/blob/master/sample-conf/lcompact_csppmemtab.yaml#L66-L71)**
```yaml
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
```
在 yaml 中定义好 cspp 对象之后，这样[引用该 cspp memtable](https://github.com/topling/rockside/blob/master/sample-conf/lcompact_csppmemtab.yaml#L82)

### **[配置样例：使用 json](https://github.com/topling/rockside/blob/master/sample-conf/lcompact_csppmemtab.json#L81-L88)**
```json
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
```
在 json 中定义好 cspp 对象之后，这样[引用该 cspp memtable](https://github.com/topling/rockside/blob/master/sample-conf/lcompact_csppmemtab.json#L102)
## **memtablerep_bench**
ToplingDB 在 RocksDB 的 memtablerep_bench 中加入了 cspp，以下脚本对比 skiplist 和 cspp（linux 下必须保证设置了足够的 `vm.nr_hugepages`）
```bash
make DEBUG_LEVEL=0 memtablerep_bench -j`nproc`
./memtablerep_bench -benchmarks=fillrandom,readrandom,readwrite \
  -memtablerep=skiplist -huge_page_tlb_size=2097152 \
  -write_buffer_size=536870912 -item_size=0 -num_operations=10000000
./memtablerep_bench -benchmarks=fillrandom,readrandom,readwrite \
  -memtablerep='cspp:{"mem_cap":"16G","use_hugepage":true}' \
  -write_buffer_size=536870912 -item_size=0 -num_operations=10000000
```
* 注意：-item_size=0 表示将 value 的长度设为 0，从而去除 memcpy value 的影响
* 注意：测试结果中最有参考价值的指标是 **write us/op** 和 **read us/op**
* 注意：测试结果表现出的性能差异包含了调用链开销，如果去除调用链开销，性能的差异会更大
  * 调用链开销是固定的，在 skiplist 中占比不大，但在 cspp 中占比就很大了(~40%)
  * 在 DB 中使用 CSPP，调用链开销更大，即便如此，最终的加速比也是非常显著

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
