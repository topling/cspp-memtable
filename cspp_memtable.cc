// Copyright (c) 2021-present, Topling, Inc.  All rights reserved.
// Created by leipeng, fully rewrite by leipeng 2021-05-12
#include "db/memtable.h"
#include "topling/side_plugin_factory.h"
#include "logging/logging.h"

// dump cspp memtable as sst
#include "file/filename.h"
#include "monitoring/iostats_context_imp.h"
#include "table/top_table_builder.h"
#include "table/top_table_reader.h"
#include "topling/builtin_table_factory.h"

#if defined(_MSC_VER)
  #pragma warning(disable: 4245) // convert int to size_t in fsa of cspp
  #pragma warning(disable: 4458) // deactived_mem_sum hide class member(intentional)
#endif
#include <terark/fsa/cspptrie.inl>
#include <terark/num_to_str.hpp>
#include <terark/util/vm_util.hpp>
#include <float.h>

#if defined(OS_LINUX)
  #include <linux/mman.h>
  #include <linux/version.h>
#endif

const char* git_version_hash_info_cspp_memtable();
namespace terark {
TERARK_DLL_EXPORT void CSPP_SetDebugLevel(long level); // defined in cspptrie.cpp
TERARK_DLL_EXPORT long CSPP_GetDebugLevel();           // defined in cspptrie.cpp
} // namespace terark
namespace ROCKSDB_NAMESPACE {
using namespace terark;
extern bool IsRocksBackgroundThread(); // defined in util/threadpool_impl.cc
ROCKSDB_ENUM_CLASS(ConvertKind, uint08_t, kDontConvert, kDumpMem, kFileMmap);
static const uint32_t LOCK_FLAG = uint32_t(1) << 31;
struct CSPPMemTabFactory;
struct MemTabLinkListNode {
  MemTabLinkListNode *m_prev, *m_next;
};
struct CSPPMemTab : public MemTableRep, public MemTabLinkListNode {
  static constexpr size_t Align = MainPatricia::AlignSize;
  static_assert(Align == 4);
#pragma pack(push, 4)
  struct Entry {
    uint64_t tag;
    uint32_t pos;
    operator uint64_t() const noexcept { return tag; } // NOLINT
    Slice GetValue(const void* mempool) const noexcept {
      if (size_t p = pos) {
        auto enc_valptr = (const char*)(mempool) + p * Align;
        return GetLengthPrefixedSlice(enc_valptr);
      } else {
        return Slice();
      }
    }
    void DebugCheckUserKey(const CSPPMemTab*, Slice) const {}
  };
  struct VecPin { // once allocated, never realloc
    uint32_t num;
    uint32_t pos;
  };
  struct KeyValueToLogRef {
    operator uint64_t() const noexcept { return tag; } // NOLINT
    uint64_t tag;
    union {
      struct {
        uint32_t val_len;
        uint64_t val_pos : 48; // to wal
        uint64_t wal_idx :  8;
        uint64_t inline_val_len : 8;
      };
      char value[11];
    };
    Slice GetValue(const CSPPMemTab* mtab) const noexcept {
      if (inline_val_len <= sizeof(value)) {
        return {value, inline_val_len};
      }
      ROCKSDB_ASSERT_LT(wal_idx, mtab->m_num_wals);
      auto wal = mtab->m_wals[wal_idx].wal;
      auto base = wal->data_;
      return {base + val_pos, val_len};
    }
    void DebugCheckUserKey(const CSPPMemTab* mtab, Slice uk) const {
     #if !defined(NDEBUG)
      if (inline_val_len <= sizeof(value)) {
        return;
      }
      ROCKSDB_ASSERT_LT(wal_idx, mtab->m_num_wals);
      auto wal = mtab->m_wals[wal_idx].wal;
      auto base = wal->data_;
      auto val_lenlen = VarintLength(val_len);
      Slice wal_uk(base + val_pos - val_lenlen - uk.size_, uk.size_);
      assert(uk == wal_uk);
     #endif
    }
  };
  static_assert(sizeof(KeyValueToLogRef) == 20);
  struct KV_ToShortLogRef {
    operator uint64_t() const noexcept { return tag; } // NOLINT
    uint64_t tag;
    union {
      struct {
        uint64_t val_pos : 48; // to wal
        uint64_t wal_idx :  8;
        uint64_t inline_val_len : 8;
      };
      char value[7];
    };
    Slice GetValue(const CSPPMemTab* mtab) const noexcept {
      if (inline_val_len <= sizeof(value)) {
        return {value, inline_val_len};
      }
      ROCKSDB_ASSERT_LT(wal_idx, mtab->m_num_wals);
      auto wal = mtab->m_wals[wal_idx].wal;
      auto base = wal->data_;
      return GetLengthPrefixedSlice(base + val_pos);
    }
    void DebugCheckUserKey(const CSPPMemTab* mtab, Slice uk) const {
     #if !defined(NDEBUG)
      if (inline_val_len <= sizeof(value)) {
        return;
      }
      ROCKSDB_ASSERT_LT(wal_idx, mtab->m_num_wals);
      auto wal = mtab->m_wals[wal_idx].wal;
      auto base = wal->data_;
      Slice wal_uk(base + val_pos - uk.size_, uk.size_);
      assert(uk == wal_uk);
     #endif
    }
  };
  static_assert(sizeof(KV_ToShortLogRef) == 16);
  ROCKSDB_ENUM_PLAIN_INCLASS(LogRef_Format, uint8_t,
    kNoLogRef = 0x0,
    kPlainLogRef = 0x1,
    kShortLogRef = 0x2
  );
#pragma pack(pop)
  static void encode_pre(Slice d, void* buf) {
    assert(d.size_ > 0); // empty `d` will not call this function
    char* p = EncodeVarint32((char*)buf, (uint32_t)d.size());
    memcpy(p, d.data_, d.size_);
  }
  mutable MainPatricia m_trie;
  bool          m_read_by_writer_token;
  bool          m_token_use_idle;
  bool          m_accurate_memsize;
  LogRef_Format m_ref_to_wal;
  bool          m_rev : 1;
  bool          m_is_flushed : 1;
  bool          m_is_empty : 1;
  bool          m_is_sst : 1;
  bool          m_has_converted_to_sst : 1;
  bool          m_has_marked_readonly : 1; // pre C++20 can not init on define
  ConvertKind   m_convert_to_sst;
  CSPPMemTabFactory* m_fac;
  Logger*  m_log;
  size_t   m_instance_idx;
  size_t   max_dup_len = 1;
  size_t   num_dup_user_keys = 0;
  uint32_t m_cumu_iter_num = 0;
  uint32_t m_live_iter_num = 0;
  uint64_t m_fill_time = 0;
#if defined(ROCKSDB_UNIT_TEST)
  size_t   m_mem_size = 0;
#endif
  struct LogFileLookup {
    uint64_t fileno = 0;
    uint64_t cnt = 0;
    uint64_t bytes = 0;
    const ReadonlyFileMmap* wal = 0;
  };
  static constexpr size_t MAX_WALS = 16; // for fast search
  size_t m_num_wals = 0;
  LogFileLookup m_wals[MAX_WALS] = {};
  std::vector<std::shared_ptr<ReadonlyFileMmap> > m_hold_wals; // just hold
  std::mutex m_mtx;
  size_t add_wal(size_t fileno, const ReadonlyFileMmap* wal) {
    assert(0 != fileno);
    size_t i = 0;
    while (i < m_num_wals) {
      if (m_wals[i].fileno == fileno) {
        TERARK_VERIFY_EQ(m_wals[i].wal, wal);
        return i;
      }
      i++;
    }
    std::lock_guard<std::mutex> lk(m_mtx);
    while (i < m_num_wals) {
      if (m_wals[i].fileno == fileno) {
        TERARK_VERIFY_EQ(m_wals[i].wal, wal);
        return i;
      }
      i++;
    }
    TERARK_VERIFY_LT(m_num_wals, MAX_WALS);
    m_wals[i].cnt = 0;
    m_wals[i].wal = wal;
    m_wals[i].bytes = 0;
    m_wals[i].fileno = fileno;
    as_atomic(m_num_wals).fetch_add(1); // update last
    m_hold_wals.emplace_back(((ReadonlyFileMmap*)wal)->shared_from_this());
    return i;
  }
  CSPPMemTab(intptr_t cap, bool rev, Logger*, CSPPMemTabFactory*,
             size_t instance_idx, ConvertKind, fstring fpath_or_conf);
  CSPPMemTab(bool rev, Logger*, CSPPMemTabFactory*, size_t instance_idx);
  void init(bool rev, Logger*, CSPPMemTabFactory*);
  ~CSPPMemTab() noexcept override;
  void InitSetMemTableAsLogIndex(bool b) final;
  bool SupportMemTableAsLogIndex() const final { return m_ref_to_wal; }
  KeyHandle Allocate(const size_t, char**) final { TERARK_DIE("Bad call"); }
  void Insert(KeyHandle) final { TERARK_DIE("Bad call"); }
  struct LogFileCntBytesThreadLocal {
    uint64_t cnt = 0;
    uint64_t bytes = 0;
  };
  struct Token : public Patricia::WriterToken {
    uint64_t tag_ = UINT64_MAX;
    Slice val_;
    size_t max_dup_len = 1;
    size_t num_dup_user_keys = 0;
    LogFileCntBytesThreadLocal m_wal_cnt_bytes[MAX_WALS] = {};
    ~Token();
    template<class EntryLogRef>
    void SetKeyValueToLogRef(CSPPMemTab*, EntryLogRef*);
    bool init_value(void* trie_valptr, size_t trie_valsize) noexcept final;
    void destroy_value(void* valptr, size_t valsize) noexcept final;
    bool insert_for_dup_user_key(CSPPMemTab*);
  };
  void OnDupUserKeyYield();
  bool insert_kv(fstring ukey, Token*);
  bool InsertKeyValueConcurrently(uint64_t tag, const Slice& ukey, const Slice& val)
  final {
    if (UNLIKELY(m_is_empty)) { // must check, avoid write as possible
      m_fill_time = Env::Default()->NowNanos();
      m_is_empty = false;
    }
    Token* token = m_trie.tls_writer_token_nn<Token>();
    token->acquire(&m_trie);
    token->tag_ = tag;
    token->val_ = val;
    auto ret = insert_kv(ukey, token);
    m_token_use_idle ? token->idle() : token->release();
    return ret;
  }
  bool InsertKeyValue(uint64_t tag, const Slice& k, const Slice& v) final {
    return InsertKeyValueConcurrently(tag, k, v);
  }
  bool InsertKeyValueWithHintConcurrently
  (uint64_t tag, const Slice& ukey, const Slice& val, void** hint) final {
    if (UNLIKELY(m_is_empty)) { // must check, avoid write as possible
      m_fill_time = Env::Default()->NowNanos();
      m_is_empty = false;
    }
    // SkipListMemTable use `*hint` as last insertion position, We use `*hint`
    // as the tls writer token ptr to avoid calling of tls_writer_token_nn
    assert(nullptr != hint);
    Token*& token = *(Token**)(hint);
    if (LIKELY(nullptr != token)) {
      assert(m_trie.tls_writer_token_nn<Token>() == token);
    } else {
      token = m_trie.tls_writer_token_nn<Token>();
      token->acquire(&m_trie);
    }
    token->tag_ = tag;
    token->val_ = val;
    return insert_kv(ukey, token);
  }
  bool InsertKeyValueWithHint(uint64_t tag, const Slice& k, const Slice& v, void** hint)
  final {
    return InsertKeyValueWithHintConcurrently(tag, k, v, hint);
  }
  void FinishHint(void* hint) final {
    if (nullptr != hint) {
      auto token = (Token*)hint;
      m_token_use_idle ? token->idle() : token->release();
    }
  }
  inline Patricia::TokenBase* reader_token() const {
    if (m_read_by_writer_token)
      return m_trie.tls_writer_token_nn<Token>();
    else
      return m_trie.tls_reader_token();
  }
  bool Contains(const Slice& ikey) const final {
    fstring user_key(ikey.data(), ikey.size() - 8);
    auto token = reader_token();
    token->acquire(&m_trie);
    if (!m_trie.lookup(user_key, token)) {
      m_token_use_idle ? token->idle() : token->release();
      return false;
    }
    uint64_t find_tag = DecodeFixed64(user_key.end());
    auto vec_pin = (VecPin*)m_trie.mem_get(m_trie.value_of<uint32_t>(*token));
    auto num = vec_pin->num & ~LOCK_FLAG;
    auto bs = [&](auto entry) {
      return binary_search_0(entry, num, find_tag);
    };
    auto p = m_trie.mem_get(vec_pin->pos);
    bool ret = m_ref_to_wal == kPlainLogRef ? bs((KeyValueToLogRef*)p)
             : m_ref_to_wal == kShortLogRef ? bs((KV_ToShortLogRef*)p)
             : bs((Entry*)p);
    m_token_use_idle ? token->idle() : token->release();
    return ret;
  }
  void ConvertToReadOnly(const char* caller, fstring sst_name);
  void MarkReadOnly() final;
  void MarkFlushed() final;
  void ColdizeMemory(const char* func);
  bool SupportConvertToSST() const final {
    return ConvertKind::kDontConvert != m_convert_to_sst;
  }
  Status ConvertToSST(FileMetaData*, const TableBuilderOptions&) final;
  size_t ApproximateMemoryUsage() final {
    size_t walsize = 0;
    for (size_t i = 0; i < m_num_wals; i++) {
      walsize += m_wals[i].bytes;
    }
#if defined(ROCKSDB_UNIT_TEST)
    size_t free_sz;
    if (m_trie.is_readonly()) {
      // fast and accurate once become readonly
      free_sz = m_trie.mem_frag_size();
    }
    else {
      if (m_accurate_memsize) {
        // !!this is slow!!
        // other threads are concurrently running, to minimize race condition,
        // we get free_sz first
        free_sz = m_trie.slow_get_free_size();
      }
      else {
        // We always eliminate free size, because it seem rocksdb MemTableList
        // has a bug(or a feature) which leaks memtables when size is not
        // accurate. We found this bug by our online webview, and more assure
        // by running MemTableList unit test.
        free_sz = m_trie.mem_frag_size(); // fast but not accurate
        // more tolerations, use tls as a second chance
        size_t tls_free_sz = m_trie.get_cur_tls_free_size();
        free_sz = std::max(free_sz, tls_free_sz);
      }
    }
    size_t all_sz = m_trie.mem_size_inline();
    if (terark_likely(all_sz > free_sz)) {
      maximize(m_mem_size, all_sz - free_sz);
    } else {
      // if this happens, it should be a bug, just ignore it on release!
      ROCKS_LOG_ERROR(m_log,
       "CSPPMemTab::ApproximateMemoryUsage: all <= free : %zd %zd, ignore",
        all_sz, free_sz);
      ROCKSDB_ASSERT_LE(free_sz, all_sz);
      // read recent mem size again from mem_size_inline
      maximize(m_mem_size, m_trie.mem_size_inline());
    }
    return m_mem_size + walsize;
#else
    return m_trie.mem_size_inline() + walsize;
#endif
  }
  uint64_t ApproximateNumEntries(const Slice&, const Slice&) final;
  terark_forceinline Slice GetValue(const Entry& e) const {
    return e.GetValue(m_trie.mem_get(0));
  }
  terark_forceinline Slice GetValue(const KeyValueToLogRef& e) const {
    return e.GetValue(this);
  }
  terark_forceinline Slice GetValue(const KV_ToShortLogRef& e) const {
    return e.GetValue(this);
  }
  ROCKSDB_FLATTEN
  void Get(const ReadOptions& ro, const LookupKey& k, void* callback_args,
           bool(*callback_func)(void*, const KeyValuePair&)) final {
    if (UNLIKELY(m_is_empty)) {
      return;
    }
    if (m_ref_to_wal == kPlainLogRef)
      return GetTpl<KeyValueToLogRef>(ro, k, callback_args, callback_func);
    else if (m_ref_to_wal == kShortLogRef)
      return GetTpl<KV_ToShortLogRef>(ro, k, callback_args, callback_func);
    else
      return GetTpl<Entry>(ro, k, callback_args, callback_func);
  }
  template<class Entry>
  void GetTpl(const ReadOptions& ro, const LookupKey& k, void* callback_args,
              bool(*callback_func)(void*, const KeyValuePair&)) {
    KeyValuePair key_val(ExtractUserKey(k.internal_key()));
    auto token = reader_token();
    token->acquire(&m_trie);
    if (!m_trie.lookup(fstring(key_val.ukey), token)) {
      m_token_use_idle ? token->idle() : token->release();
      return;
    }
    uint32_t vec_pin_pos = m_trie.value_of<uint32_t>(*token);
    auto vec_pin = (VecPin*)m_trie.mem_get(vec_pin_pos);
    size_t num = vec_pin->num & ~LOCK_FLAG;
    auto entry = (Entry*)m_trie.mem_get(vec_pin->pos);
    uint64_t find_tag = DecodeFixed64(key_val.ukey.end());
    intptr_t idx = upper_bound_0(entry, num, find_tag);
    if (UNLIKELY(ro.just_check_key_exists)) {
      while (idx--) {
        entry[idx].DebugCheckUserKey(this, k.user_key());
        uint64_t tag = entry[idx].tag;
        if ((tag & 255) == kTypeMerge) {
          // instruct get_context to stop earlier
          tag = (tag & ~uint64_t(255)) | kTypeValue;
        }
        key_val.tag = tag;
        if (!callback_func(callback_args, key_val))
          break;
      }
    }
    else while (idx--) {
      entry[idx].DebugCheckUserKey(this, k.user_key());
      key_val.tag = entry[idx].tag;
      key_val.value = GetValue(entry[idx]);
      if (!callback_func(callback_args, key_val))
        break;
    }
    m_token_use_idle ? token->idle() : token->release();
  }
  Status SST_Get(const ReadOptions& ro,  const Slice& ikey,
                 GetContext* get_context) const {
    if (m_ref_to_wal == kPlainLogRef)
      return SST_GetTpl<KeyValueToLogRef>(ro, ikey, get_context);
    else if (m_ref_to_wal == kShortLogRef)
      return SST_GetTpl<KV_ToShortLogRef>(ro, ikey, get_context);
    else
      return SST_GetTpl<Entry>(ro, ikey, get_context);
  }
  template<class Entry>
  Status SST_GetTpl(const ReadOptions& ro,  const Slice& ikey,
                    GetContext* get_context) const {
    ROCKSDB_ASSERT_GE(ikey.size(), kNumInternalBytes);
    ParsedInternalKey pikey(ikey);
    Status st;
    MainPatricia::SingleReaderToken token(&m_trie);
    if (!m_trie.lookup(pikey.user_key, &token)) {
      return st;
    }
    const SequenceNumber find_tag = pikey.GetTag();
    Cleanable noop_pinner;
    Cleanable* pinner = ro.pinning_tls ? &noop_pinner : nullptr;
    uint32_t vec_pin_pos = m_trie.value_of<uint32_t>(token);
    auto vec_pin = (VecPin*)m_trie.mem_get(vec_pin_pos);
    size_t num = vec_pin->num & ~LOCK_FLAG;
    auto entry = (Entry*)m_trie.mem_get(vec_pin->pos);
    intptr_t idx = upper_bound_0(entry, num, find_tag);
    if (ro.just_check_key_exists) {
      while (idx--) {
        entry[idx].DebugCheckUserKey(this, pikey.user_key);
        uint64_t tag = entry[idx].tag;
        UnPackSequenceAndType(tag, &pikey.sequence, &pikey.type);
        if (pikey.type == kTypeMerge) {
          // instruct get_context to stop earlier
          pikey.type = kTypeValue;
        }
        if (!get_context->SaveValue(pikey, "", pinner)) {
          break;
        }
      }
    }
    else while (idx--) {
      entry[idx].DebugCheckUserKey(this, pikey.user_key);
      uint64_t tag = entry[idx].tag;
      UnPackSequenceAndType(tag, &pikey.sequence, &pikey.type);
      Slice value = GetValue(entry[idx]);
      if (!get_context->SaveValue(pikey, value, pinner)) {
        break;
      }
    }
    return st;
  }
  bool GetRandomInternalKeysAppend(size_t num, std::vector<std::string>* output) const;
  std::string FirstInternalKey(Slice user_key, MainPatricia::TokenBase&) const;
#if (ROCKSDB_MAJOR * 10000 + ROCKSDB_MINOR * 10 + ROCKSDB_PATCH) >= 70060
  using Anchor = TableReader::Anchor;
  Status ApproximateKeyAnchors(const ReadOptions&, std::vector<Anchor>&) const;
#endif
  bool NeedsUserKeyCompareInGet() const final { return false; }
  MemTableRep::Iterator* GetIterator(Arena*) final;
  template<class EntryType>
  struct Iter;
  static size_t EncValueLen(size_t raw_val_len) {
    if (raw_val_len)
      return pow2_align_up(VarintLength(raw_val_len) + raw_val_len, Align);
    else
      return 0; // does not occupy space
  }
  void ToWebViewJson(json&, const json& dump_options) const;
};
template<class EntryLogRef>
void CSPPMemTab::Token::SetKeyValueToLogRef(CSPPMemTab* mtab, EntryLogRef* entry) {
  entry->tag = tag_;
  if (0 == val_.size()) { // Delete/SingleDelete/...
    memset(entry->value, 0, sizeof(entry->value)+1);
    return;
  }
  ROCKSDB_VERIFY_EQ(val_.size(), sizeof(KeyValuePassMemTable));
  auto kv_pmt = (const KeyValuePassMemTable*)(val_.data_);
  auto valsize = kv_pmt->value.size_;
  if (valsize <= sizeof(entry->value)) { // save inline
    static_assert(sizeof(entry->value) % 4 == 3);
    memset(entry->value, 0, sizeof(entry->value)+1);
    memcpy(entry->value, kv_pmt->value.data_, valsize);
    entry->inline_val_len = valsize;
  } else {
    auto fidx = mtab->add_wal(kv_pmt->fileno, kv_pmt->wal_file);
    auto& x = m_wal_cnt_bytes[fidx];
    x.cnt++;
    x.bytes += valsize;
    size_t THREAD_LOCAL_THRESHOLD = TERARK_IF_DEBUG(1, 512 * 1024);
    size_t approximate_inc_bytes = x.cnt * sizeof(EntryLogRef) + x.bytes;
    if (UNLIKELY(approximate_inc_bytes > THREAD_LOCAL_THRESHOLD)) {
      as_atomic(mtab->m_wals[fidx].cnt).fetch_add(x.cnt, std::memory_order_relaxed);
      as_atomic(mtab->m_wals[fidx].bytes).fetch_add(x.bytes, std::memory_order_relaxed);
      x = {}; // reset
    }
    entry->wal_idx = fidx;
    if constexpr (std::is_same_v<EntryLogRef, KeyValueToLogRef>) {
      entry->val_pos = kv_pmt->val_pos;
      entry->val_len = valsize;
    } else {
      entry->val_pos = kv_pmt->val_pos - VarintLength(valsize);
    }
    entry->inline_val_len = 255; // as a flag
  }
  TERARK_ASSERT_S_EQ(entry->GetValue(mtab), kv_pmt->value);
}
bool CSPPMemTab::Token::init_value(void* trie_valptr, size_t valsize) noexcept {
  TERARK_ASSERT_EQ(valsize, sizeof(uint32_t));
  auto trie = static_cast<MainPatricia*>(m_trie);
  // 1. one memory block, 3 logical blocks are contiguous, CPU cache friendly
  // 2. one memory block can be free'ed partially, we using this feature here
  static_assert(Align == 4); // now it must be 4
  static_assert(sizeof(VecPin) % Align == 0);
  auto mtab = (CSPPMemTab*)((char*)(trie) - offsetof(CSPPMemTab, m_trie));
  auto init_ref = [=](auto* dummy) {
    using KeyValueToLogRef = std::remove_reference_t<decltype(*dummy)>;
    size_t vec_pin_pos = trie->mem_alloc(sizeof(VecPin) + sizeof(KeyValueToLogRef));
    TERARK_VERIFY_NE(vec_pin_pos, MainPatricia::mem_alloc_fail);
    auto vec_pin = (VecPin*)(trie->mem_get(vec_pin_pos));
    SetKeyValueToLogRef(mtab, (KeyValueToLogRef*)(vec_pin + 1));
    vec_pin->pos = (uint32_t)(vec_pin_pos + (sizeof(VecPin) / Align));
    vec_pin->num = 1;
    *(uint32_t*)trie_valptr = (uint32_t)vec_pin_pos;
    return true;
  };
  if (mtab->m_ref_to_wal == kPlainLogRef) {
    return init_ref((KeyValueToLogRef*)nullptr);
  }
  if (mtab->m_ref_to_wal == kShortLogRef) {
    return init_ref((KV_ToShortLogRef*)nullptr);
  }
  size_t enc_val_len = EncValueLen(val_.size());
  size_t vec_pin_pos = trie->mem_alloc(sizeof(VecPin) + sizeof(Entry) + enc_val_len);
  TERARK_VERIFY_NE(vec_pin_pos, MainPatricia::mem_alloc_fail);
  size_t entry_pos = vec_pin_pos + (sizeof(VecPin) / Align);
  auto vec_pin = (VecPin*)(trie->mem_get(vec_pin_pos));
  auto entry = (Entry*)(vec_pin + 1);
  *(uint32_t*)trie_valptr = (uint32_t)vec_pin_pos;
  vec_pin->pos = (uint32_t)entry_pos;
  vec_pin->num = 1;
  entry->tag = tag_;
  if (val_.size_) {
    auto enc_val_ptr = (byte_t*)(entry + 1);
    size_t enc_val_pos = vec_pin_pos + ((sizeof(VecPin) + sizeof(Entry)) / Align);
    entry->pos = (uint32_t)enc_val_pos;
    encode_pre(val_, enc_val_ptr);
  } else {
    entry->pos = 0;
  }
  return true;
}
void CSPPMemTab::Token::destroy_value(void* trie_valptr, size_t valsize) noexcept {
  // should be called very rarely: multi threads racing insert same user_key.
  // if do nothing, the memory block allocated in init_value will be leaked.
  TERARK_ASSERT_EQ(valsize, sizeof(uint32_t));
  auto trie = static_cast<MainPatricia*>(m_trie);
  size_t vec_pin_pos = *(const uint32_t*)trie_valptr;
  auto mtab = (CSPPMemTab*)((char*)(trie) - offsetof(CSPPMemTab, m_trie));
  if (mtab->m_ref_to_wal == kPlainLogRef) {
    size_t mem_block_len = sizeof(VecPin) + sizeof(KeyValueToLogRef);
    trie->mem_free(vec_pin_pos, mem_block_len); // free right now, not lazy free
    return;
  }
  if (mtab->m_ref_to_wal == kShortLogRef) {
    size_t mem_block_len = sizeof(VecPin) + sizeof(KV_ToShortLogRef);
    trie->mem_free(vec_pin_pos, mem_block_len); // free right now, not lazy free
    return;
  }
  size_t enc_val_len = EncValueLen(val_.size());
  size_t mem_block_len = sizeof(VecPin) + sizeof(Entry) + enc_val_len;
  trie->mem_free(vec_pin_pos, mem_block_len); // free right now, not lazy free
}
terark_forceinline
bool CSPPMemTab::insert_kv(fstring user_key, Token* tok) {
  uint32_t value_storage = UINT32_MAX;
  if (LIKELY(m_trie.insert(user_key, &value_storage, tok))) {
    TERARK_VERIFY_S(tok->has_value(), "OOM: mem_cap=%zd is too small: %s",
                    m_trie.mem_capacity(), m_trie.mmap_fpath());
    return true; // done: value insert has been handled in init_value
  }
  return tok->insert_for_dup_user_key(this);
}
bool CSPPMemTab::Token::insert_for_dup_user_key(CSPPMemTab* tab) {
  auto trie = &tab->m_trie;
  auto vec_pin_pos = trie->value_of<uint32_t>(*this);
  auto vec_pin = (VecPin*)trie->mem_get(vec_pin_pos);
  uint32_t num;
  while (LOCK_FLAG & (num = as_atomic(vec_pin->num)
                           .fetch_or(LOCK_FLAG, std::memory_order_acquire))) {
    tab->OnDupUserKeyYield();
    std::this_thread::yield(); // has been locked by other threads, yield
  }
  // is power of 2 --------vvvvvvvvvvvvvvvv
  const uint32_t old_cap = (num&(num-1))==0 ? num : 2u << terark_bsr_u32(num);
  TERARK_ASSERT_GT(num, 0);
  TERARK_ASSERT_LE(num, old_cap);
  const auto entry_old_pos = vec_pin->pos;
  auto insert_dup = [&,this](auto* dummy) {
    using KeyValueToLogRef = std::remove_reference_t<decltype(*dummy)>;
    const auto entry_old = (KeyValueToLogRef*)trie->mem_get(entry_old_pos);
    const uint64_t curr_seq = tag_ >> 8;
    const uint64_t last_seq = entry_old[num-1].tag >> 8;
    if (UNLIKELY(curr_seq == last_seq)) {
      as_atomic(vec_pin->num).store(num, std::memory_order_release);
      return false; // duplicate internal_key(user_key, tag)
    }
    maximize(max_dup_len, num + 1);
    if (num < old_cap && last_seq < curr_seq) {
      SetKeyValueToLogRef(tab, &entry_old[num]);
      // this atomic store also clears LOCK_FLAG
      as_atomic(vec_pin->num).store(num + 1, std::memory_order_release);
      return true;
    }
    if (1 == num) {
      num_dup_user_keys++;
    }
    trie->mem_gc(this); // on many dup, gc is needed to revoke lazy free'ed mem
    uint32_t new_cap = num == old_cap ? old_cap * 2 : old_cap;
    size_t entry_cow_pos = trie->mem_alloc(sizeof(KeyValueToLogRef) * new_cap);
    TERARK_VERIFY_NE(entry_cow_pos, MainPatricia::mem_alloc_fail);
    auto entry_cow = (KeyValueToLogRef*)trie->mem_get(entry_cow_pos);
    if (LIKELY(last_seq < curr_seq)) {
      memcpy(entry_cow, entry_old, sizeof(KeyValueToLogRef) * num);
      SetKeyValueToLogRef(tab, &entry_cow[num]);
    } else {
      auto idx = lower_bound_0(entry_old, num, curr_seq << 8);
      if (UNLIKELY(entry_old[idx].tag >> 8 == curr_seq)) { // very rare
        as_atomic(vec_pin->num).store(num, std::memory_order_release);
        trie->mem_free(entry_cow_pos, sizeof(KeyValueToLogRef) * new_cap);
        return false; // duplicate internal_key(user_key, tag)
      }
      memcpy(entry_cow, entry_old, sizeof(KeyValueToLogRef) * idx);
      SetKeyValueToLogRef(tab, &entry_cow[idx]);
      memcpy(entry_cow + idx+1, entry_old + idx, sizeof(KeyValueToLogRef)*(num-idx));
    }
    vec_pin->pos = (uint32_t)entry_cow_pos; // not need atomic
    // this memory_order_release makes all previous write visiable to other CPUs
    // vec_pin->num.store also clears LOCK_FLAG
    as_atomic(vec_pin->num).store(num + 1, std::memory_order_release);
    trie->mem_lazy_free(entry_old_pos, sizeof(KeyValueToLogRef) * old_cap, this);
    return true;
  };
  if (tab->m_ref_to_wal == kPlainLogRef) {
    return insert_dup((KeyValueToLogRef*)nullptr);
  }
  if (tab->m_ref_to_wal == kShortLogRef) {
    return insert_dup((KV_ToShortLogRef*)nullptr);
  }
  const auto entry_old = (Entry*)trie->mem_get(entry_old_pos);
  const uint64_t curr_seq = tag_ >> 8;
  const uint64_t last_seq = entry_old[num-1].tag >> 8;
  if (UNLIKELY(curr_seq == last_seq)) {
    as_atomic(vec_pin->num).store(num, std::memory_order_release);
    return false; // duplicate internal_key(user_key, tag)
  }
  trie->mem_gc(this); // on many dup, gc is needed to revoke lazy free'ed mem
  size_t enc_val_pos;
  if (val_.size_) {
    enc_val_pos = trie->mem_alloc(VarintLength(val_.size()) + val_.size());
    TERARK_VERIFY_NE(enc_val_pos, MainPatricia::mem_alloc_fail);
    encode_pre(val_, trie->mem_get(enc_val_pos));
  } else {
    enc_val_pos = 0;
  }
  maximize(max_dup_len, num + 1);
  if (num < old_cap && last_seq < curr_seq) {
    entry_old[num].pos = (uint32_t)enc_val_pos;
    entry_old[num].tag = tag_;
    // this atomic store also clears LOCK_FLAG
    as_atomic(vec_pin->num).store(num + 1, std::memory_order_release);
    return true;
  }
  if (1 == num) {
    num_dup_user_keys++;
  }
  uint32_t new_cap = num == old_cap ? old_cap * 2 : old_cap;
  size_t entry_cow_pos = trie->mem_alloc(sizeof(Entry) * new_cap);
  TERARK_VERIFY_NE(entry_cow_pos, MainPatricia::mem_alloc_fail);
  auto entry_cow = (Entry*)trie->mem_get(entry_cow_pos);
  if (LIKELY(last_seq < curr_seq)) {
    memcpy(entry_cow, entry_old, sizeof(Entry) * num);
    entry_cow[num].pos = (uint32_t)enc_val_pos;
    entry_cow[num].tag = tag_;
  } else {
    auto idx = lower_bound_0(entry_old, num, curr_seq << 8);
    if (UNLIKELY(entry_old[idx].tag >> 8 == curr_seq)) { // very rare
      as_atomic(vec_pin->num).store(num, std::memory_order_release);
      trie->mem_free(entry_cow_pos, sizeof(Entry) * new_cap);
      if (enc_val_pos) {
        size_t enc_val_len = VarintLength(val_.size()) + val_.size();
        trie->mem_free(enc_val_pos, enc_val_len);
      }
      return false; // duplicate internal_key(user_key, tag)
    }
    memcpy(entry_cow, entry_old, sizeof(Entry) * idx);
    entry_cow[idx].pos = (uint32_t)enc_val_pos;
    entry_cow[idx].tag = tag_;
    memcpy(entry_cow + idx+1, entry_old + idx, sizeof(Entry)*(num-idx));
  }
  vec_pin->pos = (uint32_t)entry_cow_pos; // not need atomic
  // this memory_order_release makes all previous write visiable to other CPUs
  // vec_pin->num.store also clears LOCK_FLAG
  as_atomic(vec_pin->num).store(num + 1, std::memory_order_release);
  trie->mem_lazy_free(entry_old_pos, sizeof(Entry) * old_cap, this);
  return true;
}
template<class Entry>
struct CSPPMemTab::Iter : public MemTableRep::Iterator, boost::noncopyable {
  Patricia::Iterator* m_iter;
 #if defined(_MSC_VER) || defined(__clang__)
  void CreateDfaIter() {
    m_iter = m_tab->m_trie.new_iter();
  }
  bool InvokeDfaIterNext() { return m_iter->incr(); }
  bool InvokeDfaIterPrev() { return m_iter->decr(); }
 #else
  #pragma GCC diagnostic ignored "-Wpmf-conversions"
  typedef bool (*DfaIterScanFN)(ADFA_LexIterator*);
  DfaIterScanFN m_dfa_iter_next;
  DfaIterScanFN m_dfa_iter_prev;
  void CreateDfaIter() {
    m_iter = m_tab->m_trie.new_iter();
    m_dfa_iter_next = (DfaIterScanFN)(m_iter->*(&ADFA_LexIterator::incr));
    m_dfa_iter_prev = (DfaIterScanFN)(m_iter->*(&ADFA_LexIterator::decr));
  }
  inline bool InvokeDfaIterNext() { return m_dfa_iter_next(m_iter); }
  inline bool InvokeDfaIterPrev() { return m_dfa_iter_prev(m_iter); }
 #endif
  CSPPMemTab* m_tab;
  const char* m_mempool = nullptr; // used for speed up memory access
  const VecPin* m_vec_pin = nullptr; // used for speed up memory access
  int         m_idx = -1;
  bool        m_rev;
  struct EntryVec { int num; const Entry* vec; };
  terark_forceinline EntryVec GetEntryVec() {
    assert(m_iter->has_value());
    auto mempool = m_mempool;
    auto vec_pin_pos = *(uint32_t*)(mempool + m_iter->get_valpos());
    auto vec_pin_ptr = (VecPin*)(mempool + Align * vec_pin_pos);
    m_vec_pin = vec_pin_ptr; // save to m_vec_pin for laster use for speed up
    return AccessEntryVec(vec_pin_ptr, mempool);
  }
  terark_forceinline
  EntryVec AccessEntryVec(const VecPin* vec_pin, const char* mempool) const {
    auto entry_num = int(vec_pin->num & ~LOCK_FLAG);
    auto entry_vec = (Entry*)(mempool + Align * vec_pin->pos);
    return { entry_num, entry_vec };
  }
  terark_forceinline void AppendTag(uint64_t tag) const {
    unaligned_save(m_iter->mutable_word().ensure_unused(8), tag);
  }
  explicit Iter(CSPPMemTab*);
  ~Iter() noexcept override;
  bool Valid() const final { return m_idx >= 0; }
  const char* varlen_key() const final { TERARK_DIE("Bad call"); }
  Slice user_key() const final {
    TERARK_ASSERT_GE(m_idx, 0);
    return SliceOf(m_iter->word());
  }
  Slice key() const final {
    TERARK_ASSERT_GE(m_idx, 0);
    fstring user_key = m_iter->word();
    return Slice(user_key.p, user_key.n + 8);
  }
  Slice value() const final {
    TERARK_ASSERT_GE(m_idx, 0);
    auto mempool = m_mempool;
    auto entry = (const Entry*)(mempool + Align * m_vec_pin->pos);
    entry[m_idx].DebugCheckUserKey(m_tab, user_key());
    if constexpr (std::is_same_v<Entry, CSPPMemTab::Entry>)
      return entry[m_idx].GetValue(mempool);
    else
      return entry[m_idx].GetValue(m_tab);
  }
  std::pair<Slice, Slice>
  GetKeyValue() const final { return {key(), value()}; }
  void Next() final {
    NextAndCheckValid(); // ignore return value
  }
  bool NextAndCheckValid() final {
    TERARK_ASSERT_GE(m_idx, 0);
    if (m_idx-- == 0) {
      if (UNLIKELY(!(m_rev ? InvokeDfaIterPrev() : InvokeDfaIterNext()))) {
        TERARK_ASSERT_LT(m_idx, 0);
        return false; // fail
      }
      auto entry = GetEntryVec();
      AppendTag(entry.vec[m_idx = entry.num - 1].tag);
    } else {
      auto entry = (const Entry*)(m_mempool + Align * m_vec_pin->pos);
      AppendTag(entry[m_idx].tag);
    }
    return true;
  }
  bool NextAndGetResult(IterateResult* result) final {
    if (LIKELY(NextAndCheckValid())) {
      result->SetKey(this->key());
      result->bound_check_result = IterBoundCheck::kUnknown;
      result->value_prepared = true;
      result->is_valid = true;
      return true;
    } else {
      result->is_valid = false;
      return false;
    }
  }
  void Prev() final {
    PrevAndCheckValid(); // ignore return value
  }
  bool PrevAndCheckValid() final {
    TERARK_ASSERT_GE(m_idx, 0);
    auto entry = AccessEntryVec(m_vec_pin, m_mempool);
    if (++m_idx == entry.num) {
      if (UNLIKELY(!(m_rev ? InvokeDfaIterNext() : InvokeDfaIterPrev()))) {
        m_idx = -1;
        return false; // fail
      }
      entry = GetEntryVec();
      m_idx = 0;
    }
    AppendTag(entry.vec[m_idx].tag);
    return true;
  }
  void Seek(const Slice& ikey, const char*) final {
    return Seek(ikey);
  }
  void Seek(const Slice& ikey) final {
    if (UNLIKELY(!m_iter)) {
      if (m_tab->m_is_empty) return;
      CreateDfaIter();
    }
    fstring user_key = ExtractUserKey(ikey);
    uint64_t find_tag = DecodeFixed64(user_key.end());
    auto& iter = *m_iter;
    if (UNLIKELY(!(m_rev ? iter.seek_rev_lower_bound(user_key)
                         : iter.seek_lower_bound(user_key)))) {
      m_idx = -1;
      return; // fail
    }
    auto entry = GetEntryVec();
    if (iter.word() == user_key) {
      m_idx = (int)upper_bound_0(entry.vec, entry.num, find_tag) - 1;
      if (m_idx >= 0) {
        AppendTag(entry.vec[m_idx].tag);
        return; // success
      }
      if (UNLIKELY(!(m_rev ? InvokeDfaIterPrev() : InvokeDfaIterNext()))) {
        TERARK_ASSERT_LT(m_idx, 0);
        return; // fail
      }
      entry = GetEntryVec();
    }
    assert((iter.word() > user_key) ^ m_rev);
    AppendTag(entry.vec[m_idx = entry.num - 1].tag);
  }
  void SeekForPrev(const Slice& ikey, const char*) final {
    return SeekForPrev(ikey);
  }
  void SeekForPrev(const Slice& ikey) final {
    if (UNLIKELY(!m_iter)) {
      if (m_tab->m_is_empty) return;
      CreateDfaIter();
    }
    fstring user_key = ExtractUserKey(ikey);
    uint64_t find_tag = DecodeFixed64(user_key.end());
    auto& iter = *m_iter;
    if (UNLIKELY(!(m_rev ? iter.seek_lower_bound(user_key)
                         : iter.seek_rev_lower_bound(user_key)))) {
      m_idx = -1;
      return; // fail
    }
    auto entry = GetEntryVec();
    if (iter.word() == user_key) {
      m_idx = (int)lower_bound_0(entry.vec, entry.num, find_tag);
      if (m_idx != entry.num) {
        AppendTag(entry.vec[m_idx].tag);
        return; // success
      }
      if (UNLIKELY(!(m_rev ? InvokeDfaIterNext() : InvokeDfaIterPrev()))) {
        m_idx = -1;
        return; // fail
      }
      entry = GetEntryVec();
    }
    assert((iter.word() < user_key) ^ m_rev);
    AppendTag(entry.vec[m_idx = 0].tag);
  }
  void SeekToFirst() final {
    if (UNLIKELY(!m_iter)) {
      if (m_tab->m_is_empty) return;
      CreateDfaIter();
    }
    if (UNLIKELY(!(m_rev ? m_iter->seek_end() : m_iter->seek_begin()))) {
      m_idx = -1;
      return; // fail
    }
    auto entry = GetEntryVec();
    AppendTag(entry.vec[m_idx = entry.num - 1].tag);
  }
  void SeekToLast() final {
    if (UNLIKELY(!m_iter)) {
      if (m_tab->m_is_empty) return;
      CreateDfaIter();
    }
    if (UNLIKELY(!(m_rev ? m_iter->seek_begin() : m_iter->seek_end()))) {
      m_idx = -1;
      return; // fail
    }
    auto entry = GetEntryVec();
    AppendTag(entry.vec[m_idx = 0].tag);
  }
  bool IsKeyPinned() const final { return false; }
};
void JS_CSPPMemTab_AddVersion(json& djs, bool html) {
  auto& ver = djs["cspp-memtable"];
  const char* git_ver = git_version_hash_info_cspp_memtable();
  if (html) {
    std::string topling_rocks = HtmlEscapeMin(strstr(git_ver, "commit ") + strlen("commit "));
    auto headstr = [](const std::string& s, auto pos) {
      return terark::fstring(s.data(), pos - s.begin());
    };
    auto tailstr = [](const std::string& s, auto pos) {
      return terark::fstring(&*pos, s.end() - pos);
    };
    auto topling_rocks_sha_end = std::find_if(topling_rocks.begin(), topling_rocks.end(), &isspace);
    terark::string_appender<> oss_rocks(valvec_reserve(), 512);
    oss_rocks|"<pre>"
             |"<a href='https://github.com/topling/cspp-memtable/commit/"
             |headstr(topling_rocks, topling_rocks_sha_end)|"'>"
             |headstr(topling_rocks, topling_rocks_sha_end)|"</a>"
             |tailstr(topling_rocks, topling_rocks_sha_end)
             |"</pre>";
    ver = static_cast<std::string&&>(oss_rocks);
  } else {
    ver = git_ver;
  }
}
ROCKSDB_ENUM_CLASS(HugePageEnum, uint8_t, kNone = 0, kMmap = 1, kTransparent = 2);
constexpr size_t huge_2m = 2 << 20;
struct CSPPMemTabFactory final : public MemTableRepFactory {
  size_t m_mem_cap = 2LL << 30;
  bool   use_vm = true;
  HugePageEnum  use_hugepage = HugePageEnum::kNone;
  bool   vm_explicit_commit = false;
  bool   vm_background_commit = false; // true almost always makes slow
  bool   vm_coldize_on_flush = false;
  bool   read_by_writer_token = true;
  bool   token_use_idle = true;
  bool   accurate_memsize = false; // mainly for debug and unit test
  bool   sync_sst_file = true;
  bool   enableApproximateNumEntries = false; // may be pretty not accurate
  CSPPMemTab::LogRef_Format log_ref_format = CSPPMemTab::kShortLogRef;
  ConvertKind convert_to_sst = ConvertKind::kDontConvert;
  std::string chroot_dir; // default empty
  size_t chunk_size = huge_2m;
  size_t cumu_num = 0, cumu_iter_num = 0;
  size_t live_num = 0, live_iter_num = 0;
  size_t max_dup_len = 1;
  size_t num_dup_user_keys = 0;
  size_t num_dup_yields = 0;
  uint64_t deactived_mem_sum = 0;
  MemTabLinkListNode m_head;
  mutable std::mutex m_mtx;
  CSPPMemTabFactory(const json& js, const SidePluginRepo& r) {
    m_head.m_next = m_head.m_prev = &m_head;
    ROCKSDB_JSON_OPT_PROP(js, chroot_dir); // immutable
    Update({}, js, r);
  }
  MemTableRep* CreateMemTableRep(const MemTableRep::KeyComparator& cmp,
                                 Allocator* a, const SliceTransform* s,
                                 Logger* logger) final {
    return CreateMemTableRep("", MutableCFOptions(), cmp, a, s, logger, 0);
  }
  MemTableRep* CreateMemTableRep(const MemTableRep::KeyComparator& cmp,
                                 Allocator* a, const SliceTransform* s,
                                 Logger* logger, uint32_t cf_id) final {
    return CreateMemTableRep("", MutableCFOptions(), cmp, a, s, logger, cf_id);
  }
  MemTableRep* CreateMemTableRep(const std::string& level0_dir,
                                 const MutableCFOptions& mcfopt,
                                 const MemTableRep::KeyComparator& cmp,
                                 Allocator*, const SliceTransform*,
                                 Logger* logger, uint32_t cf_id) final {
    auto uc = cmp.icomparator()->user_comparator();
    if (!uc->IsBytewise()) {
      return nullptr;
    }
    // may be updated by webview
    auto curr_chunk_size = this->chunk_size;
    auto curr_use_hugepage = this->use_hugepage;
    auto curr_convert_to_sst = this->convert_to_sst;
    auto curr_num = as_atomic(cumu_num).fetch_add(1, std::memory_order_relaxed);
    terark::string_appender<> conf(valvec_reserve(), 512);
    conf|"?chunk_size="|curr_chunk_size;
    if (ConvertKind::kFileMmap == curr_convert_to_sst) {
      // File mmap does not support hugepage
      conf|"&file_path="|chroot_dir|level0_dir;
      conf^"/cspp-%06zd.memtab"^curr_num^"-"^cf_id;
    } else {
      conf|"&hugepage="|int(curr_use_hugepage);
      if (HugePageEnum::kNone == curr_use_hugepage || huge_2m == curr_chunk_size) {
        if (vm_explicit_commit)
          conf|"&vm_explicit_commit=true"; // default is false
      }
    }
    // config param mem_cap is required, DONT delete it!
    // because write_buffer_size can be changed dynamically, if it is changed
    // larger, and existing CSPPMemTab was created with
    //             mem_cap = old write_bufer_size * 2
    // which is smaller than new write_bufer_size, that CSPPMemTab will be
    // add data size with respect to new write_bufer_size, thus cause memory
    // alloc in CSPP trie failed.
    auto require = std::min({mcfopt.write_buffer_size * 2,
                             mcfopt.write_buffer_size + (1ul << 30),
                             size_t(16) << 30});
    auto mem_cap = std::max(m_mem_cap, require);
    auto tab = new CSPPMemTab(mem_cap, uc->IsReverseBytewise(), logger,
                              this, curr_num, curr_convert_to_sst, conf);
    auto len = std::min(mcfopt.write_buffer_size, tab->m_trie.mem_capacity());
    if (ConvertKind::kFileMmap == curr_convert_to_sst && len >= 4096 &&
                vm_background_commit && IsRocksBackgroundThread()) {
      // this is almost always slow, may be NUMA, if not populate write all
      // memory, os will populate it as needed, thus the memory will almost
      // always allocated on/near working CPUs, for NUMA, this is more friendly
    #ifdef __linux__
      if (g_linux_kernel_version >= KERNEL_VERSION(5,14,0)) {
        auto populate_write = 23; // MADV_POPULATE_WRITE = 23
        auto mem = tab->m_trie.get_mmap();
        auto t0 = std::chrono::steady_clock::now();
        if (madvise((void*)mem.p, len, populate_write) < 0) {
          ROCKS_LOG_WARN(logger, "MADV_POPULATE_WRITE(%s, %zd) = %m",
                         tab->m_trie.mmap_fpath().c_str(), len);
        }
        auto t1 = std::chrono::steady_clock::now();
        using namespace std::chrono;
        ROCKS_LOG_DEBUG(logger, "MADV_POPULATE_WRITE(%s, %zd) = %.6f ms",
                        tab->m_trie.mmap_fpath().c_str(), len,
                        duration_cast<nanoseconds>(t1-t0).count()/1e6);
      }
    #endif
    }
    return tab;
  }
  const char *Name() const final { return "CSPPMemTabFactory"; }
  bool IsInsertConcurrentlySupported() const final { return true; }
  bool CanHandleDuplicatedKey() const final { return true; }
//-----------------------------------------------------------------
  void Update(const json&, const json& js, const SidePluginRepo&) {
    size_t mem_cap = m_mem_cap;
    ROCKSDB_JSON_OPT_SIZE(js, mem_cap);
    ROCKSDB_JSON_OPT_PROP(js, use_vm);
    auto iter = js.find("use_hugepage");
    if (js.end() != iter) {
      auto& jhg = iter.value();
      if (jhg.is_boolean()) {
        use_hugepage = jhg.get<bool>() ? HugePageEnum::kMmap
                                       : HugePageEnum::kNone;
      } else if (jhg.is_string()) {
        ROCKSDB_JSON_OPT_ENUM(js, use_hugepage);
      } else {
        THROW_InvalidArgument("use_hugepage must be bool or HugePageEnum");
      }
    }
    ROCKSDB_JSON_OPT_PROP(js, vm_explicit_commit);
    ROCKSDB_JSON_OPT_PROP(js, vm_background_commit);
    ROCKSDB_JSON_OPT_PROP(js, vm_coldize_on_flush);
    ROCKSDB_JSON_OPT_PROP(js, read_by_writer_token);
    ROCKSDB_JSON_OPT_PROP(js, token_use_idle);
    ROCKSDB_JSON_OPT_PROP(js, accurate_memsize);
    ROCKSDB_JSON_OPT_ENUM(js, log_ref_format);
    ROCKSDB_JSON_OPT_ENUM(js, convert_to_sst);
    ROCKSDB_JSON_OPT_PROP(js, sync_sst_file);
    ROCKSDB_JSON_OPT_PROP(js, enableApproximateNumEntries);
    iter = js.find("chunk_size");
    if (js.end() != iter) {
      ROCKSDB_JSON_OPT_SIZE(js, chunk_size);
      ROCKSDB_VERIFY_F((chunk_size & (chunk_size-1)) == 0, "%zd(%#zX)",
                        chunk_size, chunk_size);
    }
    else {
     #if defined(ROCKSDB_UNIT_TEST)
      chunk_size = 1024;
     #endif
    }
    { // cspp global conf
      if (js.contains("cspp_debug_level")) {
        if (js["cspp_debug_level"].is_string()) {
          InfoLogLevel cspp_debug_level = InfoLogLevel::ERROR_LEVEL;
          ROCKSDB_JSON_OPT_ENUM(js, cspp_debug_level);
          CSPP_SetDebugLevel(3 - cspp_debug_level);
        } else {
          long cspp_debug_level = 0; // ERROR_LEVEL
          ROCKSDB_JSON_OPT_PROP(js, cspp_debug_level);
          CSPP_SetDebugLevel(cspp_debug_level);
        }
      }
    }
    m_mem_cap = mem_cap;
  }
  std::string ToString(const json& d, const SidePluginRepo&) const {
    return JsonToString(ToJson(d), d);
  }
  json ToJson(const json& d) const {
    size_t mem_cap = m_mem_cap;
    bool html = JsonSmartBool(d, "html");
    json djs;
    if (html) {
      const auto document =
        "<a href='https://github.com/topling/cspp-memtab/blob/main/README-en.md'>Document(English)</a>"
        " | "
        "<a href='https://github.com/topling/cspp-memtab/blob/main/README.md'>文档（中文）</a>"
        ;
      ROCKSDB_JSON_SET_PROP(djs, document);
    }
    ROCKSDB_JSON_SET_SIZE(djs, mem_cap);
    ROCKSDB_JSON_SET_SIZE(djs, chunk_size);
    ROCKSDB_JSON_SET_PROP(djs, use_vm);
    ROCKSDB_JSON_SET_ENUM(djs, use_hugepage);
    ROCKSDB_JSON_SET_PROP(djs, vm_explicit_commit);
    ROCKSDB_JSON_SET_PROP(djs, vm_background_commit);
    ROCKSDB_JSON_SET_PROP(djs, vm_coldize_on_flush);
    ROCKSDB_JSON_SET_PROP(djs, read_by_writer_token);
    ROCKSDB_JSON_SET_PROP(djs, token_use_idle);
    ROCKSDB_JSON_SET_PROP(djs, accurate_memsize);
    ROCKSDB_JSON_SET_ENUM(djs, log_ref_format);
    ROCKSDB_JSON_SET_ENUM(djs, convert_to_sst);
    ROCKSDB_JSON_SET_PROP(djs, sync_sst_file);
    ROCKSDB_JSON_SET_PROP(djs, enableApproximateNumEntries);
    ROCKSDB_JSON_SET_PROP(djs, chroot_dir);
    { // cspp global conf
      long val = CSPP_GetDebugLevel();
      if (val >= 0 && val <= 3) {
        auto cspp_debug_level = InfoLogLevel(3 - val);
        ROCKSDB_JSON_SET_ENUM(djs, cspp_debug_level);
      } else {
        auto cspp_debug_level = val;
        ROCKSDB_JSON_SET_PROP(djs, cspp_debug_level);
      }
    }
    ROCKSDB_JSON_SET_PROP(djs, max_dup_len);
    ROCKSDB_JSON_SET_PROP(djs, num_dup_user_keys);
    ROCKSDB_JSON_SET_PROP(djs, num_dup_yields);
    ROCKSDB_JSON_SET_PROP(djs, cumu_iter_num);
    ROCKSDB_JSON_SET_PROP(djs, live_iter_num);
    size_t active_num = 0;
    size_t active_used_mem = 0;
    size_t live_used_mem = 0;
    size_t token_qlen = 0;
    size_t total_raw_iter = 0;
    string_appender<> detail_qlen(valvec_reserve(), 128*live_num);
    detail_qlen << "[ ";
    m_mtx.lock();
    for (auto node = m_head.m_next; node != &m_head; node = node->m_next) {
      auto memtab = static_cast<CSPPMemTab*>(node);
      live_used_mem += memtab->m_trie.mem_size_inline();
      if (!memtab->m_has_marked_readonly && !memtab->m_is_sst)
        active_num++,
        active_used_mem += memtab->m_trie.mem_size_inline();
      size_t idx = memtab->m_instance_idx;
      size_t raw_iter = memtab->m_trie.live_iter_num();
      size_t cur_qlen = memtab->m_trie.get_token_qlen();
      token_qlen += cur_qlen;
      total_raw_iter += raw_iter;
      if (memtab->m_is_flushed)
        if (html)
          detail_qlen|"<strong>("|idx|","|cur_qlen|","|raw_iter|")</strong>, ";
        else
          detail_qlen|"**("|idx|","|cur_qlen|","|raw_iter|")**, ";
      else if (memtab->m_trie.is_readonly()) // real readonly
        detail_qlen|"("|idx|","|cur_qlen|","|raw_iter|"), ";
      else if (memtab->m_has_marked_readonly)
        if (html)
          detail_qlen|"<span style='color:darkgreen'>("|idx|","|cur_qlen|","|raw_iter|")</span>, ";
        else
          detail_qlen|"-("|idx|","|cur_qlen|","|raw_iter|")-, ";
      else if (!memtab->m_is_empty) // active
        if (html)
          detail_qlen|"<strong style='color:darkred'>("|idx|","|cur_qlen|","|raw_iter|")</strong>, ";
        else
          detail_qlen|"*("|idx|","|cur_qlen|","|raw_iter|")*, ";
      else // prepared
        if (html)
          // counter intuitive: darkgray is lighter than gray, so use gray
          detail_qlen|"<span style='color:gray'>("|idx|","|cur_qlen|","|raw_iter|")</span>, ";
        else
          detail_qlen|"+("|idx|","|cur_qlen|","|raw_iter|")+, ";
    }
    size_t deactived_num; // include history and living readonly memtab
    if (LIKELY(m_head.m_prev != &m_head)) { // not empty
      // m_head.m_prev is the most recent memtab in the list
      // likely be same with cumu_num, when racing, may be not same
      deactived_num = static_cast<CSPPMemTab*>(m_head.m_prev)->m_instance_idx + 1;
    } else { // very very unlikely goes here
      deactived_num = cumu_num; // not accurate on racing
    }
    m_mtx.unlock();
    deactived_num -= active_num; // more accurate than deactived_mem_sum
    auto deactived_mem_sum = this->deactived_mem_sum; // not accurate on racing
    auto deactived_mem_avg = deactived_num ? deactived_mem_sum / deactived_num : 0;
    ROCKSDB_JSON_SET_PROP(djs, deactived_num);     // more accurate
    ROCKSDB_JSON_SET_SIZE(djs, deactived_mem_sum); // less accurate
    ROCKSDB_JSON_SET_SIZE(djs, deactived_mem_avg); // less accurate
    if (detail_qlen.size() >= 4) {
      detail_qlen.end()[-2] = ' ';
      detail_qlen.end()[-1] = ']';
    } else {
      detail_qlen << " ]";
    }
    ROCKSDB_JSON_SET_SIZE(djs, active_used_mem);
    ROCKSDB_JSON_SET_SIZE(djs, live_used_mem);
    ROCKSDB_JSON_SET_PROP(djs, live_num);
    ROCKSDB_JSON_SET_PROP(djs, token_qlen);
    ROCKSDB_JSON_SET_PROP(djs, total_raw_iter);
    djs["comment"] = "(idx, qlen, raw_iter_num) | "
                     "<strong>flushed</strong> | "
                     "real readonly | "
      "<span style='color:darkgreen'>marked readonly</span> | "
      "<strong style='color:darkred'>active</strong> | "
      // counter intuitive: darkgray is lighter than gray, so use gray
      "<span style='color:gray'>prepared</span>"
                     ;
    ROCKSDB_JSON_SET_PROP(djs, detail_qlen);
    JS_CSPPMemTab_AddVersion(djs, html);
    return djs;
  }
};
void CSPPMemTab::OnDupUserKeyYield() {
  as_atomic(m_fac->num_dup_yields).fetch_add(1, std::memory_order_relaxed);
}
template<class Iter>
static MemTableRep::Iterator* MakeIter(CSPPMemTab* tab, Arena* a) {
  return a ? new(a->AllocateAligned(sizeof(Iter))) Iter(tab) : new Iter(tab);
}
MemTableRep::Iterator* CSPPMemTab::GetIterator(Arena* a) {
#if 0
  if (m_is_sst) {
    m_is_sst = true;
  } else {
    m_is_sst = false;
  }
#endif
  as_atomic(m_fac->cumu_iter_num).fetch_add(1, std::memory_order_relaxed);
  as_atomic(m_fac->live_iter_num).fetch_add(1, std::memory_order_relaxed);
  as_atomic(m_cumu_iter_num).fetch_add(1, std::memory_order_relaxed);
  as_atomic(m_live_iter_num).fetch_add(1, std::memory_order_relaxed);
  if (m_ref_to_wal == kPlainLogRef)
    return MakeIter<Iter<KeyValueToLogRef> >(this, a);
  else if (m_ref_to_wal == kShortLogRef)
    return MakeIter<Iter<KV_ToShortLogRef> >(this, a);
  else
    return MakeIter<Iter<Entry> >(this, a);
}
template<class Entry>
CSPPMemTab::Iter<Entry>::Iter(CSPPMemTab* tab) {
  m_tab = tab;
  m_rev = tab->m_rev;
  m_iter = nullptr;
  m_mempool = (const char*)tab->m_trie.mem_get(0);
}
template<class Entry>
CSPPMemTab::Iter<Entry>::~Iter() noexcept {
  if (m_iter) {
    m_iter->dispose();
  }
  auto factory = m_tab->m_fac;
  as_atomic(factory->live_iter_num).fetch_sub(1, std::memory_order_relaxed);
  as_atomic(m_tab->m_live_iter_num).fetch_sub(1, std::memory_order_relaxed);
}
CSPPMemTab::CSPPMemTab(intptr_t cap, bool rev, Logger* log, CSPPMemTabFactory* f,
      size_t instance_idx, ConvertKind convert_to_sst, fstring fpath_or_conf)
    : MemTableRep(nullptr)
    , m_trie(4, f->use_vm ? -cap : cap, Patricia::MultiWriteMultiRead,
             fpath_or_conf) {
  init(rev, log, f);
  m_is_sst = false;
  m_instance_idx = instance_idx;
  m_convert_to_sst = convert_to_sst;
}
/// For SST
CSPPMemTab::CSPPMemTab(bool rev, Logger* log, CSPPMemTabFactory* f,
                       size_t instance_idx)
    : MemTableRep(nullptr) {
  init(rev, log, f);
  m_is_empty = false;
  m_is_sst = true;
  m_instance_idx = instance_idx;
  m_convert_to_sst = ConvertKind::kDontConvert;
}
inline void CSPPMemTab::init(bool rev, Logger* log, CSPPMemTabFactory* f) {
  m_fac = f;
  m_log = log;
  m_rev = rev;
  m_is_flushed = false;
  m_is_empty = true;
  m_has_converted_to_sst = false;
  m_has_marked_readonly = false;
  m_read_by_writer_token = f->read_by_writer_token;
  m_token_use_idle = f->token_use_idle;
  m_accurate_memsize = f->accurate_memsize;
  m_ref_to_wal = kNoLogRef;
  f->m_mtx.lock();
  f->live_num++;
  m_next = &f->m_head; // insert 'this' at linked list tail
  m_prev = f->m_head.m_prev;
  m_next->m_prev = this;
  m_prev->m_next = this;
  f->m_mtx.unlock();
}
CSPPMemTab::~CSPPMemTab() noexcept {
#if 1
  TERARK_VERIFY_EZ(m_live_iter_num);
#else // debug code
  if (m_live_iter_num) {
    fprintf(stderr,
      "ERROR: ~CSPPMemTab: is_sst = %d, instance_idx = %zd, live_iter_num = %d\n",
      m_is_sst, m_instance_idx, m_live_iter_num);
  }
#endif
  m_fac->m_mtx.lock();
  m_fac->live_num--;
  m_next->m_prev = m_prev; // remove 'this' from linked list
  m_prev->m_next = m_next;
  m_fac->m_mtx.unlock();

  if (ConvertKind::kFileMmap == m_convert_to_sst) {
    ROCKSDB_VERIFY(!m_is_sst);
    ROCKSDB_VERIFY(!m_trie.mmap_fpath().empty());
    if (!m_has_converted_to_sst) {
      std::remove(m_trie.mmap_fpath().c_str());
    }
  }
}
void CSPPMemTab::InitSetMemTableAsLogIndex(bool b) {
  if (b)
    m_ref_to_wal = m_fac->log_ref_format;
  else
    m_ref_to_wal = kNoLogRef;
}
CSPPMemTab::Token::~Token() {
  // sync Token stats to MemTab
  auto trie = (MainPatricia*)(m_trie);
  auto mtab = (CSPPMemTab*)((char*)(trie) - offsetof(CSPPMemTab, m_trie));
  if (num_dup_user_keys) {
    atomic_maximize(mtab->max_dup_len, max_dup_len, std::memory_order_relaxed);
    as_atomic(mtab->num_dup_user_keys)
        .fetch_add(num_dup_user_keys, std::memory_order_relaxed);
    num_dup_user_keys = 0; // notify sync'ed
  }
  for (size_t i = 0; i < mtab->m_num_wals; ++i) {
    assert(mtab->m_ref_to_wal);
    auto& x = m_wal_cnt_bytes[i];
    as_atomic(mtab->m_wals[i].cnt).fetch_add(x.cnt, std::memory_order_relaxed);
    as_atomic(mtab->m_wals[i].bytes).fetch_add(x.bytes, std::memory_order_relaxed);
    m_wal_cnt_bytes[i] = {}; // reset
  }
}
void CSPPMemTab::ConvertToReadOnly(const char* caller, fstring sst_name) {
  TERARK_VERIFY(!m_trie.is_readonly());
  auto clock = Env::Default()->GetSystemClock();
  auto t0 = clock->NowNanos();
  m_fill_time = t0 - m_fill_time;
  m_trie.for_each_tls_token([&,this](Patricia::TokenBase* tok) {
    if (auto wtok = dynamic_cast<Token*>(tok)) {
      if (wtok->num_dup_user_keys) {
        // not need atomic
        maximize(this->max_dup_len, wtok->max_dup_len);
        this->num_dup_user_keys += wtok->num_dup_user_keys;
        wtok->num_dup_user_keys = 0;
      }
      for (size_t i = 0; i < this->m_num_wals; ++i) {
        this->m_wals[i].cnt += wtok->m_wal_cnt_bytes[i].cnt;
        this->m_wals[i].bytes += wtok->m_wal_cnt_bytes[i].bytes;
        wtok->m_wal_cnt_bytes[i] = {}; // reset
      }
    }
  });
  if (m_trie.is_mmap()) {
    auto header = (DFA_MmapHeader*)(m_trie.get_mmap().data());
    header->reserve1[0] = max_dup_len; // persistent to mmap
    header->reserve1[1] = num_dup_user_keys;
    header->reserve1[2] = m_fill_time;
  }
  atomic_maximize(m_fac->max_dup_len, max_dup_len, std::memory_order_relaxed);
  as_atomic(m_fac->num_dup_user_keys)
        .fetch_add(num_dup_user_keys, std::memory_order_relaxed);
  m_trie.set_readonly(); // set readonly is the last step
  auto tt1 = clock->NowNanos();
  ROCKS_LOG_INFO(m_log,
    "%s ConvertToReadOnly %s in %s, mem_size = %8.3f M, time = %9.3f us",
    m_trie.mmap_fpath().c_str(), sst_name.c_str(), caller,
    m_trie.mem_size_inline()/double(1<<20), (tt1-t0)/1e3);
}
void CSPPMemTab::MarkReadOnly() {
  auto used = m_trie.mem_size_inline();
  as_atomic(m_fac->deactived_mem_sum).fetch_add(used, std::memory_order_relaxed);
  if (ConvertKind::kFileMmap == m_convert_to_sst && !IsRocksBackgroundThread()) {
    // m_trie.set_readonly() may time consuming, do not run in foreground
  } else {
    ConvertToReadOnly("MarkReadOnly", ""); // sst_name is unknow
  }
  m_has_marked_readonly = true;
}
void CSPPMemTab::MarkFlushed() {
  if (!m_trie.is_readonly()) {
    // ROCKSDB_VERIFY_EQ(m_convert_to_sst, ConvertKind::kDontConvert); // false verify
    ConvertToReadOnly("MarkFlushed", ""); // sst_name is unknow
  }
  if (auto& mp = m_trie.risk_get_mempool_mwmr(); mp.m_vm_commit_fail_cnt) {
    ROCKS_LOG_WARN(m_log, "cspp-%06zd: vm_commit_fail: cnt = %zd, len = %zd",
        m_instance_idx, mp.m_vm_commit_fail_cnt, mp.m_vm_commit_fail_len);
  }
  if (m_fac->vm_coldize_on_flush) {
    ColdizeMemory("CSPPMemTab::MarkFlushed");
  }
  m_is_flushed = true;
}
void CSPPMemTab::ColdizeMemory(const char* func) {
#if defined(OS_LINUX)
 #if !defined(MADV_COLD)
  const int MADV_COLD = 20;
 #endif
  if (g_linux_kernel_version < KERNEL_VERSION(5,4,0)) {
    return; // MADV_COLD requires kernel 5.4+
  }
  fstring cold; // to be MADV_COLD'ed
  if (ConvertKind::kFileMmap == m_convert_to_sst) {
    cold = m_trie.get_mmap();
    TERARK_VERIFY_AL(size_t(cold.p), 4096);
  } else {
    cold = fstring((const char*)m_trie.mem_get(0), m_trie.mem_capacity());
    if (size_t(cold.p) != 4096) // did not aligned if use malloc
      cold = cold.substr(4096 - (size_t(cold.p) % 4096)); // cut to align
  }
  if (madvise((void*)cold.data(), cold.size(), MADV_COLD) != 0) {
    ROCKS_LOG_WARN(m_log,
     "%s(%s): used = %zd, madvise(len=%zd, MADV_COLD) = %m", func,
      m_trie.mmap_fpath().c_str(), m_trie.mem_size_inline(), cold.size());
  }
#endif
}
bool CSPPMemTab::GetRandomInternalKeysAppend
(size_t num, std::vector<std::string>* output)
const {
  SortableStrVec keys;
  m_trie.dfa_get_random_keys(&keys, num);
  MainPatricia::SingleReaderToken token(&m_trie);
  for (size_t i = 0; i < keys.size(); ++i) {
    fstring onekey = keys[i];
    output->push_back(FirstInternalKey(SliceOf(onekey), token));
  }
  return true;
}
std::string CSPPMemTab::FirstInternalKey
(Slice user_key, MainPatricia::TokenBase& token)
const {
  uint32_t vec_pin_pos = m_trie.value_of<uint32_t>(token);
  auto vec_pin = (CSPPMemTab::VecPin*)m_trie.mem_get(vec_pin_pos);
  auto entry = (CSPPMemTab::Entry*)m_trie.mem_get(vec_pin->pos);
  // entry[0].tag is at same pos for Entry & KeyValueToLogRef, no need changes
  std::string ikey;
  ikey.reserve(user_key.size() + 8);
  ikey.append(user_key.data(), user_key.size());
  PutFixed64(&ikey, entry[0].tag);
  return ikey;
}
#if (ROCKSDB_MAJOR * 10000 + ROCKSDB_MINOR * 10 + ROCKSDB_PATCH) >= 70060
Status CSPPMemTab::ApproximateKeyAnchors
(const ReadOptions& ro, std::vector<Anchor>& anchors) const
{
  size_t num = 256;
  SortableStrVec keys;
  m_trie.dfa_get_random_keys(&keys, num);
  if (keys.size() == 0) {
    return Status::OK();
  }
  num = keys.size();
  keys.sort();
  Patricia::IteratorPtr raw_iter(m_trie.new_iter());
  if (m_rev) {
    std::reverse(keys.m_index.begin(), keys.m_index.end());
    raw_iter->seek_begin(); // rev largest
  } else {
    raw_iter->seek_end(); // largest
  }
  if (keys.back() != raw_iter->word()) {
    keys.push_back(raw_iter->word());
  }
  num = keys.size();
  size_t avg_size = m_trie.mem_size_inline() / num;
  for (size_t i = 0; i < num; ++i) {
    size_t curr_size = avg_size;
    for (; i+1 < num && keys[i] == keys[i+1]; ++i) {
      curr_size += avg_size;
    }
    fstring onekey = keys[i];
    anchors.emplace_back(SliceOf(onekey), curr_size);
  }
  return Status::OK();
}
#endif
uint64_t CSPPMemTab::ApproximateNumEntries(const Slice& beg_ikey,
                                           const Slice& end_ikey) {
  // dfa_approximate_rank may be pretty not accurate because trie may be
  // highly skewed!
  if (!m_fac->enableApproximateNumEntries) {
    return 0;
  }
  ROCKSDB_VERIFY_GE(beg_ikey.size(), 8);
  ROCKSDB_VERIFY_GE(end_ikey.size(), 8);
  fstring beg_ukey(beg_ikey.data(), beg_ikey.size() - 8);
  fstring end_ukey(end_ikey.data(), end_ikey.size() - 8);
  double  beg_rank = m_trie.dfa_approximate_rank(beg_ukey);
  double  end_rank = m_trie.dfa_approximate_rank(end_ukey);
  return m_trie.num_words() * fabs(end_rank - beg_rank);
}

ROCKSDB_REG_Plugin("cspp", CSPPMemTabFactory, MemTableRepFactory);
ROCKSDB_REG_EasyProxyManip("cspp", CSPPMemTabFactory, MemTableRepFactory);
ROCKSDB_REG_Plugin("CSPPMemTab", CSPPMemTabFactory, MemTableRepFactory);
ROCKSDB_REG_EasyProxyManip("CSPPMemTab", CSPPMemTabFactory, MemTableRepFactory);
MemTableRepFactory* NewCSPPMemTabForPlain(const std::string& jstr) {
  json js = json::parse(jstr);
  const SidePluginRepo repo;
  return new CSPPMemTabFactory(js, repo);
}
// For debuging in gdb call this function by `print`
void CSPPMemTab_print_mempool_stat(const CSPPMemTab* tab) {
  tab->m_trie.print_mempool_stat(stderr);
}
/////////////////////////////////////////////////////////////////////////////
////  Use CSPPMemTab as TableReader
/////////////////////////////////////////////////////////////////////////////
static const uint64_t kCSPPMemTabMagic = 0x546d654d50505343ULL; // CSPPMemT
class CSPPMemTabTableBuilder : public TopTableBuilderBase {
public:
  using TopTableBuilderBase::properties_;
  CSPPMemTabTableBuilder(const TableBuilderOptions& tbo, WritableFileWriter* writer)
      : TopTableBuilderBase(tbo, writer) {
    offset_ = writer->GetFileSize();
  }
  void Add(const Slice& key, const Slice& value) final {
    ROCKSDB_DIE("Should not be called");
  }
  uint64_t EstimatedFileSize() const final {
    ROCKSDB_DIE("Should not be called");
  }
  Status Finish() final {
    closed_ = true;
    WriteMeta(kCSPPMemTabMagic, {}); // write properties and footer
    return Status::OK();
  }
  void Abandon() final { closed_ = true; }
  void DoWrite(fstring data) {
    WriteBlock(data, file_, &offset_); // ignore ret
  }
};
#if defined(_MSC_VER)
  #pragma warning(disable: 4702) // unreachable code, must out of func
#endif
static size_t SeekToEnd(WritableFileWriter& writer, Logger* log) {
  auto fs_file = writer.writable_file();
  auto fd = fs_file->FileDescriptor();
#if defined(_MSC_VER)
  auto endpos = fd; // use fd
  ROCKSDB_DIE("TODO");
#else
  auto endpos = ::lseek(int(fd), 0, SEEK_END);
  if (endpos < 0) {
    std::string strerr = strerror(errno);
    std::string fname = writer.file_name().c_str();
    ROCKS_LOG_ERROR(log, "lseek(%s, 0, SEEK_END) = %s",
                    fname.c_str(), strerr.c_str());
    throw Status::IOError(fname, strerr);
  }
#endif
  fs_file->SetFileSize(endpos);
  writer.SetFileSize(endpos);
  return size_t(endpos);
}
Status CSPPMemTab::ConvertToSST(FileMetaData* meta,
                                const TableBuilderOptions& tbo)
try {
  auto& ioptions = tbo.ioptions;
  auto* clock = ioptions.clock;
  auto* fs = ioptions.fs.get();
  ROCKSDB_VERIFY_NE(m_convert_to_sst, ConvertKind::kDontConvert);
  bool sync_sst_file = m_fac->sync_sst_file; // consitency param snapshot
  IODebugContext dbg_ctx;
  FileOptions fopt;
  fopt.allow_fallocate = false;
  std::string fname = TableFileName(tbo.ioptions.cf_paths,
                                    meta->fd.GetNumber(),
                                    meta->fd.GetPathId());
  if (!m_trie.is_readonly()) {
    ConvertToReadOnly("ConvertToSST", fname);
  }
  std::unique_ptr<FSWritableFile> fs_file;
  const bool is_file_mmap = ConvertKind::kFileMmap == m_convert_to_sst;
  double t0 = clock->NowMicros();
  if (is_file_mmap) {
    std::string src_fname = m_trie.mmap_fpath();
    size_t chroot_len = m_fac->chroot_dir.size();
    TERARK_VERIFY_S_EQ(fstring(src_fname).prefix(chroot_len), m_fac->chroot_dir);
    src_fname.erase(0, chroot_len);
    IOStatus ios = fs->RenameFile(src_fname, fname, fopt.io_options, &dbg_ctx);
    if (!ios.ok()) {
      ROCKS_LOG_ERROR(m_log, "rename(%s, %s) = %s",
          src_fname.c_str(), fname.c_str(), ios.ToString().c_str());
      return ios; // IOStatus to Status
    }
    ios = fs->ReopenWritableFile(fname, fopt, &fs_file, &dbg_ctx);
    if (!ios.ok())
      return ios;
  }
  else {
    IOStatus ios = fs->NewWritableFile(fname, fopt, &fs_file, &dbg_ctx);
    if (!ios.ok())
      return ios;
  }
  fs_file->SetPreallocationBlockSize(0); // disable fallocate
  double t1 = clock->NowMicros();
  WritableFileWriter writer(std::move(fs_file), fname, fopt, ioptions.clock,
              nullptr, ioptions.statistics.get(), ioptions.listeners);
  if (is_file_mmap) {
    auto endpos = SeekToEnd(writer, m_log);
    ROCKSDB_VERIFY_EQ(m_trie.get_mmap().size(), endpos);
    IOSTATS_ADD(bytes_written, endpos);
  }
  CSPPMemTabTableBuilder builder(tbo, &writer);
  if (!is_file_mmap) {
    try {
      m_trie.save_mmap([&](fstring data){ builder.DoWrite(data); });
    } catch (const Status& s) {
      builder.Abandon();
      fs->DeleteFile(fname, fopt.io_options, &dbg_ctx);
      return s;
    } catch (const std::exception& ex) {
      string_appender<> msg;
      msg|"CSPPMemTab::ConvertToSST("|fname|"): save_mmap() fail: "|ex.what();
      builder.Abandon();
      fs->DeleteFile(fname, fopt.io_options, &dbg_ctx);
      return Status::IOError(msg);
    }
  }
  //m_trie.print_mempool_stat(stderr);
  double t2 = clock->NowMicros();
  builder.properties_.num_data_blocks = 1;
  builder.properties_.num_entries = meta->num_entries;
  builder.properties_.num_deletions = meta->num_deletions;
  builder.properties_.num_range_deletions = meta->num_range_deletions;
  builder.properties_.num_merge_operands = meta->num_merges;
  builder.properties_.raw_key_size = meta->raw_key_size;
  builder.properties_.raw_value_size = meta->raw_value_size;
  if (m_ref_to_wal) {
    auto& oss = static_cast<string_appender<>&>(builder.properties_.compression_options);
    oss.clear();
    if (m_ref_to_wal == kPlainLogRef) {
      oss|"LogRef:Plain;";
    } else if (m_ref_to_wal == kShortLogRef) {
      oss|"LogRef:Short;";
    } else {
      ROCKSDB_DIE("Unexpected m_ref_to_wal = %d", m_ref_to_wal);
    }
    if (m_num_wals) {
      meta->oldest_blob_file_number = UINT64_MAX;
      for (size_t i = 0; i < m_num_wals; i++) {
        auto& e = m_wals[i];
        auto blob_no = tbo.generate_file_no();
        auto walname = LogFileName(ioptions.GetWalDir(), e.fileno);
        auto refname = BlobFileName(ioptions.cf_paths[0].path, blob_no);
        IOStatus ios = fs->LinkFile(walname, refname, fopt.io_options, &dbg_ctx);
        if (!ios.ok())
          return ios;
        oss|blob_no|":"|e.fileno|":"|e.cnt|":"|e.bytes|",";
        tbo.add_blob_file({blob_no, e.cnt, e.bytes, "", ""});
        terark::minimize(meta->oldest_blob_file_number, blob_no);
      }
      oss.pop_back(); // remove the trailing comma ','
    }
  }
  Status s = builder.Finish();
  if (!s.ok()) {
    return s;
  }
  double t3 = clock->NowMicros();
  std::unique_ptr<MemTableRep::Iterator> iter(GetIterator(nullptr));
  iter->SeekToFirst();  meta->smallest.DecodeFrom(iter->key());
  iter->SeekToLast();   meta->largest.DecodeFrom(iter->key());
  meta->fd.file_size = writer.GetFileSize();
  meta->tail_size = builder.GetTailSize();
  if (!tbo.db_id.empty() && !tbo.db_session_id.empty()) {
    if (!GetSstInternalUniqueId(tbo.db_id, tbo.db_session_id,
                                meta->fd.GetNumber(), &meta->unique_id).ok()) {
      // if failed to get unique id, just set it Null
      meta->unique_id = kNullUniqueId64x2;
    }
  }
  double t4 = clock->NowMicros();
  s = writer.Flush(); // not sync
  double t5 = clock->NowMicros();
  if (sync_sst_file) {
    s = writer.writable_file()->Fsync(fopt.io_options, &dbg_ctx);
  }
  double t6 = clock->NowMicros();
  writer.Close();
  double t7 = clock->NowMicros();
  double fsize_mb = meta->fd.file_size / double(1<<20);
  ROCKS_LOG_INFO(m_log, "CSPPMemTab::ConvertToSST(%s): fsize = %8.3f M, time(ms): "
    "open: %.3f, %s: %.3f, finish: %.3f, meta: %.3f, Flush: %.3f, sync: %.3f, close: %.3f, all: %.3f",
    fname.c_str(), fsize_mb, (t1-t0)/1e3, is_file_mmap ? "seek" : "write",
    (t2-t1)/1e3, (t3-t2)/1e3, (t4-t3)/1e3, (t5-t4)/1e3, (t6-t5)/1e3, (t7-t6)/1e3, (t7-t0)/1e3);
  m_has_converted_to_sst = true;
  return s;
}
catch (const std::exception& ex) {
  return Status::Aborted(ex.what()); // this error is recoverable
}
catch (const Status& s) {
  return s;
}

class CSPPMemTabTableFactory : public TableFactory {
public:
  CSPPMemTabTableFactory(const json& js, const SidePluginRepo& repo) {
    memtable_factory = std::make_shared<CSPPMemTabFactory>(js, repo);
  }
  const char* Name() const override { return "CSPPMemTabTable"; }
  using TableFactory::NewTableReader;
  Status NewTableReader(const ReadOptions&,
                        const TableReaderOptions&,
                        std::unique_ptr<RandomAccessFileReader>&&,
                        uint64_t file_size,
                        std::unique_ptr<TableReader>*,
                        bool prefetch_index_and_filter) const override;
  TableBuilder* NewTableBuilder(const TableBuilderOptions&,
                                WritableFileWriter*) const override {
    ROCKSDB_DIE("Should not be called");
  }
  std::string GetPrintableOptions() const final {
    json djs = memtable_factory->ToJson({});
    ROCKSDB_JSON_SET_PROP(djs, populate_read);
    return djs.dump();
  }
  Status ValidateOptions(const DBOptions&, const ColumnFamilyOptions&)
  const final {
    return Status::OK();
  }
  bool IsDeleteRangeSupported() const override { return true; }
  void Update(const json& q, const json& js, const SidePluginRepo& repo) {
    ROCKSDB_JSON_OPT_PROP(js, populate_read);
    memtable_factory->Update(q, js, repo);
  }
  std::string ToString(const json& d, const SidePluginRepo& repo) const {
    json djs = memtable_factory->ToJson(d);
    ROCKSDB_JSON_SET_PROP(djs, populate_read);
    return JsonToString(djs, d);
  }
  std::shared_ptr<CSPPMemTabFactory> memtable_factory;
  bool populate_read = true;
};
class CSPPMemTabTableReader : public TopTableReaderBase {
public:
  ~CSPPMemTabTableReader() override;
  CSPPMemTabTableReader(RandomAccessFileReader*, Slice file_data,
                        const TableReaderOptions&,
                        const CSPPMemTabTableFactory*);
  InternalIterator*
  NewIterator(const ReadOptions&, const SliceTransform* prefix_extractor,
              Arena* arena, bool skip_filters, TableReaderCaller caller,
              size_t compaction_readahead_size,
              bool allow_unprepared_value) final {
    return m_memtab->GetIterator(arena);
  }
  uint64_t ApproximateOffsetOf(ROCKSDB_8_X_COMMA(const ReadOptions&)
                               const Slice& key, TableReaderCaller) final {
    // dfa_approximate_rank may be pretty not accurate because trie may be
    // highly skewed!
    if (!m_factory->memtable_factory->enableApproximateNumEntries) {
      return 0;
    }
    ROCKSDB_VERIFY_GE(key.size(), 8);
    fstring user_key(key.data(), key.size() - 8);
    double rank = m_memtab->m_trie.dfa_approximate_rank(user_key);
    return rank * file_data_.size_;
  }
  uint64_t ApproximateSize(ROCKSDB_8_X_COMMA(const ReadOptions&)
                           const Slice& beg_ik, const Slice& end_ik,
                           TableReaderCaller) final {
    // dfa_approximate_rank may be pretty not accurate because trie may be
    // highly skewed!
    if (!m_factory->memtable_factory->enableApproximateNumEntries) {
      return 0;
    }
    ROCKSDB_VERIFY_GE(beg_ik.size(), 8);
    ROCKSDB_VERIFY_GE(end_ik.size(), 8);
    fstring beg_uk(beg_ik.data(), beg_ik.size() - 8);
    fstring end_uk(end_ik.data(), end_ik.size() - 8);
    double  beg_rank = m_memtab->m_trie.dfa_approximate_rank(beg_uk);
    double  end_rank = m_memtab->m_trie.dfa_approximate_rank(end_uk);
    return fabs(end_rank - beg_rank) * file_data_.size_;
  }
  size_t ApproximateMemoryUsage() const final {
    // a little larger than CSPPMemTable::ApproximateMemoryUsage(), because
    // file_data_.size() include the SST file footer and gdic_size is walsize
    return file_data_.size() + table_properties_->gdic_size;
  }
  Status Get(const ReadOptions& ro, const Slice& ikey, GetContext* get_context,
             const SliceTransform*, bool/*skip_filters*/) final {
    return m_memtab->SST_Get(ro, ikey, get_context);
  }
  Status VerifyChecksum(const ReadOptions&, TableReaderCaller) final {
    return Status::OK();
  }
  bool GetRandomInternalKeysAppend(size_t num, std::vector<std::string>* output)
  const final {
    return m_memtab->GetRandomInternalKeysAppend(num, output);
  }
#if (ROCKSDB_MAJOR * 10000 + ROCKSDB_MINOR * 10 + ROCKSDB_PATCH) >= 70060
  Status ApproximateKeyAnchors(const ReadOptions& ro,
                               std::vector<Anchor>& anchors) final {
    return m_memtab->ApproximateKeyAnchors(ro, anchors);
  }
#endif
  bool IsMyFactory(const TableFactory* fac) const final {
    return fac && dynamic_cast<const CSPPMemTabTableFactory*>(fac);
  }
  std::string ToWebViewString(const json& dump_options) const final;

// data member also public
  std::unique_ptr<CSPPMemTab> m_memtab;
  const CSPPMemTabTableFactory* m_factory = nullptr;
};
CSPPMemTabTableReader::CSPPMemTabTableReader(RandomAccessFileReader* file,
    Slice file_data, const TableReaderOptions& tro,
    const CSPPMemTabTableFactory* f) {
  LoadCommonPart(file, tro, file_data, kCSPPMemTabMagic);
  auto memtab_fac = f->memtable_factory.get();
  auto curr_num = as_atomic(memtab_fac->cumu_num)
                 .fetch_add(1, std::memory_order_relaxed);
  m_memtab.reset(new CSPPMemTab(isReverseBytewiseOrder_, tro.ioptions.logger,
                                memtab_fac, curr_num));
  m_memtab->m_trie.self_mmap_user_mem(file_data);
  as_atomic(memtab_fac->deactived_mem_sum)
           .fetch_add(file_data.size(), std::memory_order_relaxed);
  auto header = (DFA_MmapHeader*)(file_data.data());
  m_memtab->max_dup_len = header->reserve1[0];
  m_memtab->num_dup_user_keys = header->reserve1[1];
  m_memtab->m_fill_time = header->reserve1[2];
  atomic_maximize(memtab_fac->max_dup_len,
                    m_memtab->max_dup_len, std::memory_order_relaxed);
  as_atomic(memtab_fac->num_dup_user_keys)
   .fetch_add(m_memtab->num_dup_user_keys, std::memory_order_relaxed);

  table_properties_->compression_name = "CSPPMemTab";
  std::string& compression_options = table_properties_->compression_options;
  if (Slice(compression_options).starts_with("LogRef:")) {
    const char* item = strchr(compression_options.c_str(), ';');
    ROCKSDB_VERIFY(item != nullptr);
    const fstring name(compression_options.c_str(), item);
    if (name == "LogRef:Plain") {
      m_memtab->m_ref_to_wal = CSPPMemTab::kPlainLogRef;
    } else if (name == "LogRef:Short") {
      m_memtab->m_ref_to_wal = CSPPMemTab::kShortLogRef;
    } else {
      ROCKSDB_DIE("Unexpected LogRef: %s", compression_options.c_str());
    }
    item += 1; // skip ';'
    for (size_t i = 0; true; i++) {
      size_t blob_no = 0, wal_no = 0, cnt = 0, bytes = 0;
      int fields = sscanf(item, "%zd:%zd:%zd:%zd", &blob_no, &wal_no, &cnt, &bytes);
      if (fields <= 0) {
        break; // treat as end of list
      }
      ROCKSDB_ASSERT_EQ(fields, 4);
      if (4 != fields) {
        THROW_STD(logic_error, "must be blob_no:wal_no:cnt:bytes, but is: %s", item);
      }
      auto fpath = BlobFileName(tro.ioptions.cf_paths[0].path, blob_no);
      auto [fmap, ios] = ReadonlyFileMmap::New(*tro.ioptions.fs, blob_no, fpath);
      TERARK_VERIFY_S(ios.ok(), "ReadonlyFileMmap %s, %s", fpath, ios.ToString());
     #ifdef __linux__
      if (f->populate_read && g_linux_kernel_version >= KERNEL_VERSION(5,14,0)) {
        auto logger = tro.ioptions.logger;
        auto madv_populate_read = 22; // MADV_POPULATE_READ = 22
        auto mem = (void*)fmap->data();
        auto len = fmap->size();
        auto t0 = std::chrono::steady_clock::now();
        if (madvise(mem, len, madv_populate_read) < 0) {
          ROCKS_LOG_WARN(logger, "MADV_POPULATE_READ(%s, %zd) = %m",
                         fpath.c_str(), len);
        }
        auto t1 = std::chrono::steady_clock::now();
        using namespace std::chrono;
        ROCKS_LOG_DEBUG(logger, "MADV_POPULATE_READ(%s, %zd) = %.6f ms",
                        fpath.c_str(), len,
                        duration_cast<nanoseconds>(t1-t0).count()/1e6);
      }
     #endif
      m_memtab->m_wals[i].fileno = wal_no;
      m_memtab->m_wals[i].cnt = cnt;
      m_memtab->m_wals[i].wal = fmap.get();
      m_memtab->m_wals[i].bytes = bytes;
      m_memtab->m_hold_wals.push_back(fmap);
      // gdic_size is also used in version_set.cc FileSizeForScore()
      table_properties_->gdic_size += bytes;
      item = strchr(item, ',');
      if (item)
        item += 1;
      else
        break;
    }
    m_memtab->m_num_wals = m_memtab->m_hold_wals.size();
    if (m_memtab->m_num_wals)
      compression_options.push_back(';');
  }
  as_string_appender(table_properties_->compression_options)
    | "Free = "|SizeToString(m_memtab->m_trie.mem_frag_size());
  as_string_appender(table_properties_->compression_options)
    ^ ", %.2f%%" ^ 100.0*m_memtab->m_trie.mem_frag_size()/file_data_.size();

  size_t num_entries = table_properties_->num_entries;
  size_t num_user_keys = m_memtab->m_trie.num_words();
  table_properties_->tag_size = 8 * num_entries;
  if (m_memtab->m_ref_to_wal == CSPPMemTab::kPlainLogRef) {
    table_properties_->data_size = // no raw_value_size which is in wal
      (sizeof(CSPPMemTab::VecPin) + sizeof(uint32_t)) * num_user_keys +
      (sizeof(CSPPMemTab::KeyValueToLogRef) - sizeof(uint64_t)) * num_entries;
  }
  else if (m_memtab->m_ref_to_wal == CSPPMemTab::kShortLogRef) {
    table_properties_->data_size = // no raw_value_size which is in wal
      (sizeof(CSPPMemTab::VecPin) + sizeof(uint32_t)) * num_user_keys +
      (sizeof(CSPPMemTab::KV_ToShortLogRef) - sizeof(uint64_t)) * num_entries;
  }
  else {
    table_properties_->data_size = table_properties_->raw_value_size +
      (sizeof(CSPPMemTab::VecPin) + sizeof(uint32_t)) * num_user_keys +
      (sizeof(CSPPMemTab::Entry) + 1 - sizeof(uint64_t)) * num_entries;
      // for varint encoded value ^^^ len, this is less than real usage
  }
  table_properties_->index_size = m_memtab->m_trie.mem_size_inline() -
                                  m_memtab->m_trie.mem_frag_size() -
                                  table_properties_->data_size -
                                  table_properties_->tag_size;
  m_factory = f;
  //fprintf(stderr, "CSPPMemTabTableReader: %s: %s\n",
  //  file->file_name().c_str(), m_memtab->m_trie.str_stat().c_str());
}
CSPPMemTabTableReader::~CSPPMemTabTableReader() {
  TERARK_VERIFY_EZ(m_memtab->m_live_iter_num);
  m_memtab.reset(nullptr); // explicit delete
}
static std::string StrPercent(size_t num, size_t denom) {
  if (denom == 0) {
    return "INF%";
  }
  double percent =  100.0 * num  / denom;
  string_appender<> oss;
  oss^"%.2f%%"^percent;
  return oss.str();
}
static std::string SizeToStringFixedLen(size_t size) {
  std::string str = SizeToString(size);
  if (str.size() < 12) {
    str.insert(0, 12 - str.size(), ' ');
  }
  return str;
}
auto vertical_rule = R"( <div id="vertical-rule"></div> )";
static std::string SizeAvgPercent(size_t size, size_t cnt, size_t denom, const char* comment = "") {
  //auto vertical_rule = " │ "; // longer than "|"
  //auto vertical_rule = R"( <div style="border-left:1px solid;height:2em;display:inline-block;margin-top:-0.3em;margin-bottom:-0.6em"></div> )";
  string_appender<> oss;
  oss|"<pre>";
  oss|SizeToStringFixedLen(size);
  oss|vertical_rule;
  oss^"%9.2f"^double(size)/(cnt+FLT_EPSILON);
  oss|vertical_rule;
  oss^"%6.2f%%"^100.0*size/(denom+FLT_EPSILON);
  oss|"  of "|SizeToStringFixedLen(denom)|comment;
  oss|"</pre>";
  return std::move(oss.str());
}
static std::string CntPercent(size_t cnt, size_t denom, const char* comment = "") {
  string_appender<> oss;
  oss|"<pre>";
  oss^"%9zd"^cnt;
  oss|vertical_rule;
  oss^"%6.2f%%"^100.0*cnt/(denom+FLT_EPSILON);
  oss^"  of %9zd"^denom;
  oss|comment;
  oss|"</pre>";
  return std::move(oss.str());
}
std::string
CSPPMemTabTableReader::ToWebViewString(const json& dump_options) const {
  json djs;
  size_t num_user_keys = m_memtab->m_trie.num_words();
  djs["log_ref_format"] = enum_stdstr(m_memtab->m_ref_to_wal);
  djs["num_user_keys"] = num_user_keys;
  djs["num_entries"] = table_properties_->num_entries;
  djs["num_deletions"] = table_properties_->num_deletions;
  djs["num_merge_operands"] = table_properties_->num_merge_operands;
  djs["num_range_deletions"] = table_properties_->num_range_deletions;
  auto& tp = *table_properties_;
  size_t trie_mem_size = m_memtab->m_trie.mem_size_inline();
  size_t garbage_size = m_memtab->m_trie.mem_frag_size();
  size_t kv_size = tp.raw_key_size + tp.raw_value_size;
  size_t num_entries = tp.num_entries;
  auto fill_time = m_memtab->m_fill_time;
  terark::EmptyClass ends;
  djs["performance"] = string_appender<>()
    ^ "<pre>"
    ^ "fill time %.6f sec" ^ fill_time/1e9 ^ vertical_rule
    ^ "%.3f MB/s" ^ 1e3*kv_size/fill_time ^ vertical_rule
    ^ "%.0f KV/s" ^ 1e9*tp.num_entries/fill_time ^ vertical_rule
    ^ "</pre>"
    ^ ends;
  djs["raw_key_size"] = SizeAvgPercent(tp.raw_key_size, num_entries, kv_size, " (kv_size)");
  djs["raw_value_size"] = SizeAvgPercent(tp.raw_value_size, num_entries, kv_size);
  djs["kv_size"] = SizeAvgPercent(kv_size, num_entries, kv_size);
  djs["tag_size"] = SizeAvgPercent(tp.tag_size, num_entries, trie_mem_size, " (trie mem)");
  djs["index_size"] = SizeAvgPercent(tp.index_size, num_entries, trie_mem_size);
  djs["data_size"] = SizeAvgPercent(tp.data_size, num_entries, trie_mem_size);
  djs["garbage_size"] = SizeAvgPercent(garbage_size, num_entries, trie_mem_size);
  djs["trie_mem_size"] = SizeAvgPercent(trie_mem_size, num_entries, trie_mem_size);

  json& ref_to_wal = djs["ref_to_wal"];
  if (m_memtab->m_num_wals) {
    size_t sum_ref_cnt = 0, sum_ref_size = 0, sum_file_size = 0;
    for (size_t i = 0; i < m_memtab->m_num_wals; i++) {
      auto& e = m_memtab->m_wals[i];
      sum_ref_cnt += e.cnt;
      sum_ref_size += e.bytes;
      sum_file_size += e.wal->size();
      json blobjs;
      blobjs["blob_file"] = m_memtab->m_hold_wals[i]->fileno;
      blobjs["wal_file"] = e.fileno;
      blobjs["ref_cnt"] = e.cnt;
      blobjs["ref_size"] = SizeToString(e.bytes);
      blobjs["ref_avg"] = e.bytes / double(e.cnt);
      blobjs["file_size"] = SizeToString(e.wal->size());
      blobjs["ref_ratio"] = StrPercent(e.bytes, e.wal->size());
      ref_to_wal.push_back(std::move(blobjs));
    }
    if (m_memtab->m_num_wals > 1) {
      ref_to_wal.push_back(json::object({
        {"blob_file", "sum"},
        {"wal_file", "sum"},
        {"ref_cnt", sum_ref_cnt},
        {"ref_size", SizeToString(sum_ref_size)},
        {"ref_avg", sum_ref_size / double(sum_ref_cnt)},
        {"file_size", SizeToString(sum_file_size)},
        {"ref_ratio", StrPercent(sum_ref_size, sum_file_size)},
      }));
    }
    ref_to_wal[0]["<htmltab:col>"] = json::array({
      "blob_file",
      "wal_file",
      "ref_cnt",
      "ref_size",
      "ref_avg",
      "file_size",
      "ref_ratio",
    });
    size_t inline_cnt = num_entries - sum_ref_cnt;
    size_t inline_size = tp.raw_value_size - sum_ref_size;
    size_t trie_file_size = file_data_.size_; // trie_mem_size + meta + footer
    djs["refwal_cnt"] = CntPercent(sum_ref_cnt, num_entries, " (num_entries)");
    djs["inline_cnt"] = CntPercent(inline_cnt, num_entries, " (num_entries)");
    djs["inline_size"] = SizeAvgPercent(inline_size, inline_cnt, tp.raw_value_size, " (raw_value_size)");
    djs["trie_plus_wal_mem"] = SizeToString(trie_mem_size + sum_ref_size);
    djs["trie_plus_wal_file"] = SizeToString(trie_file_size + sum_file_size);
    djs["trie_mem"] = SizeAvgPercent(trie_mem_size, num_entries, trie_mem_size + sum_ref_size, " (trie+wal mem)");
    djs["trie_file"] = SizeAvgPercent(trie_file_size, num_entries, trie_file_size + sum_file_size, " (trie+wal file)");
    // ref_ptr_unit does not count the 8 bytes of uint64 tag
    size_t sizeof_ref_struct = m_memtab->m_ref_to_wal == CSPPMemTab::kPlainLogRef
                             ? sizeof(CSPPMemTab::KeyValueToLogRef)
                             : sizeof(CSPPMemTab::KV_ToShortLogRef);
    size_t ref_ptr_unit = sizeof_ref_struct - sizeof(uint64_t); // exclude tag
    size_t vec_pin_size = sizeof(CSPPMemTab::VecPin) * num_user_keys;
    size_t ref_ptr_size = ref_ptr_unit * num_entries;
    size_t ref_overhead = sizeof(uint32_t) * num_user_keys + vec_pin_size + ref_ptr_size;
    djs["vec_pin_size"] = SizeAvgPercent(vec_pin_size, num_entries, trie_mem_size, " (trie mem)");
    djs["ref_ptr_size"] = SizeAvgPercent(ref_ptr_size, num_entries, trie_mem_size, " (trie mem)");
    djs["ref_overhead"] = SizeAvgPercent(ref_overhead, num_entries, trie_mem_size, " (trie mem)");
    // djs["refwal_avg"] = sum_ref_size / double(sum_ref_cnt); // has shown in "ref_to_wal"
  } else {
    auto ref_to_wal = m_memtab->m_ref_to_wal;
    ROCKSDB_JSON_SET_ENUM(djs, ref_to_wal);
  }
  m_memtab->ToWebViewJson(djs, dump_options);
  return JsonToString(djs, dump_options);
}
void CSPPMemTab::ToWebViewJson(json& djs, const json& dump_options) const {
  const auto& fac = *m_fac;
  ROCKSDB_JSON_SET_PROP(djs, max_dup_len);
  ROCKSDB_JSON_SET_PROP(djs, num_dup_user_keys);
  ROCKSDB_JSON_SET_PROP(djs, fac.max_dup_len);
  ROCKSDB_JSON_SET_PROP(djs, fac.num_dup_user_keys);
}
Status CSPPMemTabTableFactory::NewTableReader(
              const ReadOptions&,
              const TableReaderOptions& tro,
              std::unique_ptr<RandomAccessFileReader>&& file,
              uint64_t file_size,
              std::unique_ptr<TableReader>* table,
              bool prefetch_index_and_filter)
const try {
  (void)prefetch_index_and_filter; // now ignore
  file->exchange(new MmapReadWrapper(file, populate_read));
  Slice file_data;
  Status s = TopMmapReadAll(*file, file_size, &file_data);
  if (!s.ok()) {
    return s;
  }
  if (populate_read) {
    // has populated in `new MmapReadWrapper`
  } else { // not populated, do madvise
    MmapAdvSeq(file_data);
    MmapWarmUp(file_data);
  }
  table->reset(new CSPPMemTabTableReader(file.release(), file_data, tro, this));
  return Status::OK();
}
catch (const IOStatus& s) {
  WARN(tro.ioptions.info_log, "%s: Status: %s", ROCKSDB_FUNC, s.ToString().c_str());
  return Status::IOError(ROCKSDB_FUNC, s.ToString());
}
catch (const Status& s) {
  WARN(tro.ioptions.info_log, "%s: Status: %s", ROCKSDB_FUNC, s.ToString().c_str());
  return s;
}
catch (const std::exception& ex) {
  WARN(tro.ioptions.info_log, "%s: std::exception: %s", ROCKSDB_FUNC, ex.what());
  return Status::Corruption(ROCKSDB_FUNC, ex.what());
}
ROCKSDB_REG_Plugin("CSPPMemTabTable", CSPPMemTabTableFactory, TableFactory);
ROCKSDB_REG_EasyProxyManip("CSPPMemTabTable", CSPPMemTabTableFactory, TableFactory);
ROCKSDB_RegTableFactoryMagicNumber(kCSPPMemTabMagic, "CSPPMemTabTable");
} // namespace ROCKSDB_NAMESPACE
