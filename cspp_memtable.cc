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

#include <terark/fsa/cspptrie.inl>
#include <terark/num_to_str.hpp>
#include <terark/util/vm_util.hpp>

#if defined(OS_LINUX)
  #include <linux/mman.h>
  #include <linux/version.h>
#endif

const char* git_version_hash_info_cspp_memtable();
namespace ROCKSDB_NAMESPACE {
using namespace terark;
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
  };
  struct VecPin { // once allocated, never realloc
    uint32_t num;
    uint32_t cap;
    uint32_t pos;
  };
#pragma pack(pop)
  static void encode_pre(Slice d, void* buf) {
    char* p = EncodeVarint32((char*)buf, (uint32_t)d.size());
    memcpy(p, d.data_, d.size_);
  }
  mutable MainPatricia m_trie;
  bool          m_read_by_writer_token;
  bool          m_token_use_idle;
  bool          m_accurate_memsize;
  bool          m_rev;
  bool          m_is_flushed = false;
  bool          m_is_empty = true;
  bool          m_is_sst : 1;
  bool          m_has_converted_to_sst : 1;
  ConvertKind   m_convert_to_sst;
  CSPPMemTabFactory* m_fac;
  Logger*  m_log;
  size_t   m_instance_idx;
  uint32_t m_cumu_iter_num = 0;
  uint32_t m_live_iter_num = 0;
#if defined(ROCKSDB_UNIT_TEST)
  size_t   m_mem_size = 0;
#endif
  CSPPMemTab(intptr_t cap, bool rev, Logger*, CSPPMemTabFactory*,
             size_t instance_idx, ConvertKind, fstring fpath_or_conf);
  CSPPMemTab(bool rev, Logger*, CSPPMemTabFactory*, size_t instance_idx);
  void init(bool rev, Logger*, CSPPMemTabFactory*);
  ~CSPPMemTab() noexcept override;
  KeyHandle Allocate(const size_t, char**) final { TERARK_DIE("Bad call"); }
  void Insert(KeyHandle) final { TERARK_DIE("Bad call"); }
  struct Token : public Patricia::WriterToken {
    uint64_t tag_ = UINT64_MAX;
    Slice val_;
    bool init_value(void* trie_valptr, size_t trie_valsize) noexcept final;
    void destroy_value(void* valptr, size_t valsize) noexcept final;
    bool insert_for_dup_user_key();
  };
  bool insert_kv(fstring ikey, const Slice& val, Token*);
  bool InsertKeyValueConcurrently(const Slice& ikey, const Slice& val) final {
    if (UNLIKELY(m_is_empty)) { // must check, avoid write as possible
      m_is_empty = false;
    }
    Token* token = m_trie.tls_writer_token_nn<Token>();
    token->acquire(&m_trie);
    auto ret = insert_kv(ikey, val, token);
    m_token_use_idle ? token->idle() : token->release();
    return ret;
  }
  bool InsertKeyValue(const Slice& k, const Slice& v) final {
    return InsertKeyValueConcurrently(k, v);
  }
  bool InsertKeyValueWithHintConcurrently(const Slice& k, const Slice& v,
                                          void** hint) final {
    if (UNLIKELY(m_is_empty)) { // must check, avoid write as possible
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
    return insert_kv(k, v, token);
  }
  bool InsertKeyValueWithHint(const Slice& k, const Slice& v, void** hint)
  final {
    return InsertKeyValueWithHintConcurrently(k, v, hint);
  }
  void FinishHint(void* hint) final {
    assert(nullptr != hint);
    auto token = (Token*)hint;
    m_token_use_idle ? token->idle() : token->release();
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
    auto entry = (Entry*)m_trie.mem_get(vec_pin->pos);
    bool ret = binary_search_0(entry, num, find_tag);
    m_token_use_idle ? token->idle() : token->release();
    return ret;
  }
  void MarkReadOnly() final;
  void MarkFlushed() final;
  void ColdizeMemory(const char* func);
  bool SupportConvertToSST() const final {
    return ConvertKind::kDontConvert != m_convert_to_sst;
  }
  Status ConvertToSST(FileMetaData*, const TableBuilderOptions&) final;
  size_t ApproximateMemoryUsage() final {
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
    return m_mem_size;
#else
    return m_trie.mem_size_inline();
#endif
  }
  struct KeyValueForGet : public KeyValuePair {
    inline static Slice cp(Slice ikey, void* buf) {
      memcpy(buf, ikey.data_, ikey.size_ - 8); // just copy user key
      return Slice((char*)buf, ikey.size_); // ikey: tag is pending
    }
    KeyValueForGet(Slice ikey, void* buf) : KeyValuePair(cp(ikey, buf), Slice()) {}
    void SetTag(uint64_t tag) { memcpy((char*)ikey.end() - 8, &tag, 8); }
  };
  ROCKSDB_FLATTEN
  void Get(const ReadOptions& ro, const LookupKey& k, void* callback_args,
           bool(*callback_func)(void*, const KeyValuePair&)) final {
    if (m_is_empty) {
      return;
    }
    const Slice ikey = k.internal_key();
    auto token = reader_token();
    token->acquire(&m_trie);
    if (!m_trie.lookup(fstring(ikey.data_, ikey.size_ - 8), token)) {
      m_token_use_idle ? token->idle() : token->release();
      return;
    }
    uint32_t vec_pin_pos = m_trie.value_of<uint32_t>(*token);
    auto vec_pin = (VecPin*)m_trie.mem_get(vec_pin_pos);
    size_t num = vec_pin->num & ~LOCK_FLAG;
    auto entry = (Entry*)m_trie.mem_get(vec_pin->pos);
    KeyValueForGet key_val(ikey, alloca(ikey.size_));
    uint64_t find_tag = DecodeFixed64(ikey.data_ + ikey.size_ - 8);
    intptr_t idx = upper_bound_0(entry, num, find_tag);
    if (ro.just_check_key_exists) {
      while (idx--) {
        uint64_t tag = entry[idx].tag;
        if ((tag & 255) == kTypeMerge) {
          // instruct get_context to stop earlier
          tag = (tag & ~uint64_t(255)) | kTypeValue;
        }
        key_val.SetTag(tag);
        if (!callback_func(callback_args, key_val))
          break;
      }
    }
    else while (idx--) {
      auto enc_valptr = (const char*)m_trie.mem_get(entry[idx].pos);
      key_val.SetTag(entry[idx].tag);
      key_val.value = GetLengthPrefixedSlice(enc_valptr);
      if (!callback_func(callback_args, key_val))
        break;
    }
    m_token_use_idle ? token->idle() : token->release();
  }
  Status SST_Get(const ReadOptions& ro,  const Slice& ikey,
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
        uint64_t tag = entry[idx].tag;
        UnPackSequenceAndType(tag, &pikey.sequence, &pikey.type);
        if (pikey.type == kTypeMerge) {
          // instruct get_context to stop earlier
          pikey.type = kTypeValue;
        }
        if (!get_context->SaveValue(pikey, "", pinner)) {
          return st;
        }
      }
    }
    else while (idx--) {
      uint64_t tag = entry[idx].tag;
      UnPackSequenceAndType(tag, &pikey.sequence, &pikey.type);
      auto enc_valptr = (const char*)m_trie.mem_get(entry[idx].pos);
      Slice value = GetLengthPrefixedSlice(enc_valptr);
      if (!get_context->SaveValue(pikey, value, pinner)) {
        return st;
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
  struct Iter;
};
bool CSPPMemTab::Token::init_value(void* trie_valptr, size_t valsize) noexcept {
  TERARK_ASSERT_EQ(valsize, sizeof(uint32_t));
  auto trie = static_cast<MainPatricia*>(m_trie);
  // 1. one memory block, 3 logical blocks are contiguous, CPU cache friendly
  // 2. one memory block can be free'ed partially, we using this feature here
  static_assert(Align == 4); // now it must be 4
  static_assert(sizeof(VecPin) % Align == 0);
  size_t enc_val_len = pow2_align_up(VarintLength(val_.size()) + val_.size(), Align);
  size_t vec_pin_pos = trie->mem_alloc(sizeof(VecPin) + sizeof(Entry) + enc_val_len);
  TERARK_VERIFY_NE(vec_pin_pos, MainPatricia::mem_alloc_fail);
  size_t entry_pos = vec_pin_pos + (sizeof(VecPin) / Align);
  size_t enc_val_pos = vec_pin_pos + ((sizeof(VecPin) + sizeof(Entry)) / Align);
  auto vec_pin = (VecPin*)(trie->mem_get(vec_pin_pos));
  auto entry = (Entry*)(vec_pin + 1);
  auto enc_val_ptr = (byte_t*)(entry + 1);
  *(uint32_t*)trie_valptr = (uint32_t)vec_pin_pos;
  vec_pin->pos = (uint32_t)entry_pos;
  vec_pin->cap = 1;
  vec_pin->num = 1;
  entry->pos = (uint32_t)enc_val_pos;
  entry->tag = tag_;
  encode_pre(val_, enc_val_ptr);
  return true;
}
void CSPPMemTab::Token::destroy_value(void* trie_valptr, size_t valsize) noexcept {
  // should be called very rarely: multi threads racing insert same user_key.
  // if do nothing, the memory block allocated in init_value will be leaked.
  TERARK_ASSERT_EQ(valsize, sizeof(uint32_t));
  auto trie = static_cast<MainPatricia*>(m_trie);
  size_t vec_pin_pos = *(const uint32_t*)trie_valptr;
  size_t enc_val_len = pow2_align_up(VarintLength(val_.size()) + val_.size(), Align);
  size_t mem_block_len = sizeof(VecPin) + sizeof(Entry) + enc_val_len;
  trie->mem_free(vec_pin_pos, mem_block_len); // free right now, not lazy free
}
terark_forceinline
bool CSPPMemTab::insert_kv(fstring ikey, const Slice& val, Token* tok) {
  fstring user_key(ikey.data(), ikey.size() - 8);
  tok->tag_ = DecodeFixed64(user_key.end());
  tok->val_ = val;
  uint32_t value_storage = UINT32_MAX;
  if (LIKELY(m_trie.insert(user_key, &value_storage, tok))) {
    TERARK_VERIFY_S(tok->has_value(), "OOM: mem_cap=%zd is too small: %s",
                    m_trie.mem_capacity(), m_trie.mmap_fpath());
    return true; // done: value insert has been handled in init_value
  }
  return tok->insert_for_dup_user_key();
}
bool CSPPMemTab::Token::insert_for_dup_user_key() {
  auto trie = static_cast<MainPatricia*>(m_trie);
  auto vec_pin_pos = trie->value_of<uint32_t>(*this);
  auto vec_pin = (VecPin*)trie->mem_get(vec_pin_pos);
  uint32_t num;
  while (LOCK_FLAG & (num = as_atomic(vec_pin->num)
                           .fetch_or(LOCK_FLAG, std::memory_order_acquire))) {
    std::this_thread::yield(); // has been locked by other threads, yield
  }
  const uint32_t old_cap = vec_pin->cap;
  TERARK_ASSERT_GT(num, 0);
  TERARK_ASSERT_LE(num, old_cap);
  const auto entry_old_pos = vec_pin->pos;
  const auto entry_old = (Entry*)trie->mem_get(entry_old_pos);
  const uint64_t curr_seq = tag_ >> 8;
  const uint64_t last_seq = entry_old[num-1].tag >> 8;
  if (UNLIKELY(curr_seq == last_seq)) {
    as_atomic(vec_pin->num).store(num, std::memory_order_release);
    return false; // duplicate internal_key(user_key, tag)
  }
  size_t enc_val_pos = trie->mem_alloc(VarintLength(val_.size()) + val_.size());
  TERARK_VERIFY_NE(enc_val_pos, MainPatricia::mem_alloc_fail);
  encode_pre(val_, trie->mem_get(enc_val_pos));
  if (num < old_cap && last_seq < curr_seq) {
    entry_old[num].pos = (uint32_t)enc_val_pos;
    entry_old[num].tag = tag_;
    // this atomic store also clears LOCK_FLAG
    as_atomic(vec_pin->num).store(num + 1, std::memory_order_release);
    return true;
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
    auto idx = lower_bound_0(entry_old, num, tag_);
    memcpy(entry_cow, entry_old, sizeof(Entry) * idx);
    entry_cow[idx].pos = (uint32_t)enc_val_pos;
    entry_cow[idx].tag = tag_;
    memcpy(entry_cow + idx+1, entry_old + idx, sizeof(Entry)*(num-idx));
  }
  as_atomic(vec_pin->pos).store((uint32_t)entry_cow_pos, std::memory_order_release);
  as_atomic(vec_pin->cap).store(new_cap, std::memory_order_release);
  // vec_pin->num.store also clears LOCK_FLAG
  as_atomic(vec_pin->num).store(num + 1, std::memory_order_release);
  trie->mem_lazy_free(entry_old_pos, sizeof(Entry) * num);
  return true;
}
struct CSPPMemTab::Iter : public MemTableRep::Iterator, boost::noncopyable {
  Patricia::Iterator* m_iter;
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
    return AccessEntryVec(vec_pin_ptr);
  }
  terark_forceinline EntryVec AccessEntryVec(const VecPin* vec_pin) const {
    auto entry_num = int(vec_pin->num & ~LOCK_FLAG);
    auto entry_vec = (Entry*)(m_mempool + Align * vec_pin->pos);
    return { entry_num, entry_vec };
  }
  terark_forceinline void AppendTag(uint64_t tag) const {
    memcpy(m_iter->mutable_word().ensure_unused(8), &tag, 8);
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
    auto enc_val_pos = entry[m_idx].pos;
    return GetLengthPrefixedSlice(mempool + Align * enc_val_pos);
  }
  std::pair<Slice, Slice>
  GetKeyValue() const final { return {key(), value()}; }
  void Next() final {
    NextAndCheckValid(); // ignore return value
  }
  bool NextAndCheckValid() final {
    TERARK_ASSERT_GE(m_idx, 0);
    if (m_idx-- == 0) {
      if (UNLIKELY(!(m_rev ? m_iter->decr() : m_iter->incr()))) {
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
  bool NextAndGetResult(IterateResult* result) {
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
    auto entry = AccessEntryVec(m_vec_pin);
    if (++m_idx == entry.num) {
      if (UNLIKELY(!(m_rev ? m_iter->incr() : m_iter->decr()))) {
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
      m_iter = m_tab->m_trie.new_iter();
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
      if (UNLIKELY(!(m_rev ? iter.decr() : iter.incr()))) {
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
      m_iter = m_tab->m_trie.new_iter();
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
      if (UNLIKELY(!(m_rev ? iter.incr() : iter.decr()))) {
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
      m_iter = m_tab->m_trie.new_iter();
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
      m_iter = m_tab->m_trie.new_iter();
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
    terark::string_appender<> oss_rocks;
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
struct CSPPMemTabFactory final : public MemTableRepFactory {
  intptr_t m_mem_cap = 2LL << 30;
  bool   use_vm = true;
  HugePageEnum  use_hugepage = HugePageEnum::kNone;
  bool   vm_explicit_commit = false;
  bool   read_by_writer_token = true;
  bool   token_use_idle = true;
  bool   accurate_memsize = false; // mainly for debug and unit test
  bool   sync_sst_file = true;
  ConvertKind convert_to_sst = ConvertKind::kDontConvert;
  size_t chunk_size = 2 << 20; // 2MiB
  size_t cumu_num = 0, cumu_iter_num = 0;
  size_t live_num = 0, live_iter_num = 0;
  uint64_t deactived_mem_sum = 0;
  MemTabLinkListNode m_head;
  mutable std::mutex m_mtx;
  CSPPMemTabFactory(const json& js, const SidePluginRepo& r) {
    m_head.m_next = m_head.m_prev = &m_head;
    Update({}, js, r);
  }
  MemTableRep* CreateMemTableRep(const MemTableRep::KeyComparator& cmp,
                                 Allocator* a, const SliceTransform* s,
                                 Logger* logger) final {
    return CreateMemTableRep(std::string(), cmp, a, s, logger, 0);
  }
  MemTableRep* CreateMemTableRep(const MemTableRep::KeyComparator& cmp,
                                 Allocator* a, const SliceTransform* s,
                                 Logger* logger, uint32_t cf_id) final {
    return CreateMemTableRep(std::string(), cmp, a, s, logger, cf_id);
  }
  MemTableRep* CreateMemTableRep(const std::string& level0_dir,
                                 const MemTableRep::KeyComparator& cmp,
                                 Allocator*, const SliceTransform*,
                                 Logger* logger, uint32_t cf_id) final {
    auto uc = cmp.icomparator()->user_comparator();
    if (!uc->IsBytewise()) {
      return nullptr;
    }
    auto curr_convert_to_sst = convert_to_sst; // may be updated by webview
    auto curr_num = as_atomic(cumu_num).fetch_add(1, std::memory_order_relaxed);
    terark::string_appender<> conf;
    conf.reserve(512);
    conf|"?chunk_size="|chunk_size;
    if (ConvertKind::kFileMmap == curr_convert_to_sst) {
      // File mmap does not support hugepage
      conf|"&file_path="|level0_dir;
      conf^"/cspp-%06zd.memtab"^curr_num^"-"^cf_id;
    } else {
      conf|"&hugepage="|int(use_hugepage);
      if (vm_explicit_commit)
        conf|"&vm_explicit_commit=true"; // default is false
    }
    return new CSPPMemTab(m_mem_cap, uc->IsReverseBytewise(), logger,
                          this, curr_num, curr_convert_to_sst, conf);
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
    ROCKSDB_JSON_OPT_PROP(js, read_by_writer_token);
    ROCKSDB_JSON_OPT_PROP(js, token_use_idle);
    ROCKSDB_JSON_OPT_PROP(js, accurate_memsize);
    ROCKSDB_JSON_OPT_ENUM(js, convert_to_sst);
    ROCKSDB_JSON_OPT_PROP(js, sync_sst_file);
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
    ROCKSDB_JSON_SET_PROP(djs, read_by_writer_token);
    ROCKSDB_JSON_SET_PROP(djs, token_use_idle);
    ROCKSDB_JSON_SET_PROP(djs, accurate_memsize);
    ROCKSDB_JSON_SET_ENUM(djs, convert_to_sst);
    ROCKSDB_JSON_SET_PROP(djs, sync_sst_file);
    ROCKSDB_JSON_SET_PROP(djs, cumu_iter_num);
    ROCKSDB_JSON_SET_PROP(djs, live_iter_num);
    size_t active_num = 0;
    size_t active_used_mem = 0;
    size_t live_used_mem = 0;
    size_t token_qlen = 0;
    size_t total_raw_iter = 0;
    string_appender<> detail_qlen;
    detail_qlen.reserve(128*live_num);
    detail_qlen << "[ ";
    m_mtx.lock();
    for (auto node = m_head.m_next; node != &m_head; node = node->m_next) {
      auto memtab = static_cast<CSPPMemTab*>(node);
      live_used_mem += memtab->m_trie.mem_size_inline();
      if (!memtab->m_trie.is_readonly())
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
      else if (memtab->m_trie.is_readonly())
        detail_qlen|"("|idx|","|cur_qlen|","|raw_iter|"), ";
      else
        if (html)
          detail_qlen|"<em>("|idx|","|cur_qlen|","|raw_iter|")</em>, ";
        else
          detail_qlen|"*("|idx|","|cur_qlen|","|raw_iter|")*, ";
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
    djs["comment"] = "(idx, qlen, raw_iter_num), <strong>strong: flushed</strong>, normal: readonly, <em>em: active</em>";
    ROCKSDB_JSON_SET_PROP(djs, detail_qlen);
    JS_CSPPMemTab_AddVersion(djs, html);
    return djs;
  }
};
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
  return a ? new(a->AllocateAligned(sizeof(Iter))) Iter(this) : new Iter(this);
}
CSPPMemTab::Iter::Iter(CSPPMemTab* tab) {
  m_tab = tab;
  m_rev = tab->m_rev;
  m_iter = nullptr;
  m_mempool = (const char*)tab->m_trie.mem_get(0);
}
CSPPMemTab::Iter::~Iter() noexcept {
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
  m_has_converted_to_sst = false;
  m_read_by_writer_token = f->read_by_writer_token;
  m_token_use_idle = f->token_use_idle;
  m_accurate_memsize = f->accurate_memsize;
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
void CSPPMemTab::MarkReadOnly() {
  auto used = m_trie.mem_size_inline();
  as_atomic(m_fac->deactived_mem_sum).fetch_add(used, std::memory_order_relaxed);
  m_trie.set_readonly();
}
void CSPPMemTab::MarkFlushed() {
  ROCKSDB_VERIFY(m_trie.is_readonly());
  ColdizeMemory("CSPPMemTab::MarkFlushed");
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
static size_t SeekToEnd(WritableFileWriter& writer, Logger* log) {
  auto fs_file = writer.writable_file();
  auto fd = fs_file->FileDescriptor();
#if defined(_MSC_VER)
  TODO ......
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
  double t0 = clock->NowMicros();
  ROCKSDB_VERIFY_NE(m_convert_to_sst, ConvertKind::kDontConvert);
  bool sync_sst_file = m_fac->sync_sst_file; // consitency param snapshot
  IODebugContext dbg_ctx;
  FileOptions fopt;
  fopt.allow_fallocate = false;
  std::string fname = TableFileName(tbo.ioptions.cf_paths,
                                    meta->fd.GetNumber(),
                                    meta->fd.GetPathId());
  std::unique_ptr<FSWritableFile> fs_file;
  const bool is_file_mmap = ConvertKind::kFileMmap == m_convert_to_sst;
  if (is_file_mmap) {
    const std::string& src_fname = m_trie.mmap_fpath();
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
    return djs.dump();
  }
  Status ValidateOptions(const DBOptions&, const ColumnFamilyOptions&)
  const final {
    return Status::OK();
  }
  bool IsDeleteRangeSupported() const override { return true; }
  void Update(const json&, const json& js, const SidePluginRepo&) {}
  std::string ToString(const json& d, const SidePluginRepo& repo) const {
    json djs = memtable_factory->ToJson(d);
    return JsonToString(djs, d);
  }
  std::shared_ptr<CSPPMemTabFactory> memtable_factory;
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
    return 0;
  }
  uint64_t ApproximateSize(ROCKSDB_8_X_COMMA(const ReadOptions&)
                           const Slice&, const Slice&, TableReaderCaller) final {
    return 0;
  }
  size_t ApproximateMemoryUsage() const final { return file_data_.size(); }
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
  table_properties_->compression_name = "CSPPMemTab";
  table_properties_->compression_options.clear();
  as_string_appender(table_properties_->compression_options)
    | "Free = "|SizeToString(m_memtab->m_trie.mem_frag_size());
  as_string_appender(table_properties_->compression_options)
    ^ ", %.2f%%" ^ 100.0*m_memtab->m_trie.mem_frag_size()/file_data_.size();

  table_properties_->tag_size = 8 * table_properties_->num_entries;
  table_properties_->data_size = table_properties_->raw_value_size;
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
std::string
CSPPMemTabTableReader::ToWebViewString(const json& dump_options) const {
  std::string str;
  str = "TODO";
  return str;
}
Status CSPPMemTabTableFactory::NewTableReader(
              const ReadOptions& ro,
              const TableReaderOptions& tro,
              std::unique_ptr<RandomAccessFileReader>&& file,
              uint64_t file_size,
              std::unique_ptr<TableReader>* table,
              bool prefetch_index_and_filter)
const try {
  (void)prefetch_index_and_filter; // now ignore
  file->exchange(new MmapReadWrapper(file));
  Slice file_data;
  Status s = TopMmapReadAll(*file, file_size, &file_data);
  if (!s.ok()) {
    return s;
  }
  MmapAdvSeq(file_data);
  MmapWarmUp(file_data);
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
