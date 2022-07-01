// Copyright (c) 2021-present, Topling, Inc.  All rights reserved.
// Created by leipeng, fully rewrite by leipeng 2021-05-12
#include "db/memtable.h"
#include "topling/side_plugin_factory.h"
#include "logging/logging.h"
#include <terark/fsa/cspptrie.inl>
#include <terark/num_to_str.hpp>
const char* git_version_hash_info_cspp_memtable();
namespace ROCKSDB_NAMESPACE {
using namespace terark;
static const uint32_t LOCK_FLAG = uint32_t(1) << 31;
struct CSPPMemTabFactory;
struct CSPPMemTab : public MemTableRep {
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
  bool          m_token_use_idle;
  bool          m_accurate_memsize;
  bool          m_rev;
  CSPPMemTabFactory* m_fac;
  Logger*  m_log;
  size_t   m_instance_idx;
  uint32_t m_cumu_iter_num = 0;
  uint32_t m_live_iter_num = 0;
  size_t   m_mem_size = 0;
  CSPPMemTab(intptr_t cap, bool rev, Logger*, CSPPMemTabFactory*);
  ~CSPPMemTab() noexcept override;
  KeyHandle Allocate(const size_t, char**) final { TERARK_DIE("Bad call"); }
  void Insert(KeyHandle) final { TERARK_DIE("Bad call"); }
  struct Token : public Patricia::WriterToken {
    uint64_t tag_ = UINT64_MAX;
    Slice val_;
    bool init_value(void* trie_valptr, size_t trie_valsize) noexcept final;
    bool insert_kv(fstring ikey, Slice val);
    bool insert_for_dup_user_key();
  };
  bool InsertKeyValue(const Slice& ikey, const Slice& val) final {
    Token* token = m_trie.tls_writer_token_nn<Token>();
    token->acquire(&m_trie);
    auto ret = token->insert_kv(ikey, val);
    m_token_use_idle ? token->idle() : token->release();
    return ret;
  }
  bool InsertKeyValueConcurrently(const Slice& k, const Slice& v) final {
    return InsertKeyValue(k, v);
  }
  bool InsertKeyValueWithHint(const Slice& k, const Slice& v, void**) final {
    return InsertKeyValue(k, v);
  }
  bool InsertKeyValueWithHintConcurrently(const Slice& k, const Slice& v,
                                          void** /*hint*/) final {
    return InsertKeyValue(k, v);
  }
  bool Contains(const Slice& ikey) const final {
    fstring user_key(ikey.data(), ikey.size() - 8);
    auto token = m_trie.tls_reader_token();
    token->acquire(&m_trie);
    if (!m_trie.lookup(user_key, token)) {
      m_token_use_idle ? token->idle() : token->release();
      return false;
    }
    uint64_t find_tag = DecodeFixed64(user_key.end());
    auto vec_pin = (VecPin*)m_trie.mem_get(*(uint32_t*)token->value());
    auto num = vec_pin->num & ~LOCK_FLAG;
    auto entry = (Entry*)m_trie.mem_get(vec_pin->pos);
    bool ret = binary_search_0(entry, num, find_tag);
    m_token_use_idle ? token->idle() : token->release();
    return ret;
  }
  void MarkReadOnly() final;
  size_t ApproximateMemoryUsage() final {
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
  }
  static constexpr size_t MAX_alloca = 512;
  struct Context : public KeyValuePair {
    Slice GetKey() const final { return {ikey_buf, ikey_len}; }
    Slice GetValue() const final { return GetLengthPrefixedSlice(enc_valptr); }
    std::pair<Slice, Slice> GetKeyValue() const final {
      return { {ikey_buf, ikey_len}, GetLengthPrefixedSlice(enc_valptr) };
    }
    Context(Slice ikey, void* buf) {
      ikey_buf = (char*)buf;
      ikey_len = ikey.size_;
      memcpy(buf, ikey.data_, ikey.size_ - 8);
    }
    ~Context() override { if (ikey_len > MAX_alloca) free(ikey_buf); }
    char*  ikey_buf;
    size_t ikey_len;
    const char* enc_valptr = nullptr; // prefixed len encoded value ptr
  };
  void Get(const ReadOptions& ro, const LookupKey& k, void* callback_args,
           bool(*callback_func)(void*, const KeyValuePair*)) final {
    const Slice ikey = k.internal_key();
    auto token = m_trie.tls_reader_token();
    token->acquire(&m_trie);
    if (!m_trie.lookup(fstring(ikey.data_, ikey.size_ - 8), token)) {
      m_token_use_idle ? token->idle() : token->release();
      return;
    }
    uint32_t vec_pin_pos = *(uint32_t*)token->value();
    auto vec_pin = (VecPin*)m_trie.mem_get(vec_pin_pos);
    size_t num = vec_pin->num & ~LOCK_FLAG;
    auto entry = (Entry*)m_trie.mem_get(vec_pin->pos);
    Context ctx(ikey, ikey.size_ > MAX_alloca ? malloc(ikey.size_)
                                              : alloca(ikey.size_));
    uint64_t find_tag = DecodeFixed64(ikey.data_ + ikey.size_ - 8);
    intptr_t idx = upper_bound_0(entry, num, find_tag);
    if (ro.just_check_key_exists) {
      while (idx--) {
        uint64_t tag = entry[idx].tag;
        if ((tag & 255) == kTypeMerge) {
          // instruct get_context to stop earlier
          tag = (tag & ~uint64_t(255)) | kTypeValue;
        }
        memcpy(ctx.ikey_buf + ikey.size_ - 8, &tag, 8);
        ctx.enc_valptr = ""; // empty value
        if (!callback_func(callback_args, &ctx))
          break;
      }
    }
    else while (idx--) {
      memcpy(ctx.ikey_buf + ikey.size_ - 8, &entry[idx].tag, 8);
      ctx.enc_valptr = (const char*)m_trie.mem_get(entry[idx].pos);
      if (!callback_func(callback_args, &ctx))
        break;
    }
    m_token_use_idle ? token->idle() : token->release();
  }
  MemTableRep::Iterator* GetIterator(Arena*) final;
  struct Iter;
};
bool CSPPMemTab::Token::init_value(void* trie_valptr, size_t valsize) noexcept {
  TERARK_ASSERT_EQ(valsize, sizeof(uint32_t));
  auto trie = static_cast<MainPatricia*>(m_trie);
  size_t vec_pin_pos = trie->mem_alloc(sizeof(VecPin));
  TERARK_VERIFY_NE(vec_pin_pos, MainPatricia::mem_alloc_fail);
  size_t entry_pos = trie->mem_alloc(sizeof(Entry));
  TERARK_VERIFY_NE(entry_pos, MainPatricia::mem_alloc_fail);
  size_t enc_val_pos = trie->mem_alloc(VarintLength(val_.size()) + val_.size());
  TERARK_VERIFY_NE(enc_val_pos, MainPatricia::mem_alloc_fail);
  encode_pre(val_, trie->mem_get(enc_val_pos));
  auto entry = (Entry*)trie->mem_get(entry_pos);
  entry->pos = (uint32_t)enc_val_pos;
  entry->tag = tag_;
  auto vec_pin = (VecPin*)trie->mem_get(vec_pin_pos);
  vec_pin->pos = (uint32_t)entry_pos;
  vec_pin->cap = 1;
  vec_pin->num = 1;
  *(uint32_t*)trie_valptr = (uint32_t)vec_pin_pos;
  return true;
}
bool CSPPMemTab::Token::insert_kv(fstring ikey, Slice val) {
  fstring user_key(ikey.data(), ikey.size() - 8);
  tag_ = DecodeFixed64(user_key.end());
  val_ = val;
  uint32_t value_storage = 0;
  if (m_trie->insert(user_key, &value_storage, this)) {
    size_t mem_cap = static_cast<MainPatricia*>(m_trie)->mem_capacity();
    TERARK_VERIFY_F(this->value() != nullptr, "OOM: mem_cap=%zd is too small", mem_cap);
    return true; // done: value insert has been handled in init_value
  }
  return insert_for_dup_user_key();
}
bool CSPPMemTab::Token::insert_for_dup_user_key() {
  auto trie = static_cast<MainPatricia*>(m_trie);
  auto vec_pin_pos = *(uint32_t*)this->value();
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
  int         m_idx = -1;
  bool        m_rev;
  struct EntryVec { int num; const Entry* vec; };
  terark_forceinline EntryVec GetEntryVec() const {
    auto trie = &m_tab->m_trie;
    auto vec_pin = (VecPin*)trie->mem_get(*(uint32_t*)m_iter->value());
    auto entry_num = int(vec_pin->num & ~LOCK_FLAG);
    auto entry_vec = (Entry*)trie->mem_get(vec_pin->pos);
    return { entry_num, entry_vec };
  }
  terark_forceinline void AppendTag(uint64_t tag) const {
    memcpy(m_iter->mutable_word().ensure_unused(8), &tag, 8);
  }
  explicit Iter(CSPPMemTab*);
  ~Iter() noexcept override;
  bool Valid() const final { return m_idx >= 0; }
  const char* key() const final { TERARK_DIE("Bad call"); }
  Slice GetKey() const final {
    TERARK_ASSERT_GE(m_idx, 0);
    fstring user_key = m_iter->word();
    return Slice(user_key.p, user_key.n + 8);
  }
  Slice GetValue() const final {
    TERARK_ASSERT_GE(m_idx, 0);
    auto trie = &m_tab->m_trie;
    auto vec_pin = (VecPin*)trie->mem_get(*(uint32_t*)m_iter->value());
    auto entry = (Entry*)trie->mem_get(vec_pin->pos);
    auto enc_val_pos = entry[m_idx].pos;
    return GetLengthPrefixedSlice((const char*)trie->mem_get(enc_val_pos));
  }
  std::pair<Slice, Slice>
  GetKeyValue() const final { return {GetKey(), GetValue()}; }
  void Next() final {
    TERARK_ASSERT_GE(m_idx, 0);
    if (m_idx-- == 0) {
      if (UNLIKELY(!(m_rev ? m_iter->decr() : m_iter->incr()))) {
        TERARK_ASSERT_LT(m_idx, 0);
        return; // fail
      }
      auto entry = GetEntryVec();
      AppendTag(entry.vec[m_idx = entry.num - 1].tag);
    } else {
      auto entry = GetEntryVec();
      AppendTag(entry.vec[m_idx].tag);
    }
  }
  void Prev() final {
    TERARK_ASSERT_GE(m_idx, 0);
    auto entry = GetEntryVec();
    if (++m_idx == entry.num) {
      if (UNLIKELY(!(m_rev ? m_iter->incr() : m_iter->decr()))) {
        m_idx = -1;
        return; // fail
      }
      entry = GetEntryVec();
      m_idx = 0;
    }
    AppendTag(entry.vec[m_idx].tag);
  }
  static fstring GetUserKey(Slice ikey, const char *memtable_key) {
    if (memtable_key != nullptr)
      ikey = GetLengthPrefixedSlice(memtable_key);
    return fstring(ikey.data(), ikey.size() - 8);
  }
  void Seek(const Slice& ikey, const char *memtable_key) final {
    fstring user_key = GetUserKey(ikey, memtable_key);
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
  void SeekForPrev(const Slice& ikey, const char* memtable_key) final {
    fstring user_key = GetUserKey(ikey, memtable_key);
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
    if (UNLIKELY(!(m_rev ? m_iter->seek_end() : m_iter->seek_begin()))) {
      m_idx = -1;
      return; // fail
    }
    auto entry = GetEntryVec();
    AppendTag(entry.vec[m_idx = entry.num - 1].tag);
  }
  void SeekToLast() final {
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
  auto& ver = djs["version"];
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
  std::string m_conf_str = "?hugepage=0";
  intptr_t m_mem_cap = 2LL << 30;
  bool   use_vm = true;
  HugePageEnum  use_hugepage = HugePageEnum::kNone;
  bool   token_use_idle = true;
  bool   accurate_memsize = false; // mainly for debug and unit test
  size_t chunk_size = 2 << 20; // 2MiB
  size_t cumu_num = 0, cumu_iter_num = 0;
  size_t live_num = 0, live_iter_num = 0;
  uint64_t cumu_used_mem = 0;
  std::vector<CSPPMemTab*> m_all;
  mutable std::mutex m_mtx;
  CSPPMemTabFactory(const json& js, const SidePluginRepo& r) { Update({}, js, r); }
  using MemTableRepFactory::CreateMemTableRep;
  MemTableRep* CreateMemTableRep(const MemTableRep::KeyComparator& cmp,
                                 Allocator*, const SliceTransform*,
                                 Logger* logger) final {
    auto uc = cmp.icomparator()->user_comparator();
    if (IsForwardBytewiseComparator(uc))
      return new CSPPMemTab(m_mem_cap, false, logger, this);
    else if (IsBytewiseComparator(uc))
      return new CSPPMemTab(m_mem_cap, true, logger, this);
    else
      return nullptr;
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
      m_conf_str = "?hugepage=" + std::to_string(int(use_hugepage));
    }
    ROCKSDB_JSON_OPT_PROP(js, token_use_idle);
    ROCKSDB_JSON_OPT_PROP(js, accurate_memsize);
    iter = js.find("chunk_size");
    if (js.end() != iter) {
      ROCKSDB_JSON_OPT_SIZE(js, chunk_size);
      ROCKSDB_VERIFY_F((chunk_size & (chunk_size-1)) == 0, "%zd(%#zX)",
                        chunk_size, chunk_size);
      static_cast<string_appender<>&>(m_conf_str)|"&chunk_size="|chunk_size;
    }
    m_mem_cap = mem_cap;
  }
  std::string ToString(const json& d, const SidePluginRepo&) const {
    size_t mem_cap = m_mem_cap;
    auto avg_used_mem = cumu_num ? cumu_used_mem / cumu_num : 0;
    bool html = JsonSmartBool(d, "html");
    json djs;
    ROCKSDB_JSON_SET_SIZE(djs, mem_cap);
    ROCKSDB_JSON_SET_SIZE(djs, chunk_size);
    ROCKSDB_JSON_SET_PROP(djs, use_vm);
    ROCKSDB_JSON_SET_ENUM(djs, use_hugepage);
    ROCKSDB_JSON_SET_PROP(djs, token_use_idle);
    ROCKSDB_JSON_SET_PROP(djs, cumu_num);
    ROCKSDB_JSON_SET_PROP(djs, live_num);
    ROCKSDB_JSON_SET_PROP(djs, cumu_iter_num);
    ROCKSDB_JSON_SET_PROP(djs, live_iter_num);
    ROCKSDB_JSON_SET_SIZE(djs, avg_used_mem);
    ROCKSDB_JSON_SET_SIZE(djs, cumu_used_mem);
    size_t live_used_mem = 0;
    size_t token_qlen = 0;
    size_t total_raw_iter = 0;
    string_appender<> detail_qlen;
    detail_qlen.reserve(4096);
    detail_qlen << "[ ";
    m_mtx.lock();
    for (auto memtab : m_all) {
      live_used_mem += memtab->m_trie.mem_size_inline();
      size_t idx = memtab->m_instance_idx;
      size_t raw_iter = memtab->m_trie.live_iter_num();
      size_t cur_qlen = memtab->m_trie.get_token_qlen();
      token_qlen += cur_qlen;
      total_raw_iter += raw_iter;
      if (memtab->m_trie.is_readonly())
        detail_qlen|"("|idx|","|cur_qlen|","|raw_iter|"), ";
      else
        if (html)
          detail_qlen|"<em>("|idx|","|cur_qlen|","|raw_iter|")</em>, ";
        else
          detail_qlen|"*("|idx|","|cur_qlen|","|raw_iter|")*, ";
    }
    m_mtx.unlock();
    if (detail_qlen.size() >= 4) {
      detail_qlen.end()[-2] = ' ';
      detail_qlen.end()[-1] = ']';
    } else {
      detail_qlen << " ]";
    }
    ROCKSDB_JSON_SET_SIZE(djs, live_used_mem);
    ROCKSDB_JSON_SET_PROP(djs, token_qlen);
    ROCKSDB_JSON_SET_PROP(djs, total_raw_iter);
    ROCKSDB_JSON_SET_PROP(djs, detail_qlen);
    JS_CSPPMemTab_AddVersion(djs, html);
    return JsonToString(djs, d);
  }
};
MemTableRep::Iterator* CSPPMemTab::GetIterator(Arena* a) {
  as_atomic(m_fac->cumu_iter_num).fetch_add(1, std::memory_order_relaxed);
  as_atomic(m_fac->live_iter_num).fetch_add(1, std::memory_order_relaxed);
  as_atomic(m_cumu_iter_num).fetch_add(1, std::memory_order_relaxed);
  as_atomic(m_live_iter_num).fetch_add(1, std::memory_order_relaxed);
  return a ? new(a->AllocateAligned(sizeof(Iter))) Iter(this) : new Iter(this);
}
CSPPMemTab::Iter::Iter(CSPPMemTab* tab) {
  m_tab = tab;
  m_rev = tab->m_rev;
  m_iter = tab->m_trie.new_iter();
}
CSPPMemTab::Iter::~Iter() noexcept {
  m_iter->dispose();
  auto factory = m_tab->m_fac;
  as_atomic(factory->live_iter_num).fetch_sub(1, std::memory_order_relaxed);
  as_atomic(m_tab->m_live_iter_num).fetch_sub(1, std::memory_order_relaxed);
}
CSPPMemTab::CSPPMemTab(intptr_t cap, bool rev, Logger* log, CSPPMemTabFactory* f)
    : MemTableRep(nullptr)
    , m_trie(4, f->use_vm ? -cap : cap, Patricia::MultiWriteMultiRead,
             f->m_conf_str) {
  m_fac = f;
  m_log = log;
  m_rev = rev;
  m_token_use_idle = f->token_use_idle;
  m_accurate_memsize = f->accurate_memsize;
  as_atomic(f->live_num).fetch_add(1, std::memory_order_relaxed);
  m_instance_idx = as_atomic(f->cumu_num).fetch_add(1, std::memory_order_relaxed);
  f->m_mtx.lock();
  f->m_all.push_back(this);
  f->m_mtx.unlock();
}
CSPPMemTab::~CSPPMemTab() noexcept {
  TERARK_ASSERT_EZ(m_live_iter_num);
  as_atomic(m_fac->live_num).fetch_sub(1, std::memory_order_relaxed);
  m_fac->m_mtx.lock();
  m_fac->m_all.erase(std::find(m_fac->m_all.begin(), m_fac->m_all.end(), this));
  m_fac->m_mtx.unlock();
}
void CSPPMemTab::MarkReadOnly() {
  auto used = m_trie.mem_size_inline();
  as_atomic(m_fac->cumu_used_mem).fetch_add(used, std::memory_order_relaxed);
  m_trie.set_readonly();
}
ROCKSDB_REG_Plugin("cspp", CSPPMemTabFactory, MemTableRepFactory);
ROCKSDB_REG_EasyProxyManip("cspp", CSPPMemTabFactory, MemTableRepFactory);
MemTableRepFactory* NewCSPPMemTabForPlain(const std::string& jstr) {
  json js = json::parse(jstr);
  const SidePluginRepo repo;
  return new CSPPMemTabFactory(js, repo);
}
} // namespace ROCKSDB_NAMESPACE
