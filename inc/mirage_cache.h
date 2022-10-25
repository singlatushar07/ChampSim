#ifndef MIRAGE_CACHE_H
#define MIRAGE_CACHE_H

#include <functional>
#include <list>
#include <string>
#include <vector>

#include "champsim.h"
#include "delay_queue.hpp"
#include "memory_class.h"
#include "ooo_cpu.h"
#include "operable.h"

// virtual address space prefetching
#define VA_PREFETCH_TRANSLATION_LATENCY 2

extern std::array<O3_CPU*, NUM_CPUS> ooo_cpu;

class TAG
{
public:
  bool valid = false, prefetch = false, dirty = false;

  uint64_t address = 0, v_address = 0, tag = 0, data_ptr = 0, ip = 0, cpu = 0, instr_id = 0;

  // replacement state
  uint32_t lru = std::numeric_limits<uint32_t>::max() >> 1;
};

class SKEW
{
  uint64_t hash();

public:
  uint32_t skew_id;
  uint64_t get_skew_address();
};

struct datapoint{
  bool valid;
  uint64_t skew;
  uint64_t way;
  uint64_t set;
};

class MIRAGE_CACHE : public champsim::operable, public MemoryRequestConsumer, public MemoryRequestProducer
{
public:
  uint32_t cpu;
  const std::string NAME;
  const uint32_t NUM_SET, NUM_WAY, NUM_SKEWS, WQ_SIZE, RQ_SIZE, PQ_SIZE, MSHR_SIZE, NUM_EXTRA = 0;
  const uint32_t HIT_LATENCY, FILL_LATENCY, OFFSET_BITS;

  // Skews
  std::vector<std::vector<MIRAGE_TAG>> block{NUM_SKEWS, std::vector<MIRAGE_TAG>(NUM_SET*(NUM_WAY))};
  std::vector<std::pair<uint64_t, uint64_t>> keys{NUM_SKEWS};
  // std::vector<BLOCK> block{NUM_SET * NUM_WAY};

  // Datastore
  vector<datapoint> datastore{NUM_SET*(NUM_WAY-NUM_EXTRA)};
  uint64_t datastore_find_victim();
  bool is_datastore_full = false;
  uint64_t datastore_fill_level;

  const uint32_t MAX_READ, MAX_WRITE;
  uint32_t reads_available_this_cycle, writes_available_this_cycle;
  const bool prefetch_as_load;
  const bool match_offset_bits;
  const bool virtual_prefetch;
  bool ever_seen_data = false;
  const unsigned pref_activate_mask = (1 << static_cast<int>(LOAD)) | (1 << static_cast<int>(PREFETCH));

  // prefetch stats
  uint64_t pf_requested = 0, pf_issued = 0, pf_useful = 0, pf_useless = 0, pf_fill = 0;

  // queues
  champsim::delay_queue<PACKET> RQ{RQ_SIZE, HIT_LATENCY}, // read queue
      PQ{PQ_SIZE, HIT_LATENCY},                           // prefetch queue
      VAPQ{PQ_SIZE, VA_PREFETCH_TRANSLATION_LATENCY},     // virtual address prefetch queue
      WQ{WQ_SIZE, HIT_LATENCY};                           // write queue

  std::list<PACKET> MSHR; // MSHR

  uint64_t sim_access[NUM_CPUS][NUM_TYPES] = {}, sim_hit[NUM_CPUS][NUM_TYPES] = {}, sim_miss[NUM_CPUS][NUM_TYPES] = {}, roi_access[NUM_CPUS][NUM_TYPES] = {},
           roi_hit[NUM_CPUS][NUM_TYPES] = {}, roi_miss[NUM_CPUS][NUM_TYPES] = {};

  uint64_t RQ_ACCESS = 0, RQ_MERGED = 0, RQ_FULL = 0, RQ_TO_CACHE = 0, PQ_ACCESS = 0, PQ_MERGED = 0, PQ_FULL = 0, PQ_TO_CACHE = 0, WQ_ACCESS = 0, WQ_MERGED = 0,
           WQ_FULL = 0, WQ_FORWARD = 0, WQ_TO_CACHE = 0;

  uint64_t total_miss_latency = 0;

  // functions
  int add_rq(PACKET* packet) override;
  int add_wq(PACKET* packet) override;
  int add_pq(PACKET* packet) override;

  void return_data(PACKET* packet) override;
  void operate() override;
  void operate_writes();
  void operate_reads();

  uint32_t get_occupancy(uint8_t queue_type, uint64_t address) override;
  uint32_t get_size(uint8_t queue_type, uint64_t address) override;

  uint32_t get_set(uint64_t address, std::pair<uint64_t, uint64_t> key);
  uint32_t get_way(uint64_t address, std::size_t skew, uint32_t set);

  int invalidate_entry(uint64_t inval_addr, std::size_t skew);
  int prefetch_line(uint64_t pf_addr, bool fill_this_level, uint32_t prefetch_metadata);
  int prefetch_line(uint64_t ip, uint64_t base_addr, uint64_t pf_addr, bool fill_this_level, uint32_t prefetch_metadata); // deprecated

  void add_mshr(PACKET* packet);
  void va_translate_prefetches();

  void handle_fill();
  void handle_writeback();
  void handle_read();
  void handle_prefetch();

  void readlike_hit(std::size_t skew, std::size_t set, std::size_t way, PACKET& handle_pkt);
  bool readlike_miss(PACKET& handle_pkt);
  bool filllike_miss(std::size_t skew, std::size_t set, std::size_t way, PACKET& handle_pkt);

  bool should_activate_prefetcher(int type);

  void print_deadlock() override;

#include "cache_modules.inc"

  const repl_t repl_type;
  const pref_t pref_type;

  // constructor
  MIRAGE_CACHE(std::string v1, double freq_scale, unsigned fill_level, uint32_t v2, uint32_t v3, uint32_t skews, uint32_t v5, uint32_t v6, uint32_t v7,
               uint32_t v8, uint32_t hit_lat, uint32_t fill_lat, uint32_t max_read, uint32_t max_write, std::size_t offset_bits, bool pref_load,
               bool wq_full_addr, bool va_pref, unsigned pref_act_mask, MemoryRequestConsumer* ll, pref_t pref, repl_t repl)
      : champsim::operable(freq_scale), MemoryRequestConsumer(fill_level), MemoryRequestProducer(ll), NAME(v1), NUM_SET(v2), NUM_WAY(v3), NUM_SKEWS(skews),
        WQ_SIZE(v5), RQ_SIZE(v6), PQ_SIZE(v7), MSHR_SIZE(v8), HIT_LATENCY(hit_lat), FILL_LATENCY(fill_lat), OFFSET_BITS(offset_bits), MAX_READ(max_read),
        MAX_WRITE(max_write), prefetch_as_load(pref_load), match_offset_bits(wq_full_addr), virtual_prefetch(va_pref), pref_activate_mask(pref_act_mask),
        repl_type(repl), pref_type(pref)
  {
    for (int i = 0; i < NUM_SKEWS; i++) {
      keys[i].first = ((long long)rand() << 32) | rand();
      keys[i].second = ((long long)rand() << 32) | rand();
    }
  }
};

#endif
