#include "mirage_cache.h"

#include <algorithm>
#include <iterator>

#include "champsim.h"
#include "champsim_constants.h"
#include "prince_ref.h"
#include "util.h"
#include "vmem.h"

#ifndef SANITY_CHECK
#define NDEBUG
#endif

extern VirtualMemory vmem;
extern uint8_t warmup_complete[NUM_CPUS];

void MIRAGE_CACHE::handle_fill()
{
  while (writes_available_this_cycle > 0) {
    auto fill_mshr = MSHR.begin();
    if (fill_mshr == std::end(MSHR) || fill_mshr->event_cycle > current_cycle)
      return;

    // find victim
    int32_t max_invalid = -1;
    uint32_t skew = UINT32_MAX;
    for (uint32_t i = 0; i < NUM_SKEWS; i++) {
      uint32_t set = get_set(fill_mshr->address, keys[i]);
      auto set_begin = std::next(std::begin(block[i]), set * NUM_WAY);
      auto set_end = std::next(set_begin, NUM_WAY);
      auto count = std::count_if(set_begin, set_end, [](MIRAGE_TAG& tag) { return !tag.valid; });
      if (count > max_invalid) {
        max_invalid = count;
        skew = i;
      }
    }

    assert(skew != UINT32_MAX);
    uint32_t set = get_set(fill_mshr->address, keys[skew]);

    auto set_begin = std::next(std::begin(block[skew]), set * NUM_WAY);
    auto set_end = std::next(set_begin, NUM_WAY);
    auto first_inv = std::find_if_not(set_begin, set_end, is_valid<BLOCK>());
    uint32_t way = std::distance(set_begin, first_inv);

    // Should never be true for mirage cache
    if (way == NUM_WAY){
      std::cout << "\n\nOOPS!! SET ASSOCIATIVE EVICTION\n" << endl;
      way = impl_replacement_find_victim(fill_mshr->cpu, fill_mshr->instr_id, set, &block[skew].data()[set * NUM_WAY], fill_mshr->ip, fill_mshr->address,
                                         fill_mshr->type);
    }

    bool success = filllike_miss(skew, set, way, *fill_mshr);
    if (!success)
      return;

    if (way != NUM_WAY) {
      // update processed packets
      fill_mshr->data = block[skew][set * NUM_WAY + way].data;

      for (auto ret : fill_mshr->to_return)
        ret->return_data(&(*fill_mshr));
    }

    MSHR.erase(fill_mshr);
    writes_available_this_cycle--;
  }
}

bool MIRAGE_CACHE::cuckoo_relocate(int height, tag_addr t){
  if(!height)return false;
  auto addr = block[t.skew][t.set * NUM_WAY + t.way].address;
  std::vector<tag_addr> candidates;

  int32_t max_invalid = -1;
  uint32_t skew = UINT32_MAX;
  for (uint32_t i = 0; i < NUM_SKEWS; i++) {
    uint32_t set = get_set(addr, keys[i]);
    for(int j = 0; j < NUM_WAY; j++){
      if(tag_addr(i, set, j) != t){
        candidates.emplace_back(i, set, j);
      }
    }
    auto set_begin = std::next(std::begin(block[i]), set * NUM_WAY);
    auto set_end = std::next(set_begin, NUM_WAY);
    auto count = std::count_if(set_begin, set_end, [](MIRAGE_TAG& tag) { return !tag.valid; });
    if (count > max_invalid) {
      max_invalid = count;
      skew = i;
    }
  }
  assert(skew != UINT32_MAX);
  if(max_invalid == 0){
    int n = candidates.size();
    int idx = gen() % n;
    tag_addr tmp = candidates[idx];
    bool success = cuckoo_relocate(height-1, tmp);
    if(!success)
      return false;
    block[tmp.skew][tmp.set * NUM_WAY + tmp.way] = block[t.skew][t.set * NUM_WAY + t.way];
    auto &data_entry = datastore[block[tmp.skew][tmp.set * NUM_WAY + tmp.way].data_ptr];
    data_entry.skew = tmp.skew;
    data_entry.set = tmp.set;
    data_entry.way = tmp.way;
  } else {
    uint32_t set = get_set(addr, keys[t.skew]);

    auto set_begin = std::next(std::begin(block[t.skew]), set * NUM_WAY);
    auto set_end = std::next(set_begin, NUM_WAY);
    auto first_inv = std::find_if_not(set_begin, set_end, is_valid<BLOCK>());
    uint32_t way = std::distance(set_begin, first_inv);
    assert(way != NUM_WAY);

    block[skew][set * NUM_WAY + way] = block[t.skew][t.set * NUM_WAY + t.way];
    auto &data_entry = datastore[block[skew][set * NUM_WAY + way].data_ptr];
    data_entry.skew = skew;
    data_entry.set = set;
    data_entry.way = way;
  }
  return true;
}

void MIRAGE_CACHE::handle_writeback()
{
  while (writes_available_this_cycle > 0) {
    if (!WQ.has_ready())
      return;

    // handle the oldest entry
    PACKET& handle_pkt = WQ.front();

    // access cache
    bool hit = false;
    for (uint32_t skew = 0; skew < NUM_SKEWS; skew++) {
      uint32_t set = get_set(handle_pkt.address, keys[skew]);
      uint32_t way = get_way(handle_pkt.address, skew, set);
      BLOCK& fill_block = block[skew][set * NUM_WAY + way];

      if (way < NUM_WAY) // HIT
      {
        hit = true;
        impl_replacement_update_state(handle_pkt.cpu, set, way, fill_block.address, handle_pkt.ip, 0, handle_pkt.type, 1);

        // COLLECT STATS
        sim_hit[handle_pkt.cpu][handle_pkt.type]++;
        sim_access[handle_pkt.cpu][handle_pkt.type]++;

        // mark dirty
        fill_block.dirty = 1;
        break;
      }
    }
    if (!hit) // MISS
    {
      bool success;
      if (handle_pkt.type == RFO && handle_pkt.to_return.empty()) {
        success = readlike_miss(handle_pkt);
      } else {
        // find victim
        int32_t max_invalid = -1;
        uint32_t skew = UINT32_MAX;
        for (uint32_t i = 0; i < NUM_SKEWS; i++) {
          uint32_t set = get_set(handle_pkt.address, keys[i]);
          auto set_begin = std::next(std::begin(block[i]), set * NUM_WAY);
          auto set_end = std::next(set_begin, NUM_WAY);
          auto count = std::count_if(set_begin, set_end, [](MIRAGE_TAG& tag) { return !tag.valid; });
          if (count > max_invalid) {
            max_invalid = count;
            skew = i;
          }
        }
        assert(skew != UINT32_MAX);
        uint32_t set = get_set(handle_pkt.address, keys[skew]);

        auto set_begin = std::next(std::begin(block[skew]), set * NUM_WAY);
        auto set_end = std::next(set_begin, NUM_WAY);
        auto first_inv = std::find_if_not(set_begin, set_end, is_valid<BLOCK>());
        uint32_t way = std::distance(set_begin, first_inv);

        // Should never be true for mirage cache
        if (way == NUM_WAY){
          skew = cuckoo_relocate(MAX_HEIGHT, handle_pkt.address);
          if(skew == -1){
            std::cout << "\n\nOOPS!! SET ASSOCIATIVE EVICTION\n" << endl;
            way = impl_replacement_find_victim(handle_pkt.cpu, handle_pkt.instr_id, set, &block[skew].data()[set * NUM_WAY], handle_pkt.ip, handle_pkt.address,
                                             handle_pkt.type);
          }
        }

        success = filllike_miss(skew, set, way, handle_pkt);
      }

      if (!success)
        return;
    }

    // remove this entry from WQ
    writes_available_this_cycle--;
    WQ.pop_front();
  }
}

void MIRAGE_CACHE::handle_read()
{
  while (reads_available_this_cycle > 0) {

    if (!RQ.has_ready())
      return;

    // handle the oldest entry
    PACKET& handle_pkt = RQ.front();

    // A (hopefully temporary) hack to know whether to send the evicted paddr or
    // vaddr to the prefetcher
    ever_seen_data |= (handle_pkt.v_address != handle_pkt.ip);

    bool hit = false;
    for (uint32_t skew = 0; skew < NUM_SKEWS; skew++) {
      uint32_t set = get_set(handle_pkt.address, keys[skew]);
      uint32_t way = get_way(handle_pkt.address, skew, set);
      if (way < NUM_WAY) {
        hit = true;
        readlike_hit(skew, set, way, handle_pkt);
        break;
      }
    }

    if (!hit) {
      bool success = readlike_miss(handle_pkt);
      if (!success)
        return;
    }

    // remove this entry from RQ
    RQ.pop_front();
    reads_available_this_cycle--;
  }
}

void MIRAGE_CACHE::handle_prefetch()
{
  while (reads_available_this_cycle > 0) {
    if (!PQ.has_ready())
      return;

    // handle the oldest entry
    PACKET& handle_pkt = PQ.front();

    bool hit = false;
    for (uint32_t skew = 0; skew < NUM_SKEWS; skew++) {
      uint32_t set = get_set(handle_pkt.address, keys[skew]);
      uint32_t way = get_way(handle_pkt.address, skew, set);
      if (way < NUM_WAY) {
        hit = true;
        readlike_hit(skew, set, way, handle_pkt);
        break;
      }
    }

    if (!hit) {
      bool success = readlike_miss(handle_pkt);
      if (!success)
        return;
    }

    // remove this entry from PQ
    PQ.pop_front();
    reads_available_this_cycle--;
  }
}

void MIRAGE_CACHE::readlike_hit(std::size_t skew, std::size_t set, std::size_t way, PACKET& handle_pkt)
{
  DP(if (warmup_complete[handle_pkt.cpu]) {
    std::cout << "[" << NAME << "] " << __func__ << " hit";
    std::cout << " instr_id: " << handle_pkt.instr_id << " address: " << std::hex << (handle_pkt.address >> OFFSET_BITS);
    std::cout << " full_addr: " << handle_pkt.address;
    std::cout << " full_v_addr: " << handle_pkt.v_address << std::dec;
    std::cout << " type: " << +handle_pkt.type;
    std::cout << " cycle: " << current_cycle << std::endl;
  });

  BLOCK& hit_block = block[skew][set * NUM_WAY + way];

  handle_pkt.data = hit_block.data;

  // update prefetcher on load instruction
  if (should_activate_prefetcher(handle_pkt.type) && handle_pkt.pf_origin_level < fill_level) {
    cpu = handle_pkt.cpu;
    uint64_t pf_base_addr = (virtual_prefetch ? handle_pkt.v_address : handle_pkt.address) & ~bitmask(match_offset_bits ? 0 : OFFSET_BITS);
    handle_pkt.pf_metadata = impl_prefetcher_cache_operate(pf_base_addr, handle_pkt.ip, 1, handle_pkt.type, handle_pkt.pf_metadata);
  }

  // update replacement policy
  impl_replacement_update_state(handle_pkt.cpu, set, way, hit_block.address, handle_pkt.ip, 0, handle_pkt.type, 1);

  // COLLECT STATS
  sim_hit[handle_pkt.cpu][handle_pkt.type]++;
  sim_access[handle_pkt.cpu][handle_pkt.type]++;

  for (auto ret : handle_pkt.to_return)
    ret->return_data(&handle_pkt);

  // update prefetch stats and reset prefetch bit
  if (hit_block.prefetch) {
    pf_useful++;
    hit_block.prefetch = 0;
  }
}

bool MIRAGE_CACHE::readlike_miss(PACKET& handle_pkt)
{
  DP(if (warmup_complete[handle_pkt.cpu]) {
    std::cout << "[" << NAME << "] " << __func__ << " miss";
    std::cout << " instr_id: " << handle_pkt.instr_id << " address: " << std::hex << (handle_pkt.address >> OFFSET_BITS);
    std::cout << " full_addr: " << handle_pkt.address;
    std::cout << " full_v_addr: " << handle_pkt.v_address << std::dec;
    std::cout << " type: " << +handle_pkt.type;
    std::cout << " cycle: " << current_cycle << std::endl;
  });

  // check mshr
  auto mshr_entry = std::find_if(MSHR.begin(), MSHR.end(), eq_addr<PACKET>(handle_pkt.address, OFFSET_BITS));
  bool mshr_full = (MSHR.size() == MSHR_SIZE);

  if (mshr_entry != MSHR.end()) // miss already inflight
  {
    // update fill location
    mshr_entry->fill_level = std::min(mshr_entry->fill_level, handle_pkt.fill_level);

    packet_dep_merge(mshr_entry->lq_index_depend_on_me, handle_pkt.lq_index_depend_on_me);
    packet_dep_merge(mshr_entry->sq_index_depend_on_me, handle_pkt.sq_index_depend_on_me);
    packet_dep_merge(mshr_entry->instr_depend_on_me, handle_pkt.instr_depend_on_me);
    packet_dep_merge(mshr_entry->to_return, handle_pkt.to_return);

    if (mshr_entry->type == PREFETCH && handle_pkt.type != PREFETCH) {
      // Mark the prefetch as useful
      if (mshr_entry->pf_origin_level == fill_level)
        pf_useful++;

      uint64_t prior_event_cycle = mshr_entry->event_cycle;
      *mshr_entry = handle_pkt;

      // in case request is already returned, we should keep event_cycle
      mshr_entry->event_cycle = prior_event_cycle;
    }
  } else {
    if (mshr_full)  // not enough MSHR resource
      return false; // TODO should we allow prefetches anyway if they will not
                    // be filled to this level?

    bool is_read = prefetch_as_load || (handle_pkt.type != PREFETCH);

    // check to make sure the lower level queue has room for this read miss
    int queue_type = (is_read) ? 1 : 3;
    if (lower_level->get_occupancy(queue_type, handle_pkt.address) == lower_level->get_size(queue_type, handle_pkt.address))
      return false;

    // Allocate an MSHR
    if (handle_pkt.fill_level <= fill_level) {
      auto it = MSHR.insert(std::end(MSHR), handle_pkt);
      it->cycle_enqueued = current_cycle;
      it->event_cycle = std::numeric_limits<uint64_t>::max();
    }

    if (handle_pkt.fill_level <= fill_level)
      handle_pkt.to_return = {this};
    else
      handle_pkt.to_return.clear();

    if (!is_read)
      lower_level->add_pq(&handle_pkt);
    else
      lower_level->add_rq(&handle_pkt);
  }

  // update prefetcher on load instructions and prefetches from upper levels
  if (should_activate_prefetcher(handle_pkt.type) && handle_pkt.pf_origin_level < fill_level) {
    cpu = handle_pkt.cpu;
    uint64_t pf_base_addr = (virtual_prefetch ? handle_pkt.v_address : handle_pkt.address) & ~bitmask(match_offset_bits ? 0 : OFFSET_BITS);
    handle_pkt.pf_metadata = impl_prefetcher_cache_operate(pf_base_addr, handle_pkt.ip, 0, handle_pkt.type, handle_pkt.pf_metadata);
  }

  return true;
}

bool MIRAGE_CACHE::filllike_miss(std::size_t skew, std::size_t set, std::size_t way, PACKET& handle_pkt)
{
  DP(if (warmup_complete[handle_pkt.cpu]){
    std::cout << "[" << NAME << "] " << __func__ << " miss";
    std::cout << " instr_id: " << handle_pkt.instr_id << " address: " << std::hex << (handle_pkt.address >> OFFSET_BITS);
    std::cout << " full_addr: " << handle_pkt.address;
    std::cout << " full_v_addr: " << handle_pkt.v_address << std::dec;
    std::cout << " type: " << +handle_pkt.type;
    std::cout << " cycle: " << current_cycle << std::endl;
  });

  bool bypass = (way == NUM_WAY) ;
#ifndef LLC_BYPASS
  assert(!bypass);
#endif
  assert(handle_pkt.type != WRITEBACK || !bypass);

  MIRAGE_TAG& fill_block = block[skew][set * NUM_WAY + way];
  bool evicting_global = is_datastore_full() && !fill_block.valid;
  bool evicting_dirty = !bypass && (lower_level != NULL) && fill_block.dirty;
  uint64_t evicting_address = 0;
  uint64_t datastore_fwdptr = fill_block.data_ptr;

  if (!bypass) {
    if (fill_block.valid) {
      if (evicting_dirty) {
        PACKET writeback_packet;
        writeback_packet.fill_level = lower_level->fill_level;
        writeback_packet.cpu = handle_pkt.cpu;
        writeback_packet.address = fill_block.address;
        writeback_packet.data = fill_block.data;
        writeback_packet.instr_id = handle_pkt.instr_id;
        writeback_packet.ip = 0;
        writeback_packet.type = WRITEBACK;
        datastore_fwdptr = fill_block.data_ptr; // Get datastore ptr of evicted
        datastore[datastore_fwdptr].valid = 0;  // Set datastore invalid
        datastore_fill_level--;                 // Decrement datastore fill level
        auto result = lower_level->add_wq(&writeback_packet);
        if (result == -2)
          return false;
      }
    } else {
      datastore_fwdptr = datastore_find_victim();
      if (evicting_global) {

        datapoint data = datastore[datastore_fwdptr];
        MIRAGE_TAG& global_evict_block = block[data.skew][data.set * NUM_WAY + data.way];
        bool evicting_dirty_global = (lower_level != NULL) && global_evict_block.dirty;
        // datastore_fwdptr = global_evict_block.data_ptr; // Get datastore ptr of evicted
        datastore[datastore_fwdptr].valid = 0; // Set datastore invalid
        datastore_fill_level--;
        global_evict_block.valid = 0;
        global_evict_block.dirty = 0;
        if (evicting_dirty_global) {
          PACKET writeback_packet;

          writeback_packet.fill_level = lower_level->fill_level;
          writeback_packet.cpu = handle_pkt.cpu;
          writeback_packet.address = global_evict_block.address;
          writeback_packet.data = global_evict_block.data;
          writeback_packet.instr_id = handle_pkt.instr_id;
          writeback_packet.ip = 0;
          writeback_packet.type = WRITEBACK;

          auto result = lower_level->add_wq(&writeback_packet);
          if (result == -2)
            return false;
        }
      }
    }
  }
  // HAS TO DO WITH PREFETCHER
  if (ever_seen_data)
    evicting_address = fill_block.address & ~bitmask(match_offset_bits ? 0 : OFFSET_BITS);
  else
    evicting_address = fill_block.v_address & ~bitmask(match_offset_bits ? 0 : OFFSET_BITS);

  if (fill_block.prefetch)
    pf_useless++;

  if (handle_pkt.type == PREFETCH)
    pf_fill++;

  datapoint &data = datastore[datastore_fwdptr];
  fill_block.valid = true;
  fill_block.prefetch = (handle_pkt.type == PREFETCH && handle_pkt.pf_origin_level == fill_level);
  fill_block.dirty = (handle_pkt.type == WRITEBACK || (handle_pkt.type == RFO && handle_pkt.to_return.empty()));
  fill_block.address = handle_pkt.address;
  fill_block.v_address = handle_pkt.v_address;
  fill_block.data = handle_pkt.data;
  fill_block.ip = handle_pkt.ip;
  fill_block.cpu = handle_pkt.cpu;
  fill_block.instr_id = handle_pkt.instr_id;
  fill_block.data_ptr = datastore_fwdptr;
  data.valid = 1;
  data.skew = skew;
  data.set = set;
  data.way = way;
  datastore_fill_level++;

  if (warmup_complete[handle_pkt.cpu] && (handle_pkt.cycle_enqueued != 0))
    total_miss_latency += current_cycle - handle_pkt.cycle_enqueued;

  // update prefetcher
  cpu = handle_pkt.cpu;
  handle_pkt.pf_metadata =
      impl_prefetcher_cache_fill((virtual_prefetch ? handle_pkt.v_address : handle_pkt.address) & ~bitmask(match_offset_bits ? 0 : OFFSET_BITS), set, way,
                                handle_pkt.type == PREFETCH, evicting_address, handle_pkt.pf_metadata);

  // update replacement policy
  impl_replacement_update_state(handle_pkt.cpu, set, way, handle_pkt.address, handle_pkt.ip, 0, handle_pkt.type, 0);

  // COLLECT STATS
  sim_miss[handle_pkt.cpu][handle_pkt.type]++;
  sim_access[handle_pkt.cpu][handle_pkt.type]++;

  return true;
}

bool MIRAGE_CACHE::is_datastore_full(){
  return datastore.size() == datastore_fill_level;
}

uint64_t MIRAGE_CACHE::datastore_find_victim(){
  // std::cout << "Datastore victim" << datastore.size() << std::endl;
  if (!is_datastore_full()) {
    for (uint64_t i = 0; i < datastore.size(); i++) {
      if (!datastore[i].valid)
        return i;
    }
  }
  uint64_t victim = gen() % datastore.size();
  return victim;
}

void MIRAGE_CACHE::operate()
{
  operate_writes();
  operate_reads();

  impl_prefetcher_cycle_operate();
}

void MIRAGE_CACHE::operate_writes()
{
  // perform all writes
  writes_available_this_cycle = MAX_WRITE;
  handle_fill();
  handle_writeback();

  WQ.operate();
}

void MIRAGE_CACHE::operate_reads()
{
  // perform all reads
  reads_available_this_cycle = MAX_READ;
  handle_read();
  va_translate_prefetches();
  handle_prefetch();

  RQ.operate();
  PQ.operate();
  VAPQ.operate();
}

uint32_t MIRAGE_CACHE::get_set(uint64_t address, std::pair<uint64_t, uint64_t> key)
{
  uint64_t hashed_address = prince_enc_dec_uint64(address, key.first, key.second, 0);
  return ((hashed_address >> OFFSET_BITS) & bitmask(lg2(NUM_SET)));
}

uint32_t MIRAGE_CACHE::get_way(uint64_t address, std::size_t skew, uint32_t set)
{
  auto begin = std::next(block[skew].begin(), set * NUM_WAY);
  auto end = std::next(begin, NUM_WAY);
  return std::distance(begin, std::find_if(begin, end, eq_addr<BLOCK>(address, OFFSET_BITS)));
}

int MIRAGE_CACHE::invalidate_entry(uint64_t inval_addr, std::size_t skew)
{
  uint32_t set = get_set(inval_addr, keys[skew]);
  uint32_t way = get_way(inval_addr, skew, set);

  if (way < NUM_WAY)
    block[skew][set * NUM_WAY + way].valid = 0;

  return way;
}

int MIRAGE_CACHE::add_rq(PACKET* packet)
{
  assert(packet->address != 0);
  RQ_ACCESS++;

  DP(if (warmup_complete[packet->cpu]) {
    std::cout << "[" << NAME << "_RQ] " << __func__ << " instr_id: " << packet->instr_id << " address: " << std::hex << (packet->address >> OFFSET_BITS);
    std::cout << " full_addr: " << packet->address << " v_address: " << packet->v_address << std::dec << " type: " << +packet->type
              << " occupancy: " << RQ.occupancy();
  })

  // check for the latest writebacks in the write queue
  champsim::delay_queue<PACKET>::iterator found_wq = std::find_if(WQ.begin(), WQ.end(), eq_addr<PACKET>(packet->address, match_offset_bits ? 0 : OFFSET_BITS));

  if (found_wq != WQ.end()) {

    DP(if (warmup_complete[packet->cpu]) std::cout << " MERGED_WQ" << std::endl;)

    packet->data = found_wq->data;
    for (auto ret : packet->to_return)
      ret->return_data(packet);

    WQ_FORWARD++;
    return -1;
  }

  // check for duplicates in the read queue
  auto found_rq = std::find_if(RQ.begin(), RQ.end(), eq_addr<PACKET>(packet->address, OFFSET_BITS));
  if (found_rq != RQ.end()) {

    DP(if (warmup_complete[packet->cpu]) std::cout << " MERGED_RQ" << std::endl;)

    packet_dep_merge(found_rq->lq_index_depend_on_me, packet->lq_index_depend_on_me);
    packet_dep_merge(found_rq->sq_index_depend_on_me, packet->sq_index_depend_on_me);
    packet_dep_merge(found_rq->instr_depend_on_me, packet->instr_depend_on_me);
    packet_dep_merge(found_rq->to_return, packet->to_return);

    RQ_MERGED++;

    return 0; // merged index
  }

  // check occupancy
  if (RQ.full()) {
    RQ_FULL++;

    DP(if (warmup_complete[packet->cpu]) std::cout << " FULL" << std::endl;)

    return -2; // cannot handle this request
  }

  // if there is no duplicate, add it to RQ
  if (warmup_complete[cpu])
    RQ.push_back(*packet);
  else
    RQ.push_back_ready(*packet);

  DP(if (warmup_complete[packet->cpu]) std::cout << " ADDED" << std::endl;)

  RQ_TO_CACHE++;
  return RQ.occupancy();
}

int MIRAGE_CACHE::add_wq(PACKET* packet)
{
  WQ_ACCESS++;

  DP(if (warmup_complete[packet->cpu]) {
    std::cout << "[" << NAME << "_WQ] " << __func__ << " instr_id: " << packet->instr_id << " address: " << std::hex << (packet->address >> OFFSET_BITS);
    std::cout << " full_addr: " << packet->address << " v_address: " << packet->v_address << std::dec << " type: " << +packet->type
              << " occupancy: " << RQ.occupancy();
  })

  // check for duplicates in the write queue
  champsim::delay_queue<PACKET>::iterator found_wq = std::find_if(WQ.begin(), WQ.end(), eq_addr<PACKET>(packet->address, match_offset_bits ? 0 : OFFSET_BITS));

  if (found_wq != WQ.end()) {

    DP(if (warmup_complete[packet->cpu]) std::cout << " MERGED" << std::endl;)

    WQ_MERGED++;
    return 0; // merged index
  }

  // Check for room in the queue
  if (WQ.full()) {
    DP(if (warmup_complete[packet->cpu]) std::cout << " FULL" << std::endl;)

    ++WQ_FULL;
    return -2;
  }

  // if there is no duplicate, add it to the write queue
  if (warmup_complete[cpu])
    WQ.push_back(*packet);
  else
    WQ.push_back_ready(*packet);

  DP(if (warmup_complete[packet->cpu]) std::cout << " ADDED" << std::endl;)

  WQ_TO_CACHE++;
  WQ_ACCESS++;

  return WQ.occupancy();
}

int MIRAGE_CACHE::prefetch_line(uint64_t pf_addr, bool fill_this_level, uint32_t prefetch_metadata)
{
  pf_requested++;

  PACKET pf_packet;
  pf_packet.type = PREFETCH;
  pf_packet.fill_level = (fill_this_level ? fill_level : lower_level->fill_level);
  pf_packet.pf_origin_level = fill_level;
  pf_packet.pf_metadata = prefetch_metadata;
  pf_packet.cpu = cpu;
  pf_packet.address = pf_addr;
  pf_packet.v_address = virtual_prefetch ? pf_addr : 0;

  if (virtual_prefetch) {
    if (!VAPQ.full()) {
      VAPQ.push_back(pf_packet);
      return 1;
    }
  } else {
    int result = add_pq(&pf_packet);
    if (result != -2) {
      if (result > 0)
        pf_issued++;
      return 1;
    }
  }

  return 0;
}

int MIRAGE_CACHE::prefetch_line(uint64_t ip, uint64_t base_addr, uint64_t pf_addr, bool fill_this_level, uint32_t prefetch_metadata)
{
  static bool deprecate_printed = false;
  if (!deprecate_printed) {
    std::cout << "WARNING: The extended signature MIRAGE_CACHE::prefetch_line(ip, "
                 "base_addr, pf_addr, fill_this_level, prefetch_metadata) is "
                 "deprecated."
              << std::endl;
    std::cout << "WARNING: Use MIRAGE_CACHE::prefetch_line(pf_addr, fill_this_level, "
                 "prefetch_metadata) instead."
              << std::endl;
    deprecate_printed = true;
  }
  return prefetch_line(pf_addr, fill_this_level, prefetch_metadata);
}

void MIRAGE_CACHE::va_translate_prefetches()
{
  // TEMPORARY SOLUTION: mark prefetches as translated after a fixed latency
  if (VAPQ.has_ready()) {
    VAPQ.front().address = vmem.va_to_pa(cpu, VAPQ.front().v_address).first;

    // move the translated prefetch over to the regular PQ
    int result = add_pq(&VAPQ.front());

    // remove the prefetch from the VAPQ
    if (result != -2)
      VAPQ.pop_front();

    if (result > 0)
      pf_issued++;
  }
}

int MIRAGE_CACHE::add_pq(PACKET* packet)
{
  assert(packet->address != 0);
  PQ_ACCESS++;

  DP(if (warmup_complete[packet->cpu]) {
    std::cout << "[" << NAME << "_WQ] " << __func__ << " instr_id: " << packet->instr_id << " address: " << std::hex << (packet->address >> OFFSET_BITS);
    std::cout << " full_addr: " << packet->address << " v_address: " << packet->v_address << std::dec << " type: " << +packet->type
              << " occupancy: " << RQ.occupancy();
  })

  // check for the latest wirtebacks in the write queue
  champsim::delay_queue<PACKET>::iterator found_wq = std::find_if(WQ.begin(), WQ.end(), eq_addr<PACKET>(packet->address, match_offset_bits ? 0 : OFFSET_BITS));

  if (found_wq != WQ.end()) {

    DP(if (warmup_complete[packet->cpu]) std::cout << " MERGED_WQ" << std::endl;)

    packet->data = found_wq->data;
    for (auto ret : packet->to_return)
      ret->return_data(packet);

    WQ_FORWARD++;
    return -1;
  }

  // check for duplicates in the PQ
  auto found = std::find_if(PQ.begin(), PQ.end(), eq_addr<PACKET>(packet->address, OFFSET_BITS));
  if (found != PQ.end()) {
    DP(if (warmup_complete[packet->cpu]) std::cout << " MERGED_PQ" << std::endl;)

    found->fill_level = std::min(found->fill_level, packet->fill_level);
    packet_dep_merge(found->to_return, packet->to_return);

    PQ_MERGED++;
    return 0;
  }

  // check occupancy
  if (PQ.full()) {

    DP(if (warmup_complete[packet->cpu]) std::cout << " FULL" << std::endl;)

    PQ_FULL++;
    return -2; // cannot handle this request
  }

  // if there is no duplicate, add it to PQ
  if (warmup_complete[cpu])
    PQ.push_back(*packet);
  else
    PQ.push_back_ready(*packet);

  DP(if (warmup_complete[packet->cpu]) std::cout << " ADDED" << std::endl;)

  PQ_TO_CACHE++;
  return PQ.occupancy();
}

void MIRAGE_CACHE::return_data(PACKET* packet)
{
  // check MSHR information
  auto mshr_entry = std::find_if(MSHR.begin(), MSHR.end(), eq_addr<PACKET>(packet->address, OFFSET_BITS));
  auto first_unreturned = std::find_if(MSHR.begin(), MSHR.end(), [](auto x) { return x.event_cycle == std::numeric_limits<uint64_t>::max(); });

  // sanity check
  if (mshr_entry == MSHR.end()) {
    std::cerr << "[" << NAME << "_MSHR] " << __func__ << " instr_id: " << packet->instr_id << " cannot find a matching entry!";
    std::cerr << " address: " << std::hex << packet->address;
    std::cerr << " v_address: " << packet->v_address;
    std::cerr << " address: " << (packet->address >> OFFSET_BITS) << std::dec;
    std::cerr << " event: " << packet->event_cycle << " current: " << current_cycle << std::endl;
    assert(0);
  }

  // MSHR holds the most updated information about this request
  mshr_entry->data = packet->data;
  mshr_entry->pf_metadata = packet->pf_metadata;
  mshr_entry->event_cycle = current_cycle + (warmup_complete[cpu] ? FILL_LATENCY : 0);

  DP(if (warmup_complete[packet->cpu]) {
    std::cout << "[" << NAME << "_MSHR] " << __func__ << " instr_id: " << mshr_entry->instr_id;
    std::cout << " address: " << std::hex << (mshr_entry->address >> OFFSET_BITS) << " full_addr: " << mshr_entry->address;
    std::cout << " data: " << mshr_entry->data << std::dec;
    std::cout << " index: " << std::distance(MSHR.begin(), mshr_entry) << " occupancy: " << get_occupancy(0, 0);
    std::cout << " event: " << mshr_entry->event_cycle << " current: " << current_cycle << std::endl;
  });

  // Order this entry after previously-returned entries, but before non-returned
  // entries
  std::iter_swap(mshr_entry, first_unreturned);
}

uint32_t MIRAGE_CACHE::get_occupancy(uint8_t queue_type, uint64_t address)
{
  if (queue_type == 0)
    return std::count_if(MSHR.begin(), MSHR.end(), is_valid<PACKET>());
  else if (queue_type == 1)
    return RQ.occupancy();
  else if (queue_type == 2)
    return WQ.occupancy();
  else if (queue_type == 3)
    return PQ.occupancy();

  return 0;
}

uint32_t MIRAGE_CACHE::get_size(uint8_t queue_type, uint64_t address)
{
  if (queue_type == 0)
    return MSHR_SIZE;
  else if (queue_type == 1)
    return RQ.size();
  else if (queue_type == 2)
    return WQ.size();
  else if (queue_type == 3)
    return PQ.size();

  return 0;
}

bool MIRAGE_CACHE::should_activate_prefetcher(int type) { return (1 << static_cast<int>(type)) & pref_activate_mask; }

void MIRAGE_CACHE::print_deadlock()
{
  if (!std::empty(MSHR)) {
    std::cout << NAME << " MSHR Entry" << std::endl;
    std::size_t j = 0;
    for (PACKET entry : MSHR) {
      std::cout << "[" << NAME << " MSHR] entry: " << j++ << " instr_id: " << entry.instr_id;
      std::cout << " address: " << std::hex << (entry.address >> LOG2_BLOCK_SIZE) << " full_addr: " << entry.address << std::dec << " type: " << +entry.type;
      std::cout << " fill_level: " << +entry.fill_level << " event_cycle: " << entry.event_cycle << std::endl;
    }
  } else {
    std::cout << NAME << " MSHR empty" << std::endl;
  }
}
