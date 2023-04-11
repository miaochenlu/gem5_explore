#include "mem/cache/prefetch/spp_ppf.hh"

#include <cassert>
#include <climits>
#include <iostream>

#include "debug/HWPrefetch.hh"
#include "mem/cache/prefetch/associative_set_impl.hh"
#include "params/SPP_PPFPrefetcher.hh"

using namespace std;

namespace gem5
{

GEM5_DEPRECATED_NAMESPACE(Prefetcher, prefetch);
namespace prefetch
{

SPP_PPF::SPP_PPF(const SPP_PPFPrefetcherParams &p)
    : Queued(p),
      stridesPerPatternEntry(p.strides_per_pattern_entry),
      signatureShift(p.signature_shift),
      signatureBits(p.signature_bits),
      prefetchConfidenceThreshold(p.prefetch_confidence_threshold),
      lookaheadConfidenceThreshold(p.lookahead_confidence_threshold),
      signatureTable(p.signature_table_assoc, p.signature_table_entries,
                     p.signature_table_indexing_policy,
                     p.signature_table_replacement_policy),
      patternTable(p.pattern_table_assoc, p.pattern_table_entries,
                   p.pattern_table_indexing_policy,
                   p.pattern_table_replacement_policy,
                   PatternEntry(stridesPerPatternEntry, p.num_counter_bits)),
      globalHistoryRegister(p.global_history_register_entries,
                    p.global_history_register_entries,
                    p.global_history_register_indexing_policy,
                    p.global_history_register_replacement_policy,
                    GlobalHistoryEntry()),
      perceptron(),
      prefetchTable(p.prefetch_table_entries,
                    p.prefetch_table_entries,
                    p.prefetch_table_indexing_policy,
                    p.prefetch_table_replacement_policy,
                    PFTableEntry()),
      rejectTable(p.reject_table_entries,
                    p.reject_table_entries,
                    p.reject_table_indexing_policy,
                    p.reject_table_replacement_policy,
                    PFTableEntry()),
      prefetchFilter(),
      ppfThresholdHigh(p.ppf_threshold_high),
      ppfThresholdLow(p.ppf_threshold_low),
      pc(0), pc1(0), pc2(0), pc3(0)
{
    fatal_if(prefetchConfidenceThreshold < 0,
        "The prefetch confidence threshold must be greater than 0\n");
    fatal_if(prefetchConfidenceThreshold > 1,
        "The prefetch confidence threshold must be less than 1\n");
    fatal_if(lookaheadConfidenceThreshold < 0,
        "The lookahead confidence threshold must be greater than 0\n");
    fatal_if(lookaheadConfidenceThreshold > 1,
        "The lookahead confidence threshold must be less than 1\n");
    perceptron.pSPP = this;
    prefetchFilter.pGHR = &globalHistoryRegister;
    prefetchFilter.pPerceptron = &perceptron;
    prefetchFilter.pPrefetchTable = &prefetchTable;
    prefetchFilter.pRejectTable = &rejectTable;
    prefetchFilter.pSPP = this;
}

SPP_PPF::PatternStrideEntry &
SPP_PPF::PatternEntry::getStrideEntry(stride_t stride)
{
    PatternStrideEntry *pstride_entry = findStride(stride);
    if (pstride_entry == nullptr) {
        // Specific replacement algorithm for this table,
        // pick the entry with the lowest counter value,
        // then decrease the counter of all entries

        // If all counters have the max value, this will be the pick
        PatternStrideEntry *victim_pstride_entry = &(strideEntries[0]);

        unsigned long current_counter = ULONG_MAX;
        for (auto &entry : strideEntries) {
            if (entry.counter < current_counter) {
                victim_pstride_entry = &entry;
                current_counter = entry.counter;
            }
            entry.counter--;
        }
        pstride_entry = victim_pstride_entry;
        pstride_entry->counter.reset();
        pstride_entry->stride = stride;
    }
    return *pstride_entry;
}

void
SPP_PPF::addPPFPrefetch(Addr request_addr, stride_t last_block,
    stride_t train_delta, stride_t delta, double path_confidence,
    signature_t cur_sig, uint32_t depth, bool is_secure,
    std::vector<AddrPriority> &addresses)
{
    stride_t block = last_block + delta;
    Addr ppn = request_addr / pageBytes;

    Addr pf_ppn;
    stride_t pf_block;
    if (block < 0) {
        stride_t num_cross_pages = 1 + (-block) / (pageBytes/blkSize);
        if (num_cross_pages > ppn) {
            // target address smaller than page 0, ignore this request;
            return;
        }
        pf_ppn = ppn - num_cross_pages;
        pf_block = block + (pageBytes/blkSize) * num_cross_pages;
        handlePageCrossingLookahead(cur_sig, last_block, delta,
                                    path_confidence);
    } else if (block >= (pageBytes/blkSize)) {
        stride_t num_cross_pages = block / (pageBytes/blkSize);
        if (MaxAddr/pageBytes < (ppn + num_cross_pages)) {
            // target address goes beyond MaxAddr, ignore this request;
            return;
        }
        pf_ppn = ppn + num_cross_pages;
        pf_block = block - (pageBytes/blkSize) * num_cross_pages;
        handlePageCrossingLookahead(cur_sig, last_block, delta,
                                    path_confidence);
    } else {
        pf_ppn = ppn;
        pf_block = block;
    }

    Addr new_addr = pf_ppn * pageBytes;
    new_addr += pf_block * (Addr)blkSize;

    int32_t percSum = perceptron.percPredict(
        request_addr, pc, pc1, pc2, pc3,
        train_delta + delta, cur_sig, path_confidence * 100, depth
    );

// std::cout << "Debug: percSum = " << percSum << " fillL2: "
        // << (percSum >= ppfThresholdHigh) << std::endl;
    bool fillL2 = (percSum >= ppfThresholdHigh) ? 1 : 0;

    if (fillL2) {
        bool canPrefetch = prefetchFilter.check(
            new_addr, request_addr, pc, SPP_L2C_PREFETCH,
            train_delta + delta, cur_sig, path_confidence * 100,
            percSum, depth
        );

        if (canPrefetch) {
            DPRINTF(HWPrefetch,
                "Queuing prefetch to %#x.\n", new_addr);
            addresses.push_back(AddrPriority(new_addr, 0));
        }

    }

    if (percSum < ppfThresholdHigh) {
        prefetchFilter.check(
            new_addr, request_addr, pc, SPP_PERC_REJECT,
            train_delta + delta, cur_sig, path_confidence * 100,
            percSum, depth
        );
    }
}

void
SPP_PPF::addPrefetch(Addr ppn, stride_t last_block,
    stride_t delta, double path_confidence, signature_t signature,
    bool is_secure, std::vector<AddrPriority> &addresses)
{
    stride_t block = last_block + delta;

    Addr pf_ppn;
    stride_t pf_block;
    if (block < 0) {
        stride_t num_cross_pages = 1 + (-block) / (pageBytes/blkSize);
        if (num_cross_pages > ppn) {
            // target address smaller than page 0, ignore this request;
            return;
        }
        pf_ppn = ppn - num_cross_pages;
        pf_block = block + (pageBytes/blkSize) * num_cross_pages;
        handlePageCrossingLookahead(signature, last_block, delta,
                                    path_confidence);
    } else if (block >= (pageBytes/blkSize)) {
        stride_t num_cross_pages = block / (pageBytes/blkSize);
        if (MaxAddr/pageBytes < (ppn + num_cross_pages)) {
            // target address goes beyond MaxAddr, ignore this request;
            return;
        }
        pf_ppn = ppn + num_cross_pages;
        pf_block = block - (pageBytes/blkSize) * num_cross_pages;
        handlePageCrossingLookahead(signature, last_block, delta,
                                    path_confidence);
    } else {
        pf_ppn = ppn;
        pf_block = block;
    }

    Addr new_addr = pf_ppn * pageBytes;
    new_addr += pf_block * (Addr)blkSize;

    DPRINTF(HWPrefetch, "Queuing prefetch to %#x.\n", new_addr);
    addresses.push_back(AddrPriority(new_addr, 0));
}

void
SPP_PPF::handleSignatureTableMiss(stride_t current_block,
    signature_t &new_signature, double &new_conf, stride_t &new_stride)
{
    bool found = false;

    // This should return all entries of the GHR, since it is a fully
    // associative table
    std::vector<GlobalHistoryEntry *> all_ghr_entries =
             globalHistoryRegister.getPossibleEntries(0 /* any value works */);

    for (auto gh_entry : all_ghr_entries) {
        if (gh_entry->lastBlock + gh_entry->delta == current_block) {
            new_signature = gh_entry->signature;
            new_conf = gh_entry->confidence;
            new_stride = gh_entry->delta;
            found = true;
            globalHistoryRegister.accessEntry(gh_entry);
            break;
        }
    }
    if (!found) {
        new_signature = current_block;
        new_conf = 1.0;
        new_stride = current_block;
    }
}

void
SPP_PPF::increasePatternEntryCounter(
        PatternEntry &pattern_entry, PatternStrideEntry &pstride_entry)
{
    pstride_entry.counter++;
}

void
SPP_PPF::updatePatternTable(Addr signature, stride_t stride)
{
    assert(stride != 0);
    // The pattern table is indexed by signatures
    PatternEntry &p_entry = getPatternEntry(signature);
    PatternStrideEntry &ps_entry = p_entry.getStrideEntry(stride);
    increasePatternEntryCounter(p_entry, ps_entry);
}

SPP_PPF::SignatureEntry &
SPP_PPF::getSignatureEntry(Addr ppn, bool is_secure,
        stride_t block, bool &miss, stride_t &stride,
        double &initial_confidence)
{
    SignatureEntry* signature_entry = signatureTable.findEntry(ppn, is_secure);
    if (signature_entry != nullptr) {
        signatureTable.accessEntry(signature_entry);
        miss = false;
        stride = block - signature_entry->lastBlock;
    } else {
        signature_entry = signatureTable.findVictim(ppn);
        assert(signature_entry != nullptr);

        // Sets signature_entry->signature, initial_confidence, and stride
        handleSignatureTableMiss(block, signature_entry->signature,
            initial_confidence, stride);

        signatureTable.insertEntry(ppn, is_secure, signature_entry);
        miss = true;
    }
    signature_entry->lastBlock = block;
    return *signature_entry;
}

SPP_PPF::PatternEntry &
SPP_PPF::getPatternEntry(Addr signature)
{
    PatternEntry* pattern_entry = patternTable.findEntry(signature, false);
    if (pattern_entry != nullptr) {
        // Signature found
        patternTable.accessEntry(pattern_entry);
    } else {
        // Signature not found
        pattern_entry = patternTable.findVictim(signature);
        assert(pattern_entry != nullptr);

        patternTable.insertEntry(signature, false, pattern_entry);
    }
    return *pattern_entry;
}

double
SPP_PPF::calculatePrefetchConfidence(PatternEntry const &sig,
        PatternStrideEntry const &entry) const
{
    return entry.counter.calcSaturation();
}

double
SPP_PPF::calculateLookaheadConfidence(PatternEntry const &sig,
        PatternStrideEntry const &lookahead) const
{
    double lookahead_confidence = lookahead.counter.calcSaturation();
    if (lookahead_confidence > 0.95) {
        /**
         * maximum confidence is 0.95, guaranteeing that
         * current confidence will eventually fall beyond
         * the threshold
         */
        lookahead_confidence = 0.95;
    }
    return lookahead_confidence;
}

void
SPP_PPF::calculatePrefetch(const PrefetchInfo &pfi,
                                 std::vector<AddrPriority> &addresses)
{
    Addr request_addr = pfi.getAddr();
    Addr ppn = request_addr / pageBytes;
    stride_t current_block = (request_addr % pageBytes) / blkSize;
    stride_t stride;
    bool is_secure = pfi.isSecure();
    double initial_confidence = 1.0;

    pc3 = pc2;
    pc2 = pc1;
    pc1 = pc;
    pc = pfi.getPC();

    // Get the SignatureEntry of this page to:
    // - compute the current stride
    // - obtain the current signature of accesses
    bool miss;
    SignatureEntry &signature_entry = getSignatureEntry(ppn, is_secure,
            current_block, miss, stride, initial_confidence);

    if (miss) {
        // No history for this page, can't continue
        return;
    }

    if (stride == 0) {
        // Can't continue with a stride 0
        return;
    }

    // Update the confidence of the current signature
    updatePatternTable(signature_entry.signature, stride);

    // Update the current SignatureEntry signature
    signature_entry.signature =
        updateSignature(signature_entry.signature, stride);

    prefetchFilter.check(request_addr, 0, 0, L2C_DEMAND, 0, 0, 0, 0, 0);

    signature_t current_signature = signature_entry.signature;
    double current_confidence = initial_confidence;
    stride_t current_stride = signature_entry.lastBlock;

    uint32_t depth = 0;
    stride_t train_delta = 0, prev_delta = 0;

    // Look for prefetch candidates while the current path confidence is
    // high enough
    while (current_confidence > lookaheadConfidenceThreshold) {
        // With the updated signature, attempt to generate prefetches
        // - search the PatternTable and select all entries with enough
        //   confidence, these are prefetch candidates
        // - select the entry with the highest counter as the "lookahead"
        train_delta = prev_delta;

        PatternEntry *current_pattern_entry =
            patternTable.findEntry(current_signature, false);
        PatternStrideEntry const *lookahead = nullptr;
        if (current_pattern_entry != nullptr) {
            unsigned long max_counter = 0;
            for (auto const &entry : current_pattern_entry->strideEntries) {
                //select the entry with the maximum counter value as lookahead
                if (max_counter < entry.counter) {
                    max_counter = entry.counter;
                    lookahead = &entry;
                }
                double prefetch_confidence =
                    calculatePrefetchConfidence(*current_pattern_entry, entry);

                if (prefetch_confidence >= prefetchConfidenceThreshold) {
                    if (entry.stride != 0) {
                        //prefetch candidate
                        addPPFPrefetch(request_addr, current_stride,
                            train_delta, entry.stride, current_confidence,
                            current_signature, depth, is_secure, addresses);
                    }
                }
            }
        }

        if (lookahead != nullptr) {
            current_confidence *= calculateLookaheadConfidence(
                    *current_pattern_entry, *lookahead);
            current_signature =
                updateSignature(current_signature, lookahead->stride);
            current_stride += lookahead->stride;
            prev_delta += lookahead->stride;
        } else {
            current_confidence = 0.0;
        }

        depth++;
    }

    auxiliaryPrefetcher(ppn, current_block, is_secure, addresses);
}

void
SPP_PPF::auxiliaryPrefetcher(Addr ppn, stride_t current_block,
        bool is_secure, std::vector<AddrPriority> &addresses)
{
    if (addresses.empty()) {
        // Enable the next line prefetcher if no prefetch candidates are found
        addPrefetch(ppn, current_block, 1, 0.0 /* unused*/, 0 /* unused */,
                    is_secure, addresses);
    }
}

void
SPP_PPF::handlePageCrossingLookahead(signature_t signature,
            stride_t last_offset, stride_t delta, double path_confidence)
{
    // Always use the replacement policy to assign new entries, as all
    // of them are unique, there are never "hits" in the GHR
    GlobalHistoryEntry *gh_entry = globalHistoryRegister.findVictim(0);
    assert(gh_entry != nullptr);
    // Any address value works, as it is never used
    globalHistoryRegister.insertEntry(0, false, gh_entry);

    gh_entry->signature = signature;
    gh_entry->lastBlock = last_offset;
    gh_entry->delta = delta;
    gh_entry->confidence = path_confidence;
}

void
SPP_PPF::Perceptron::getPercIndex(Addr baseAddr, uint64_t pc,
            uint64_t pc1, uint64_t pc2, uint64_t pc3,
            stride_t curDelta, signature_t curSig,
            uint32_t confidence, uint32_t depth,
            uint64_t percSet[PERC_FEATURES])
{
    uint64_t cacheLine = baseAddr / pSPP->blkSize;
    uint64_t pageAddr = baseAddr / pSPP->pageBytes;
    int sigDelta = curDelta;
    uint64_t preHash[PERC_FEATURES];

        preHash[0] = baseAddr;
        preHash[1] = cacheLine;
        preHash[2] = pageAddr;
        preHash[3] = confidence ^ pageAddr;
        preHash[4] = curSig ^ sigDelta;
        preHash[5] = pc1 ^ (pc2 >> 1) ^ (pc3 >> 2);
        preHash[6] = pc ^ depth;
        preHash[7] = pc ^ sigDelta;
        preHash[8] = confidence;

        for (int i = 0; i < PERC_FEATURES; i++) {
                percSet[i] = (preHash[i]) % percDepth[i];
        }
}

int32_t
SPP_PPF::Perceptron::percPredict(Addr baseAddr, uint64_t pc,
            uint64_t pc1, uint64_t pc2, uint64_t pc3,
            stride_t curDelta, signature_t curSig,
            uint32_t confidence, uint32_t depth)
{
    uint64_t percSet[PERC_FEATURES];

    getPercIndex(baseAddr, pc, pc1,
        pc2, pc3, curDelta, curSig,
        confidence, depth, percSet);

    // Calculate Sum
    int32_t sum = 0;
        for (int i = 0; i < PERC_FEATURES; i++) {
                sum += percWeights[percSet[i]][i];
        }
    return sum;
}

void
SPP_PPF::Perceptron::percUpdate(PFTableEntry* entry, bool direction)
{
    uint64_t percSet[PERC_FEATURES];
    getPercIndex(entry->address, entry->pc, entry->pc1,
        entry->pc2, entry->pc3, entry->delta, entry->curSignature,
        entry->confidence, entry->depth, percSet);

    int32_t sum = entry->percSum;

    if (!direction) {
        for (int i = 0; i < PERC_FEATURES; i++) {
            if (sum >= pSPP->ppfThresholdHigh) {
                if (percWeights[percSet[i]][i] > -1 * (PERC_COUNTER_MAX + 1)) {
                    percWeights[percSet[i]][i]--;
                }
            }
            if (sum < pSPP->ppfThresholdHigh) {
                if (percWeights[percSet[i]][i] < PERC_COUNTER_MAX) {
                    percWeights[percSet[i]][i]++;
                }
            }
        }
    }

        if (direction && sum > NEG_UPDT_THRESHOLD
                      && sum < POS_UPDT_THRESHOLD) {
        for (int i = 0; i < PERC_FEATURES; i++) {
            if (sum >= pSPP->ppfThresholdHigh) {
                if (percWeights[percSet[i]][i] < PERC_COUNTER_MAX) {
                    percWeights[percSet[i]][i]++;
                }
            }
            if (sum < pSPP->ppfThresholdHigh) {
                if (percWeights[percSet[i]][i] > -1 * (PERC_COUNTER_MAX + 1)) {
                    percWeights[percSet[i]][i]--;
                }
            }
        }
    }
}


bool
SPP_PPF::PrefetchFilter::check(Addr pfAddr, Addr baseAddr,
    uint64_t pc, FILTER_REQUEST filterReq, stride_t curDelta,
    signature_t curSig, uint32_t confidence,
    int32_t sum, uint32_t depth)
{
    //Ten bits of the address are used to index into the tables,
    // and another six bits are stored to perform tag matching.
    uint64_t cacheIndex = pfAddr / pSPP->blkSize;
    PFTableEntry* prefetchEntry = pPrefetchTable->findEntry(cacheIndex, false);
    PFTableEntry* rejectEntry = pRejectTable->findEntry(cacheIndex, false);

    switch(filterReq) {
    case SPP_L2C_PREFETCH:
        if (prefetchEntry) {
            // line already prefetched
            return false;
        } else {
            prefetchEntry = pPrefetchTable->findVictim(cacheIndex);
            assert(prefetchEntry != nullptr);
            prefetchEntry->useful = false;
            prefetchEntry->address = baseAddr;
            // todo
            prefetchEntry->pc = pSPP->pc;
            prefetchEntry->pc1 = pSPP->pc1;
            prefetchEntry->pc2 = pSPP->pc2;
            prefetchEntry->pc3 = pSPP->pc3;
            prefetchEntry->delta = curDelta;
            prefetchEntry->curSignature = curSig;
            prefetchEntry->confidence = confidence;
            prefetchEntry->depth = depth;
            prefetchEntry->percSum = sum;
            pPrefetchTable->insertEntry(cacheIndex, false, prefetchEntry);
        }
        break;
    case SPP_LLC_PREFETCH:
            std::cout << "not handling" << std::endl;
        break;
    case L2C_DEMAND:
        if (prefetchEntry && !prefetchEntry->useful) {
            prefetchEntry->useful = true;
            pPerceptron->percUpdate(prefetchEntry, true);
        }

        if (prefetchEntry == nullptr && rejectEntry) {
            pPerceptron->percUpdate(rejectEntry, false);
            pRejectTable->findVictim(cacheIndex);
        }

        break;
    case L2C_EVICT:
        // Decrease global pf_useful counter when there is
        // a useless prefetch (prefetched but not used)
        if (prefetchEntry) {
            // Prefetch leads to eviction
            if (!prefetchEntry->useful)
                pPerceptron->percUpdate(prefetchEntry, false);
            // Reset filter entry
            pPrefetchTable->findVictim(cacheIndex);
        }

        // Reset reject filter too
        if (rejectEntry)
            pRejectTable->findVictim(cacheIndex);


        break;
    case SPP_PERC_REJECT:
        if (prefetchEntry) {
            return false;
        } else {
            if (rejectEntry == nullptr) {
                rejectEntry = pRejectTable->findVictim(cacheIndex);
                assert(rejectEntry != nullptr);
                rejectEntry->address = baseAddr;
                rejectEntry->pc = pSPP->pc;
                rejectEntry->pc1 = pSPP->pc1;
                rejectEntry->pc2 = pSPP->pc2;
                rejectEntry->pc3 = pSPP->pc3;
                rejectEntry->delta = curDelta;
                rejectEntry->curSignature = curSig;
                rejectEntry->confidence = confidence;
                rejectEntry->depth = depth;
                rejectEntry->percSum = sum;
                pRejectTable->insertEntry(cacheIndex, false, rejectEntry);
            }
        }

        break;
    default:
        break;

    }
    return true;

}

void
SPP_PPF::notifyEvict(const PacketPtr &pkt) {
    prefetchFilter.check(
        pkt->getAddr(), 0, 0, L2C_EVICT, 0, 0, 0, 0, 0
    );
}

} // namespace prefetch

} // namespace gem5
