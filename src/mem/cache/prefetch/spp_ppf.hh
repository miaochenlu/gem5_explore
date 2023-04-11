#ifndef __MEM_CACHE_PREFETCH_SPP_PPF_HH__
#define __MEM_CACHE_PREFETCH_SPP_PPF_HH__

#include "base/sat_counter.hh"
#include "mem/cache/prefetch/associative_set.hh"
#include "mem/cache/prefetch/queued.hh"
#include "mem/packet.hh"
#include "sim/eventq.hh"

// Perceptron paramaters
#define PERC_ENTRIES 4096 //Upto 12-bit addressing in hashed perceptron
#define PERC_FEATURES 9 //Keep increasing based on new features
#define PERC_COUNTER_MAX 15 //-16 to +15: 5 bits counter
#define POS_UPDT_THRESHOLD  90
#define NEG_UPDT_THRESHOLD -80

namespace gem5
{

struct SPP_PPFPrefetcherParams;

GEM5_DEPRECATED_NAMESPACE(Prefetcher, prefetch);
namespace prefetch
{

enum FILTER_REQUEST
{
    SPP_L2C_PREFETCH, SPP_LLC_PREFETCH,
    L2C_DEMAND, L2C_EVICT, SPP_PERC_REJECT
}; // Request type for prefetch filter

class SPP_PPF : public Queued
{
  public:
    /** Signature type */
    typedef uint16_t signature_t;
    /** Stride type */
    typedef int16_t stride_t;

    /** Number of strides stored in each pattern entry */
    const unsigned stridesPerPatternEntry;
    /** Number of bits to shift when generating a new signature */
    const uint8_t signatureShift;
    /** Size of the signature, in bits */
    const signature_t signatureBits;
    /** Minimum confidence to issue a prefetch */
    const double prefetchConfidenceThreshold;
    /** Minimum confidence to keep navigating lookahead entries */
    double lookaheadConfidenceThreshold;

    /** Signature entry data type */
    struct SignatureEntry : public TaggedEntry
    {
        /** Path signature */
        signature_t signature;
        /** Last accessed block within a page */
        stride_t lastBlock;
        SignatureEntry() : signature(0), lastBlock(0)
        {}
    };
    /** Signature table */
    AssociativeSet<SignatureEntry> signatureTable;

    /** A stride entry with its counter */
    struct PatternStrideEntry
    {
        /** stride in a page in blkSize increments */
        stride_t stride;
        /** Saturating counter */
        SatCounter8 counter;
        PatternStrideEntry(unsigned bits) : stride(0), counter(bits)
        {}
    };
    /** Pattern entry data type, a set of stride and counter entries */
    struct PatternEntry : public TaggedEntry
    {
        /** group of stides */
        std::vector<PatternStrideEntry> strideEntries;
        /** use counter, used by SPPv2 */
        SatCounter8 counter;
        PatternEntry(size_t num_strides, unsigned counter_bits)
          : TaggedEntry(), strideEntries(num_strides, counter_bits),
            counter(counter_bits)
        {
        }

        /** Reset the entries to their initial values */
        void
        invalidate() override
        {
            TaggedEntry::invalidate();
            for (auto &entry : strideEntries) {
                entry.counter.reset();
                entry.stride = 0;
            }
            counter.reset();
        }

        /**
         * Returns the entry with the desired stride
         * @param stride the stride to find
         * @result a pointer to the entry, if the stride was found, or nullptr,
         *         if the stride was not found
         */
        PatternStrideEntry *findStride(stride_t stride)
        {
            PatternStrideEntry *found_entry = nullptr;
            for (auto &entry : strideEntries) {
                if (entry.stride == stride) {
                    found_entry = &entry;
                    break;
                }
            }
            return found_entry;
        }

        /**
         * Gets the entry with the provided stride, if there is no entry with
         * the associated stride, it replaces one of them.
         * @param stride the stride to find
         * @result reference to the selected entry
         */
        PatternStrideEntry &getStrideEntry(stride_t stride);
    };
    /** Pattern table */
    AssociativeSet<PatternEntry> patternTable;

    /** Global History Register entry datatype */
    struct GlobalHistoryEntry : public TaggedEntry
    {
        signature_t signature;
        double confidence;
        stride_t lastBlock;
        stride_t delta;
        GlobalHistoryEntry() : signature(0), confidence(0.0), lastBlock(0),
                               delta(0) {}
    };

    /** Global History Register */
    AssociativeSet<GlobalHistoryEntry> globalHistoryRegister;

    struct PFTableEntry : public TaggedEntry
    {
        bool useful;
        int32_t percSum;
        Addr pc, pc1, pc2, pc3;
        uint64_t address;
        signature_t curSignature;
        stride_t delta;
        uint32_t confidence;
        uint32_t depth;

        PFTableEntry() : useful(false),
            percSum(0), pc(0), pc1(0), pc2(0), pc3(0),
            address(0), curSignature(0),
            delta(0), confidence(0), depth(0)
        {}
    };

    struct Perceptron
    {
        int32_t percWeights[PERC_ENTRIES][PERC_FEATURES];
        int32_t percDepth[PERC_FEATURES];
        SPP_PPF* pSPP;

        Perceptron(): pSPP(nullptr) {
            percDepth[0] = 2048; //base_addr;
            percDepth[1] = 4096; //cache_line;
            percDepth[2] = 4096; //page_addr;
            percDepth[3] = 4096; //confidence ^ page_addr;
            percDepth[4] = 1024; //curr_sig ^ sig_delta;
            percDepth[5] = 4096; //ip_1 ^ ip_2 ^ ip_3;
            percDepth[6] = 1024; //ip ^ depth;
            percDepth[7] = 2048; //ip ^ sig_delta;
            percDepth[8] = 128;  //confidence;

            for (int i = 0; i < PERC_ENTRIES; i++)
                for (int j = 0; j < PERC_FEATURES; j++)
                    percWeights[i][j] = 0;
        }

        void percUpdate(PFTableEntry* entry, bool direction);
        int32_t percPredict(Addr checkAddr, uint64_t ip,
            uint64_t ip_1, uint64_t ip_2, uint64_t ip_3,
            stride_t cur_delta, signature_t curr_sig,
            uint32_t confidence, uint32_t depth);
        void getPercIndex(Addr baseAddr, uint64_t ip,
            uint64_t ip_1, uint64_t ip_2, uint64_t ip_3,
            stride_t cur_delta, signature_t curr_sig,
            uint32_t confidence, uint32_t depth,
            uint64_t perc_set[PERC_FEATURES]);
    };

    Perceptron perceptron;

    AssociativeSet<PFTableEntry> prefetchTable;
    AssociativeSet<PFTableEntry> rejectTable;

    struct PrefetchFilter
    {
    public:
        AssociativeSet<GlobalHistoryEntry>* pGHR;
        Perceptron* pPerceptron;
        AssociativeSet<PFTableEntry>* pPrefetchTable;
        AssociativeSet<PFTableEntry>* pRejectTable;
        SPP_PPF* pSPP;

        PrefetchFilter(): pGHR(nullptr),
            pPerceptron(nullptr), pPrefetchTable(nullptr),
            pRejectTable(nullptr), pSPP(nullptr)
        {
        }

        bool check(Addr pfAddr, Addr baseAddr, uint64_t ip,
            FILTER_REQUEST filter_request, stride_t cur_delta,
            signature_t cur_sig, uint32_t confidence,
            int32_t sum, uint32_t depth);
    };

    PrefetchFilter prefetchFilter;

    int64_t ppfThresholdHigh;
    int64_t ppfThresholdLow;

    /**
     * Generates a new signature from an existing one and a new stride
     * @param sig current signature
     * @param str stride to add to the new signature
     * @result the new signature
     */
    inline signature_t updateSignature(signature_t sig, stride_t str) const {
        sig <<= signatureShift;
        sig ^= str;
        sig &= mask(signatureBits);
        return sig;
    }

    /**
     * Generates an address to be prefetched.
     * @param ppn page number to prefetch from
     * @param last_block last accessed block within the page ppn
     * @param delta difference, in number of blocks, from the last_block
     *        accessed to the block to prefetch. The block to prefetch is
     *        computed by this formula:
     *          ppn * pageBytes + (last_block + delta) * blkSize
     *        This value can be negative.
     * @param path_confidence the confidence factor of this prefetch
     * @param signature the current path signature
     * @param is_secure whether this page is inside the secure memory area
     * @param addresses addresses to prefetch will be added to this vector
     */
    void addPrefetch(Addr ppn, stride_t last_block, stride_t delta,
                          double path_confidence, signature_t signature,
                          bool is_secure,
                          std::vector<AddrPriority> &addresses);

    void addPPFPrefetch(Addr request_addr, stride_t last_block,
                          stride_t train_delta, stride_t delta,
                          double path_confidence, signature_t cur_sig,
                          uint32_t depth, bool is_secure,
                          std::vector<AddrPriority> &addresses);
    /**
     * Obtains the SignatureEntry of the given page, if the page is not found,
     * it allocates a new one, replacing an existing entry if needed
     * It also provides the stride of the current block and the initial
     * path confidence of the corresponding entry
     * @param ppn physical page number of the page
     * @param is_secure whether this page is inside the secure memory area
     * @param block accessed block within the page
     * @param miss if the entry is not found, this will be set to true
     * @param stride set to the computed stride
     * @param initial_confidence set to the initial confidence value
     * @result a reference to the SignatureEntry
     */
    SignatureEntry &getSignatureEntry(Addr ppn, bool is_secure, stride_t block,
            bool &miss, stride_t &stride, double &initial_confidence);
    /**
     * Obtains the PatternEntry of the given signature, if the signature is
     * not found, it allocates a new one, replacing an existing entry if needed
     * @param signature the signature of the desired entry
     * @result a reference to the PatternEntry
     */
    PatternEntry& getPatternEntry(Addr signature);

    /**
     * Updates the pattern table with the provided signature and stride
     * @param signature the signature to use to index the pattern table
     * @param stride the stride to use to index the set of strides of the
     *        pattern table entry
     */
    void updatePatternTable(Addr signature, stride_t stride);

    /**
     * Computes the lookahead path confidence of the provided pattern entry
     * @param sig the PatternEntry to use
     * @param lookahead PatternStrideEntry within the provided PatternEntry
     * @return the computed confidence factor
     */
    virtual double calculateLookaheadConfidence(PatternEntry const &sig,
            PatternStrideEntry const &lookahead) const;

    /**
     * Computes the prefetch confidence of the provided pattern entry
     * @param sig the PatternEntry to use
     * @param entry PatternStrideEntry within the provided PatternEntry
     * @return the computed confidence factor
     */
    virtual double calculatePrefetchConfidence(PatternEntry const &sig,
            PatternStrideEntry const &entry) const;

    /**
     * Increases the counter of a given PatternEntry/PatternStrideEntry
     * @param pattern_entry the corresponding PatternEntry
     * @param pstride_entry the PatternStrideEntry within the PatternEntry
     */
    virtual void increasePatternEntryCounter(PatternEntry &pattern_entry,
            PatternStrideEntry &pstride_entry);

    /**
     * Whenever a new SignatureEntry is allocated, it computes the new
     * signature to be used with the new entry, the resulting stride and the
     * initial path confidence of the new entry.
     * @param current_block accessed block within the page of the associated
              entry
     * @param new_signature new signature of the allocated entry
     * @param new_conf the initial path confidence of this entry
     * @param new_stride the resulting current stride
     */
    virtual void handleSignatureTableMiss(stride_t current_block,
            signature_t &new_signature, double &new_conf,
            stride_t &new_stride);

    /**
     * Auxiliar prefetch mechanism used at the end of calculatePrefetch.
     * This prefetcher uses this to activate the next line prefetcher if
     * no prefetch candidates have been found.
     * @param ppn physical page number of the current accessed page
     * @param current_block last accessed block within the page ppn
     * @param is_secure whether this page is inside the secure memory area
     * @param addresses the addresses to be prefetched are added to this vector
     * @param updated_filter_entries set of addresses containing these that
     *        their filter has been updated, if this call updates a new entry
     */
    virtual void auxiliaryPrefetcher(Addr ppn, stride_t current_block,
            bool is_secure, std::vector<AddrPriority> &addresses);

    /**
     * Handles the situation when the lookahead process has crossed the
     * boundaries of the current page. This is not fully described in the
     * paper that was used to implement this code, however, the article
     * describing the upgraded version of this prefetcher provides some
     * details. For this prefetcher, there are no specific actions to be
     * done.
     * @param signature the lookahead signature that crossed the page
     * @param delta the current stride that caused it
     * @param last_offset the last accessed block within the page
     * @param path_confidence the path confidence at the moment of crossing
     */
    virtual void handlePageCrossingLookahead(signature_t signature,
            stride_t last_offset, stride_t delta, double path_confidence);

    virtual void notifyEvict(const PacketPtr &pkt);

    Addr pc, pc1, pc2, pc3;

  public:
    SPP_PPF(const SPP_PPFPrefetcherParams &p);
    ~SPP_PPF() = default;

    void calculatePrefetch(const PrefetchInfo &pfi,
                           std::vector<AddrPriority> &addresses) override;
};

}
}

#endif
