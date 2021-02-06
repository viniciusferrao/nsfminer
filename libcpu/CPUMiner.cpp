
#if defined(__linux__)
#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* we need sched_setaffinity() */
#endif
#include <error.h>
#include <sched.h>
#include <unistd.h>
#endif

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/error.h>
#include <mach/thread_act.h>
#include <mach/thread_policy.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sched.h>
#include <unistd.h>
#endif

#include <libeth/Farm.h>
#include <ethash/ethash.hpp>

#include <boost/version.hpp>

#if 0
#include <boost/fiber/numa/pin_thread.hpp>
#include <boost/fiber/numa/topology.hpp>
#endif

#include "CPUMiner.h"


/* Sanity check for defined OS */
#if defined(__linux__)
/* linux */
#elif defined(__APPLE__)
/* macOS */
#elif defined(_WIN32)
/* windows */
#else
#error "Invalid OS configuration"
#endif

using namespace std;
using namespace dev;
using namespace eth;


/* ################## OS-specific functions ################## */

/*
 * returns physically available memory (no swap)
 */
static size_t getTotalPhysAvailableMemory()
{
#if defined(__linux__)
    long pages = sysconf(_SC_AVPHYS_PAGES);
    if (pages == -1L)
    {
        cwarn << "Error in func " << __FUNCTION__ << " at sysconf(_SC_AVPHYS_PAGES) \""
              << strerror(errno) << "\"\n";
        return 0;
    }

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size == -1L)
    {
        cwarn << "Error in func " << __FUNCTION__ << " at sysconf(_SC_PAGESIZE) \""
              << strerror(errno) << "\"\n";
        return 0;
    }

    return (size_t)pages * (size_t)page_size;
#elif defined(__APPLE__)
    mach_port_t host_port = mach_host_self();
    if (host_port == MACH_PORT_NULL)
        return 0;

    vm_size_t page_size = 0;
    host_page_size(host_port, &page_size);

    vm_statistics_data_t vmstat;
    mach_msg_type_number_t count = HOST_VM_INFO_COUNT;
    kern_return_t kernReturn = host_statistics(host_port, HOST_VM_INFO, (host_info_t)&vmstat, &count);
    if (kernReturn != KERN_SUCCESS)
        return 0;

    [[maybe_unused]] size_t used_mem = (vmstat.active_count + vmstat.inactive_count + vmstat.wire_count) * page_size;
    size_t free_mem = vmstat.free_count * page_size;
    return free_mem;
#else
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo) == 0)
    {
        // Handle Errorcode (GetLastError) ??
        return 0;
    }
    return memInfo.ullAvailPhys;
#endif
}

/*
 * return numbers of available CPUs
 */
unsigned CPUMiner::getNumDevices()
{
#if defined(__linux__)
    long cpus_available;
    cpus_available = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus_available == -1L)
    {
        cwarn << "Error in func " << __FUNCTION__ << " at sysconf(_SC_NPROCESSORS_ONLN) \""
              << strerror(errno) << "\"\n";
        return 0;
    }
    return cpus_available;
#elif defined(__APPLE__)
    unsigned cpus_available;
    size_t length = sizeof(cpus_available);
    int name[] = {
            CTL_HW,
            HW_NCPU
    };
    int retvalue = sysctl(name, sizeof(name) / sizeof(int), &cpus_available, &length, 0, 0);

    if (retvalue <= 0)
        /* Assume one CPU */
        return 1;
    else
        return cpus_available;
#else
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
#endif
}


/* ######################## CPU Miner ######################## */

CPUMiner::CPUMiner(unsigned _index, DeviceDescriptor& _device) : Miner("cpu-", _index)
{
    m_deviceDescriptor = _device;
}


CPUMiner::~CPUMiner()
{
    stopWorking();
    kick_miner();
}


/*
 * Bind the current thread to a spcific CPU
 */
bool CPUMiner::initDevice()
{
    cnote << "Using CPU: " << m_deviceDescriptor.cpCpuNumer << " " << m_deviceDescriptor.name
          << " Memory : " << dev::getFormattedMemory((double)m_deviceDescriptor.totalMemory);

#if defined(__linux__)
    cpu_set_t cpuset;
    int err;

    CPU_ZERO(&cpuset);
    CPU_SET(m_deviceDescriptor.cpCpuNumer, &cpuset);

    err = sched_setaffinity(0, sizeof(cpuset), &cpuset);
    if (err != 0)
    {
        cwarn << "Error in func " << __FUNCTION__ << " at sched_setaffinity() \"" << strerror(errno)
              << "\"\n";
        cwarn << "cp-" << m_index << "could not bind thread to cpu" << m_deviceDescriptor.cpCpuNumer
              << "\n";
    }
#elif defined(__APPLE__)
    cwarn << "Thread affinity is not yet supported on macOS";
#else
    DWORD_PTR dwThreadAffinityMask = 1i64 << m_deviceDescriptor.cpCpuNumer;
    DWORD_PTR previous_mask;
    previous_mask = SetThreadAffinityMask(GetCurrentThread(), dwThreadAffinityMask);
    if (previous_mask == NULL)
    {
        cwarn << "cp-" << m_index << "could not bind thread to cpu" << m_deviceDescriptor.cpCpuNumer
              << "\n";
        // Handle Errorcode (GetLastError) ??
    }
#endif
    return true;
}


/*
 * A new epoch was receifed with last work package (called from Miner::initEpoch())
 *
 * If we get here it means epoch has changed so it's not necessary
 * to check again dag sizes. They're changed for sure
 * We've all related infos in m_epochContext (.dagSize, .dagNumItems, .lightSize, .lightNumItems)
 */
void CPUMiner::initEpoch()
{
    m_initialized = true;
}


/*
   Miner should stop working on the current block
   This happens if a
     * new work arrived                       or
     * miner should stop (eg exit ethminer)   or
     * miner should pause
*/
void CPUMiner::kick_miner()
{
    m_new_work.store(true, memory_order_relaxed);
    m_new_work_signal.notify_one();
}


void CPUMiner::search(const dev::eth::WorkPackage& w)
{
    constexpr size_t blocksize = 30;

    const auto& context = ethash::get_global_epoch_context_full(w.epoch);
    const auto header = ethash::hash256_from_bytes(w.header.data());
    const auto boundary = ethash::hash256_from_bytes(w.boundary.data());
    auto nonce = w.startNonce;

    while (true)
    {
        if (m_new_work.load(memory_order_relaxed))  // new work arrived ?
        {
            m_new_work.store(false, memory_order_relaxed);
            break;
        }

        if (shouldStop())
            break;


        auto r = ethash::search(context, header, boundary, nonce, blocksize);
        if (r.solution_found)
        {
            h256 mix{reinterpret_cast<byte*>(r.mix_hash.bytes), h256::ConstructFromPointer};
            auto sol = Solution{r.nonce, mix, w, chrono::steady_clock::now(), m_index};

            cnote << EthWhite << "Job: " << w.header.abridged()
                  << " Solution: " << toHex(sol.nonce, HexPrefix::Add);
            Farm::f().submitProof(sol);
        }
        nonce += blocksize;

        // Update the hash rate
        updateHashRate(blocksize, 1);
    }
}


/*
 * The main work loop of a Worker thread
 */
void CPUMiner::workLoop()
{
    WorkPackage current;
    current.header = h256();

    if (!initDevice())
        return;

    while (!shouldStop())
    {
        // Wait for work or 3 seconds (whichever the first)
        const WorkPackage w = work();
        if (!w)
        {
            unique_lock<mutex> l(miner_work_mutex);
            m_new_work_signal.wait_for(l, chrono::seconds(3));
            continue;
        }

        if (w.algo == "ethash")
        {
            // Epoch change ?
            if (current.epoch != w.epoch)
            {
                initEpoch();

                // As DAG generation takes a while we need to
                // ensure we're on latest job, not on the one
                // which triggered the epoch change
                current = w;
                continue;
            }

            // Persist most recent job.
            // Job's differences should be handled at higher level
            current = w;

            // Start searching
            search(w);
        }
        else
        {
            throw runtime_error("Algo : " + w.algo + " not yet implemented");
        }
    }
}


void CPUMiner::enumDevices(map<string, DeviceDescriptor>& _DevicesCollection)
{
    unsigned numDevices = getNumDevices();

    for (unsigned i = 0; i < numDevices; i++)
    {
        string uniqueId;
        ostringstream s;
        DeviceDescriptor deviceDescriptor;

        s << "cpu-" << i;
        uniqueId = s.str();
        if (_DevicesCollection.find(uniqueId) != _DevicesCollection.end())
            deviceDescriptor = _DevicesCollection[uniqueId];
        else
            deviceDescriptor = DeviceDescriptor();

        s.str("");
        s.clear();
        s << "ethash::eval()/boost " << (BOOST_VERSION / 100000) << "."
          << (BOOST_VERSION / 100 % 1000) << "." << (BOOST_VERSION % 100);
        deviceDescriptor.name = s.str();
        deviceDescriptor.uniqueId = uniqueId;
        deviceDescriptor.type = DeviceTypeEnum::Cpu;
        deviceDescriptor.totalMemory = getTotalPhysAvailableMemory();

        deviceDescriptor.cpCpuNumer = i;

        _DevicesCollection[uniqueId] = deviceDescriptor;
    }
}
