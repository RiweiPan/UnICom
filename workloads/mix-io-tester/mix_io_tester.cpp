#include <iostream>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <cstdint>
#include <climits>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <getopt.h>
#include <chrono>
#include <sched.h>
#include <algorithm>
#include <cmath>
#include <random>
#include <string>
#include <sstream>
#include <iomanip>
#include <liburing.h>

#define MIX_IO_TESTER_URING
// #define DEBUG_IO_DISTRIBUTION
// #define DEBUG_IOPS_PER_THREAD_PER_CPUID
// #define DEBUG_PER_THREAD_CPU_TIME_USAGE

#define PAGE_SIZE 4096
#define BLOCK_SIZE 512

struct Config {
    size_t io_size = 4096;
    std::vector<size_t> io_sizes;    // support multiple I/O size
    std::vector<double> io_weights;  // ratio of each I/O size
    size_t file_size = 1024 * 1024;
    int num_threads = 0;
    int num_counter_threads = 0;
    std::string io_mode = "randread";
    bool direct_io = false;
    std::vector<int> cpus;
    int runtime = 10;
    bool latency_stats = false;
    std::string path = ""; // path to store files
    std::string io_engine = "psync";
#ifdef MIX_IO_TESTER_URING
    bool uring_shared = false;
#endif
};

struct ThreadStats {
    int tid = 0;
    int real_tid = 0;
    std::string filename;
    uint64_t io_count = 0;
    uint64_t io_sizes_sum = 0;
    uint64_t total_bytes = 0;
    uint64_t total_latency_ns = 0;
    std::vector<uint64_t> latencies;
#ifdef MIX_IO_TESTER_URING
    int shared_wq_fd = -1;
#endif
#ifdef DEBUG_IO_DISTRIBUTION
    std::unordered_map<size_t, uint64_t> io_size_count;
#endif
#ifdef DEBUG_IOPS_PER_THREAD_PER_CPUID
    std::unordered_map<int, uint64_t> iops_per_thread_per_cpuid;
    std::unordered_map<int, uint64_t> sumcnt_per_thread_per_cpuid;
#endif
#ifdef DEBUG_PER_THREAD_CPU_TIME_USAGE
    unsigned long io_worker_cpu_time = 0;
    unsigned long counter_worker_cpu_time = 0;
#endif
    // for counter thread
    uint64_t count1 = 0;
    uint64_t count2 = 0;
    uint64_t count3 = 0;
};

struct ThreadContext {
    std::unordered_map<size_t, void*> buffers;  // I/O size to buffer
    std::unordered_map<size_t, std::uniform_int_distribution<size_t>> dist_map; // I/O size to random distribution
    std::mt19937 size_gen;
};

enum class IOMode { 
    SEQ_READ, 
    RAND_READ, 
    SEQ_WRITE, 
    RAND_WRITE 
};

// synchronization controls
std::atomic<bool> stop_flag(false);
std::mutex start_mutex;
std::condition_variable ready_cv;
std::condition_variable start_cv;
bool all_ready = false;
int ready_count = 0;

void parse_cpu_affinity(const std::string& str, std::vector<int>& cpus) {
    size_t dash_pos = str.find('-');
    if (dash_pos != std::string::npos) {
        int start = std::stoi(str.substr(0, dash_pos));
        int end = std::stoi(str.substr(dash_pos + 1));
        for (int i = start; i <= end; ++i) {
            cpus.push_back(i);
        }
    } else {
        std::stringstream ss(str);
        std::string item;
        while (std::getline(ss, item, ',')) {
            cpus.push_back(std::stoi(item));
        }
    }
}

size_t parse_size(const std::string& s) {
    size_t multiplier = 1;
    size_t num = 0;
    std::string suffix;

    for (char c : s) {
        if (isdigit(c)) {
            num = num * 10 + (c - '0');
        } else {
            suffix += tolower(c);
        }
    }

    if (suffix == "k" || suffix == "K") multiplier = 1024;
    else if (suffix == "m" || suffix == "M") multiplier = 1024 * 1024;
    else if (suffix == "g" || suffix == "G") multiplier = 1024 * 1024 * 1024;

    return num * multiplier;
}

void parse_io_sizes(const std::string& s, Config& cfg) {
    std::stringstream ss(s);
    std::string item;

    while (std::getline(ss, item, ',')) {
        size_t colon_pos = item.find(':');
        if (colon_pos == std::string::npos) {
            throw std::invalid_argument("Invalid io-size-ratio format");
        }
        
        std::string size_str = item.substr(0, colon_pos);
        std::string weight_str = item.substr(colon_pos+1);
        
        cfg.io_sizes.push_back(parse_size(size_str));
        cfg.io_weights.push_back(std::stod(weight_str));
    }
}

void parse_args(int argc, char* argv[], Config& cfg) {
    static struct option long_options[] = {
        {"io-size",    required_argument, 0, 's'},
        {"io-size-ratio",    required_argument, 0, 'S'},
        {"file-size",  required_argument, 0, 'f'},
        {"num-threads",required_argument, 0, 't'},
        {"num-counter-threads",required_argument,0,'p'},
        {"io-mode",    required_argument, 0, 'm'},
        {"direct-io",  no_argument,       0, 'd'},
        {"cpu-affinity",required_argument,0, 'c'},
        {"runtime",    required_argument, 0, 'r'},
        {"latency-stats",no_argument,     0, 'l'},
        {"path",   required_argument, 0, 'o'},
        {"io-engine", required_argument, 0, 'e'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "s:S:f:t:p:m:dc:r:lo:e:", long_options, nullptr)) != -1) {
        switch (opt) {
            case 's': cfg.io_size = parse_size(optarg); break;
            case 'S': parse_io_sizes(optarg, cfg); break;
            case 'f': cfg.file_size = parse_size(optarg); break;
            case 't': cfg.num_threads = std::stoi(optarg); break;
            case 'p': cfg.num_counter_threads = std::stoi(optarg); break;
            case 'm': cfg.io_mode = optarg; break;
            case 'd': cfg.direct_io = true; break;
            case 'c': parse_cpu_affinity(optarg, cfg.cpus); break;
            case 'r': cfg.runtime = std::stoi(optarg); break;
            case 'l': cfg.latency_stats = true; break;
            case 'o': cfg.path = optarg; break;
            case 'e': cfg.io_engine = optarg; break;
            default: std::exit(EXIT_FAILURE);
        }
    }

    if (cfg.cpus.empty()) {
        cfg.cpus.push_back(0);
    }

    if (cfg.io_sizes.empty()) {
        cfg.io_sizes.push_back(cfg.io_size);
        cfg.io_weights.push_back(1.0);
    }
}

void set_affinity(std::vector<int> cpus) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);

    for (int cpu : cpus) {
        CPU_SET(cpu, &cpuset);
    }

    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) == -1) {
        perror("sched_setaffinity");
    }
}

#ifdef MIX_IO_TESTER_URING
int get_sqpoll_worker_affinity(std::vector<int> cpus) {
    int min_cpu_id = -1, max_cpu_id = -1;
    for (int cpu : cpus) {
        if (min_cpu_id == -1 || cpu < min_cpu_id) {
            min_cpu_id = cpu;
        }
        if (max_cpu_id == -1 || cpu > max_cpu_id) {
            max_cpu_id = cpu;
        }
    }

    int random_cpu_id = min_cpu_id + rand() % (max_cpu_id - min_cpu_id + 1);
    return random_cpu_id;
}
#endif


long get_thread_cpu_time() {
    struct rusage ru;
    getrusage(RUSAGE_THREAD, &ru);  // Linux特有调用
    return (ru.ru_utime.tv_sec * 1000000 + ru.ru_utime.tv_usec) +
           (ru.ru_stime.tv_sec * 1000000 + ru.ru_stime.tv_usec);
}

int init_per_thread_test_files(const Config& cfg, std::vector<ThreadStats>& thread_stats, bool is_dir) {
    for (int i = 0; i < cfg.num_threads; ++i) {
        struct stat st;
        ThreadStats& stats = thread_stats[i];
        
        if (is_dir) {
            stats.filename = cfg.path + "/testfile_" + std::to_string(i);
        } else {
            stats.filename = cfg.path;
        }
        
        int fd = open(stats.filename.c_str(), O_RDWR | O_CREAT, 0644);
        if (fd == -1) {
            perror("open");
            return -1;
        }

        if (fstat(fd, &st) == -1) {
            perror("fstat");
            close(fd);
            return -1;
        }

        //  if file size is not equal to cfg.file_size, truncate it
        if (static_cast<size_t>(st.st_size) != cfg.file_size) {
            // write some data into this file and do not use ftruncate
            char buf[PAGE_SIZE] = {0};
            for (unsigned long i = 0; i < cfg.file_size / PAGE_SIZE; ++i) {
                ssize_t ret = write(fd, buf, PAGE_SIZE);
                if (ret != PAGE_SIZE) {
                    perror("write");
                    close(fd);
                    return -1;
                }
            }

            fsync(fd);
        }

        close(fd);
    }
    return 0;
}

#ifdef MIX_IO_TESTER_URING
struct RequestContext {
    long int start; // start time in nanoseconds
    size_t io_size;
};
#endif

void counter_worker(int tid, const Config& cfg, ThreadStats& stats) {
    unsigned long count3 = 0;
    unsigned long count2 = 0;
    unsigned long count1 = 0;
#ifdef DEBUG_IOPS_PER_THREAD_PER_CPUID
    unsigned long last_sum_cnt = 0;
#endif
    stats.tid = tid;
    stats.real_tid = gettid();
    // bind CPUs
    set_affinity(cfg.cpus);

    // counter thread is ready and notify main thread
    {
        std::lock_guard<std::mutex> lk(start_mutex);
        ready_count++;
    }
    ready_cv.notify_one();

    // wait for start signal
    {
        std::unique_lock<std::mutex> lk(start_mutex);
        start_cv.wait(lk, []{ return all_ready; });
    }
#ifdef DEBUG_PER_THREAD_CPU_TIME_USAGE
    const long start_cpu = get_thread_cpu_time();
#endif
    // std::cout << "Counter thread " << tid << " starts\n";
    while (!stop_flag.load(std::memory_order_relaxed)) {
        count1 += 1;
        if(count1 >= ULONG_MAX) {
            count1 = 0;
            count2 += 1;
            if(count2 >= ULONG_MAX) {
                count2 = 0;
                count3 += 1;
            }
        }
#ifdef DEBUG_IOPS_PER_THREAD_PER_CPUID
        if(count1 % 10000 == 0) {
            int cpuid = sched_getcpu();
            stats.sumcnt_per_thread_per_cpuid[cpuid] = count1 - last_sum_cnt;
            last_sum_cnt = count1;
        }
#endif
    }
#ifdef DEBUG_IOPS_PER_THREAD_PER_CPUID
    int cpuid = sched_getcpu();
    stats.sumcnt_per_thread_per_cpuid[cpuid] = count1 - last_sum_cnt;
#endif

    stats.count1 = count1;
    stats.count2 = count2;
    stats.count3 = count3;
#ifdef DEBUG_PER_THREAD_CPU_TIME_USAGE
    const long end_cpu = get_thread_cpu_time();
    stats.counter_worker_cpu_time = end_cpu - start_cpu;
#endif
}

void io_worker(int tid, const Config& cfg, ThreadStats& stats) {
    ThreadContext ctx;
    stats.tid = tid;
    stats.real_tid = gettid();
    // bind CPUs

    // std::vector<int> temp;
    // temp.push_back(27);
    // set_affinity(temp);

    set_affinity(cfg.cpus);

    std::string filename = stats.filename;
    int flags = O_RDWR;
    if (cfg.direct_io) flags |= O_DIRECT;

    //////////////// 智能缓冲区初始化
    for (auto size : cfg.io_sizes) {
        void* buf;
        if (posix_memalign(&buf, PAGE_SIZE, size) != 0) {
            perror("posix_memalign");
            // 清理已分配缓冲区
            for (auto& pair : ctx.buffers) free(pair.second);
            {
                std::lock_guard<std::mutex> lk(start_mutex);
                ready_count++;
            }
            ready_cv.notify_one();
            return;
        }
        ctx.buffers[size] = buf;
        
        // 预先生成各size的随机分布器
        if (cfg.io_mode.find("rand") != std::string::npos) {
            size_t max_block = (cfg.file_size - size) / size;
            ctx.dist_map.emplace(size, 
                std::uniform_int_distribution<size_t>(0, max_block));
        }
    }
    // 初始化随机数生成器
    std::random_device rd;
    ctx.size_gen = std::mt19937(rd());
    std::discrete_distribution<> size_dist(cfg.io_weights.begin(), cfg.io_weights.end());
    auto& gen = ctx.size_gen;
    ////////////////////////////////////////////////

    size_t offset = 0;
    bool is_read = cfg.io_mode.find("read") != std::string::npos;
    bool is_seq = cfg.io_mode.find("seq") != std::string::npos;
    // printf("Config: filename %s is read %d, is seq %d, io_mode %s, is_dirct %d\n", 
    //        filename.c_str(), is_read, is_seq, cfg.io_mode.c_str(), flags & O_DIRECT ? 1 : 0);
    int fd = open(filename.c_str(), flags, 0644);
    if (fd == -1) {
        perror("open");
        {
            std::lock_guard<std::mutex> lk(start_mutex);
            ready_count++;
        }
        ready_cv.notify_one(); // if error, notify main thread
        return;
    }

    // I/O thread is ready and notify main thread
    {
        std::lock_guard<std::mutex> lk(start_mutex);
        ready_count++;
    }
    ready_cv.notify_one();

    // wait for start signal
    {
        std::unique_lock<std::mutex> lk(start_mutex);
        start_cv.wait(lk, []{ return all_ready; });
    }
#ifdef DEBUG_PER_THREAD_CPU_TIME_USAGE
    const long start_cpu = get_thread_cpu_time();
#endif
    while (!stop_flag.load(std::memory_order_relaxed)) {
        uint64_t latency = 0;
        ssize_t ret;
        const size_t io_size = cfg.io_sizes[size_dist(gen)];
        void* buf = ctx.buffers[io_size];

        if (!is_seq) {
            auto& dist = ctx.dist_map[io_size];
            offset = dist(gen) * io_size;
        }

        auto start = std::chrono::high_resolution_clock::now();
        ret = is_read ? 
            pread(fd, buf, io_size, offset) :
            pwrite(fd, buf, io_size, offset);
        auto end = std::chrono::high_resolution_clock::now();
        latency = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

        if (ret != static_cast<ssize_t>(io_size)) {
            perror("IO error");
            printf("Thread %d: I/O operation failed at offset %zu, expected %zu bytes, got %zd bytes\n",
                   tid, offset, io_size, ret);
            break;
        }

        // 更新统计信息
        stats.io_count++;
        stats.total_bytes += io_size;
        stats.io_sizes_sum += io_size;
        stats.total_latency_ns += latency;
        if (cfg.latency_stats) {
            stats.latencies.push_back(latency);
        }
#ifdef DEBUG_IO_DISTRIBUTION
        stats.io_size_count[io_size]++;
#endif
#ifdef DEBUG_IOPS_PER_THREAD_PER_CPUID
        int cpuid = sched_getcpu();
        stats.iops_per_thread_per_cpuid[cpuid]++;
#endif
        if (is_seq) {
            offset += io_size;
            if (offset + io_size > cfg.file_size) {
                offset = 0;
            }
        }
    }
#ifdef DEBUG_PER_THREAD_CPU_TIME_USAGE
    const long end_cpu = get_thread_cpu_time();
    stats.io_worker_cpu_time = end_cpu - start_cpu;
#endif
    for (auto& pair : ctx.buffers) free(pair.second);
    close(fd);
}


#ifdef MIX_IO_TESTER_URING
void uring_worker(int tid, const Config& cfg, ThreadStats& stats) {
    ThreadContext ctx;
    stats.tid = tid;
    stats.real_tid = gettid();
    set_affinity(cfg.cpus);

    std::string filename = stats.filename;
    int flags = O_RDWR;
    if (cfg.direct_io) flags |= O_DIRECT;

    // Initialize buffers for different I/O sizes
    for (auto size : cfg.io_sizes) {
        void* buf;
        if (posix_memalign(&buf, PAGE_SIZE, size) != 0) {
            perror("posix_memalign");
            for (auto& pair : ctx.buffers) free(pair.second);
            {
                std::lock_guard<std::mutex> lk(start_mutex);
                ready_count++;
            }
            ready_cv.notify_one();
            return;
        }
        ctx.buffers[size] = buf;
        
        if (cfg.io_mode.find("rand") != std::string::npos) {
            size_t max_block = (cfg.file_size - size) / size;
            ctx.dist_map.emplace(size, 
                std::uniform_int_distribution<size_t>(0, max_block));
        }
    }

    std::random_device rd;
    ctx.size_gen = std::mt19937(rd());
    std::discrete_distribution<> size_dist(cfg.io_weights.begin(), cfg.io_weights.end());
    auto& gen = ctx.size_gen;

    bool is_read = cfg.io_mode.find("read") != std::string::npos;
    bool is_seq = cfg.io_mode.find("seq") != std::string::npos;
    size_t offset = 0;

    int fd = open(filename.c_str(), flags, 0644);
    if (fd == -1) {
        perror("open");
        {
            std::lock_guard<std::mutex> lk(start_mutex);
            ready_count++;
        }
        ready_cv.notify_one();
        return;
    }

    // Initialize io_uring
    struct io_uring ring;

    struct io_uring_params params = {};
    if (cfg.uring_shared && stats.shared_wq_fd != -1) {
        // 附加到全局工作队列模式
        params.flags = IORING_SETUP_ATTACH_WQ;
        params.wq_fd = stats.shared_wq_fd; // 关键：附加参数
    } else {
        // 独立模式
        //printf("Using independent io_uring instance for thread %d\n", tid);
        int sqpoll_cpu_id = get_sqpoll_worker_affinity(cfg.cpus);
        // printf("sqpoll cpu id = %d\n", sqpoll_cpu_id);
        params.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF;
        params.sq_thread_cpu = sqpoll_cpu_id;
        params.sq_thread_idle = 1000;
    }

    if (io_uring_queue_init_params(1024, &ring, &params) < 0) {
        perror("io_uring_queue_init");
        {
            std::lock_guard<std::mutex> lk(start_mutex);
            ready_count++;
        }
        close(fd);
        ready_cv.notify_one();
        return;
    }

    // Thread is ready
    {
        std::lock_guard<std::mutex> lk(start_mutex);
        ready_count++;
    }
    ready_cv.notify_one();

    // Wait for start signal
    {
        std::unique_lock<std::mutex> lk(start_mutex);
        start_cv.wait(lk, []{ return all_ready; });
    }

#ifdef DEBUG_PER_THREAD_CPU_TIME_USAGE
    const long start_cpu = get_thread_cpu_time();
#endif

    while (!stop_flag.load(std::memory_order_relaxed)) {
        const size_t io_size = cfg.io_sizes[size_dist(gen)];
        void* buf = ctx.buffers[io_size];

        if (!is_seq) {
            auto& dist = ctx.dist_map[io_size];
            offset = dist(gen) * io_size;
        }

        // Prepare and submit I/O request
        
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            io_uring_submit(&ring); // If no SQE available, wait for completions
            continue;
        }

        if (is_read) {
            io_uring_prep_read(sqe, fd, buf, io_size, offset);
        } else {
            io_uring_prep_write(sqe, fd, buf, io_size, offset);
        }


        RequestContext* rctx = new RequestContext {
            .start = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch()).count(),
            .io_size = io_size,
        };

        io_uring_sqe_set_data(sqe, rctx);

        io_uring_submit(&ring);  // Submit and wait for completion


        struct io_uring_cqe* cqe;
        int ret = io_uring_wait_cqe(&ring, &cqe);

        RequestContext* completed_ctx = static_cast<RequestContext*>(io_uring_cqe_get_data(cqe));

        // async I/O completion time
        unsigned long end_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()).count();
        uint64_t latency = end_ns - completed_ctx->start;

        if (ret < 0 || cqe->res != static_cast<int>(io_size)) {
            if (ret < 0) {
                perror("io_uring_wait_cqe");
            } else {
                fprintf(stderr, "Thread %d: I/O operation failed, expected %zu bytes, got %d bytes\n",
                        tid, io_size, cqe->res);
            }
            delete completed_ctx;
            io_uring_cqe_seen(&ring, cqe);
            break;
        }

        // Update statistics
        // acquire_uring_stat_lock();
        stats.io_count++;
        stats.total_bytes += completed_ctx->io_size;
        stats.io_sizes_sum += completed_ctx->io_size;
        stats.total_latency_ns += latency;
        if (cfg.latency_stats) {
            stats.latencies.push_back(latency);
        }
#ifdef DEBUG_IO_DISTRIBUTION
        stats.io_size_count[completed_ctx->io_size]++;
#endif
        // release_uring_stat_lock();

        delete completed_ctx;
        io_uring_cqe_seen(&ring, cqe);

#ifdef DEBUG_IOPS_PER_THREAD_PER_CPUID
        int cpuid = sched_getcpu();
        stats.iops_per_thread_per_cpuid[cpuid]++;
#endif

        if (is_seq) {
            offset += io_size;
            if (offset + io_size > cfg.file_size) {
                offset = 0;
            }
        }
    }

#ifdef DEBUG_PER_THREAD_CPU_TIME_USAGE
    const long end_cpu = get_thread_cpu_time();
    stats.io_worker_cpu_time = end_cpu - start_cpu;
#endif

    io_uring_queue_exit(&ring);
    
    for (auto& pair : ctx.buffers) free(pair.second);
    close(fd);

    // delete rctx; // Clean up the request context
}
#endif

void print_percentiles(std::vector<uint64_t>& latencies) {
    if (latencies.empty()) return;

    std::sort(latencies.begin(), latencies.end());
    const std::vector<double> percentiles = {
        5.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 
        95.0, 99.0, 99.5, 99.9, 99.95, 99.99
    };

    std::cout << std::fixed << std::setprecision(2);
    for (double p : percentiles) {
        size_t index = static_cast<size_t>((p / 100.0) * latencies.size());
        if (index >= latencies.size()) index = latencies.size() - 1;
        std::cout << "  " << std::setw(6) << p << "th: " 
                  << latencies[index] / 1000.0 << " us\n";
    }
}

void print_stats(const std::vector<ThreadStats>& stats, const Config& cfg) {
    uint64_t total_io = 0;
    uint64_t total_bytes = 0;
    uint64_t total_latency = 0;
    std::vector<uint64_t> all_latencies;
#ifdef DEBUG_IO_DISTRIBUTION
    std::unordered_map<size_t, uint64_t> total_io_size_count;
#endif

    std::cout << "\n=== Summary Statistics ===\n";

    for (const auto& s : stats) {
        total_io += s.io_count;
        total_bytes += s.io_sizes_sum;
        total_latency += s.total_latency_ns;
        if (cfg.latency_stats) {
            all_latencies.insert(all_latencies.end(), 
                               s.latencies.begin(), 
                               s.latencies.end());
        }
        // std::cout << "Thread" << s.tid << ": " << s.io_count << std::endl;
#ifdef DEBUG_IO_DISTRIBUTION
        for (const auto& pair : s.io_size_count) {
            total_io_size_count[pair.first] += pair.second;
        }
#endif
    }

    double runtime_sec = cfg.runtime;
    double iops = total_io / runtime_sec;
    double bw = total_bytes / (1024.0 * 1024.0) / runtime_sec;
    double avg_lat = total_latency / (total_io * 1e3);


    std::cout << "Total IOPS:    " << iops / 1000 << " K\n";
    std::cout << "Bandwidth:     " << bw << " MiB/s\n";
    std::cout << "Average Latency: " << avg_lat << " us\n";

    std::cout << "Tids: ";
    for (const auto& s : stats) {
        std::cout << s.real_tid << ",";
    }
    std::cout << "\n";
    // for (const auto& s : stats) {
    //     std::cout << "Thread" << s.tid << ": " << s.io_count << std::endl;
    // }
    // std::cout << std::endl;

    if (cfg.latency_stats && !all_latencies.empty()) {
        std::cout << "\n=== Latency Distribution (us) ===\n";
        print_percentiles(all_latencies);
    }
#ifdef DEBUG_IO_DISTRIBUTION
    std::cout << "\n=== I/O Size Distribution ===\n";
    for (const auto& pair : total_io_size_count) {
        uint64_t count = pair.second;
        double ratio = static_cast<double>(count) / total_io;
        std::cout << "  " << pair.first << " bytes: " 
                  << count << " (" << ratio * 100 << "%)\n";
    }
#endif
#ifdef DEBUG_IOPS_PER_THREAD_PER_CPUID
    std::cout << "\n=== IOPS per Thread per CPUID ===\n";
    std::unordered_set<int> cpuids;
    std::unordered_map<int, std::unordered_map<int, uint64_t>> iops_per_thread_per_cpuid;

    
    for (int i = 0; i < 32; i++) {
        cpuids.insert(i);
    }

    for(const auto& s : stats) {
        for (int cpuid : cpuids) {
            iops_per_thread_per_cpuid[s.tid][cpuid] = 0;
        }
    }


    for (const auto& s : stats) {
        uint64_t total_iops = 0;
        for (const auto& pair : s.iops_per_thread_per_cpuid) {
            total_iops += pair.second;
            iops_per_thread_per_cpuid[s.tid][pair.first] = pair.second;
        }
        std::cout << "Thread " << s.tid << ",";
        std::unordered_map<int, uint64_t> iops_per_cpuid = s.iops_per_thread_per_cpuid;
        for (int cpuid = 16; cpuid < 32; cpuid++) {
            std::cout << iops_per_cpuid[cpuid] / runtime_sec << ",";
        }
        std::cout << total_iops / runtime_sec << std::endl;
    }
#endif
#ifdef DEBUG_PER_THREAD_CPU_TIME_USAGE
    for (const auto& s : stats) {
        std::cout << "I/O Thread " << s.tid << " CPU time: "
                  << s.io_worker_cpu_time << " us (IO)\n";
    }
#endif
}

void print_counter_stats(const std::vector<ThreadStats>& stats) {
    uint64_t total_count1 = 0;
    uint64_t total_count2 = 0;
    uint64_t total_count3 = 0;

    std::cout << "\n=== Counter Statistics ===\n";

    for (const auto& s : stats) {
        total_count1 += s.count1;
        total_count2 += s.count2;
        total_count3 += s.count3;
        // std::cout << "Thread" << s.tid << ": " << s.count1 << std::endl;
    }

    std::cout << "Total count1: " << total_count1 << "\n";
    std::cout << "Total count2: " << total_count2 << "\n";
    std::cout << "Total count3: " << total_count3 << "\n";
    std::cout << "Tids: ";
    for (const auto& s : stats) {
        std::cout << s.real_tid << ",";
    }
    std::cout << "\n";
    // for (const auto& s : stats) {
    //     std::cout << "Thread" << s.tid << ": " << s.count1 << std::endl;
    // }
    // std::cout << std::endl;

#ifdef DEBUG_IOPS_PER_THREAD_PER_CPUID
    std::cout << "\n=== SUMCNT per Thread per CPUID ===\n";
    std::unordered_set<int> cpuids;
    std::unordered_map<int, std::unordered_map<int, uint64_t>> sumcnt_per_thread_per_cpuid;

    for (int i = 0; i < 32; i++) {
        cpuids.insert(i);
    }

    for(const auto& s : stats) {
        for (int cpuid : cpuids) {
            sumcnt_per_thread_per_cpuid[s.tid][cpuid] = 0;
        }
    }

    for (const auto& s : stats) {
        uint64_t total_iops = 0;
        for (const auto& pair : s.sumcnt_per_thread_per_cpuid) {
            total_iops += pair.second;
            sumcnt_per_thread_per_cpuid[s.tid][pair.first] = pair.second;
        }
        std::cout << "Thread " << s.tid << ",";
        std::unordered_map<int, uint64_t> sumcnt_per_cpuid = s.sumcnt_per_thread_per_cpuid;
        for (int cpuid = 16; cpuid < 32; cpuid++) {
            std::cout << sumcnt_per_cpuid[cpuid] << ",";
        }
        std::cout << total_iops << std::endl;
    }
#endif
#ifdef DEBUG_PER_THREAD_CPU_TIME_USAGE
    for (const auto& s : stats) {
        std::cout << "Counter Thread " << s.tid << " CPU time: "
                  << s.counter_worker_cpu_time << " us (counter)\n";
    }
#endif
}

void print_configuration(const Config& cfg) {
    std::cout << "=== Configuration ===\n";
    std::cout << "I/O Sizes:       ";
    for (size_t i = 0; i < cfg.io_sizes.size(); ++i) {
        std::cout << cfg.io_sizes[i] << " bytes (" << cfg.io_weights[i] * 100 << "%) ";
    }
    std::cout << "\n";
    std::cout << "File Size:      " << cfg.file_size << " bytes\n";
    std::cout << "Num I/O Threads:    " << cfg.num_threads << "\n";
    std::cout << "Num Counter Threads: " << cfg.num_counter_threads << "\n";
    std::cout << "I/O Mode:       " << cfg.io_mode << "\n";
    std::cout << "Direct I/O:     " << (cfg.direct_io ? "Yes" : "No") << "\n";
    std::cout << "CPU Affinity:   ";
    for (int cpu : cfg.cpus) {
        std::cout << cpu << " ";
    }
    std::cout << ", total " << cfg.cpus.size() << " cores\n";
    std::cout << "Runtime:        " << cfg.runtime << " seconds\n";
    std::cout << "Latency Stats:  " << (cfg.latency_stats ? "Yes" : "No") << "\n";
    std::cout << "Path:           " << cfg.path << "\n";
    if(cfg.io_engine == "uring") {
        std::cout << "I/O Engine:     " << (cfg.uring_shared ? "uring-shared" : "uring") << "\n";
    } else {
        std::cout << "I/O Engine:     " << cfg.io_engine << "\n";
    }
    std::cout << "=====================\n";
}

// usage: ./mix_io_tester --io-size=4k --file-size=1M --num-threads=1 --io-mode=read --direct-io --cpu-affinity=0 --runtime=10 --latency-stats --filename=testfile
int main(int argc, char* argv[]) {
    Config cfg;
    parse_args(argc, argv, cfg);

#ifdef MIX_IO_TESTER_URING
    if (cfg.io_engine != "psync" && cfg.io_engine != "uring-shared" && cfg.io_engine != "uring") {
        std::cerr << "Error: io-engine must be 'psync' or 'uring-shared' or 'uring'\n";
        std::exit(EXIT_FAILURE);
    }
    if (cfg.io_engine == "uring-shared") {
        cfg.uring_shared = true;
        cfg.io_engine = "uring"; // use uring shared mode
    }
#else
    if (cfg.io_engine != "psync") {
        std::cerr << "Error: io-engine must be 'psync', 'uring' does not support\n";
        std::exit(EXIT_FAILURE);
    }
#endif

    if(cfg.path.empty()) {
        std::cerr << "Error: path must be specified\n";
        exit(EXIT_FAILURE);
    }

    print_configuration(cfg);

    struct stat st;
    bool is_dir = (stat(cfg.path.c_str(), &st) == 0 && S_ISDIR(st.st_mode));

    std::vector<ThreadStats> thread_stats(cfg.num_threads);
    std::vector<ThreadStats> counter_thread_stats(cfg.num_counter_threads);
    std::vector<std::thread> threads;

    int total_threads = cfg.num_threads + cfg.num_counter_threads;
    if (total_threads == 0) {
        std::cerr << "Error: num_threads and num_counter_threads must be greater than 0\n";
        exit(EXIT_FAILURE);
    }

    if (cfg.direct_io) {
        for (auto size : cfg.io_sizes) {
            if (size % BLOCK_SIZE != 0) {
                std::cerr << "Error: io_size must be 512-byte aligned for direct I/O\n";
                exit(EXIT_FAILURE);
            }
        }
    }

    if(cfg.num_threads > 0) {
        if (init_per_thread_test_files(cfg, thread_stats, is_dir) != 0) {
            std::cerr << "Error initializing test files for I/O threads\n";
            exit(EXIT_FAILURE);
        }
    }

#ifdef MIX_IO_TESTER_URING
    struct io_uring shared_ring;

    if (cfg.io_engine == "uring" && cfg.uring_shared && cfg.num_threads > 0) {
        struct io_uring_params params = {};
        params.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF;
        params.sq_thread_cpu = 31;
        params.sq_thread_idle = 1000;
        
        if (io_uring_queue_init_params(1024, &shared_ring, &params) < 0) {
            perror("io_uring_queue_init for shared sqpoll");
            exit(EXIT_FAILURE);
        }

        // 获取工作队列fd传递给所有线程
        int wq_fd = shared_ring.ring_fd;

        for (int i = 0; i < cfg.num_threads; ++i) {
            thread_stats[i].shared_wq_fd = wq_fd;
        }
    }
#endif

    // 创建工作线程
    if (cfg.num_threads > 0) {
        if (cfg.io_engine == "uring") {
#ifdef MIX_IO_TESTER_URING
            for (int i = 0; i < cfg.num_threads; ++i) {
                threads.emplace_back(uring_worker, i, std::cref(cfg), std::ref(thread_stats[i]));
            }
#endif
        } else {
            for (int i = 0; i < cfg.num_threads; ++i) {
                threads.emplace_back(io_worker, i, std::cref(cfg), std::ref(thread_stats[i]));
            }
        }
    }

    if (cfg.num_counter_threads > 0) {
        for (int i = 0; i < cfg.num_counter_threads; ++i) {
            threads.emplace_back(counter_worker, i, std::cref(cfg), std::ref(counter_thread_stats[i]));
        }
    }

    // wait for all threads to be ready
    {
        std::unique_lock<std::mutex> lk(start_mutex);
        ready_cv.wait(lk, [&cfg, total_threads]{ return ready_count == total_threads; });
        all_ready = true;
    }
    std::cout << total_threads << " threads start: " 
        << "num_io_threads = " << cfg.num_threads 
        << ", num_counter_threads = " << cfg.num_counter_threads << std::endl;
    
    sleep(3);
    start_cv.notify_all(); // start all threads
    
    // start monitor thread
    std::thread monitor([&cfg]{
        auto start = std::chrono::steady_clock::now();
        while (!stop_flag.load()) {
            auto now = std::chrono::steady_clock::now();
            if (now - start >= std::chrono::seconds(cfg.runtime)) {
                stop_flag.store(true);
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    });

    // wait for all threads to finish
    for (auto& t : threads) t.join();
    monitor.join();

#ifdef MIX_IO_TESTER_URING
    if (cfg.io_engine == "uring" && cfg.uring_shared && cfg.num_threads > 0) {
        io_uring_queue_exit(&shared_ring);
    }
#endif

    // print stats
    if (cfg.num_threads > 0)
        print_stats(thread_stats, cfg);
    if (cfg.num_counter_threads > 0)
        print_counter_stats(counter_thread_stats);
    return 0;
}
