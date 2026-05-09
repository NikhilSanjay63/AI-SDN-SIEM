import time
import requests
import statistics

API_URL     = "http://localhost:5050/analyze_batch"
BATCH_SIZES = [1, 5, 10, 20, 50]
ITERATIONS  = 10

# FIX: flow_id was "192.168.1.10" (just the src_ip). After the security
# controller fix that changed flow_id to a 5-tuple string, all flows in a
# batch shared the same buffer key in Redis, corrupting inference and making
# benchmark results meaningless. Now matches the format produced by
# _build_payload(): "{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}"
SAMPLE_FLOW = {
    "flow_id":       "192.168.1.10-10.0.0.1-44321-80-6",
    "src_ip":        "192.168.1.10",
    "dst_ip":        "10.0.0.1",
    "Flow Duration": 0.5,
    "Flow IAT Mean": 0.1,
    "Flow IAT Std":  0.01,
    "Flow IAT Max":  0.15,
    "Pkt Size Avg":  64.0,
    "Tot Fwd Pkts":  5,
    "TotLen Fwd Pkts": 320,
    "Protocol":      6,
    "Src Port":      44321,
    "Dst Port":      80,
    "SYN Flag Cnt":  1,
    "ACK Flag Cnt":  4,
    "RST Flag Cnt":  0,
    "PSH Flag Cnt":  0,
    "URG Flag Cnt":  0
}


def run_benchmark():
    print("🚀 Starting AI Service Performance Benchmark")
    print("-" * 50)

    for size in BATCH_SIZES:
        latencies = []
        payload   = {"flows": [SAMPLE_FLOW] * size}

        for _ in range(ITERATIONS):
            start = time.perf_counter()
            try:
                response = requests.post(API_URL, json=payload, timeout=10)
                response.raise_for_status()
                end = time.perf_counter()
                latencies.append((end - start) * 1000)
            except Exception as e:
                print("❌ Error at batch size {}: {}".format(size, e))
                break

        if latencies:
            avg = statistics.mean(latencies)
            p95 = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else max(latencies)
            print("Batch Size: {:2d} | Avg: {:6.2f}ms | P95: {:6.2f}ms | Throughput: {:8.2f} flows/sec".format(
                size, avg, p95, size / (avg / 1000)
            ))


if __name__ == "__main__":
    try:
        run_benchmark()
    except KeyboardInterrupt:
        print("\nBenchmark stopped.")