import time
import requests
import statistics

# Configuration
API_URL = "http://localhost:5050/analyze_batch"  # Assumes ai-service is exposed on 5050
BATCH_SIZES = [1, 5, 10, 20, 50]
ITERATIONS = 10

# Sample normal flow
SAMPLE_FLOW = {
    "flow_id": "192.168.1.10",
    "src_ip": "192.168.1.10",
    "dst_ip": "10.0.0.1",
    "Flow Duration": 0.5,
    "Flow IAT Mean": 0.1,
    "Flow IAT Std": 0.01,
    "Flow IAT Max": 0.15,
    "Pkt Size Avg": 64.0,
    "Tot Fwd Pkts": 5,
    "TotLen Fwd Pkts": 320,
    "Protocol": 6,
    "Src Port": 44321,
    "Dst Port": 80,
    "SYN Flag Cnt": 1,
    "ACK Flag Cnt": 4,
    "RST Flag Cnt": 0,
    "PSH Flag Cnt": 0,
    "URG Flag Cnt": 0
}

def run_benchmark():
    print("🚀 Starting AI Service Performance Benchmark")
    print("-" * 50)
    
    for size in BATCH_SIZES:
        latencies = []
        payload = {"flows": [SAMPLE_FLOW] * size}
        
        for _ in range(ITERATIONS):
            start = time.perf_counter()
            try:
                response = requests.post(API_URL, json=payload, timeout=10)
                response.raise_for_status()
                end = time.perf_counter()
                latencies.append((end - start) * 1000) # ms
            except Exception as e:
                print(f"❌ Error at batch size {size}: {e}")
                break
        
        if latencies:
            avg = statistics.mean(latencies)
            p95 = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else max(latencies)
            print(f"Batch Size: {size:2d} | Avg Latency: {avg:6.2f}ms | P95: {p95:6.2f}ms | Throughput: {size/(avg/1000):8.2f} flows/sec")

if __name__ == "__main__":
    try:
        run_benchmark()
    except KeyboardInterrupt:
        print("\nBenchmark stopped.")
