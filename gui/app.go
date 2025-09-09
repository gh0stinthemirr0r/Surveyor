package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

var (
	latencyGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "network_latency_ms",
			Help: "Network latency in milliseconds",
		},
		[]string{"endpoint"},
	)

	packetLossGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "network_packet_loss_percent",
			Help: "Network packet loss percentage",
		},
		[]string{"endpoint"},
	)

	jitterGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "network_jitter_ms",
			Help: "Network jitter in milliseconds",
		},
		[]string{"endpoint"},
	)

	throughputGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "network_throughput_mbps",
			Help: "Network throughput in Mbps",
		},
		[]string{"endpoint"},
	)

	responseTimeGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "network_response_time_ms",
			Help: "Network response time in milliseconds",
		},
		[]string{"endpoint"},
	)
)

type EndpointData struct {
	Status     string  `json:"status"`
	OpenPorts  []int   `json:"openPorts"`
	Latency    float64 `json:"latency"`
	PacketLoss float64 `json:"packetLoss"`
}

type MetricPoint struct {
	Timestamp int64   `json:"timestamp"`
	Value     float64 `json:"value"`
}

type LiveMetrics struct {
	Latency      []MetricPoint `json:"latency"`
	PacketLoss   []MetricPoint `json:"packetLoss"`
	Jitter       []MetricPoint `json:"jitter"`
	Throughput   []MetricPoint `json:"throughput"`
	ResponseTime []MetricPoint `json:"responseTime"`
}

// App struct
type App struct {
	ctx        context.Context
	currentIP  string
	metricStop chan struct{}
}

// NewApp creates a new App application struct
func NewApp() *App {
	// Register Prometheus metrics
	prometheus.MustRegister(latencyGauge)
	prometheus.MustRegister(packetLossGauge)
	prometheus.MustRegister(jitterGauge)
	prometheus.MustRegister(throughputGauge)
	prometheus.MustRegister(responseTimeGauge)

	// Start Prometheus metrics server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.ListenAndServe(":2112", nil)
	}()

	return &App{
		metricStop: make(chan struct{}),
	}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// AnalyzeEndpoint analyzes the given endpoint and returns its data
func (a *App) AnalyzeEndpoint(ip string) (*EndpointData, error) {
	// Mock implementation for now
	time.Sleep(1 * time.Second) // Simulate network delay
	return &EndpointData{
		Status:     "Online",
		OpenPorts:  []int{22, 80, 443, 3306},
		Latency:    15.5,
		PacketLoss: 0.1,
	}, nil
}

// StartTrafficTest starts a traffic test for the given endpoint
func (a *App) StartTrafficTest(ip string, duration string) error {
	a.currentIP = ip

	// Stop any existing metric collection
	if a.metricStop != nil {
		close(a.metricStop)
	}

	a.metricStop = make(chan struct{})

	// Start collecting metrics in background
	go a.collectMetrics(ip, a.metricStop)

	return nil
}

// StopTrafficTest stops the current traffic test
func (a *App) StopTrafficTest() error {
	if a.metricStop != nil {
		close(a.metricStop)
		a.metricStop = make(chan struct{})
	}
	return nil
}

func (a *App) collectMetrics(ip string, stop chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			// Mock metrics collection
			latency := 15 + rand.Float64()*10
			packetLoss := rand.Float64() * 2
			jitter := rand.Float64() * 5
			throughput := 50 + rand.Float64()*20
			responseTime := 20 + rand.Float64()*15

			// Update Prometheus metrics
			latencyGauge.WithLabelValues(ip).Set(latency)
			packetLossGauge.WithLabelValues(ip).Set(packetLoss)
			jitterGauge.WithLabelValues(ip).Set(jitter)
			throughputGauge.WithLabelValues(ip).Set(throughput)
			responseTimeGauge.WithLabelValues(ip).Set(responseTime)
		}
	}
}

// GetLiveMetrics returns the current live metrics
func (a *App) GetLiveMetrics() (*LiveMetrics, error) {
	if a.currentIP == "" {
		return nil, fmt.Errorf("no active test running")
	}

	metrics := &LiveMetrics{
		Latency:      make([]MetricPoint, 1),
		PacketLoss:   make([]MetricPoint, 1),
		Jitter:       make([]MetricPoint, 1),
		Throughput:   make([]MetricPoint, 1),
		ResponseTime: make([]MetricPoint, 1),
	}

	now := time.Now().Unix()

	// Get current values from Prometheus metrics
	latencyValue := getGaugeValue(latencyGauge, a.currentIP)
	packetLossValue := getGaugeValue(packetLossGauge, a.currentIP)
	jitterValue := getGaugeValue(jitterGauge, a.currentIP)
	throughputValue := getGaugeValue(throughputGauge, a.currentIP)
	responseTimeValue := getGaugeValue(responseTimeGauge, a.currentIP)

	// Update the metrics arrays with current values
	metrics.Latency[0] = MetricPoint{Timestamp: now, Value: latencyValue}
	metrics.PacketLoss[0] = MetricPoint{Timestamp: now, Value: packetLossValue}
	metrics.Jitter[0] = MetricPoint{Timestamp: now, Value: jitterValue}
	metrics.Throughput[0] = MetricPoint{Timestamp: now, Value: throughputValue}
	metrics.ResponseTime[0] = MetricPoint{Timestamp: now, Value: responseTimeValue}

	return metrics, nil
}

func getGaugeValue(gauge *prometheus.GaugeVec, ip string) float64 {
	metric := &dto.Metric{}
	if err := gauge.WithLabelValues(ip).Write(metric); err != nil {
		return 0
	}
	return metric.GetGauge().GetValue()
}

// Greet returns a greeting for the given name
func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}
