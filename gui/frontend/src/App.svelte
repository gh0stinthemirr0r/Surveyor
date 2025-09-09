<script>
  import { onMount, onDestroy } from 'svelte';
  import { AnalyzeEndpoint, StartTrafficTest, StopTrafficTest, GetLiveMetrics } from '../wailsjs/go/main/App.js'
  import ApexCharts from 'apexcharts';
  
  let endpointIP = "";
  let testDuration = "30s";
  let endpointData = null;
  let analyzing = false;
  let testing = false;
  let metrics = {
    latency: [],
    packetLoss: [],
    jitter: [],
    throughput: [],
    responseTime: []
  };
  let updateInterval;
  let testEndTime = null;
  let charts = {};
  let collectedMetrics = null;

  const durations = [
    { value: "30s", label: "30 Seconds" },
    { value: "60s", label: "60 Seconds" },
    { value: "3m", label: "3 Minutes" },
    { value: "5m", label: "5 Minutes" }
  ];

  // Chart configurations
  const chartColors = {
    latency: '#00ff9d',
    packetLoss: '#ff4d4d',
    jitter: '#00c3ff',
    throughput: '#ffaa00',
    responseTime: '#ff00ff'
  };

  const getChartOptions = (metric) => ({
    chart: {
      type: 'area',
      height: 200,
      animations: {
        enabled: false
      },
      background: 'transparent',
      toolbar: {
        show: false
      },
      sparkline: {
        enabled: false
      }
    },
    stroke: {
      curve: 'smooth',
      width: 2
    },
    colors: [chartColors[metric]],
    fill: {
      type: 'gradient',
      gradient: {
        opacityFrom: 0.2,
        opacityTo: 0
      }
    },
    dataLabels: {
      enabled: false
    },
    xaxis: {
      type: 'datetime',
      labels: {
        style: {
          colors: '#e0e0e0'
        },
        datetimeFormatter: {
          year: 'yyyy',
          month: 'MMM \'yy',
          day: 'dd MMM',
          hour: 'HH:mm:ss'
        }
      },
      axisBorder: {
        show: false
      },
      axisTicks: {
        show: false
      }
    },
    yaxis: {
      labels: {
        style: {
          colors: '#e0e0e0'
        }
      },
      axisBorder: {
        show: false
      },
      axisTicks: {
        show: false
      }
    },
    grid: {
      show: true,
      borderColor: 'rgba(255, 255, 255, 0.1)',
      strokeDashArray: 4,
      position: 'back'
    },
    tooltip: {
      theme: 'dark',
      x: {
        format: 'HH:mm:ss'
      }
    }
  });

  function updateCharts(metrics) {
    if (!metrics) return;
    
    Object.entries(metrics).forEach(([metric, data]) => {
      if (!charts[metric]) {
        console.warn(`Chart for ${metric} not initialized`);
        return;
      }

      try {
        const formattedData = data.map(point => ({
          x: point.timestamp * 1000, // Convert to milliseconds
          y: point.value
        }));

        charts[metric].updateSeries([{
          name: metric,
          data: formattedData
        }]);
      } catch (error) {
        console.error(`Error updating ${metric} chart:`, error);
      }
    });
  }

  async function analyzeEndpoint() {
    if (!endpointIP) return;
    
    analyzing = true;
    try {
      endpointData = await AnalyzeEndpoint(endpointIP);
    } catch (error) {
      console.error("Analysis failed:", error);
    }
    analyzing = false;
  }

  async function startTest() {
    if (!endpointIP) return;
    
    testing = true;
    collectedMetrics = null;
    metrics = {
      latency: [],
      packetLoss: [],
      jitter: [],
      throughput: [],
      responseTime: []
    };
    
    try {
      // Parse the duration string to get seconds
      const durationInSeconds = testDuration.includes('m') 
        ? parseInt(testDuration) * 60 
        : parseInt(testDuration);
      testEndTime = Date.now() + (durationInSeconds * 1000);
      
      await StartTrafficTest(endpointIP, testDuration);
      startMetricsUpdate();
    } catch (error) {
      console.error("Test failed:", error);
      testing = false;
      testEndTime = null;
    }
  }

  async function stopTest() {
    try {
      await StopTrafficTest();
      // Save the final metrics
      collectedMetrics = { ...metrics };
    } catch (error) {
      console.error("Failed to stop test:", error);
    }
    testing = false;
    stopMetricsUpdate();
  }

  function startMetricsUpdate() {
    if (updateInterval) {
      clearInterval(updateInterval);
    }

    updateInterval = setInterval(async () => {
      try {
        // Check if we've reached the test end time
        if (testEndTime && Date.now() >= testEndTime) {
          await stopTest();
          return;
        }

        const newMetrics = await GetLiveMetrics();
        if (!newMetrics) return;

        Object.entries(newMetrics).forEach(([metric, data]) => {
          if (!metrics[metric]) metrics[metric] = [];
          
          data.forEach(point => {
            const timestamp = point.timestamp * 1000;
            metrics[metric].push({
              timestamp,
              value: point.value
            });
            
            if (metrics[metric].length > 60) {
              metrics[metric].shift();
            }
          });
        });

        metrics = metrics;
        updateCharts(metrics);
      } catch (error) {
        console.error("Failed to get metrics:", error);
        if (error.message === "no active test running") {
          await stopTest();
        }
      }
    }, 1000);
  }

  function stopMetricsUpdate() {
    if (updateInterval) {
      clearInterval(updateInterval);
      updateInterval = null;
    }
  }

  onMount(() => {
    console.log('Component mounted');
    setTimeout(() => {
      try {
        const chartElements = {
          latency: document.querySelector('#latencyChart'),
          packetLoss: document.querySelector('#packetLossChart'),
          jitter: document.querySelector('#jitterChart'),
          throughput: document.querySelector('#throughputChart'),
          responseTime: document.querySelector('#responseTimeChart')
        };

        console.log('Chart elements:', chartElements);

        Object.entries(chartElements).forEach(([metric, element]) => {
          if (!element) {
            console.error(`Chart element for ${metric} not found`);
            return;
          }

          const options = {
            chart: {
              type: 'line',
              height: 200,
              animations: {
                enabled: false
              },
              background: '#2b2b2b',
              toolbar: {
                show: false
              }
            },
            stroke: {
              curve: 'smooth',
              width: 2
            },
            colors: ['#00ff00'],
            grid: {
              show: true,
              borderColor: '#404040',
              position: 'back',
              xaxis: {
                lines: {
                  show: true
                }
              },
              yaxis: {
                lines: {
                  show: true
                }
              }
            },
            xaxis: {
              type: 'datetime',
              labels: {
                style: {
                  colors: '#ffffff'
                },
                datetimeFormatter: {
                  year: 'yyyy',
                  month: 'MMM \'yy',
                  day: 'dd MMM',
                  hour: 'HH:mm:ss'
                }
              }
            },
            yaxis: {
              labels: {
                style: {
                  colors: '#ffffff'
                }
              }
            },
            tooltip: {
              theme: 'dark',
              x: {
                format: 'HH:mm:ss'
              }
            },
            series: [{
              name: metric,
              data: []
            }]
          };

          try {
            charts[metric] = new ApexCharts(element, options);
            charts[metric].render();
            console.log(`${metric} chart initialized`);
          } catch (error) {
            console.error(`Error initializing ${metric} chart:`, error);
          }
        });
      } catch (error) {
        console.error('Error during chart initialization:', error);
      }
    }, 100);

    return () => {
      Object.values(charts).forEach(chart => {
        try {
          chart.destroy();
        } catch (error) {
          console.error('Error destroying chart:', error);
        }
      });
    };
  });

  onDestroy(() => {
    stopMetricsUpdate();
  });
</script>

<main>
  <div class="container">
    <header>
      <h1>SURVEYOR</h1>
      <p class="subtitle">Network Connection Analysis & Testing</p>
    </header>

    <section class="control-panel">
      <div class="input-group">
        <label for="endpointIP">Endpoint IP:</label>
        <input 
          type="text" 
          id="endpointIP" 
          bind:value={endpointIP} 
          placeholder="e.g. 192.168.1.100"
        />
      </div>

      <div class="input-group">
        <label for="testDuration">Test Duration:</label>
        <select id="testDuration" bind:value={testDuration}>
          {#each durations as duration}
            <option value={duration.value}>{duration.label}</option>
          {/each}
        </select>
      </div>

      <div class="button-group">
        <button 
          class="primary-btn" 
          on:click={analyzeEndpoint} 
          disabled={analyzing || testing}
        >
          {analyzing ? 'Analyzing...' : 'Analyze Endpoint'}
        </button>

        <button 
          class="secondary-btn" 
          on:click={testing ? stopTest : startTest} 
          disabled={analyzing || !endpointData}
        >
          {testing ? 'Stop Test' : 'Start Test'}
        </button>
      </div>
    </section>

    {#if endpointData}
      <section class="results-panel">
        <div class="endpoint-info">
          <h2>Endpoint Analysis</h2>
          <div class="info-grid">
            <div class="info-item">
              <span class="label">Status:</span>
              <span class="value status" class:online={endpointData.status === 'Online'}>
                {endpointData.status}
              </span>
            </div>
            <div class="info-item">
              <span class="label">Open Ports:</span>
              <span class="value">{endpointData.openPorts.join(', ')}</span>
            </div>
            <div class="info-item">
              <span class="label">Base Latency:</span>
              <span class="value">{endpointData.latency.toFixed(2)}ms</span>
            </div>
            <div class="info-item">
              <span class="label">Packet Loss:</span>
              <span class="value">{endpointData.packetLoss.toFixed(2)}%</span>
            </div>
          </div>
        </div>

        {#if testing}
          <div class="metrics-panel">
            <h2>Data Collection in Progress...</h2>
            <div class="loading-container">
              <div class="loading-spinner"></div>
              <p>Collecting network metrics...</p>
            </div>
          </div>
        {:else if collectedMetrics}
          <div class="metrics-panel">
            <h2>Test Results</h2>
            <div class="results-grid">
              <div class="metric-card">
                <h3>Average Latency</h3>
                <div class="metric-value">{(collectedMetrics.latency.reduce((sum, m) => sum + m.value, 0) / collectedMetrics.latency.length).toFixed(2)} ms</div>
              </div>
              <div class="metric-card">
                <h3>Average Packet Loss</h3>
                <div class="metric-value">{(collectedMetrics.packetLoss.reduce((sum, m) => sum + m.value, 0) / collectedMetrics.packetLoss.length).toFixed(2)}%</div>
              </div>
              <div class="metric-card">
                <h3>Average Jitter</h3>
                <div class="metric-value">{(collectedMetrics.jitter.reduce((sum, m) => sum + m.value, 0) / collectedMetrics.jitter.length).toFixed(2)} ms</div>
              </div>
              <div class="metric-card">
                <h3>Average Throughput</h3>
                <div class="metric-value">{(collectedMetrics.throughput.reduce((sum, m) => sum + m.value, 0) / collectedMetrics.throughput.length).toFixed(2)} Mbps</div>
              </div>
              <div class="metric-card">
                <h3>Average Response Time</h3>
                <div class="metric-value">{(collectedMetrics.responseTime.reduce((sum, m) => sum + m.value, 0) / collectedMetrics.responseTime.length).toFixed(2)} ms</div>
              </div>
            </div>
          </div>
        {/if}
      </section>
    {/if}
  </div>
  
  <footer class="text-center text-gray-400 py-4 mt-auto">
    © Aaron Stovall
  </footer>
</main>

<style>
  :root {
    --primary-color: #00ff9d;
    --secondary-color: #2a2a2a;
    --accent-color: #00c3ff;
    --text-color: #e0e0e0;
    --background-color: #1a1a1a;
    --card-background: #2a2a2a;
    --hover-color: #3a3a3a;
  }

  main {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background-color: var(--background-color);
    color: var(--text-color);
    min-height: 100vh;
    padding: 2rem;
  }

  .container {
    max-width: 1200px;
    margin: 0 auto;
  }

  header {
    text-align: center;
    margin-bottom: 2rem;
  }

  h1 {
    color: var(--primary-color);
    font-size: 2.5rem;
    margin: 0;
    text-transform: uppercase;
    letter-spacing: 2px;
    text-shadow: 0 0 10px rgba(0, 255, 157, 0.5);
  }

  .subtitle {
    color: var(--accent-color);
    font-size: 1.1rem;
    margin-top: 0.5rem;
  }

  .control-panel {
    background-color: var(--secondary-color);
    padding: 1.5rem;
    border-radius: 8px;
    display: flex;
    gap: 1.5rem;
    align-items: flex-end;
    margin-bottom: 2rem;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  }

  .input-group {
    flex: 1;
  }

  .button-group {
    display: flex;
    gap: 1rem;
  }

  label {
    display: block;
    margin-bottom: 0.5rem;
    color: var(--primary-color);
  }

  input, select {
    width: 100%;
    padding: 0.5rem;
    border: 1px solid var(--accent-color);
    background-color: var(--card-background);
    color: var(--text-color);
    border-radius: 4px;
  }

  input:focus, select:focus {
    outline: none;
    border-color: var(--primary-color);
    box-shadow: 0 0 0 2px rgba(0, 255, 157, 0.2);
  }

  .primary-btn, .secondary-btn {
    padding: 0.5rem 1.5rem;
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
    transition: all 0.3s ease;
  }

  .primary-btn {
    background-color: var(--primary-color);
    color: var(--secondary-color);
    border: none;
  }

  .primary-btn:hover {
    background-color: #00cc7d;
    box-shadow: 0 0 10px rgba(0, 255, 157, 0.5);
  }

  .secondary-btn {
    background-color: transparent;
    color: var(--accent-color);
    border: 1px solid var(--accent-color);
  }

  .secondary-btn:hover {
    background-color: rgba(0, 195, 255, 0.1);
    box-shadow: 0 0 10px rgba(0, 195, 255, 0.3);
  }

  button:disabled {
    background-color: #4a4a4a;
    border-color: #4a4a4a;
    cursor: not-allowed;
    opacity: 0.7;
  }

  .results-panel {
    background-color: var(--secondary-color);
    padding: 1.5rem;
    border-radius: 8px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  }

  .endpoint-info {
    margin-bottom: 2rem;
  }

  .info-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-top: 1rem;
  }

  .info-item {
    background-color: var(--card-background);
    padding: 1rem;
    border-radius: 6px;
  }

  .info-item .label {
    color: var(--accent-color);
    font-size: 0.9rem;
    display: block;
    margin-bottom: 0.5rem;
  }

  .info-item .value {
    font-size: 1.1rem;
    font-weight: bold;
  }

  .status {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 3px;
    font-size: 0.9rem;
    background-color: #4a4a4a;
  }

  .status.online {
    background-color: rgba(0, 255, 157, 0.2);
    color: var(--primary-color);
  }

  .metrics-panel {
    background-color: #1e1e1e;
    padding: 20px;
    border-radius: 8px;
    margin-top: 20px;
  }

  .loading-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 2rem;
  }

  .loading-spinner {
    width: 50px;
    height: 50px;
    border: 3px solid var(--accent-color);
    border-top: 3px solid transparent;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin-bottom: 1rem;
  }

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  .results-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-top: 1rem;
  }

  .metric-card {
    background-color: var(--card-background);
    padding: 1.5rem;
    border-radius: 6px;
    text-align: center;
  }

  .metric-card h3 {
    color: var(--accent-color);
    font-size: 0.9rem;
    margin: 0 0 0.5rem 0;
  }

  .metric-value {
    font-size: 1.5rem;
    font-weight: bold;
    color: var(--primary-color);
  }
</style>
