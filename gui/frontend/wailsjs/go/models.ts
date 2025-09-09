export namespace main {
	
	export class EndpointData {
	    status: string;
	    openPorts: number[];
	    latency: number;
	    packetLoss: number;
	
	    static createFrom(source: any = {}) {
	        return new EndpointData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.status = source["status"];
	        this.openPorts = source["openPorts"];
	        this.latency = source["latency"];
	        this.packetLoss = source["packetLoss"];
	    }
	}
	export class MetricPoint {
	    timestamp: number;
	    value: number;
	
	    static createFrom(source: any = {}) {
	        return new MetricPoint(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = source["timestamp"];
	        this.value = source["value"];
	    }
	}
	export class LiveMetrics {
	    latency: MetricPoint[];
	    packetLoss: MetricPoint[];
	    jitter: MetricPoint[];
	    throughput: MetricPoint[];
	    responseTime: MetricPoint[];
	
	    static createFrom(source: any = {}) {
	        return new LiveMetrics(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.latency = this.convertValues(source["latency"], MetricPoint);
	        this.packetLoss = this.convertValues(source["packetLoss"], MetricPoint);
	        this.jitter = this.convertValues(source["jitter"], MetricPoint);
	        this.throughput = this.convertValues(source["throughput"], MetricPoint);
	        this.responseTime = this.convertValues(source["responseTime"], MetricPoint);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

