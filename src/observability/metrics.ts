import {
  collectDefaultMetrics,
  Counter,
  Histogram,
  Registry,
} from "prom-client";

export class Metrics {
  public readonly registry = new Registry();
  public readonly authentication = new Counter({
    help: "Authentication operation outcomes",
    labelNames: ["operation", "outcome"],
    name: "auth_operations_total",
    registers: [this.registry],
  });
  public readonly authorization = new Counter({
    help: "Authorization decision outcomes",
    labelNames: ["permission", "outcome"],
    name: "authorization_decisions_total",
    registers: [this.registry],
  });
  public readonly requests = new Histogram({
    buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
    help: "HTTP request duration in seconds",
    labelNames: ["method", "route", "status_code"],
    name: "http_request_duration_seconds",
    registers: [this.registry],
  });

  public constructor(prefix = "saas_auth_") {
    collectDefaultMetrics({ prefix, register: this.registry });
  }
}
