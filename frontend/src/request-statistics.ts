import type { Metrics } from "./telemetry-state";
import type { ChartPoint } from "./RequestCharts";

export function continuous(previous: Metrics, next: Metrics): boolean {
  const elapsed = next.observed_at_unix_ms - previous.observed_at_unix_ms;
  return (
    previous.epoch === next.epoch &&
    next.sequence === previous.sequence + 1 &&
    !next.stream_gap &&
    elapsed > 0 &&
    elapsed <= Math.max(next.window_ms * 1.5, 1500)
  );
}

export function metricPoints(
  metrics: Metrics[],
  values: (metric: Metrics) => (number | null)[],
): ChartPoint[] {
  return metrics.flatMap((metric, index) => {
    const point = {
      time: metric.observed_at_unix_ms,
      values: values(metric),
    };
    return index && !continuous(metrics[index - 1], metric)
      ? [{ time: point.time - 1, values: point.values.map(() => null) }, point]
      : [point];
  });
}

export function ratePoints(metrics: Metrics[]): ChartPoint[] {
  return metricPoints(metrics, (m) => [
    m.incoming_rps,
    m.forwarded_rps,
    m.blocked_rps,
  ]);
}

// Counts come from cumulative counters, never from the sampled live log ring.
// Missing intervals and restarts remain unknown rather than appearing as zeros.
export function countPoints(
  metrics: Metrics[],
  responses = false,
): ChartPoint[] {
  return metrics.map((metric, index) => {
    const previous = metrics[index - 1];
    const current = responses
      ? metric.totals.status_classes
      : [
          metric.totals.incoming,
          metric.totals.completed,
          metric.totals.blocked,
        ];
    const before =
      previous &&
      (responses
        ? previous.totals.status_classes
        : [
            previous.totals.incoming,
            previous.totals.completed,
            previous.totals.blocked,
          ]);
    return {
      time: metric.observed_at_unix_ms,
      values: current.map((value, i) =>
        previous &&
        continuous(previous, metric) &&
        Number.isFinite(value) &&
        Number.isFinite(before[i]) &&
        value >= before[i]
          ? value - before[i]
          : null,
      ),
    };
  });
}
