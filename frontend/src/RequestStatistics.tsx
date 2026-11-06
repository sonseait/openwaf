import dayjs from "dayjs";
import { useMemo } from "react";
import {
  Alert,
  Flex,
  Paper,
  Progress,
  SimpleGrid,
  Stack,
  Tabs,
  Text,
  Title,
  rem,
} from "@mantine/core";
import { scaleLinear } from "d3-scale";
import { RequestChart, type ChartSeries } from "./RequestCharts";
import { RATE_SERIES } from "./chart-series";
import { countPoints, ratePoints, metricPoints } from "./request-statistics";
import { BlockRatio, TrafficBreakdown } from "./TrafficBreakdown";
import type { Metrics } from "./telemetry-state";

const counts: ChartSeries[] = [
  { ...RATE_SERIES[0], label: "Started" },
  { ...RATE_SERIES[1], label: "Completed" },
  RATE_SERIES[2],
];
const responses: ChartSeries[] = [
  { label: "No final response / other", color: "#6f878b" },
  { label: "1xx", color: "#9964ce" },
  { label: "2xx", color: "#128e86" },
  { label: "3xx", color: "#347fb9" },
  { label: "4xx", color: "#c96424" },
  { label: "5xx", color: "#cc5371" },
];
const LATENCY_SERIES = ["p50", "p95", "p99"].map((label, i) => ({
  label,
  color: RATE_SERIES[i].color,
}));
const BANDWIDTH_SERIES = [
  { label: "Request body", color: RATE_SERIES[0].color },
  { label: "Upstream response body", color: RATE_SERIES[1].color },
];
export function RequestStatistics({
  metrics,
  latest,
}: {
  metrics: Metrics[];
  latest: Metrics;
}) {
  const rate = useMemo(() => ratePoints(metrics), [metrics]);
  const volume = useMemo(() => countPoints(metrics), [metrics]);
  const status = useMemo(() => countPoints(metrics, true), [metrics]);
  const performance = useMemo(
    () =>
      metricPoints(metrics, (m) => [
        m.latency_p50_ms,
        m.latency_p95_ms,
        m.latency_p99_ms,
      ]),
    [metrics],
  );
  const bandwidth = useMemo(
    () =>
      metricPoints(metrics, (m) => [
        m.received_bytes_per_second ?? null,
        m.response_bytes_per_second ?? null,
      ]),
    [metrics],
  );
  const totals = latest.totals;
  const bar = scaleLinear()
    .domain([0, Math.max(1, ...totals.status_classes)])
    .range([0, 100]);
  return (
    <Stack gap="md">
      {latest.host && (
        <Alert title={`Host: ${latest.host}`} color="teal">
          All request statistics below are scoped to this host. Collection
          started{" "}
          {latest.statistics_started_at_unix_ms
            ? dayjs(latest.statistics_started_at_unix_ms).format(
                "YYYY-MM-DD HH:mm:ss Z",
              )
            : "at an unavailable time"}
          ; older gateway totals are not backfilled.
        </Alert>
      )}
      <Text size="sm">
        Observed{" "}
        {dayjs(latest.observed_at_unix_ms).format("YYYY-MM-DD HH:mm:ss Z")} ·
        Sample window {latest.window_ms} ms
      </Text>
      <Text size="sm" c="dimmed">
        Gateway counters · cumulative totals across restarts when persistence is
        configured. Charts retain up to 15 minutes of live observations.
      </Text>
      {latest.persistence?.configured ? (
        <Alert
          color={latest.persistence.degraded ? "orange" : "teal"}
          title={
            latest.persistence.degraded
              ? "Statistics persistence degraded"
              : "Statistics persisted in PostgreSQL"
          }
        >
          Last successful checkpoint:{" "}
          {latest.persistence.last_success_unix_ms
            ? dayjs(latest.persistence.last_success_unix_ms).format(
                "YYYY-MM-DD HH:mm:ss Z",
              )
            : "none"}
          . Saved every {latest.persistence.interval_ms / 1000} seconds and on
          graceful shutdown.
          {latest.persistence.degraded &&
            " Traffic continues; changes since the last successful checkpoint may be lost on restart."}
        </Alert>
      ) : (
        <Alert color="orange" title="Statistics persistence unavailable">
          Counters cover this process only and reset on restart.
        </Alert>
      )}
      <SimpleGrid cols={{ base: 2, md: 3, xl: 6 }}>
        {[
          ["Requests started", totals.incoming],
          ["Completed", totals.completed],
          ["Forwarded", totals.forwarded],
          ["Blocked", totals.blocked],
          ["Cancelled", totals.cancelled],
          ["Upstream errors", totals.upstream_errors],
        ].map(([label, value]) => (
          <Paper key={label} withBorder p="md">
            <Text size="xs" c="dimmed">
              {label}
            </Text>
            <Text className="stat-value" fw={700} size="xl">
              {Number(value).toLocaleString()}
            </Text>
          </Paper>
        ))}
      </SimpleGrid>
      <Tabs defaultValue="volume" keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="volume">Request volume</Tabs.Tab>
          <Tabs.Tab value="responses">Response outcomes</Tabs.Tab>
          <Tabs.Tab value="clients">GEO & user agents</Tabs.Tab>
          <Tabs.Tab value="performance">Performance</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="volume" pt="md">
          <Stack gap="md">
            <BlockRatio received={totals.incoming} blocked={totals.blocked} />
            <Paper withBorder p="md">
              <Title order={2}>Request rate · last 15 minutes</Title>
              <Text size="sm" c="dimmed" mb="sm">
                Incoming counts request starts; forwarded and blocked count
                their respective decisions.
              </Text>
              <RequestChart
                points={rate}
                series={RATE_SERIES}
                label="Request rate chart, incoming, forwarded and blocked requests per second"
                unit="requests / second"
              />
            </Paper>
            <Paper withBorder p="md">
              <Title order={2}>Request counts per observed interval</Title>
              <Text size="sm" c="dimmed" mb="sm">
                Counter changes between consecutive snapshots, normally one
                second apart. Missing intervals stay blank; starts and
                completions can differ for long requests.
              </Text>
              <RequestChart
                points={volume}
                series={counts}
                label="Request count chart, started, completed and blocked per observed interval"
                unit="requests / interval"
              />
            </Paper>
          </Stack>
        </Tabs.Panel>
        <Tabs.Panel value="responses" pt="md">
          <Stack gap="md">
            <Paper withBorder p="md">
              <Title order={2}>Response distribution</Title>
              <Text size="sm" c="dimmed" mb="md">
                Completed requests in the cumulative gateway counters. HTTP
                error responses and security blocks are different counters.
              </Text>
              <Stack
                component="ul"
                p={0}
                m={0}
                gap="md"
                style={{ listStyle: "none" }}
                aria-label="Completed response counts by status class"
              >
                {responses.map((item, i) => (
                  <Flex
                    component="li"
                    align="center"
                    key={item.label}
                    wrap="nowrap"
                    gap={{ base: "xs", sm: "md" }}
                  >
                    <Text
                      size="sm"
                      w={{ base: rem(105), sm: rem(170) }}
                      flex="0 0 auto"
                    >
                      {item.label}
                    </Text>
                    <Progress
                      value={bar(totals.status_classes[i] ?? 0)}
                      color={item.color}
                      size={rem(14)}
                      radius="xs"
                      flex={1}
                      miw={rem(20)}
                      aria-hidden="true"
                    />
                    <Text
                      component="strong"
                      size="sm"
                      fw={700}
                      ta="right"
                      miw={rem(40)}
                      style={{ fontVariantNumeric: "tabular-nums" }}
                    >
                      {(totals.status_classes[i] ?? 0).toLocaleString()}
                    </Text>
                  </Flex>
                ))}
              </Stack>
              {totals.completed === 0 && (
                <Text size="sm" c="dimmed">
                  No completed requests recorded.
                </Text>
              )}
            </Paper>
            <Paper withBorder p="md">
              <Title order={2}>Completed responses per observed interval</Title>
              <Text size="sm" c="dimmed" mb="sm">
                Groups refer to final response status. Missing observations are
                gaps, not zero traffic.
              </Text>
              <RequestChart
                points={status}
                series={responses}
                label="Response count chart by HTTP status class per observed interval"
                unit="completed requests / interval"
              />
            </Paper>
          </Stack>
        </Tabs.Panel>
        <Tabs.Panel value="clients" pt="md">
          <Stack gap="md">
            <Text size="sm" c="dimmed">
              Source: {latest.dimensions?.source ?? "unavailable"} · Received
              and blocked cumulative counters. Approximate snapshots may briefly
              differ during concurrent updates.
            </Text>
            <TrafficBreakdown
              title="Requests by country"
              items={latest.dimensions?.countries}
              countries
              description="Local GeoIP lookup of the client IP resolved through trusted-proxy rules. Unavailable: no database; Unknown: no country match; Lookup failed: database lookup error; Unattributed: client identity not resolved, including early rejects. Top 10 by received traffic; remaining groups are combined."
            />
            <TrafficBreakdown
              title="Requests by user agent"
              items={latest.dimensions?.user_agents}
              description="Coarse browser, crawler and CLI families from the client-supplied User-Agent. Claims can be spoofed; raw headers are never retained. Missing, unrecognized and oversized values have explicit buckets."
            />
            <TrafficBreakdown
              title="Requests by HTTP method"
              items={latest.dimensions?.methods}
              description="Fixed standard method groups. Nonstandard methods are combined into OTHER."
            />
          </Stack>
        </Tabs.Panel>
        <Tabs.Panel value="performance" pt="md">
          <Stack gap="md">
            <Paper withBorder p="md">
              <Title order={2}>Completed request latency</Title>
              <Text size="sm" c="dimmed" mb="sm">
                Per-window p50 / p95 / p99 histogram upper bounds, in
                milliseconds. Empty windows or unbounded percentiles stay blank;
                percentiles are not averaged.
              </Text>
              <RequestChart
                points={performance}
                series={LATENCY_SERIES}
                label="Completed request latency chart, p50 p95 and p99 milliseconds"
                unit="milliseconds"
              />
            </Paper>
            <Paper withBorder p="md">
              <Title order={2}>Body throughput</Title>
              <Text size="sm" c="dimmed" mb="sm">
                Request body received and upstream response body observed per
                second. Excludes protocol headers and wire overhead.
              </Text>
              <RequestChart
                points={bandwidth}
                series={BANDWIDTH_SERIES}
                label="Body throughput chart, received request and observed upstream response bytes per second"
                unit="bytes / second"
              />
            </Paper>
          </Stack>
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
