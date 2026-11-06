import { InvestigationHistory } from "./Investigation";
import { OperationsStatistics } from "./OperationsStatistics";
import { useEffect, useMemo, useState, Fragment, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Controller, useForm, useWatch } from "react-hook-form";
import {
  Alert,
  Badge,
  Button,
  Divider,
  Group,
  Loader,
  Paper,
  SimpleGrid,
  Select,
  Stack,
  Text,
  TextInput,
  Title,
  rem,
} from "@mantine/core";
import {
  Activity,
  ArrowUpRight,
  Gauge,
  Pause,
  Play,
  ShieldCheck,
} from "lucide-react";
import dayjs from "dayjs";
import { Link } from "react-router-dom";
import { TrafficFeed } from "./TrafficFeed";
import { RequestChart } from "./RequestCharts";
import { RATE_SERIES } from "./chart-series";
import { RequestStatistics } from "./RequestStatistics";
import { ratePoints } from "./request-statistics";
import { windowCountUrl } from "./window-count";
import { api, ApiError, forgetSession, queryClient } from "./api";
import { DiscoveryStatusBadge, Failure } from "./shared";
import { discoveryReason } from "./format";

import { empty, trimMetrics, appendLog, appendMetric } from "./telemetry-state";
import type { CandidatePage } from "./types";
import type { Live } from "./telemetry-state";
function useLive(withLogs = true, host = "") {
  const [paused, setPaused] = useState(false);
  const [connected, setConnected] = useState(false);
  const [lastSeen, setLastSeen] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  const query = useQuery({
    queryKey: ["live", host],
    gcTime: 0,
    queryFn: async () => empty(),
    enabled: false,
    initialData: empty,
  });
  useEffect(() => {
    if (paused) return;
    const streams: EventSource[] = [];
    const metricsPath = `/api/v1/events/metrics${host ? `?host=${encodeURIComponent(host)}` : ""}`;
    const paths = withLogs
      ? [metricsPath, "/api/v1/events/logs"]
      : [metricsPath];
    const lastActivity = [Date.now(), Date.now()];
    const opened = new Set<number>();
    let disposed = false;
    const update = (f: (state: Live) => Live) =>
      queryClient.setQueryData<Live>(["live", host], (state) =>
        f(state ?? empty()),
      );
    const connect = (index: number) => {
      const source = new EventSource(paths[index]);
      streams[index] = source;
      source.onopen = () => {
        if (disposed || streams[index] !== source) return;
        opened.add(index);
        setConnected(opened.size === paths.length);
      };
      source.onerror = () => {
        if (disposed || streams[index] !== source) return;
        opened.delete(index);
        setConnected(false);
        void api("/auth/session").catch((error: unknown) => {
          if (!disposed && error instanceof ApiError && error.status === 401) {
            streams.forEach((stream) => stream.close());
            forgetSession();
          }
        });
      };
      const receive = (event: MessageEvent<string>) => {
        if (disposed || streams[index] !== source || event.data.length > 65536)
          return;
        lastActivity[index] = Date.now();
        setLastSeen(lastActivity[index]);
        try {
          const value = JSON.parse(event.data);
          if (event.type === "sync") {
            update((state) => {
              const epochChanged =
                value.snapshot &&
                state.latest &&
                value.snapshot.epoch !== state.latest.epoch;
              const lateSnapshot =
                value.snapshot &&
                state.latest &&
                state.latest.epoch === value.snapshot.epoch &&
                value.snapshot.sequence < state.latest.sequence;
              return {
                ...state,
                gap: state.gap || value.gap || !!epochChanged,
                latest: lateSnapshot
                  ? state.latest
                  : (value.snapshot ?? state.latest),
                metrics: value.snapshot?.observed_at_unix_ms
                  ? appendMetric(state.metrics, value.snapshot, !!value.gap)
                  : state.metrics,
              };
            });
          } else if (event.type === "metrics") {
            update((state) => {
              const metrics = appendMetric(
                state.metrics,
                value.data,
                !!value.gap,
              );
              return {
                ...state,
                latest: metrics === state.metrics ? state.latest : value.data,
                metrics,
                gap:
                  state.gap ||
                  value.gap ||
                  !!(state.latest && state.latest.epoch !== value.data.epoch),
              };
            });
          } else if (event.type === "log") {
            update((state) => ({
              ...state,
              logs: appendLog(state.logs, value.data),
              gap: state.gap || value.gap,
            }));
          } else if (event.type === "gap") {
            update((state) => ({
              ...state,
              gap: true,
              lost: state.lost + Number(value.data?.lost ?? 0),
            }));
          }
        } catch {
          update((state) => ({ ...state, gap: true }));
        }
      };
      ["sync", "metrics", "log", "gap", "heartbeat"].forEach((kind) =>
        source.addEventListener(kind, receive),
      );
    };
    connect(0);
    if (withLogs) connect(1);
    // Intermediaries can leave a half-open stream without delivering onerror.
    // Two owned streams and one timer bound reconnect work and retained state.
    const watchdog = setInterval(() => {
      for (let index = 0; index < paths.length; index++) {
        if (Date.now() - lastActivity[index] > 8000) {
          streams[index].close();
          opened.delete(index);
          setConnected(false);
          update((state) => ({ ...state, gap: true }));
          lastActivity[index] = Date.now();
          connect(index);
        }
      }
    }, 1000);
    return () => {
      disposed = true;
      clearInterval(watchdog);
      streams.forEach((source) => source.close());
    };
  }, [paused, withLogs, host]);
  useEffect(() => {
    const timer = setInterval(() => {
      setNow(Date.now());
      queryClient.setQueryData<Live>(["live", host], (state) =>
        state ? { ...state, metrics: trimMetrics(state.metrics) } : empty(),
      );
    }, 1000);
    return () => clearInterval(timer);
  }, [host]);
  const toggle = () => {
    setPaused((value) => !value);
    setConnected(false);
    queryClient.setQueryData<Live>(["live", host], (state) => ({
      ...(state ?? empty()),
      gap: true,
    }));
  };
  return {
    ...query.data,
    paused,
    toggle,
    connected,
    stale:
      !lastSeen ||
      now - lastSeen > 6000 ||
      !query.data.latest?.observed_at_unix_ms ||
      now - query.data.latest.observed_at_unix_ms > 3000,
  };
}
export function Telemetry({
  traffic = false,
  statistics = false,
}: {
  traffic?: boolean;
  statistics?: boolean;
}) {
  const hostForm = useForm({ defaultValues: { host: "" } });
  const windowForm = useForm({ defaultValues: { host: "", pathPrefix: "" } });
  const [windowFilters, setWindowFilters] = useState({
    host: "",
    pathPrefix: "",
  });
  const chosenHost = useWatch({ control: hostForm.control, name: "host" });
  const host = statistics ? chosenHost : "";
  const live = useLive(traffic, host);
  const countQuery = useQuery({
    queryKey: ["telemetry-window-count", windowFilters],
    queryFn: ({ signal }) =>
      api<{
        count: number;
        source: string;
        observed_at_unix_ms: number;
        start_unix_ms: number;
        end_unix_ms: number;
        coverage_start_unix_ms: number;
        window_seconds: number;
        complete: boolean;
        overflow_requests: number;
        capacity: number;
        tracked_keys: number;
        path_semantics: string;
      }>(windowCountUrl(windowFilters.host, windowFilters.pathPrefix, 900), {
        signal,
      }),
    enabled: !traffic && !statistics,
    refetchInterval: live.paused ? false : 1000,
    gcTime: 0,
  });
  const refetchWindowCount = countQuery.refetch;
  useEffect(() => {
    if (live.paused) void refetchWindowCount();
  }, [live.paused, refetchWindowCount]);
  const onWindowSubmit = windowForm.handleSubmit((values) => {
    setWindowFilters({
      host: values.host.trim(),
      pathPrefix: values.pathPrefix,
    });
  });
  const hasControl = (value: string) =>
    Array.from(value).some((character) => character.charCodeAt(0) < 32);
  const badWindowFilter =
    windowFilters.host.length > 253 ||
    windowFilters.host.trim() !== windowFilters.host ||
    ["/", "?", "#"].some((character) =>
      windowFilters.host.includes(character),
    ) ||
    /\s/.test(windowFilters.host) ||
    windowFilters.pathPrefix.length > 2048 ||
    ["?", "#"].some((character) =>
      windowFilters.pathPrefix.includes(character),
    ) ||
    hasControl(windowFilters.pathPrefix);
  const filteredCount = badWindowFilter ? undefined : countQuery.data;
  const hosts = useQuery({
    queryKey: ["telemetry-hosts"],
    queryFn: ({ signal }) =>
      api<{ hosts: string[]; capacity: number; overflow_requests: number }>(
        "/telemetry/hosts",
        { signal },
      ),
    enabled: statistics,
    refetchInterval: live.paused ? false : 5000,
  });
  const storage = useQuery({
    queryKey: ["telemetry-storage"],
    queryFn: ({ signal }) =>
      api<{
        configured: boolean;
        degraded: boolean;
        dropped?: number;
        backlog?: number;
        written?: number;
        last_success_unix_ms?: number;
      }>("/telemetry/storage", { signal }),
    refetchInterval: live.paused ? false : 5000,
  });
  const metrics = live.latest?.observed_at_unix_ms ? live.latest : null;
  const chartPoints = useMemo(() => ratePoints(live.metrics), [live.metrics]);
  return (
    <Stack gap="md" className={traffic ? "traffic-page" : "overview-page"}>
      <Group
        justify="space-between"
        align="flex-start"
        gap="md"
        mb="xs"
        className="page-heading"
      >
        <div>
          <Text className="eyebrow">
            MONITOR /{" "}
            {traffic
              ? "REQUEST EXPLORER"
              : statistics
                ? "STATISTICS"
                : "GATEWAY OVERVIEW"}
          </Text>
          <Title order={1}>
            {statistics
              ? "Request statistics"
              : traffic
                ? "Live traffic"
                : "Overview"}
          </Title>
          <Text c="dimmed" size="sm" mt="xs">
            {traffic
              ? "Inspect individual requests as they pass through your gateway."
              : statistics
                ? "Explore request patterns, response outcomes and performance."
                : "Traffic, protection and gateway resources at a glance."}
          </Text>
        </div>
        <Group>
          <Badge
            color={
              live.connected && !live.stale && !live.paused ? "teal" : "yellow"
            }
          >
            {live.paused
              ? "Paused"
              : live.stale
                ? "Stale"
                : live.connected
                  ? "Connected"
                  : "Reconnecting"}
          </Badge>
          <Button
            variant="default"
            leftSection={
              live.paused ? <Play size={rem(16)} /> : <Pause size={rem(16)} />
            }
            onClick={live.toggle}
          >
            {live.paused ? "Resume" : "Pause"}
          </Button>
        </Group>
      </Group>
      {(live.gap ||
        live.lost > 0 ||
        (metrics?.totals.dropped_logs ?? 0) > 0) && (
        <Alert color="yellow" title="Incomplete live data" role="status">
          A pause, reconnect or overflow left a gap. Known stream losses:{" "}
          {live.lost}. Gateway dropped logs: {metrics?.totals.dropped_logs ?? 0}
          . Cancelled requests (partial records where available):{" "}
          {metrics?.totals.cancelled ?? 0}. Use history for available persisted
          records.
        </Alert>
      )}
      {!metrics && (
        <Group role="status">
          <Loader size="sm" />
          Waiting for gateway metrics…
        </Group>
      )}
      {storage.isPending && (
        <Text role="status">Checking history storage…</Text>
      )}
      {storage.isError && (
        <Group>
          <Failure error={storage.error} />
          <Button variant="default" onClick={() => void storage.refetch()}>
            Retry history storage
          </Button>
        </Group>
      )}
      {storage.data && (
        <Alert
          color={storage.data.degraded ? "yellow" : "teal"}
          title={
            storage.data.configured
              ? storage.data.degraded
                ? "History degraded"
                : "History connected"
              : "History not configured"
          }
        >
          Backlog: {storage.data.backlog ?? 0} · Dropped or unacknowledged:{" "}
          {storage.data.dropped ?? 0} · Written: {storage.data.written ?? 0}
        </Alert>
      )}
      {!traffic && !statistics && (
        <Paper withBorder p="md" aria-label="Realtime request count">
          <Stack gap="sm">
            <Group justify="space-between">
              <div>
                <Text fw={600}>Incoming requests · last 15 minutes</Text>
                <Text size="xs" c="dimmed">
                  Gateway request starts · updates every second
                </Text>
              </div>
              <Text size="xl" fw={700} role="status">
                {countQuery.isPending
                  ? "…"
                  : (filteredCount?.count.toLocaleString() ?? "Unavailable")}
              </Text>
            </Group>
            <form
              onSubmit={(event) => {
                void onWindowSubmit(event);
              }}
            >
              <Group align="end" wrap="wrap">
                <Controller
                  name="host"
                  control={windowForm.control}
                  render={({ field }) => (
                    <TextInput
                      label="Host"
                      placeholder="All hosts"
                      aria-label="Count host filter"
                      maxLength={253}
                      {...field}
                    />
                  )}
                />
                <Controller
                  name="pathPrefix"
                  control={windowForm.control}
                  render={({ field }) => (
                    <TextInput
                      label="Path prefix"
                      placeholder="All paths"
                      aria-label="Path prefix"
                      maxLength={2048}
                      {...field}
                    />
                  )}
                />
                <Button type="submit">Apply filters</Button>
              </Group>
            </form>
            <Text size="xs" c="dimmed">
              Path uses a literal, case-sensitive prefix on the original path;
              query strings are excluded. Counts reset when the gateway
              restarts.
            </Text>
            {countQuery.isError && (
              <Group>
                <Failure error={countQuery.error} />
                <Button
                  variant="default"
                  onClick={() => void countQuery.refetch()}
                >
                  Retry count
                </Button>
              </Group>
            )}
            {countQuery.data && !countQuery.data.complete && (
              <Alert
                color="orange"
                title={
                  countQuery.data.overflow_requests
                    ? "Count is partial"
                    : "Window coverage warming up"
                }
              >
                {countQuery.data.overflow_requests
                  ? `Registry/lock overflow: ${countQuery.data.overflow_requests} requests could not be tracked within ${countQuery.data.capacity} distinct host/path entries. This count may be low.`
                  : `The counter has observed traffic since ${dayjs(countQuery.data.coverage_start_unix_ms).format("HH:mm:ss")}; a full 15-minute window is not yet available.`}
              </Alert>
            )}
            {filteredCount && (
              <Text size="xs" c="dimmed">
                Window {dayjs(filteredCount.start_unix_ms).format("HH:mm:ss")}–
                {dayjs(filteredCount.end_unix_ms).format("HH:mm:ss")} · observed{" "}
                {dayjs(filteredCount.observed_at_unix_ms).format("HH:mm:ss")} ·{" "}
                {filteredCount.tracked_keys}/{filteredCount.capacity} keys
                tracked
              </Text>
            )}
          </Stack>
        </Paper>
      )}
      {statistics && (
        <Paper withBorder p="md">
          <Stack gap="xs">
            <Controller
              name="host"
              control={hostForm.control}
              render={({ field }) => (
                <Select
                  label="Host"
                  description="Applies to live statistics and Prometheus incoming history. Operational views below use their own route scope."
                  placeholder={hosts.isPending ? "Loading hosts…" : "All hosts"}
                  searchable
                  clearable
                  data={[
                    { value: "", label: "All hosts" },
                    ...(hosts.data?.hosts ?? []).map((name) => ({
                      value: name,
                      label: name,
                    })),
                  ]}
                  value={field.value || null}
                  onChange={(value) => field.onChange(value ?? "")}
                  onBlur={field.onBlur}
                  ref={field.ref}
                  disabled={hosts.isPending}
                />
              )}
            />
            {hosts.isError && (
              <Group>
                <Failure error={hosts.error} />
                <Button variant="default" onClick={() => void hosts.refetch()}>
                  Retry hosts
                </Button>
              </Group>
            )}
            {hosts.data && !hosts.data.hosts.length && (
              <Text size="sm" c="dimmed">
                No validated request hosts have been observed yet.
              </Text>
            )}
            {!!hosts.data?.overflow_requests && (
              <Alert color="orange" title="Host statistics capacity reached">
                Tracking {hosts.data.capacity} hosts.{" "}
                {hosts.data.overflow_requests.toLocaleString()} requests for
                additional hosts are included in gateway totals and available
                traffic logs only.
              </Alert>
            )}
            {host && hosts.data && !hosts.data.hosts.includes(host) && (
              <Alert color="orange" title="Host statistics unavailable">
                This host is no longer tracked. Select an available host or
                clear the filter.
              </Alert>
            )}
          </Stack>
        </Paper>
      )}
      {statistics && metrics && (
        <RequestStatistics metrics={live.metrics} latest={metrics} />
      )}
      {!statistics && !traffic && (
        <>
          <Group justify="space-between">
            <Text size="sm" c="dimmed">
              {metrics
                ? `Observed ${dayjs(metrics.observed_at_unix_ms).format("HH:mm:ss")} · ${metrics.window_ms} ms window`
                : "Waiting for an observed metrics window"}
            </Text>
            <Button
              component={Link}
              to="/traffic"
              variant="subtle"
              rightSection={<ArrowUpRight size={rem(15)} />}
            >
              Explore live traffic
            </Button>
          </Group>
          <SimpleGrid cols={{ base: 2, lg: 4 }} spacing="md">
            {[
              {
                label: "Incoming / s",
                value:
                  metrics?.incoming_rps.toLocaleString(undefined, {
                    maximumFractionDigits: 0,
                  }) ?? "—",
                detail: "Request starts",
                icon: Activity,
              },
              {
                label: "Blocked / s",
                value:
                  metrics?.blocked_rps.toLocaleString(undefined, {
                    maximumFractionDigits: 0,
                  }) ?? "—",
                detail: "Security decisions",
                icon: ShieldCheck,
              },
              {
                label: "Active requests",
                value: metrics?.totals.active_requests ?? "—",
                detail: "Currently in flight",
                icon: Gauge,
              },
              {
                label: "Latency p95",
                value:
                  metrics?.latency_p95_ms != null
                    ? `${metrics.latency_p95_ms} ms`
                    : "—",
                detail: "Completed requests",
                icon: Activity,
              },
            ].map(({ label, value, detail, icon: Icon }) => (
              <Paper withBorder p="md" key={label} className="overview-stat">
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">
                    {label}
                  </Text>
                  <Icon size={rem(17)} aria-hidden="true" />
                </Group>
                <Text
                  fz={{ base: rem(20), lg: rem(24) }}
                  fw={600}
                  mt="sm"
                  mb={rem(6)}
                  style={{
                    letterSpacing: "-.04em",
                    fontVariantNumeric: "tabular-nums",
                  }}
                >
                  {value}
                </Text>
                <Text size="xs" c="dimmed">
                  {detail}
                </Text>
              </Paper>
            ))}
          </SimpleGrid>
          <Paper withBorder p="md">
            <Group justify="space-between" mb="md">
              <div>
                <Title order={2}>Request rate · last 15 minutes</Title>
                <Text c="dimmed" size="sm" mt={rem(4)}>
                  Starts, upstream forwarding and security blocks.
                </Text>
              </div>
              <Button
                component={Link}
                to="/statistics"
                variant="subtle"
                rightSection={<ArrowUpRight size={rem(15)} />}
              >
                View statistics
              </Button>
            </Group>
            <RequestChart
              points={chartPoints}
              series={RATE_SERIES}
              label={`Request rate chart. Latest incoming ${metrics?.incoming_rps.toLocaleString(undefined, { maximumFractionDigits: 0 }) ?? "unavailable"}, forwarded ${metrics?.forwarded_rps.toLocaleString(undefined, { maximumFractionDigits: 0 }) ?? "unavailable"}, blocked ${metrics?.blocked_rps.toLocaleString(undefined, { maximumFractionDigits: 0 }) ?? "unavailable"} requests per second.`}
              unit="requests / second"
              fractionDigits={0}
            />
          </Paper>
          <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="md">
            <Paper withBorder p="md">
              <Title order={2} mb="md">
                Gateway resources
              </Title>
              <MetricFacts
                items={[
                  {
                    label: "Active connections",
                    value: metrics?.totals.active_connections ?? "Unavailable",
                  },
                  {
                    label: "Process RSS",
                    value:
                      metrics?.resources?.resident_bytes != null
                        ? `${(metrics.resources.resident_bytes / 1048576).toFixed(1)} MiB`
                        : "Unavailable",
                  },
                  {
                    label: "Request body throughput",
                    value: `${metrics?.received_bytes_per_second?.toFixed(0) ?? "—"} B/s`,
                  },
                  {
                    label: "Upstream response throughput",
                    value: `${metrics?.response_bytes_per_second?.toFixed(0) ?? "—"} B/s`,
                  },
                  {
                    label: "Log queue",
                    value: metrics
                      ? `${metrics.log_queue_depth} / ${metrics.log_queue_capacity}`
                      : "Unavailable",
                  },
                ]}
              />
            </Paper>
            <Paper withBorder p="md">
              <Title order={2} mb="md">
                Request outcomes
              </Title>
              <MetricFacts
                items={[
                  {
                    label: "Requests started",
                    value: metrics?.totals.incoming ?? "—",
                    testId: "telemetry-incoming-total",
                  },
                  {
                    label: "Completed",
                    value: metrics?.totals.completed ?? "—",
                  },
                  {
                    label: "Upstream errors",
                    value: metrics?.totals.upstream_errors ?? "—",
                  },
                  {
                    label: "Cancelled",
                    value: metrics?.totals.cancelled ?? "—",
                  },
                ]}
              />
              <Text size="xs" c="dimmed" mt="md">
                Cumulative gateway counters. Latency measures completed
                requests, including streams.
              </Text>
            </Paper>
          </SimpleGrid>
          <DiscoveryFreshness paused={live.paused} />
        </>
      )}
      {traffic && (
        <>
          <TrafficFeed logs={live.logs} />
          <InvestigationHistory />
        </>
      )}
      {statistics && <OperationsStatistics />}
      {statistics && <MetricsHistory key={host} host={host} />}
    </Stack>
  );
}
function MetricFacts({
  items,
}: {
  items: { label: string; value: ReactNode; testId?: string }[];
}) {
  return (
    <Stack component="dl" m={0} gap={0}>
      {items.map((item, i) => (
        <Fragment key={item.label}>
          {i > 0 && <Divider />}
          <Group
            component="div"
            justify="space-between"
            align="baseline"
            wrap="nowrap"
            py="xs"
            gap="md"
          >
            <Text component="dt" size="sm" c="dimmed">
              {item.label}
            </Text>
            <Text
              component="dd"
              size="sm"
              fw={600}
              m={0}
              ta="right"
              data-testid={item.testId}
            >
              {item.value}
            </Text>
          </Group>
        </Fragment>
      ))}
    </Stack>
  );
}
const HISTORY_SERIES = [RATE_SERIES[0]];
function MetricsHistory({ host }: { host: string }) {
  const [range, setRange] = useState<{ start: number; end: number } | null>(
    null,
  );
  const history = useQuery({
    queryKey: ["metrics-history", host, range],
    queryFn: ({ signal }) =>
      api<{
        source: string;
        data: { result: { values: [number, string][] }[] };
      }>(
        `/history/metrics?start=${range!.start}&end=${range!.end}&step=15&series=incoming${host ? `&host=${encodeURIComponent(host)}` : ""}`,
        { signal },
      ),
    enabled: !!range,
  });
  const points =
    history.data?.data.result.flatMap((series) =>
      series.values.flatMap(([time, rate], index) => {
        const point = {
          time: time * 1000,
          rate: Number.isFinite(Number(rate)) ? Number(rate) : null,
        };
        return index && time - series.values[index - 1][0] > 22.5
          ? [{ time: point.time - 1, rate: null }, point]
          : [point];
      }),
    ) ?? [];
  return (
    <Paper withBorder p="md">
      <Stack>
        <Group justify="space-between">
          <Title order={2}>Metrics history</Title>
          <Button
            variant="default"
            onClick={() => {
              const end = Math.floor(Date.now() / 1000);
              setRange({ start: end - 3600, end });
            }}
          >
            Load incoming RPS history
          </Button>
        </Group>
        <Text size="sm" c="dimmed">
          Prometheus · {host || "All hosts"} · previous hour · 15-second step.
          Gaps and counter resets follow Prometheus rate semantics.
        </Text>
        {history.isFetching && (
          <Text role="status">Loading metrics history…</Text>
        )}
        {history.isError && <Failure error={history.error} />}
        {history.data &&
          (points.length ? (
            <RequestChart
              points={points.map((point) => ({
                time: point.time,
                values: [point.rate],
              }))}
              series={HISTORY_SERIES}
              label="Historical incoming requests per second from Prometheus"
              unit="requests / second"
            />
          ) : (
            <Text>No Prometheus samples in this window.</Text>
          ))}
      </Stack>
    </Paper>
  );
}

function DiscoveryFreshness({ paused }: { paused: boolean }) {
  const docker = useQuery({
    queryKey: ["discovery-freshness", "docker"],
    queryFn: ({ signal }) =>
      api<CandidatePage>("/discovery/docker/candidates?limit=1", { signal }),
    refetchInterval: paused ? false : 10000,
  });
  const host = useQuery({
    queryKey: ["discovery-freshness", "host"],
    queryFn: ({ signal }) =>
      api<CandidatePage>("/discovery/host-ports/candidates?limit=1", {
        signal,
      }),
    refetchInterval: paused ? false : 10000,
  });
  return (
    <Paper withBorder p="md">
      <Title order={2} size="h4" mb="sm">
        Discovery freshness
      </Title>
      <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md">
        {(
          [
            ["Docker", docker],
            ["Host TCP ports", host],
          ] as const
        ).map(([name, query]) => (
          <Stack
            key={name}
            gap="xs"
            component="section"
            aria-label={`${name} discovery`}
          >
            <Group justify="space-between" gap="sm">
              <Text size="sm" fw={600}>
                {name}
              </Text>
              {query.isPending ? (
                <Badge color="gray">Loading</Badge>
              ) : (
                <DiscoveryStatusBadge
                  data={query.isError ? undefined : query.data}
                />
              )}
            </Group>
            {query.isPending ? (
              <Text size="xs" role="status">
                Loading source…
              </Text>
            ) : query.isError ? (
              <Text size="xs" c="dimmed">
                Source could not be loaded. Retrying automatically.
              </Text>
            ) : (
              <>
                <Text size="xs" c="dimmed">
                  {query.data.observed_at_unix_ms != null
                    ? `Last observed ${dayjs(query.data.observed_at_unix_ms).format("HH:mm:ss")}`
                    : "No observation yet"}
                </Text>
                {query.data.error && (
                  <Text size="xs" c="dimmed" title={query.data.error}>
                    {discoveryReason(query.data.error)}
                  </Text>
                )}
              </>
            )}
          </Stack>
        ))}
      </SimpleGrid>
    </Paper>
  );
}
