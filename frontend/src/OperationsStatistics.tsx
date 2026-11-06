import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Badge,
  Button,
  Group,
  NativeSelect,
  Paper,
  SimpleGrid,
  Stack,
  Tabs,
  Text,
  Title,
} from "@mantine/core";
import { Link, useSearchParams } from "react-router-dom";
import dayjs from "dayjs";
import { api } from "./api";
import { DataTable } from "./DataTable";
import { Failure } from "./shared";
import { ChangeMarkers, type RouteStatistics } from "./Investigation";
import { ResourceCapacity, type ResourceDiagnostics } from "./ResourceCapacity";
import {
  defaultRange,
  investigationLink,
  investigationParams,
} from "./investigation-state";
import { RequestChart } from "./RequestCharts";
import { InspectionCoverage } from "./TrafficProfiles";

type Bin = {
  bucket_ms: number | string;
  start_ms: number | string;
  end_ms: number | string;
  observed_ms: number | string;
  incoming: number | string;
  completed: number | string;
  blocked: number | string;
  upstream_errors: number | string;
  dropped_logs: number | string;
  would_block: number | string;
  rule_matches: number | string;
  status_classes: (number | string)[];
  p95_ms: number | null;
  p99_ms: number | null;
};
interface Rollup {
  items: Bin[];
  source: string;
  bucket_ms: number;
  version_scope: string;
  health: { degraded: boolean; dropped: number; last_success_unix_ms: number };
}
interface Top {
  items: Record<
    "routes" | "rules" | "clients",
    { label: string; records: number | string; blocked: number | string }[]
  >;
  health: { degraded: boolean; dropped: number };
}
function percentile(bins: number[], pct: number) {
  const total = bins.reduce((a, b) => a + b, 0);
  if (!total) return "Unavailable";
  let n = 0;
  const limits = [
    1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 30000, 60000,
  ];
  for (let i = 0; i < bins.length; i++) {
    n += bins[i];
    if (n >= Math.ceil((total * pct) / 100))
      return limits[i] === undefined ? "Unbounded" : `${limits[i]} ms`;
  }
  return "Unavailable";
}
export function OperationsStatistics() {
  const [params, setParams] = useSearchParams();
  const [initialEnd] = useState(Date.now);
  const [paused, setPaused] = useState(false);
  const [tab, setTab] = useState<string | null>("service");
  const range = defaultRange(params, initialEnd);
  const route = params.get("route_id") ?? "";
  const comparison = params.get("compare") ?? "previous";
  const offset =
    comparison === "day"
      ? 86400000
      : comparison === "week"
        ? 7 * 86400000
        : range.end - range.start;
  const args = (start: number, end: number) =>
    `start_ms=${start}&end_ms=${end}${route ? `&route_id=${encodeURIComponent(route)}` : ""}`;
  const routes = useQuery({
    queryKey: ["route-statistics"],
    queryFn: ({ signal }) =>
      api<RouteStatistics>("/telemetry/routes", { signal }),
    refetchInterval: paused ? false : 5000,
  });
  const current = useQuery({
    queryKey: ["rollup", range.start, range.end, route],
    queryFn: ({ signal }) =>
      api<Rollup>(`/history/statistics?${args(range.start, range.end)}`, {
        signal,
      }),
  });
  const previous = useQuery({
    queryKey: ["rollup", range.start - offset, range.end - offset, route],
    queryFn: ({ signal }) =>
      api<Rollup>(
        `/history/statistics?${args(range.start - offset, range.end - offset)}`,
        { signal },
      ),
  });
  const diagnostics = useQuery({
    queryKey: ["capacity-diagnostics"],
    queryFn: ({ signal }) =>
      api<ResourceDiagnostics>("/telemetry/dependencies", { signal }),
    enabled: tab === "capacity",
    refetchInterval: paused ? false : 5000,
  });
  const filters = investigationParams(params);
  filters.set("start_ms", String(range.start));
  filters.set("end_ms", String(range.end));
  filters.set("limit", "100");
  const top = useQuery({
    queryKey: ["investigation-top", filters.toString()],
    queryFn: ({ signal }) => api<Top>(`/history/top?${filters}`, { signal }),
    enabled: tab === "investigation",
  });
  const points = useMemo(
    () =>
      current.data?.items.map((r, i, rows) => {
        const observed = Number(r.observed_ms);
        const bucket = Number(r.bucket_ms);
        const gap =
          observed < current.data!.bucket_ms ||
          Number(r.end_ms) - Number(r.start_ms) >
            current.data!.bucket_ms + 1000 ||
          (i > 0 &&
            bucket - Number(rows[i - 1].bucket_ms) !== current.data!.bucket_ms);
        return {
          time: bucket,
          values: [
            gap ? null : (Number(r.incoming) * 1000) / observed,
            gap ? null : r.p95_ms,
            gap ? null : r.p99_ms,
          ],
        };
      }) ?? [],
    [current.data],
  );
  const rows =
    routes.data?.items.filter((r) => !route || r.route_id === route) ?? [];
  return (
    <Paper withBorder p="md">
      <Stack>
        <Group justify="space-between">
          <Title order={2}>Operational views</Title>
          <Button variant="default" onClick={() => setPaused(!paused)}>
            {paused ? "Resume route refresh" : "Pause route refresh"}
          </Button>
        </Group>
        <Badge color={paused || routes.isError ? "orange" : "teal"}>
          {paused
            ? "Paused"
            : routes.isError
              ? "Route data stale"
              : "Route polling"}
        </Badge>
        <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }}>
          <NativeSelect
            label="Route scope"
            value={route}
            data={[
              { value: "", label: "Gateway / all routes" },
              ...(routes.data?.items.map((r) => ({
                value: r.route_id,
                label: r.route_id,
              })) ?? []),
              ...(route && !routes.data?.items.some((r) => r.route_id === route)
                ? [{ value: route, label: `${route} (not observed)` }]
                : []),
            ]}
            onChange={(e) => {
              const next = new URLSearchParams(params);
              if (e.target.value) next.set("route_id", e.target.value);
              else next.delete("route_id");
              setParams(next);
            }}
          />
          <NativeSelect
            label="Compare with"
            value={comparison}
            data={[
              { value: "previous", label: "Previous equal window" },
              { value: "day", label: "Same time yesterday" },
              { value: "week", label: "Same time last week" },
            ]}
            onChange={(e) => {
              const next = new URLSearchParams(params);
              next.set("compare", e.target.value);
              setParams(next);
            }}
          />
          <NativeSelect
            label="History window"
            value="custom"
            data={[
              {
                value: "custom",
                label: `${dayjs(range.start).format("MM-DD HH:mm")} → ${dayjs(range.end).format("MM-DD HH:mm Z")}`,
              },
              ...[1, 24, 168, 720].map((h) => ({
                value: String(h),
                label: `Previous ${h} hours`,
              })),
            ]}
            onChange={(e) => {
              if (e.target.value === "custom") return;
              const end = Date.now();
              const next = new URLSearchParams(params);
              next.set("end_ms", String(end));
              next.set(
                "start_ms",
                String(end - Number(e.target.value) * 3600000),
              );
              setParams(next);
            }}
          />
        </SimpleGrid>
        <Text size="sm">
          Route counters: current process, independent of traffic logs;{" "}
          {routes.data?.items.length ?? "—"}/{routes.data?.capacity ?? 128}{" "}
          stable IDs, overflow {routes.data?.overflow_requests ?? "unavailable"}
          . Retired slots remain until restart. Route SLO targets are deferred.
        </Text>
        {(params.has("host") ||
          params.has("action") ||
          params.has("config_version") ||
          params.has("rule_id") ||
          params.has("layer") ||
          params.has("country") ||
          params.has("client_ip") ||
          params.has("path") ||
          params.has("status_class")) && (
          <Alert color="orange">
            Rollups support gateway or route scope only, across config versions.
            Other retained filters apply to request investigation, not these
            counter totals. Host incoming history remains available below.
          </Alert>
        )}
        {routes.isError && <Failure error={routes.error} />}
        <Tabs value={tab} onChange={setTab} keepMounted={false}>
          <Tabs.List>
            <Tabs.Tab value="service">Service health</Tabs.Tab>
            <Tabs.Tab value="protection">Protection</Tabs.Tab>
            <Tabs.Tab value="investigation">Investigation</Tabs.Tab>
            <Tabs.Tab value="capacity">Capacity</Tabs.Tab>
          </Tabs.List>
          <Tabs.Panel value="service" pt="md">
            <Stack>
              <Text>
                Latency upper bounds below use completed-request histograms for
                the current process. Route metrics combine configuration
                versions; inspect request metadata for a specific version.
              </Text>
              <DataTable
                idAccessor="route_id"
                records={rows}
                noRecordsText="No route counters observed"
                columns={[
                  {
                    accessor: "route_id",
                    render: (r) => (
                      <Button
                        component={Link}
                        variant="subtle"
                        to={investigationLink(
                          `/routes/${encodeURIComponent(r.route_id)}`,
                          params,
                        )}
                      >
                        {r.route_id}
                      </Button>
                    ),
                  },
                  {
                    accessor: "rps",
                    title: "Incoming / s",
                    render: (r) =>
                      r.window?.incoming_rps.toFixed(1) ?? "Not collected",
                  },
                  { accessor: "totals.incoming", title: "Started" },
                  { accessor: "totals.completed", title: "Completed" },
                  { accessor: "totals.active_requests", title: "In-flight" },
                  {
                    accessor: "totals.status_classes",
                    title: "5xx",
                    render: (r) => r.totals.status_classes[5],
                  },
                  {
                    accessor: "totals.upstream_errors",
                    title: "Upstream errors",
                  },
                  {
                    accessor: "p95",
                    render: (r) => percentile(r.totals.latency_buckets, 95),
                  },
                  {
                    accessor: "p99",
                    render: (r) => percentile(r.totals.latency_buckets, 99),
                  },
                ]}
              />
              <Button component={Link} to="/service-map" variant="default">
                Upstream health and maintenance
              </Button>
            </Stack>
          </Tabs.Panel>
          <Tabs.Panel value="protection" pt="md">
            <Stack>
              <Text>
                Would-block is a primary WAF result, independent of enforcement.
                Rule matches count recorded findings and may exceed requests;
                truncated reports undercount. Shadow has its own
                sampled/completed denominator.
              </Text>
              <DataTable
                idAccessor="route_id"
                records={rows}
                noRecordsText="No security observations"
                columns={[
                  { accessor: "route_id" },
                  {
                    accessor: "totals.blocked",
                    title: "Actual security blocks",
                  },
                  {
                    accessor: "security.would_block",
                    title: "WAF would-block",
                  },
                  { accessor: "security.rule_matches", title: "Rule matches" },
                  {
                    accessor: "security.truncated_reports",
                    title: "Truncated reports",
                  },
                  {
                    accessor: "security.coverage",
                    title: "Coverage finalized",
                    render: (r) =>
                      r.security.coverage.reduce((a, b) => a + b, 0),
                  },
                ]}
              />
              <InspectionCoverage routeId={route || undefined} />
              <Button
                component={Link}
                to={
                  route ? `/routes/${encodeURIComponent(route)}` : "/security"
                }
                variant="default"
              >
                Review exclusions, expiry and shadow
              </Button>
            </Stack>
          </Tabs.Panel>
          <Tabs.Panel value="investigation" pt="md">
            <Stack>
              <Text>
                Top 20 searchable groups in a maximum one-day window. IP is a
                network identity, not a user; user-agent is a spoofable claim.
                These counts can be incomplete when traffic records are missing.
              </Text>
              {top.isPending && (
                <Text role="status">Loading investigation groups…</Text>
              )}
              {top.isError && <Failure error={top.error} />}
              <Button
                component={Link}
                to={investigationLink("/traffic", filters)}
              >
                Inspect requests with these filters
              </Button>
              {top.data && (
                <Alert color={top.data.health.degraded ? "orange" : "teal"}>
                  Searchable-record health:{" "}
                  {top.data.health.degraded ? "degraded" : "reachable"}; dropped
                  / uncertain {top.data.health.dropped}.
                </Alert>
              )}
              {top.data &&
                (["routes", "rules", "clients"] as const).map((kind) => (
                  <Paper key={kind} withBorder p="sm">
                    <Title order={3}>Top {kind}</Title>
                    <DataTable
                      records={top.data.items[kind]}
                      idAccessor="label"
                      columns={[
                        {
                          accessor: "label",
                          title: kind === "clients" ? "Client IP" : kind,
                          render: (r) =>
                            kind === "clients" ? (
                              <Button
                                component={Link}
                                variant="subtle"
                                to={investigationLink("/traffic", filters, {
                                  client_ip: r.label,
                                })}
                              >
                                {r.label || "Unavailable"}
                              </Button>
                            ) : (
                              <Button
                                component={Link}
                                variant="subtle"
                                to={investigationLink(
                                  "/traffic",
                                  filters,
                                  kind === "routes"
                                    ? { route_id: r.label }
                                    : { rule_id: r.label },
                                )}
                              >
                                {r.label || "Not collected"}
                              </Button>
                            ),
                        },
                        {
                          accessor: "records",
                          title:
                            kind === "rules" ? "Recorded findings" : "Records",
                        },
                        { accessor: "blocked" },
                      ]}
                      noRecordsText="No searchable groups"
                    />
                  </Paper>
                ))}
            </Stack>
          </Tabs.Panel>
          <Tabs.Panel value="capacity" pt="md">
            <Stack>
              {diagnostics.isPending && (
                <Text role="status">Loading capacity…</Text>
              )}
              {diagnostics.isError && <Failure error={diagnostics.error} />}
              <ResourceCapacity
                value={diagnostics.data}
                paused={paused}
                stale={diagnostics.isError}
              />
              <Button component={Link} to="/health" variant="default">
                Process RAM / FD / dependency observations
              </Button>
            </Stack>
          </Tabs.Panel>
        </Tabs>
        <Title order={2}>Counter history and comparison</Title>
        <Text size="sm">
          ClickHouse counter rollup · 5-minute collection, hourly display for
          windows over 3 days · retention 30 days · source independent of
          traffic logs. Whole observed windows only; current unfinished bucket
          and restart tails can be absent. No backfill or percentile averaging.
        </Text>
        <Group>
          <Button
            variant="default"
            onClick={() => {
              void current.refetch();
              void previous.refetch();
            }}
          >
            Refresh history
          </Button>
          <Button
            component={Link}
            to={investigationLink("/traffic", filters)}
            variant="default"
          >
            Drill into requests
          </Button>
        </Group>
        {current.isPending && (
          <Text role="status">Loading counter history…</Text>
        )}
        {current.isError && <Failure error={current.error} />}
        {previous.isError && (
          <Alert color="orange">
            Comparison unavailable. No baseline is inferred.
          </Alert>
        )}
        {current.data && (
          <>
            <Badge color={current.data.health.degraded ? "orange" : "teal"}>
              Rollup{" "}
              {current.data.health.degraded
                ? "degraded"
                : "writer last succeeded"}{" "}
              · dropped / uncertain rows {current.data.health.dropped}
            </Badge>
            <RequestChart
              points={points.map((p) => ({ ...p, values: [p.values[0]] }))}
              series={[{ label: "Incoming", color: "#128e86" }]}
              unit="requests / second"
              label="Observed counter rollup incoming rate; incomplete windows remain gaps"
            />
            <RequestChart
              points={points.map((p) => ({ ...p, values: p.values.slice(1) }))}
              series={[
                { label: "p95", color: "#347fb9" },
                { label: "p99", color: "#cc5371" },
              ]}
              unit="milliseconds"
              label="Counter rollup completed latency histogram upper bounds"
            />
            <DataTable
              records={current.data.items}
              idAccessor="bucket_ms"
              columns={[
                {
                  accessor: "bucket_ms",
                  title: "Bucket",
                  render: (r) =>
                    dayjs(Number(r.bucket_ms)).format("MM-DD HH:mm Z"),
                },
                { accessor: "incoming", title: "Started" },
                { accessor: "completed" },
                { accessor: "dropped_logs", title: "Log drops" },
                { accessor: "p95_ms", title: "p95 ms" },
                { accessor: "p99_ms", title: "p99 ms" },
              ]}
              noRecordsText="No retained rollup windows. Collection may not have begun or data may be unavailable."
            />
            <Title order={3}>Aligned observed buckets</Title>
            <Text size="sm">
              Compare matching buckets only after reviewing completeness.
              Differences are observations, not proof that an apply caused a
              change.
            </Text>
            <DataTable
              records={current.data.items.map((r) => ({
                bucket: Number(r.bucket_ms),
                current: r,
                previous: previous.data?.items.find(
                  (p) => Number(p.bucket_ms) === Number(r.bucket_ms) - offset,
                ),
              }))}
              idAccessor="bucket"
              columns={[
                {
                  accessor: "bucket",
                  render: (r) => dayjs(r.bucket).format("MM-DD HH:mm Z"),
                },
                { accessor: "current.incoming", title: "Current starts" },
                {
                  accessor: "previous.incoming",
                  title: "Compared starts",
                  render: (r) => r.previous?.incoming ?? "Unavailable",
                },
                { accessor: "current.p95_ms", title: "Current p95" },
                {
                  accessor: "previous.p95_ms",
                  title: "Compared p95",
                  render: (r) => r.previous?.p95_ms ?? "Unavailable",
                },
              ]}
              noRecordsText="No comparable observations"
            />
          </>
        )}
        <ChangeMarkers start={range.start} end={range.end} />
      </Stack>
    </Paper>
  );
}
