import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Badge,
  Button,
  Code,
  Group,
  NativeSelect,
  Paper,
  SimpleGrid,
  Stack,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { Controller, useForm } from "react-hook-form";
import { DateTimePicker } from "@mantine/dates";
import "@mantine/dates/styles.css";
import { toPickerDateTime, fromPickerDateTime } from "./investigation-datetime";
import { Link, useParams, useSearchParams } from "react-router-dom";
import dayjs from "dayjs";
import { api } from "./api";
import { DataTable } from "./DataTable";
import { DetailsGrid, Failure } from "./shared";
import {
  RequestDetails,
  RequestDetailContent,
  type RequestRecord,
} from "./RequestDetails";
import {
  trafficColumns,
  trafficRecord,
  type TrafficRecord,
} from "./traffic-table";
import {
  defaultRange,
  FILTER_KEYS,
  investigationLink,
  investigationParams,
} from "./investigation-state";
import { InspectionCoverage } from "./TrafficProfiles";
import { ShadowPolicy } from "./OperationalControls";
import type { Route } from "./types";

export interface RouteSample {
  route_id: string;
  window: {
    incoming_rps: number;
    p95_ms: number | null;
    p99_ms: number | null;
    observed_at_unix_ms: number;
    window_ms: number;
  } | null;
  started_at_unix_ms: number;
  totals: {
    incoming: number;
    completed: number;
    blocked: number;
    forwarded: number;
    upstream_errors: number;
    active_requests: number;
    cancelled: number;
    dropped_logs: number;
    latency_buckets: number[];
    status_classes: number[];
  };
  security: {
    coverage: number[];
    would_block: number;
    rule_matches: number;
    truncated_reports: number;
  };
}
export interface RouteStatistics {
  items: RouteSample[];
  epoch: string;
  source: string;
  capacity: number;
  overflow_requests: number;
  observed_at_unix_ms: number;
  reset: string;
}
interface Change {
  id: number;
  action: string;
  target: string;
  timestamp_ms: number;
}
export function ChangeMarkers({
  start,
  end,
  version,
}: {
  start: number;
  end: number;
  version?: string;
}) {
  const [params] = useSearchParams();
  const q = useQuery({
    queryKey: ["changes", start, end, version],
    queryFn: ({ signal }) =>
      api<{ items: Change[]; may_have_more: boolean }>(
        `/history/changes?start_ms=${start}&end_ms=${end}${version ? `&version=${encodeURIComponent(version)}` : ""}`,
        { signal },
      ),
  });
  return (
    <Paper withBorder p="md">
      <Stack>
        <Title order={3}>Recorded changes</Title>
        <Text size="sm">
          PostgreSQL audit · timestamps in {dayjs().format("Z")}. Correlation
          does not establish a cause. Endpoint markers reflect bounded health
          observations; certificate renewal markers reflect changed validity
          metadata, not public CA acceptance.
        </Text>
        {q.isPending && <Text role="status">Loading changes…</Text>}
        {q.isError && <Failure error={q.error} />}
        <DataTable
          records={q.data?.items ?? []}
          noRecordsText="No recorded changes in this selection"
          columns={[
            {
              accessor: "timestamp_ms",
              title: "Time",
              render: (r) =>
                dayjs(r.timestamp_ms).format("YYYY-MM-DD HH:mm:ss Z"),
            },
            { accessor: "action" },
            {
              accessor: "target",
              render: (r) =>
                r.target.startsWith("proxy/version/") ? (
                  <Button
                    variant="subtle"
                    component={Link}
                    to={investigationLink("/configuration", params, {
                      view: "history",
                      version: r.target.split("/").at(-1) ?? "",
                    })}
                  >
                    {r.target}
                  </Button>
                ) : (
                  <Text size="sm">{r.target}</Text>
                ),
            },
          ]}
        />
        {q.data?.may_have_more && (
          <Alert color="orange">
            More changes exist. Narrow the time window.
          </Alert>
        )}
      </Stack>
    </Paper>
  );
}
export function InvestigationHistory() {
  const [params, setParams] = useSearchParams();
  const safe = investigationParams(params);
  const [initialEnd] = useState(Date.now);
  const { start, end } = defaultRange(safe, initialEnd);
  const [selected, setSelected] = useState<RequestRecord | null>(null);
  const values = Object.fromEntries(
    FILTER_KEYS.map((k) => [
      k,
      k === "start_ms"
        ? String(start)
        : k === "end_ms"
          ? String(end)
          : (safe.get(k) ?? ""),
    ]),
  );
  const form = useForm<Record<string, string>>({ values });
  const search = new URLSearchParams(safe);
  search.set("start_ms", String(start));
  search.set("end_ms", String(end));
  search.set("limit", "100");
  const history = useQuery({
    queryKey: ["investigation-history", search.toString()],
    enabled: params.has("start_ms"),
    queryFn: ({ signal }) =>
      api<{
        items: TrafficRecord[];
        may_have_more: boolean;
        health: { degraded: boolean; dropped: number };
      }>(`/history/traffic?${search}`, { signal }),
  });
  return (
    <Paper withBorder p="md">
      <Stack>
        <Title order={2}>Request investigation</Title>
        <Text size="sm">
          Searchable ClickHouse records · raw retention 7 days · up to 100
          newest matches, filters applied before limit. Missing records may
          reflect retention or telemetry loss.
        </Text>
        <form
          aria-label="Search request investigation"
          onSubmit={form.handleSubmit((v) => {
            const next = new URLSearchParams();
            for (const k of FILTER_KEYS)
              if (v[k]?.trim()) next.set(k, v[k].trim());
            setParams(investigationParams(next));
          })}
        >
          <Stack>
            <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }}>
              {[
                ["start_ms", "Start time"],
                ["end_ms", "End time"],
              ].map(([key, label]) => (
                <Controller
                  key={key}
                  name={key}
                  control={form.control}
                  rules={{ required: "Select a date and time" }}
                  render={({ field, fieldState }) => (
                    <DateTimePicker
                      label={label}
                      description="Browser local time"
                      valueFormat="YYYY-MM-DD HH:mm:ss"
                      withSeconds
                      required
                      value={toPickerDateTime(field.value)}
                      onChange={(value) =>
                        field.onChange(fromPickerDateTime(value))
                      }
                      onBlur={field.onBlur}
                      ref={field.ref}
                      error={fieldState.error?.message}
                    />
                  )}
                />
              ))}
              {[
                ["route_id", "Exact route ID"],
                ["host", "Host contains"],
                ["path", "Path contains (no query)"],
                ["country", "Country code"],
                ["config_version", "Config version"],
                ["rule_id", "Rule ID"],
                ["layer", "Security layer"],
                ["client_ip", "Exact client IP"],
              ].map(([key, label]) => (
                <TextInput
                  key={key}
                  label={label}
                  maxLength={key === "path" ? 2048 : 253}
                  {...form.register(key)}
                />
              ))}
              <NativeSelect
                label="Action"
                data={[
                  { value: "", label: "All actions" },
                  "blocked",
                  "forwarded",
                  "local",
                ]}
                {...form.register("action")}
              />
              <NativeSelect
                label="Status class"
                data={[
                  { value: "", label: "All classes" },
                  ...[0, 1, 2, 3, 4, 5].map((v) => ({
                    value: String(v),
                    label: `${v}xx`,
                  })),
                ]}
                {...form.register("status_class")}
              />
            </SimpleGrid>
            <Group>
              <Button type="submit" loading={history.isFetching}>
                Search requests
              </Button>
              <Button
                variant="default"
                onClick={() => {
                  const next = investigationParams(params);
                  const end = Date.now();
                  next.set("start_ms", String(end - 3600000));
                  next.set("end_ms", String(end));
                  setParams(next);
                }}
              >
                Previous hour
              </Button>
              <Button
                component={Link}
                variant="subtle"
                to={investigationLink("/statistics", search)}
              >
                Statistics for this selection
              </Button>
            </Group>
          </Stack>
        </form>
        {history.isFetching && <Text role="status">Loading records…</Text>}
        {history.isError && <Failure error={history.error} />}
        {history.data && (
          <>
            <Badge color={history.data.health.degraded ? "orange" : "teal"}>
              {history.data.health.degraded
                ? "History degraded"
                : "History reachable"}{" "}
              · dropped / uncertain {history.data.health.dropped}
            </Badge>
            {history.data.may_have_more && (
              <Alert color="orange">
                More records may exist; narrow the filters or time window.
              </Alert>
            )}
            <DataTable
              idAccessor={(r) => `${r.epoch}:${r.sequence}`}
              records={history.data.items.map(trafficRecord)}
              columns={trafficColumns(setSelected)}
              onRowClick={({ record }) => setSelected(record)}
              noRecordsText="No searchable records match. This does not prove no request occurred."
            />
          </>
        )}
        <RequestDetails record={selected} onClose={() => setSelected(null)} />
      </Stack>
    </Paper>
  );
}
interface RouteDescription {
  source: string;
  config_version: number | null;
  active_version: number;
  route: Route;
  global_rules: unknown;
  upstream: unknown;
  effective_timeouts: Record<string, number>;
  sources: Record<string, string>;
  upstream_health: unknown;
  observed_at_unix_ms: number;
}
export function RouteDetail() {
  const { id = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const [paused, setPaused] = useState(false);
  const selection =
    params.get("snapshot") === "draft"
      ? "draft"
      : params.has("version")
        ? "request"
        : "active";
  const version = params.get("version");
  const route = useQuery({
    queryKey: ["route-detail", id, selection, version],
    queryFn: ({ signal }) =>
      api<RouteDescription>(
        `/routes/${encodeURIComponent(id)}${selection === "draft" ? "?draft=true" : selection === "request" ? `?version=${encodeURIComponent(version ?? "")}` : ""}`,
        { signal },
      ),
    refetchInterval: selection === "active" && !paused ? 5000 : false,
  });
  const stats = useQuery({
    queryKey: ["route-statistics"],
    queryFn: ({ signal }) =>
      api<RouteStatistics>("/telemetry/routes", { signal }),
    refetchInterval: paused ? false : 5000,
  });
  const sample = stats.data?.items.find((r) => r.route_id === id);
  const [initialEnd] = useState(Date.now);
  const range = defaultRange(params, initialEnd);
  return (
    <Stack>
      <Group justify="space-between">
        <Title order={1}>Route · {id}</Title>
        <Button
          variant="default"
          onClick={() => {
            void route.refetch();
            void stats.refetch();
          }}
        >
          Refresh
        </Button>
      </Group>
      <Group>
        <NativeSelect
          label="Configuration snapshot"
          value={selection}
          data={[
            { value: "active", label: "Active" },
            { value: "draft", label: "Saved draft" },
            ...(version
              ? [{ value: "request", label: `Request version ${version}` }]
              : []),
          ]}
          onChange={(e) => {
            const next = new URLSearchParams(params);
            if (e.target.value === "draft") next.set("snapshot", "draft");
            else next.delete("snapshot");
            if (e.target.value === "active") next.delete("version");
            setParams(next);
          }}
        />
        <Button
          component={Link}
          to={investigationLink("/traffic", params, {
            route_id: id,
            start_ms: range.start,
            end_ms: range.end,
          })}
        >
          Investigate requests
        </Button>
        <Button
          component={Link}
          to={investigationLink("/statistics", params, {
            route_id: id,
            start_ms: range.start,
            end_ms: range.end,
          })}
          variant="default"
        >
          Route statistics
        </Button>
        <Button
          component={Link}
          to="/configuration?view=review"
          variant="default"
        >
          Review / apply draft
        </Button>
        <Button component={Link} to="/discovery" variant="default">
          Test backend
        </Button>
      </Group>
      {route.isPending && <Text role="status">Loading route…</Text>}
      {route.isError && (
        <>
          <Failure error={route.error} />
          <Alert color="orange">
            This route or historical version may be unavailable. Current
            configuration has not been substituted.
          </Alert>
        </>
      )}
      {route.data && !route.isError && (
        <>
          <Alert
            title={`${route.data.source} · version ${route.data.config_version ?? "draft"}`}
            color="teal"
          >
            Active version {route.data.active_version}. Profile is a copied
            template; original template provenance is not retained. Observed{" "}
            {dayjs(route.data.observed_at_unix_ms).format(
              "YYYY-MM-DD HH:mm:ss Z",
            )}
            .
          </Alert>
          <Paper withBorder p="md">
            <Title order={2}>Effective configuration</Title>
            <DetailsGrid
              items={Object.entries(route.data.sources).map(
                ([label, value]) => ({ label, value }),
              )}
            />
            <Title order={3}>Effective timeouts (ms)</Title>
            <DetailsGrid
              items={Object.entries(route.data.effective_timeouts).map(
                ([label, value]) => ({ label, value }),
              )}
            />
            <details>
              <summary>Selected configuration and backend</summary>
              <Code block>
                {JSON.stringify(
                  {
                    route: route.data.route,
                    global_rules: route.data.global_rules,
                    upstream: route.data.upstream,
                  },
                  null,
                  2,
                )}
              </Code>
            </details>
            <Title order={3}>Upstream observation</Title>
            <Code block>
              {route.data.upstream_health === null
                ? "Unavailable for historical or draft snapshots"
                : JSON.stringify(route.data.upstream_health, null, 2)}
            </Code>
          </Paper>
        </>
      )}
      {!route.isError && !!route.data?.route.waf?.exclusions?.length && (
        <Paper withBorder p="md">
          <Title order={2}>Exclusions in selected configuration</Title>
          <DataTable
            idAccessor={(r) => `${r.rule_id}:${r.target ?? ""}`}
            records={route.data.route.waf.exclusions}
            columns={[
              { accessor: "rule_id" },
              {
                accessor: "target",
                render: (r) => r.target ?? "Whole route — review scope",
              },
              { accessor: "reason" },
              { accessor: "owner" },
              {
                accessor: "expires_at_unix_ms",
                title: "Expiry",
                render: (r) =>
                  r.expires_at_unix_ms ? (
                    <Text
                      c={
                        r.expires_at_unix_ms <= Date.now() + 86400000
                          ? "orange"
                          : undefined
                      }
                    >
                      {dayjs(r.expires_at_unix_ms).format("YYYY-MM-DD HH:mm Z")}
                      {r.expires_at_unix_ms <= Date.now()
                        ? " · Expired"
                        : r.expires_at_unix_ms <= Date.now() + 86400000
                          ? " · Expires within 24h"
                          : ""}
                    </Text>
                  ) : (
                    "Permanent"
                  ),
              },
            ]}
          />
        </Paper>
      )}
      <Paper withBorder p="md">
        <Stack>
          <Group justify="space-between">
            <Title order={2}>Route observations · current process</Title>
            <Button variant="default" onClick={() => setPaused(!paused)}>
              {paused ? "Resume" : "Pause"}
            </Button>
          </Group>
          <Badge color={paused || stats.isError ? "orange" : "teal"}>
            {paused ? "Paused" : stats.isError ? "Stale" : "Polling"}
          </Badge>
          {stats.isError && <Failure error={stats.error} />}
          <Text size="sm">
            Independent counters across configuration changes; these are not the
            selected historical snapshot. Retired route IDs retain their slot
            until restart.
          </Text>
          {sample ? (
            <DetailsGrid
              items={Object.entries(sample.totals)
                .filter(([, v]) => typeof v === "number")
                .map(([label, value]) => ({ label, value: String(value) }))}
            />
          ) : (
            <Text>
              No route counters collected in this process, or route capacity
              exceeded.
            </Text>
          )}
        </Stack>
      </Paper>
      <ChangeMarkers start={range.start} end={range.end} />
      <InspectionCoverage routeId={id} />
      <ShadowPolicy routeId={id} />
      <Paper withBorder p="md">
        <Stack>
          <Title order={2}>Service setup and diagnosis</Title>
          <Text>
            Choose backend → gateway connection test → profile → domain/TLS →
            coverage → validate/review/apply. Existing requests keep their
            snapshot.
          </Text>
          <Group>
            {[
              ["/discovery", "Backend / DNS / TCP / TLS / HTTP"],
              ["/configuration?view=draft", "Route / profile / coverage"],
              ["/certificates", "Domain / TLS"],
              ["/security", "Policy / resources"],
              ["/service-map", "Upstream / maintenance"],
              ["/traffic", "Telemetry"],
            ].map(([to, label]) => (
              <Button key={to} component={Link} variant="default" to={to}>
                {label}
              </Button>
            ))}
          </Group>
          <Text size="sm">
            Single-endpoint drain/maintenance can cause downtime. Connection
            tests and active health do not establish business success.
          </Text>
        </Stack>
      </Paper>
    </Stack>
  );
}

export function RequestReferencePage() {
  const { id = "" } = useParams();
  const [params] = useSearchParams();
  const q = useQuery({
    queryKey: ["request-reference", id],
    queryFn: ({ signal }) =>
      api<{ record: RequestRecord; source: string }>(
        `/requests/${encodeURIComponent(id)}`,
        { signal },
      ),
    enabled: /^(?:[A-Za-z0-9_]{32}|[A-Za-z0-9_]{64})$/.test(id),
  });
  if (!/^(?:[A-Za-z0-9_]{32}|[A-Za-z0-9_]{64})$/.test(id))
    return <Alert color="orange">Invalid request reference.</Alert>;
  return (
    <Stack>
      <Group>
        <Title order={1}>Request reference</Title>
        <Button
          component={Link}
          variant="default"
          to={investigationLink("/traffic", params)}
        >
          Return to investigation
        </Button>
      </Group>
      {q.isPending && <Text role="status">Loading request…</Text>}
      {q.isError && (
        <>
          <Failure error={q.error} />
          <Text>
            Not found does not prove a request never existed: records can be
            lost or expire.
          </Text>
        </>
      )}
      {q.data && (
        <>
          <Badge>{q.data.source}</Badge>
          <RequestDetailContent record={q.data.record} />
        </>
      )}
    </Stack>
  );
}
