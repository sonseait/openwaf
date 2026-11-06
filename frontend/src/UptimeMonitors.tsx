import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { scaleBand } from "d3-scale";
import dayjs from "dayjs";
import {
  Alert,
  Badge,
  Button,
  Divider,
  Grid,
  Group,
  Loader,
  NavLink,
  Paper,
  ScrollArea,
  SimpleGrid,
  Stack,
  Text,
  TextInput,
  ThemeIcon,
  Title,
  rem,
} from "@mantine/core";
import {
  Activity,
  Check,
  CircleHelp,
  Pause,
  Search,
  Settings2,
  X,
} from "lucide-react";
import { DataTable } from "./DataTable";
import { api } from "./api";
import {
  DetailsGrid,
  Failure,
  StateBadge as OperationalStateBadge,
} from "./shared";
import { RequestChart } from "./RequestCharts";
import { currentEndpointHealth } from "./uptime-state";
import type {
  EndpointHealth,
  EndpointPage,
  EndpointStatus,
} from "./uptime-state";

type Health = "Up" | "Down" | "Unknown";
type MonitorState = Health | "Maintenance" | "Draining";
const tones = {
  Up: "teal",
  Down: "red",
  Unknown: "gray",
  Maintenance: "yellow",
  Draining: "yellow",
} as const;
const icons = {
  Up: Check,
  Down: X,
  Unknown: CircleHelp,
  Maintenance: Pause,
  Draining: Pause,
};
type Diagnostic = NonNullable<EndpointPage["diagnostics"]>[number];
interface CheckSample {
  observed_at_unix_ms: number;
  config_version?: number;
  status: Diagnostic;
}
function health(value?: EndpointHealth): Health {
  if (
    !value?.checked_at_ms ||
    value.phase === "pending" ||
    value.reason === "expired_or_passive_failure"
  )
    return "Unknown";
  return value.available ? "Up" : "Down";
}
function StateBadge({ state }: { state: MonitorState }) {
  return (
    <Badge variant="light" color={tones[state]} tt="none">
      {state}
    </Badge>
  );
}

export function UptimeMonitors({
  data,
  pending,
  error,
  paused,
  onRetry,
  onMaintain,
}: {
  data?: EndpointPage;
  pending: boolean;
  error: Error | null;
  paused: boolean;
  onRetry: () => void;
  onMaintain: (endpoint: EndpointStatus) => void;
}) {
  const [search, setSearch] = useState("");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  const monitors = (data?.endpoints ?? []).map((endpoint) => {
    const diagnostic = currentEndpointHealth(
      endpoint,
      data,
      now,
      paused || !!error,
    );
    const operation = data?.operations.find((o) => o.key === endpoint.key);
    const currentHealth = health(diagnostic);
    const state: MonitorState =
      operation?.mode === "maintenance"
        ? "Maintenance"
        : operation?.mode === "drain"
          ? "Draining"
          : currentHealth;
    return { endpoint, diagnostic, operation, state, currentHealth };
  });
  const visible = monitors.filter(({ endpoint }) =>
    `${endpoint.upstream_id} ${endpoint.address}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  const selected =
    monitors.find((m) => m.endpoint.key === selectedKey) ?? monitors[0];
  return (
    <Stack gap="md">
      <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="md">
        {(["Up", "Down", "Maintenance", "Unknown"] as const).map((state) => {
          const Icon = icons[state];
          const count = monitors.filter((m) =>
            state === "Maintenance"
              ? m.state === "Maintenance" || m.state === "Draining"
              : m.state === state,
          ).length;
          return (
            <Paper key={state} withBorder p="md">
              <Group gap="sm">
                <ThemeIcon color={tones[state]} variant="light" radius="xl">
                  <Icon size={rem(18)} />
                </ThemeIcon>
                <Text size="sm" c="dimmed">
                  {state}
                </Text>
              </Group>
              <Text size="xl" fw={700} mt="xs">
                {data ? count : "—"}
              </Text>
            </Paper>
          );
        })}
      </SimpleGrid>
      <Group justify="space-between">
        <Group gap="xs">
          <Activity size={rem(16)} />
          <Text size="sm" c="dimmed">
            Gateway health checks
          </Text>
          <Badge
            variant="light"
            tt="none"
            color={paused || error ? "yellow" : "teal"}
          >
            {paused
              ? "Paused"
              : error
                ? "Stale"
                : pending
                  ? "Connecting"
                  : "Refreshing every 5s"}
          </Badge>
        </Group>
      </Group>
      {pending && (
        <Group role="status">
          <Loader size="sm" />
          Loading endpoint state…
        </Group>
      )}
      {error && (
        <>
          <Alert color="yellow">
            Endpoint observations stale / unavailable.
          </Alert>
          <Failure error={error} />
          <Button variant="default" onClick={onRetry}>
            Retry monitors
          </Button>
        </>
      )}
      {data && (
        <Group gap="md" c="dimmed">
          <Text size="xs">Source: gateway</Text>
          <Text size="xs">
            Active version {data.config_version ?? "Unavailable"}
          </Text>
          <Text size="xs">
            Observed:{" "}
            {data.observed_at_unix_ms
              ? dayjs(data.observed_at_unix_ms).format("YYYY-MM-DD HH:mm:ss")
              : "Unavailable"}
          </Text>
        </Group>
      )}
      <Grid gutter="md" align="flex-start">
        <Grid.Col span={{ base: 12, md: 4 }}>
          <Paper withBorder p="md">
            <Stack gap="md">
              <Group justify="space-between">
                <Title order={2}>Monitors</Title>
                <Text size="sm" c="dimmed">
                  {visible.length} / {monitors.length}
                </Text>
              </Group>
              <TextInput
                aria-label="Search monitors"
                placeholder="Search monitors…"
                leftSection={<Search size={rem(16)} />}
                value={search}
                onChange={(e) => setSearch(e.currentTarget.value)}
              />
              <ScrollArea.Autosize
                mah={{ base: rem(280), md: rem(600) }}
                type="auto"
                scrollbars="y"
                overscrollBehavior="contain"
                offsetScrollbars="present"
                viewportProps={{
                  tabIndex: 0,
                  role: "region",
                  "aria-label": "Monitor list",
                }}
              >
                <Stack gap="xs">
                  {visible.map((monitor) => {
                    const Icon = icons[monitor.state];
                    return (
                      <NavLink
                        key={monitor.endpoint.key}
                        component="button"
                        type="button"
                        active={selected?.endpoint.key === monitor.endpoint.key}
                        aria-current={
                          selected?.endpoint.key === monitor.endpoint.key
                            ? "true"
                            : undefined
                        }
                        aria-label={`Monitor ${monitor.endpoint.upstream_id} ${monitor.endpoint.address}`}
                        onClick={() => setSelectedKey(monitor.endpoint.key)}
                        p="sm"
                        className="monitor-option"
                        color={tones[monitor.state]}
                        leftSection={
                          <ThemeIcon
                            variant="light"
                            color={tones[monitor.state]}
                            radius="xl"
                            size="sm"
                          >
                            <Icon size={rem(14)} />
                          </ThemeIcon>
                        }
                        label={
                          <Text size="sm" fw={600}>
                            {monitor.endpoint.upstream_id}
                          </Text>
                        }
                        description={
                          <Text size="xs" c="dimmed" truncate>
                            {monitor.endpoint.address}
                          </Text>
                        }
                        rightSection={<StateBadge state={monitor.state} />}
                      />
                    );
                  })}
                  {!pending && !monitors.length && (
                    <Text size="sm" c="dimmed">
                      No configured endpoints. Add an upstream in Configuration
                      to monitor it.
                    </Text>
                  )}
                  {!!monitors.length && !visible.length && (
                    <Stack gap="xs">
                      <Text size="sm">No monitors match your search.</Text>
                      <Button variant="subtle" onClick={() => setSearch("")}>
                        Clear search
                      </Button>
                    </Stack>
                  )}
                </Stack>
              </ScrollArea.Autosize>
            </Stack>
          </Paper>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 8 }}>
          {selected ? (
            <Stack gap="md">
              <Paper withBorder p="md">
                <Stack gap="md">
                  <Group justify="space-between" align="flex-start">
                    <Stack gap={rem(4)}>
                      <Group>
                        <Title order={2}>{selected.endpoint.upstream_id}</Title>
                        <StateBadge state={selected.state} />
                      </Group>
                      <Text
                        size="sm"
                        c="dimmed"
                        style={{ overflowWrap: "anywhere" }}
                      >
                        {selected.endpoint.protocol}://
                        {selected.endpoint.address}
                      </Text>
                    </Stack>
                    <Button
                      variant="default"
                      leftSection={<Settings2 size={rem(16)} />}
                      onClick={() => onMaintain(selected.endpoint)}
                    >
                      Inspect / maintain
                    </Button>
                  </Group>
                  <DetailsGrid
                    items={[
                      {
                        label: "Response time",
                        value:
                          selected.diagnostic?.latency_ms != null
                            ? `${selected.diagnostic.latency_ms} ms`
                            : "Unavailable",
                      },
                      {
                        label: "Last check",
                        value: selected.diagnostic?.checked_at_ms
                          ? dayjs(selected.diagnostic.checked_at_ms).format(
                              "YYYY-MM-DD HH:mm:ss",
                            )
                          : "Not yet observed",
                      },
                      {
                        label: "Active requests",
                        value:
                          selected.operation?.active_requests ?? "Unavailable",
                      },
                      {
                        label: "Health",
                        value: <StateBadge state={selected.currentHealth} />,
                      },
                      {
                        label: "Admission mode",
                        value: (
                          <OperationalStateBadge
                            value={selected.operation?.mode ?? "active"}
                          />
                        ),
                      },
                      {
                        label: "Reason",
                        value:
                          selected.operation?.reason ||
                          selected.diagnostic?.reason ||
                          "No observation",
                      },
                    ]}
                  />
                  {selected.endpoint.expected_downtime && (
                    <Alert color="yellow">
                      {selected.endpoint.single_endpoint
                        ? "Single endpoint: downtime expected during maintenance."
                        : "No healthy active alternative: downtime expected."}
                    </Alert>
                  )}
                  <Text size="xs" c="dimmed">
                    Drain and maintenance stop new admissions. Existing requests
                    continue unless explicitly disconnected.
                  </Text>
                </Stack>
              </Paper>
              <MonitorHistory
                key={selected.endpoint.key}
                endpoint={selected.endpoint}
                paused={paused}
              />
            </Stack>
          ) : (
            <Paper withBorder p="md">
              <Stack align="center" gap="sm">
                <ThemeIcon size="xl" variant="light" color="gray" radius="xl">
                  <Activity size={rem(24)} />
                </ThemeIcon>
                <Title order={2}>Select a monitor</Title>
                <Text size="sm" c="dimmed">
                  Endpoint status and recent checks will appear here.
                </Text>
              </Stack>
            </Paper>
          )}
        </Grid.Col>
      </Grid>
    </Stack>
  );
}

function MonitorHistory({
  endpoint,
  paused,
}: {
  endpoint: EndpointStatus;
  paused: boolean;
}) {
  const history = useQuery({
    queryKey: ["endpoint-history", endpoint.key],
    queryFn: ({ signal }) =>
      api<{ items: CheckSample[] }>("/operations/endpoints/history", {
        method: "POST",
        body: { key: endpoint.key },
        signal,
      }),
    refetchInterval: paused ? false : 10000,
    gcTime: 0,
  });
  const samples = (history.data?.items ?? [])
    .slice(0, 100)
    .sort((a, b) => a.observed_at_unix_ms - b.observed_at_unix_ms);
  const points = samples.flatMap((sample, i) => {
    const previous = samples[i - 1];
    const gap =
      previous &&
      (sample.observed_at_unix_ms - previous.observed_at_unix_ms > 45000 ||
        sample.config_version !== previous.config_version);
    const point = {
      time: sample.observed_at_unix_ms,
      values: [sample.status.last_check?.latency_ms ?? null],
    };
    return gap
      ? [{ time: previous.observed_at_unix_ms + 1, values: [null] }, point]
      : [point];
  });
  return (
    <Paper withBorder p="md">
      <Stack gap="md">
        <Group justify="space-between">
          <Title order={2}>Recent checks</Title>
          <Badge
            variant="light"
            tt="none"
            color={paused || history.isError ? "yellow" : "gray"}
          >
            {paused
              ? "Paused history"
              : history.isError
                ? "Stale history"
                : "Last 100 samples"}
          </Badge>
        </Group>
        {history.isPending && (
          <Text role="status">Loading monitor history…</Text>
        )}
        {history.isError && (
          <>
            <Alert color="yellow">
              Monitor history unavailable; retained checks may be stale.
            </Alert>
            <Failure error={history.error} />
            <Button variant="default" onClick={() => void history.refetch()}>
              Retry monitor history
            </Button>
          </>
        )}
        {!history.isPending && !history.isError && !samples.length && (
          <Text size="sm" c="dimmed">
            No persisted checks for this monitor yet.
          </Text>
        )}
        {!!samples.length && (
          <>
            <CheckTimeline samples={samples} />
            <Group justify="space-between">
              <Text size="xs" c="dimmed">
                {dayjs(samples[0].observed_at_unix_ms).format(
                  "MMM D, HH:mm:ss",
                )}
              </Text>
              <Text size="xs" c="dimmed">
                {dayjs(samples.at(-1)!.observed_at_unix_ms).format(
                  "MMM D, HH:mm:ss",
                )}
              </Text>
            </Group>
            <Group gap="md">
              {(["Up", "Down", "Unknown"] as const).map((state) => (
                <StateBadge key={state} state={state} />
              ))}
              <Text size="xs" c="dimmed">
                Gray separator: gap / configuration change
              </Text>
            </Group>
            <Divider />
            <Title order={3}>Response time</Title>
            <RequestChart
              points={points}
              series={[{ label: "Check latency", color: "#12b886" }]}
              label={`Response time for ${endpoint.upstream_id} ${endpoint.address}`}
              unit="ms"
            />
            <details>
              <summary>View check details</summary>
              <DataTable
                records={[...samples].reverse()}
                idAccessor="observed_at_unix_ms"
                minHeight={rem(100)}
                columns={[
                  {
                    accessor: "observed_at_unix_ms",
                    title: "Time",
                    render: (s) =>
                      dayjs(s.observed_at_unix_ms).format("MMM D, HH:mm:ss"),
                  },
                  {
                    accessor: "health",
                    title: "Health",
                    render: (s) => <StateBadge state={health(s.status)} />,
                  },
                  {
                    accessor: "latency",
                    title: "Latency",
                    render: (s) =>
                      s.status.last_check?.latency_ms != null
                        ? `${s.status.last_check.latency_ms} ms`
                        : "Unavailable",
                  },
                  { accessor: "status.reason", title: "Reason" },
                  { accessor: "config_version", title: "Version" },
                ]}
              />
            </details>
          </>
        )}
        <Text size="xs" c="dimmed">
          Gateway observations, retained 7 days. Samples are not a continuous
          uptime percentage. Missing checks and gateway downtime remain unknown.
        </Text>
      </Stack>
    </Paper>
  );
}

function CheckTimeline({ samples }: { samples: CheckSample[] }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    let frame = 0;
    const draw = () => {
      const ctx = canvas.getContext("2d");
      if (!ctx) return;
      const width = canvas.getBoundingClientRect().width;
      const ratio = Math.min(devicePixelRatio || 1, 2);
      canvas.width = width * ratio;
      canvas.height = 36 * ratio;
      ctx.scale(ratio, ratio);
      const entries = samples.flatMap((sample, i) => {
        const previous = samples[i - 1];
        const gap =
          previous &&
          (sample.observed_at_unix_ms - previous.observed_at_unix_ms > 45000 ||
            previous.config_version !== sample.config_version);
        return gap ? ["Gap", health(sample.status)] : [health(sample.status)];
      });
      const x = scaleBand<number>()
        .domain(entries.map((_, i) => i))
        .range([Math.max(0, width - entries.length * 12), width])
        .paddingInner(0.28);
      entries.forEach((state, i) => {
        ctx.fillStyle =
          state === "Up" ? "#12b886" : state === "Down" ? "#fa5252" : "#868e96";
        ctx.beginPath();
        ctx.roundRect(
          x(i)!,
          state === "Gap" ? 12 : 2,
          x.bandwidth(),
          state === "Gap" ? 12 : 32,
          2,
        );
        ctx.fill();
      });
    };
    const schedule = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(draw);
    };
    const observer = new ResizeObserver(schedule);
    observer.observe(canvas);
    schedule();
    return () => {
      observer.disconnect();
      cancelAnimationFrame(frame);
    };
  }, [samples]);
  return (
    <canvas
      ref={ref}
      role="img"
      aria-label={`Check timeline: ${samples.filter((s) => health(s.status) === "Up").length} up, ${samples.filter((s) => health(s.status) === "Down").length} down, ${samples.filter((s) => health(s.status) === "Unknown").length} unknown. Gaps are gray separators. Read View check details for individual samples.`}
      style={{ display: "block", width: "100%", height: rem(36) }}
    />
  );
}
