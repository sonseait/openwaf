import {
  Alert,
  Badge,
  Group,
  Paper,
  Stack,
  SimpleGrid,
  Text,
  Title,
} from "@mantine/core";
import dayjs from "dayjs";
import { DataTable } from "./DataTable";
import type { ReactNode } from "react";
import { DetailsGrid } from "./shared";
type Counts = {
  active: number;
  high_water: number;
  admitted: number;
  rejected: number;
};
export interface ResourceDiagnostics {
  ddos?: { limited_total: number; unavailable_total: number };
  admission?: {
    observed_at_unix_ms: number;
    budgets: {
      requests: number;
      connections: number;
      handshakes: number;
      headers: number;
      classes: number[];
    };
    requests: Counts;
    connections: Counts;
    handshakes: Counts;
    headers: Counts;
    classes: Counts[];
    upload_slots?: Counts[];
    stream_slots?: Counts[];
    rejections: { reason: string; total: number }[];
  };
  replay?: {
    memory_bytes: number;
    disk_bytes: number;
    high_water_memory_bytes: number;
    high_water_disk_bytes: number;
    io_slots: number;
    failures_total: number;
  };
  rate_limit?: {
    classes: ({
      keys: number;
      high_water: number;
      capacity_rejections: number;
    } | null)[];
    contention_total: number;
  };
  health_capacity?: {
    active: number;
    backlog: number;
    high_water_backlog: number;
    max_scheduling_delay_ms: number;
    deferred_total?: number;
  };
  waf_registry?: {
    available: boolean;
    pools?: number;
    active_pools?: number;
    retired_pools?: number;
    queued?: number;
    executing?: number;
    executing_after_cancel?: number;
    completed_after_cancel?: number;
  };
  retry_slots?: number;
  retry_capacity?: Counts;
}
export function ResourceCapacity({
  value,
  paused,
  stale,
}: {
  value?: ResourceDiagnostics;
  paused: boolean;
  stale: boolean;
}) {
  const data = value?.admission;
  const hasDiagnostics = Boolean(
    value?.waf_registry ||
    value?.health_capacity ||
    value?.replay ||
    value?.retry_capacity,
  );
  const classes = ["api", "upload", "stream", "critical"];
  const rows = data
    ? [
        ...(["requests", "connections", "handshakes", "headers"] as const).map(
          (name) => ({ name, ...data[name], cap: data.budgets[name] }),
        ),
        ...(data.upload_slots ?? []).map((c, i) => ({
          name: `${classes[i]} uploads`,
          ...c,
          cap: data.budgets.classes[i],
        })),
        ...(data.stream_slots ?? []).map((c, i) => ({
          name: `${classes[i]} streams`,
          ...c,
          cap: data.budgets.classes[i],
        })),
        ...data.classes.map((c, i) => ({
          name: classes[i],
          ...c,
          cap: data.budgets.classes[i],
        })),
      ]
    : [];
  return (
    <>
      <Paper
        component="section"
        aria-label="Resource capacity"
        withBorder
        p="md"
      >
        <Stack gap="md">
          <Group justify="space-between">
            <Title order={2}>Resource capacity</Title>
            <Badge color={stale || paused ? "yellow" : "teal"}>
              {stale
                ? "Stale observation"
                : paused
                  ? "Paused observation"
                  : "Refreshing"}
            </Badge>
          </Group>
          {!data && <Text>Resource observations unavailable</Text>}
          {data && (
            <>
              <DetailsGrid
                items={[
                  { label: "Source", value: "Gateway local" },
                  {
                    label: "Observed",
                    value: dayjs(data.observed_at_unix_ms).format(
                      "YYYY-MM-DD HH:mm:ss",
                    ),
                  },
                ]}
              />
              <Text size="sm" c="dimmed">
                Class partitions do not borrow capacity. Per-client quota
                exhaustion returns 429; resource exhaustion returns 503. Client
                identity is never a metric label.
              </Text>
              <Stack gap="xs">
                <Text size="sm" c="dimmed">
                  Current usage and lifetime high-water marks
                </Text>
                <DataTable
                  aria-label="Current usage and lifetime high-water marks"
                  records={rows}
                  idAccessor="name"
                  tabularNums
                  columns={[
                    { accessor: "name", title: "Resource" },
                    {
                      accessor: "active",
                      title: "Active / cap",
                      textAlign: "right",
                      render: (r) => `${r.active} / ${r.cap}`,
                    },
                    {
                      accessor: "high_water",
                      title: "High water",
                      textAlign: "right",
                    },
                    {
                      accessor: "admitted",
                      title: "Grants",
                      textAlign: "right",
                    },
                    {
                      accessor: "rejected",
                      title: "Rejected",
                      textAlign: "right",
                    },
                  ]}
                />
              </Stack>
              {data.rejections
                .filter((r) => r.total > 0)
                .map((r) => (
                  <Alert color="yellow" key={r.reason}>
                    {r.reason}: {r.total} rejected requests since restart
                  </Alert>
                ))}
              {!data.rejections.some((r) => r.total > 0) && (
                <Text size="sm">No admission rejections observed</Text>
              )}
            </>
          )}
        </Stack>
      </Paper>
      {hasDiagnostics && (
        <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="md">
          {value?.waf_registry && (
            <CapacityPanel
              title="WAF pool capacity"
              items={[
                {
                  label: "WAF pools",
                  value: value.waf_registry.pools ?? "Unavailable",
                },
                {
                  label: "Active pools",
                  value: value.waf_registry.active_pools ?? "Unavailable",
                },
                {
                  label: "Retired pools",
                  value: value.waf_registry.retired_pools ?? "Unavailable",
                },
                {
                  label: "Queued",
                  value: value.waf_registry.queued ?? "Unavailable",
                },
                {
                  label: "Executing",
                  value: value.waf_registry.executing ?? "Unavailable",
                },
                {
                  label: "Native work after cancellation",
                  value:
                    value.waf_registry.executing_after_cancel ?? "Unavailable",
                },
              ]}
            />
          )}
          {value?.health_capacity && (
            <CapacityPanel
              title="Health checks"
              items={[
                {
                  label: "Active health jobs",
                  value: value.health_capacity.active,
                },
                { label: "Backlog", value: value.health_capacity.backlog },
                {
                  label: "Deferred checks",
                  value: value.health_capacity.deferred_total ?? 0,
                },
                {
                  label: "Peak backlog",
                  value: value.health_capacity.high_water_backlog,
                },
                {
                  label: "Maximum scheduling delay",
                  value: `${value.health_capacity.max_scheduling_delay_ms} ms`,
                },
              ]}
            />
          )}
          {value?.replay && (
            <CapacityPanel
              title="Replay buffers"
              items={[
                { label: "Memory", value: `${value.replay.memory_bytes} B` },
                {
                  label: "Peak memory",
                  value: `${value.replay.high_water_memory_bytes} B`,
                },
                { label: "Disk", value: `${value.replay.disk_bytes} B` },
                {
                  label: "Peak disk",
                  value: `${value.replay.high_water_disk_bytes} B`,
                },
                { label: "I/O slots", value: value.replay.io_slots },
                { label: "Failures", value: value.replay.failures_total },
                {
                  label: "Retry slots",
                  value: value.retry_slots ?? "Unavailable",
                },
              ]}
            />
          )}
          {value?.retry_capacity && (
            <CapacityPanel
              title="Retry capacity"
              items={[
                { label: "Active retries", value: value.retry_capacity.active },
                {
                  label: "Peak retries",
                  value: value.retry_capacity.high_water,
                },
                {
                  label: "Rejected retries",
                  value: value.retry_capacity.rejected,
                },
              ]}
            />
          )}
        </SimpleGrid>
      )}
      <CapacityPanel
        title="DDoS protection (HTTP flood)"
        items={[
          {
            label: "Rate rejections",
            value: value?.ddos?.limited_total ?? "Unavailable",
          },
          {
            label: "Protection capacity rejections",
            value: value?.ddos?.unavailable_total ?? "Unavailable",
          },
        ]}
      />
      {value?.rate_limit && (
        <Paper
          component="section"
          aria-label="Rate-limit capacity"
          withBorder
          p="md"
        >
          <Stack gap="md">
            <Group justify="space-between">
              <Title order={2}>Rate-limit capacity</Title>
              <Group gap="xs">
                <Text size="sm" c="dimmed">
                  Contention
                </Text>
                <Text size="sm" fw={500}>
                  {value.rate_limit.contention_total}
                </Text>
              </Group>
            </Group>
            <DataTable
              aria-label="Rate-limit capacity"
              records={value.rate_limit.classes.map((c, i) => ({
                id: i,
                name: classes[i] ?? `Class ${i + 1}`,
                ...c,
              }))}
              tabularNums
              columns={[
                { accessor: "name", title: "Class" },
                {
                  accessor: "keys",
                  title: "Keys",
                  textAlign: "right",
                  render: (c) => c.keys ?? "Unavailable",
                },
                {
                  accessor: "high_water",
                  title: "Peak keys",
                  textAlign: "right",
                  render: (c) => c.high_water ?? "Unavailable",
                },
                {
                  accessor: "capacity_rejections",
                  title: "Capacity rejections",
                  textAlign: "right",
                  render: (c) => c.capacity_rejections ?? "Unavailable",
                },
              ]}
            />
          </Stack>
        </Paper>
      )}
    </>
  );
}

function CapacityPanel({
  title,
  items,
}: {
  title: string;
  items: { label: string; value: ReactNode }[];
}) {
  return (
    <Paper component="section" aria-label={title} withBorder p="md">
      <Stack gap="md">
        <Title order={2}>{title}</Title>
        <DataTable
          records={items}
          idAccessor="label"
          columns={[
            { accessor: "label", title: "Metric", width: "70%" },
            {
              accessor: "value",
              title: "Value",
              width: "30%",
              textAlign: "right",
              render: ({ value }) => (
                <Text size="sm" fw={500}>
                  {value}
                </Text>
              ),
            },
          ]}
        />
      </Stack>
    </Paper>
  );
}
