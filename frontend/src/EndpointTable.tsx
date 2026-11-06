import { useEffect, useState } from "react";
import { Button, Stack, Text, TextInput, rem } from "@mantine/core";
import dayjs from "dayjs";
import { DataTable } from "./DataTable";
import { StateBadge } from "./shared";
import { currentEndpointHealth } from "./uptime-state";
import type { EndpointPage, EndpointStatus } from "./uptime-state";

export function EndpointTable({
  data,
  pending,
  stale,
  onMaintain,
}: {
  data?: EndpointPage;
  pending: boolean;
  stale: boolean;
  onMaintain: (endpoint: EndpointStatus) => void;
}) {
  const [search, setSearch] = useState("");
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  const records = (data?.endpoints ?? [])
    .map((endpoint) => {
      const diagnostic = currentEndpointHealth(endpoint, data, now, stale);
      return {
        ...endpoint,
        diagnostic,
        operation: data?.operations.find((o) => o.key === endpoint.key),
        expired: !diagnostic,
      };
    })
    .filter((e) =>
      `${e.upstream_id} ${e.address} ${e.protocol}`
        .toLowerCase()
        .includes(search.toLowerCase()),
    );
  return (
    <Stack>
      <TextInput
        label="Search endpoints"
        placeholder="Pool, address or protocol"
        value={search}
        onChange={(event) => setSearch(event.currentTarget.value)}
        maw={rem(416)}
      />
      {data?.observed_at_unix_ms && (
        <Text size="xs" c="dimmed">
          Observed{" "}
          {dayjs(data.observed_at_unix_ms).format("YYYY-MM-DD HH:mm:ss")} ·
          configuration v{data.config_version ?? "unknown"}
        </Text>
      )}
      <DataTable
        aria-label="Endpoint diagnostics and maintenance"
        idAccessor="key"
        records={records}
        fetching={pending}
        minHeight={rem(160)}
        styles={{ table: { minWidth: rem(1040) } }}
        pinLastColumn
        noRecordsText={
          search ? "No endpoints match your search" : "No configured endpoints"
        }
        columns={[
          {
            accessor: "address",
            title: "Endpoint / pool",
            width: "24%",
            render: (e) => (
              <Stack gap={rem(3)}>
                <Text fw={600} size="sm" style={{ overflowWrap: "anywhere" }}>
                  {e.protocol}://{e.address}
                </Text>
                <Text size="xs" c="dimmed">
                  {e.upstream_id}
                </Text>
              </Stack>
            ),
          },
          {
            accessor: "health",
            title: "Health",
            width: "23%",
            render: (e) => (
              <Stack gap={rem(3)} align="flex-start">
                <StateBadge
                  value={
                    e.expired || !e.diagnostic
                      ? "unknown"
                      : e.diagnostic.available
                        ? "available"
                        : "unavailable"
                  }
                />
                <Text size="xs" c="dimmed">
                  {e.expired || !e.diagnostic
                    ? "Current health unknown; observation missing, stale or version mismatch."
                    : e.diagnostic.reason}
                </Text>
                {e.diagnostic?.checked_at_ms && (
                  <Text size="xs" c="dimmed">
                    Checked{" "}
                    {dayjs(e.diagnostic.checked_at_ms).format("HH:mm:ss")}
                  </Text>
                )}
              </Stack>
            ),
          },
          {
            accessor: "mode",
            title: "Admission / leases",
            width: "20%",
            render: (e) => (
              <Stack gap={rem(3)} align="flex-start">
                <StateBadge
                  value={stale ? "unknown" : (e.operation?.mode ?? "active")}
                />
                <Text size="xs">
                  {e.operation?.active_requests ?? 0} active ·{" "}
                  {e.operation?.remaining_leases ??
                    e.operation?.active_requests ??
                    0}{" "}
                  remaining
                </Text>
                {e.operation?.reason && (
                  <Text
                    size="xs"
                    c="dimmed"
                    style={{ overflowWrap: "anywhere" }}
                  >
                    {e.operation.reason}
                  </Text>
                )}
              </Stack>
            ),
          },
          {
            accessor: "impact",
            title: "Maintenance impact",
            render: (e) => (
              <Stack gap={rem(3)}>
                <Text
                  size="xs"
                  c={
                    e.expected_downtime
                      ? "light-dark(var(--mantine-color-orange-9), var(--mantine-color-orange-3))"
                      : "dimmed"
                  }
                >
                  {e.expected_downtime
                    ? e.single_endpoint
                      ? "Single endpoint: downtime expected during maintenance."
                      : "No healthy active alternative: downtime expected."
                    : `${e.eligible_alternatives ?? "Unknown"} eligible alternatives`}
                </Text>
                {e.operation?.deadline_unix_ms && (
                  <Text
                    size="xs"
                    c={
                      e.operation.deadline_exceeded
                        ? "light-dark(var(--mantine-color-orange-9), var(--mantine-color-orange-3))"
                        : "dimmed"
                    }
                  >
                    Deadline{" "}
                    {dayjs(e.operation.deadline_unix_ms).format(
                      "YYYY-MM-DD HH:mm:ss",
                    )}{" "}
                    · {e.operation.deadline_exceeded ? "exceeded" : "pending"}
                  </Text>
                )}
                {e.operation?.drained && <Text size="xs">Drain complete</Text>}
              </Stack>
            ),
          },
          {
            accessor: "actions",
            title: "Actions",
            width: rem(165),
            render: (e) => (
              <Button
                size="compact-xs"
                variant="light"
                onClick={() => onMaintain(e)}
              >
                Inspect / maintain
              </Button>
            ),
          },
        ]}
      />
    </Stack>
  );
}
