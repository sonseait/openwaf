import {
  Alert,
  Box,
  Group,
  Paper,
  Progress,
  Stack,
  Text,
  Title,
  rem,
} from "@mantine/core";
import { DataTable } from "./DataTable";
import { arc, pie } from "d3-shape";
import { scaleLinear } from "d3-scale";
import type { DimensionCount } from "./telemetry-state";

export function BlockRatio({
  received,
  blocked,
}: {
  received: number;
  blocked: number;
}) {
  const ratio = received > 0 ? (blocked / received) * 100 : null;
  const sectors = pie<number>().sort(null)([
    Math.min(blocked, received),
    Math.max(0, received - blocked),
  ]);
  const shape = arc<(typeof sectors)[number]>().innerRadius(58).outerRadius(78);
  return (
    <Paper withBorder p="md">
      <Title order={2}>Blocked / received</Title>
      <Group align="center" gap="md" mt="md">
        <Box flex="0 0 auto">
          <svg
            viewBox="-90 -90 180 180"
            width={rem(160)}
            height={rem(160)}
            role="img"
            aria-label={`Blocked ${blocked.toLocaleString()} of ${received.toLocaleString()} received requests${ratio == null ? "; no received requests" : `; ${ratio.toFixed(2)} percent`}`}
          >
            {!received && (
              <circle
                r="68"
                fill="none"
                stroke="var(--mantine-color-default-border)"
                strokeWidth="20"
              />
            )}
            {sectors.map((sector, i) => (
              <path
                key={i}
                d={shape(sector) ?? ""}
                fill={
                  i
                    ? "var(--mantine-color-teal-6)"
                    : "var(--mantine-color-orange-7)"
                }
              />
            ))}
            <text
              textAnchor="middle"
              y="5"
              fill="currentColor"
              fontSize="22"
              fontWeight="600"
            >
              {ratio == null ? "—" : `${ratio.toFixed(1)}%`}
            </text>
            <text textAnchor="middle" y="24" fill="currentColor" fontSize="11">
              blocked
            </text>
          </svg>
        </Box>
        <Stack gap="xs" flex={`1 1 ${rem(180)}`}>
          <Text size="sm">
            Received: <strong>{received.toLocaleString()}</strong>
          </Text>
          <Text size="sm">
            Blocked: <strong>{blocked.toLocaleString()}</strong>
          </Text>
          <Text size="sm">
            Not blocked:{" "}
            <strong>{Math.max(0, received - blocked).toLocaleString()}</strong>
          </Text>
          <Text size="xs" c="dimmed">
            Cumulative gateway counters. Not blocked includes forwarded, local
            and in-flight requests. Decisions may lag request starts.
          </Text>
        </Stack>
      </Group>
    </Paper>
  );
}

const regionNames = new Intl.DisplayNames(["en"], { type: "region" });
function countryName(code: string): string {
  if (!/^[A-Z]{2}$/.test(code)) return code;
  return `${regionNames.of(code) ?? code} (${code})`;
}

export function TrafficBreakdown({
  title,
  items,
  description,
  countries = false,
}: {
  title: string;
  items?: DimensionCount[];
  description: string;
  countries?: boolean;
}) {
  const sorted = (items ?? [])
    .filter((item) => item.received > 0 || item.blocked > 0)
    .sort((a, b) => b.received - a.received || a.label.localeCompare(b.label));
  const visible = sorted.slice(0, 10);
  if (sorted.length > 10)
    visible.push({
      label: `Other ${sorted.length - 10} groups`,
      received: sorted.slice(10).reduce((sum, item) => sum + item.received, 0),
      blocked: sorted.slice(10).reduce((sum, item) => sum + item.blocked, 0),
    });
  const scale = scaleLinear()
    .domain([0, Math.max(1, ...visible.map((item) => item.received))])
    .range([0, 100]);
  return (
    <Paper withBorder p="md">
      <Title order={2}>{title}</Title>
      <Text size="sm" c="dimmed" mb="md">
        {description}
      </Text>
      {countries &&
        items?.some(
          (item) => item.label === "Unavailable" && item.received > 0,
        ) && (
          <Alert color="blue" title="Requests recorded without GeoIP" mb="md">
            Some requests were recorded while the gateway had no GeoIP database
            loaded. These cumulative counts remain under Unavailable after GeoIP
            is configured, including across restarts when statistics are
            persisted. They do not indicate current database availability. Check
            a new request&apos;s GeoIP status in request details; if it is
            unavailable, verify OPENWAF_GEOIP_DB and restart the gateway to load
            the database.
          </Alert>
        )}
      {countries &&
        items?.some(
          (item) => item.label === "Lookup failed" && item.received > 0,
        ) && (
          <Alert color="yellow" title="Recorded GeoIP lookup errors" mb="md">
            Some requests could not be assigned a country because a GeoIP lookup
            failed. These cumulative counts may include earlier errors. Check a
            new request&apos;s GeoIP status in request details to determine
            whether lookups are still failing.
          </Alert>
        )}
      {!items ? (
        <Alert color="yellow" title={`${title} unavailable`}>
          This gateway has not supplied the aggregate counters. Refresh after
          upgrading the gateway.
        </Alert>
      ) : !sorted.length ? (
        <Text size="sm" c="dimmed">
          No requests observed for this breakdown.
        </Text>
      ) : (
        <>
          <Group gap="md" mb="sm" fz="xs" aria-hidden="true">
            <Group component="span" gap={rem(6)} wrap="nowrap">
              <Box
                component="span"
                w={rem(12)}
                h={rem(3)}
                bg="var(--mantine-color-teal-6)"
              />
              Received
            </Group>
            <Group component="span" gap={rem(6)} wrap="nowrap">
              <Box
                component="span"
                w={rem(12)}
                h={rem(3)}
                bg="var(--mantine-color-orange-7)"
              />
              Blocked subset
            </Group>
          </Group>
          <DataTable
            aria-label={`${title}: received, blocked and block percentage by group`}
            records={visible}
            idAccessor="label"
            tabularNums
            columns={[
              {
                accessor: "label",
                title: "Group",
                width: rem(180),
                render: (item) =>
                  countries ? countryName(item.label) : item.label,
              },
              {
                accessor: "volume",
                title: "Volume",
                width: "40%",
                render: (item) => (
                  <Progress.Root
                    size={rem(14)}
                    radius="xs"
                    miw={rem(90)}
                    aria-hidden="true"
                  >
                    <Progress.Section
                      value={scale(Math.min(item.received, item.blocked))}
                      color="var(--mantine-color-orange-7)"
                    />
                    <Progress.Section
                      value={scale(Math.max(0, item.received - item.blocked))}
                      color="var(--mantine-color-teal-6)"
                    />
                  </Progress.Root>
                ),
              },
              {
                accessor: "received",
                title: "Received",
                textAlign: "right",
                render: (item) => item.received.toLocaleString(),
              },
              {
                accessor: "blocked",
                title: "Blocked",
                textAlign: "right",
                render: (item) => item.blocked.toLocaleString(),
              },
              {
                accessor: "ratio",
                title: "Blocked %",
                textAlign: "right",
                render: (item) =>
                  item.received
                    ? `${((item.blocked / item.received) * 100).toFixed(1)}%`
                    : "—",
              },
            ]}
          />
        </>
      )}
    </Paper>
  );
}
