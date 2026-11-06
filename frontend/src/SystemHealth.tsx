import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Accordion,
  Alert,
  Badge,
  Button,
  Group,
  Paper,
  SegmentedControl,
  SimpleGrid,
  Skeleton,
  Stack,
  Text,
  ThemeIcon,
  Title,
  rem,
} from "@mantine/core";
import {
  Activity,
  ArrowUpRight,
  Check,
  CircleAlert,
  Clock3,
  Database,
  HardDrive,
  KeyRound,
  Layers,
  Network,
  Pause,
  Play,
  Radio,
  RefreshCw,
  Server,
  ShieldCheck,
  ShieldHalf,
  type LucideIcon,
} from "lucide-react";
import { Link } from "react-router-dom";
import dayjs from "dayjs";
import { api, message } from "./api";
import { discoveryReason } from "./format";
import { StatusBadge } from "./shared";
import {
  componentRank,
  healthState,
  type HealthComponent,
  type HealthObservation,
  type SystemHealthSnapshot,
} from "./system-health";

const components: Record<
  string,
  { label: string; description: string; Icon: LucideIcon; group: string }
> = {
  gateway: {
    label: "Gateway",
    description: "Heartbeat from the traffic aggregator.",
    Icon: Server,
    group: "Traffic & protection",
  },
  waf_workers: {
    label: "WAF workers",
    description: "Request inspection workers and queue.",
    Icon: ShieldCheck,
    group: "Traffic & protection",
  },
  crowdsec: {
    label: "CrowdSec",
    description: "Local ban synchronization and checkpoint.",
    Icon: ShieldHalf,
    group: "Traffic & protection",
  },
  postgresql: {
    label: "PostgreSQL",
    description: "Admin database connectivity.",
    Icon: Database,
    group: "Storage & telemetry",
  },
  clickhouse: {
    label: "ClickHouse",
    description: "Traffic history delivery and backlog.",
    Icon: HardDrive,
    group: "Storage & telemetry",
  },
  collector: {
    label: "Discovery collector",
    description: "Host listeners and Docker inventory.",
    Icon: Network,
    group: "Discovery & TLS",
  },
  acme: {
    label: "Certificate automation",
    description: "Certificate workers, jobs and renewal schedules.",
    Icon: KeyRound,
    group: "Discovery & TLS",
  },
  tls: {
    label: "Loaded TLS certificates",
    description: "Loaded certificate inventory; renewal is tracked separately.",
    Icon: Layers,
    group: "Discovery & TLS",
  },
};
const componentOrder = Object.keys(components);
const sourceLabels: Record<string, string> = {
  host_ports: "Host TCP ports",
  docker: "Docker",
  certificate_requests: "Certificate requests",
  bootstrap: "DNS / wildcard bootstrap",
  applications: "Applications auto TLS",
  schedules: "External schedules",
};
const reasons: Record<string, string> = {
  certificate_jobs_degraded:
    "Certificate jobs need attention. Open Certificates to inspect the error and retry after fixing it.",
  certificate_jobs_unavailable: "Certificate job status could not be read.",
  certificate_worker_health_unavailable:
    "Certificate worker status is unavailable.",
  bootstrap_observation_unavailable: "Bootstrap status could not be read.",
  bootstrap_provider_failed:
    "Provider import or certificate ownership reservation failed; inspect bootstrap-provider logs.",
  bootstrap_dns_failed:
    "DNS setup failed; inspect the pending operation before retrying.",
  bootstrap_staging_failed: "ACME staging verification failed.",
  bootstrap_production_failed:
    "Production certificate issuance or renewal failed.",
  invalid_health_file_inventory:
    "ACME health files must contain one to eight absolute paths.",
};
function reasonText(value: HealthObservation) {
  const reason = value.reason ?? value.error;
  return reason
    ? Object.hasOwn(reasons, reason)
      ? reasons[reason]
      : discoveryReason(reason)
    : null;
}
function observed(value?: number | null) {
  return typeof value === "number" &&
    Number.isFinite(value) &&
    dayjs(value).isValid()
    ? dayjs(value).format("DD MMM YYYY · HH:mm:ss Z")
    : "Not observed";
}
function HealthBadge({ value }: { value: HealthObservation }) {
  const { color, label } = healthState(value);
  return (
    <StatusBadge color={color}>
      {label.charAt(0).toUpperCase() + label.slice(1)}
    </StatusBadge>
  );
}
function ObservationDetails({ value }: { value: HealthObservation }) {
  const reason = reasonText(value);
  return (
    <Stack gap="xs">
      {reason && <Text size="xs">{reason}</Text>}
      {value.observed_at_unix_ms !== undefined && (
        <Text size="xs" c="dimmed">
          Observed {observed(value.observed_at_unix_ms)}
        </Text>
      )}
      {value.docker_events_connected != null && (
        <Group justify="space-between" gap="xs">
          <Text size="xs" c="dimmed">
            Docker events
          </Text>
          <StatusBadge
            color={value.docker_events_connected ? "teal" : "orange"}
          >
            {value.docker_events_connected ? "Connected" : "Disconnected"}
          </StatusBadge>
        </Group>
      )}
      {(
        [
          ["dns_state", "DNS setup"],
          ["tls_state", "Wildcard certificate"],
          ["provider_state", "DNS provider"],
          ["renewal_state", "Renewal"],
        ] as const
      )
        .filter(([key]) => value[key])
        .map(([key, label]) => (
          <Group key={key} justify="space-between" gap="xs">
            <Text size="xs" c="dimmed">
              {label}
            </Text>
            <HealthBadge value={{ state: value[key]! }} />
          </Group>
        ))}
      {value.schedules?.map((schedule, index) => (
        <div className="health-source" key={index}>
          <Group justify="space-between" gap="xs">
            <Text size="xs" fw={600}>
              Schedule {index + 1}
            </Text>
            <HealthBadge value={schedule} />
          </Group>
          <Text size="xs" c="dimmed">
            Observed {observed(schedule.observed_at_unix_ms)}
          </Text>
          {reasonText(schedule) && (
            <Text size="xs">{reasonText(schedule)}</Text>
          )}
        </div>
      ))}
    </Stack>
  );
}
function ComponentMetrics({
  name,
  value,
}: {
  name: string;
  value: HealthComponent;
}) {
  const details = value.details;
  if (!details) return null;
  const counts = (v?: number) =>
    typeof v === "number" && Number.isFinite(v)
      ? v.toLocaleString()
      : "Not reported";
  const rows =
    name === "waf_workers"
      ? [
          ["Queued", counts(details.queued)],
          ["Executing", counts(details.executing)],
          ["Failed (total)", counts(details.failed_inspections)],
        ]
      : name === "clickhouse"
        ? [
            ["Backlog", counts(details.backlog)],
            ["Dropped (total)", counts(details.dropped)],
            ["Written (total)", counts(details.written)],
          ]
        : name === "tls"
          ? [
              [
                "Certificate entries",
                Array.isArray(details.certificates)
                  ? counts(details.certificates.length)
                  : "Not reported",
              ],
              ["Revision", counts(details.revision)],
            ]
          : name === "crowdsec"
            ? [
                [
                  "Sync age",
                  typeof details.last_success_age_ms === "number" &&
                  Number.isFinite(details.last_success_age_ms)
                    ? `${(details.last_success_age_ms / 1000).toLocaleString(undefined, { maximumFractionDigits: 1 })} s`
                    : "Not reported",
                ],
                [
                  "Checkpoint",
                  details.checkpoint_status?.replaceAll("_", " ") ??
                    "Not reported",
                ],
              ]
            : [];
  if (!rows.length) return null;
  return (
    <div className="health-metrics">
      {rows.map(([label, value]) => (
        <div key={label}>
          <Text size="xs" c="dimmed">
            {label}
          </Text>
          <Text size="sm" fw={600}>
            {value}
          </Text>
        </div>
      ))}
    </div>
  );
}
function ComponentCard({
  name,
  value,
}: {
  name: string;
  value: HealthComponent;
}) {
  const meta = (Object.hasOwn(components, name)
    ? components[name]
    : undefined) ?? {
    label: name.replaceAll("_", " "),
    description: "Additional component observation.",
    Icon: Activity,
  };
  const status = healthState(value);
  const attention = componentRank(value) < 3;
  const sources = Object.entries(value.sources ?? {});
  const sourceIssues = sources.filter(
    ([, source]) =>
      healthState(source).rank < 3 ||
      source.schedules?.some((s) => healthState(s).rank < 3),
  ).length;
  const color = attention && status.rank >= 3 ? "orange" : status.color;
  const link =
    name === "acme" || name === "tls"
      ? { to: "/certificates", label: "Certificates" }
      : name === "collector"
        ? { to: "/discovery", label: "Discovery" }
        : null;
  return (
    <Paper
      component="article"
      withBorder
      p="md"
      radius="md"
      className="health-component"
      aria-label={`${meta.label} health`}
      style={
        {
          "--health-accent": `var(--mantine-color-${color}-6)`,
        } as React.CSSProperties
      }
    >
      <Stack gap="sm">
        <Group justify="space-between" align="start" wrap="nowrap" gap="xs">
          <Group wrap="nowrap" gap="xs" miw={0}>
            <ThemeIcon color={color} variant="light" size={rem(28)} radius="md">
              <meta.Icon size={rem(15)} aria-hidden="true" />
            </ThemeIcon>
            <Text fw={600} size="sm">
              {meta.label}
            </Text>
          </Group>
          {attention && status.rank >= 3 ? (
            <StatusBadge color="orange">Needs attention</StatusBadge>
          ) : (
            <HealthBadge value={value} />
          )}
        </Group>
        <Text size="xs" c="dimmed">
          {meta.description}
        </Text>
        <ComponentMetrics name={name} value={value} />
        {(reasonText(value) ||
          value.observed_at_unix_ms !== undefined ||
          value.docker_events_connected != null ||
          (!sources.length && value.schedules?.length)) && (
          <ObservationDetails value={value} />
        )}
        {sources.length > 0 && (
          <Accordion
            variant="default"
            chevronSize={rem(14)}
            defaultValue={sourceIssues ? "sources" : null}
            className="health-sources"
          >
            <Accordion.Item value="sources">
              <Accordion.Control>
                <Group justify="space-between" gap="xs">
                  <Text size="xs" fw={500}>
                    {sources.length} sources
                  </Text>
                  {sourceIssues > 0 && (
                    <StatusBadge color="orange">
                      {sourceIssues} need attention
                    </StatusBadge>
                  )}
                </Group>
              </Accordion.Control>
              <Accordion.Panel>
                <Stack gap="sm">
                  {sources.map(([source, observation]) => (
                    <div className="health-source" key={source}>
                      <Group justify="space-between" gap="xs" mb="xs">
                        <Text size="xs" fw={600}>
                          {Object.hasOwn(sourceLabels, source)
                            ? sourceLabels[source]
                            : source.replaceAll("_", " ")}
                        </Text>
                        <HealthBadge value={observation} />
                      </Group>
                      <ObservationDetails value={observation} />
                    </div>
                  ))}
                  {name === "acme" && (
                    <Text size="xs" c="dimmed">
                      Worker and job observations do not prove issuance,
                      certificate loading or public reachability. Admin hostname
                      renewal is monitored separately.
                    </Text>
                  )}
                </Stack>
              </Accordion.Panel>
            </Accordion.Item>
          </Accordion>
        )}
        {link && (
          <Button
            component={Link}
            to={link.to}
            variant="subtle"
            size="compact-xs"
            rightSection={<ArrowUpRight size={rem(13)} />}
            className="health-component-link"
          >
            View {link.label.toLowerCase()}
          </Button>
        )}
      </Stack>
    </Paper>
  );
}
function SummaryCard({
  label,
  value,
  description,
  color,
  Icon,
  children,
}: {
  label: string;
  value: string;
  description: string;
  color: string;
  Icon: LucideIcon;
  children?: React.ReactNode;
}) {
  return (
    <Paper withBorder p="md" radius="md">
      <Stack gap="sm">
        <Group justify="space-between" align="start">
          <Text size="xs" c="dimmed" fw={600}>
            {label}
          </Text>
          <ThemeIcon color={color} variant="light" size={rem(28)} radius="md">
            <Icon size={rem(15)} aria-hidden="true" />
          </ThemeIcon>
        </Group>
        <Text size="lg" fw={600}>
          {value}
        </Text>
        <Text size="xs" c="dimmed">
          {description}
        </Text>
        {children}
      </Stack>
    </Paper>
  );
}
export function SystemHealth() {
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("all");
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const query = useQuery({
    queryKey: ["system-health"],
    queryFn: ({ signal }) =>
      api<SystemHealthSnapshot>("/health/system", { signal }),
    refetchInterval: paused ? false : 5000,
  });
  const data = query.data;
  const stale =
    query.isError ||
    Boolean(data && !paused && now - query.dataUpdatedAt > 15000);
  const entries = Object.entries(data?.components ?? {});
  const issues = entries.filter(([, value]) => componentRank(value) < 3).length;
  const healthy = entries.filter(
    ([, value]) => healthState(value).rank === 3 && componentRank(value) >= 3,
  ).length;
  const inactive = entries.filter(
    ([, value]) => healthState(value).rank === 5 && componentRank(value) >= 3,
  ).length;
  const groups = [
    "Traffic & protection",
    "Storage & telemetry",
    "Discovery & TLS",
    "Other components",
  ];
  const visible = entries.filter(([, value]) =>
    filter === "attention"
      ? componentRank(value) < 3
      : filter === "inactive"
        ? healthState(value).rank === 5 && componentRank(value) >= 3
        : true,
  );
  return (
    <Stack gap="md" maw={rem(1400)} mx="auto" className="system-health">
      <Group justify="space-between" align="start" className="page-heading">
        <div>
          <Text size="xs" c="dimmed" className="eyebrow">
            OPERATIONS / SYSTEM HEALTH
          </Text>
          <Title order={1}>System health</Title>
          <Text c="dimmed" mt="xs">
            Gateway, protection and supporting services at a glance.
          </Text>
        </div>
        <Group gap="xs">
          <Button
            variant="default"
            leftSection={<RefreshCw size={rem(14)} />}
            loading={query.isFetching}
            onClick={() => void query.refetch()}
          >
            Refresh
          </Button>
          <Button
            variant="default"
            leftSection={
              paused ? <Play size={rem(14)} /> : <Pause size={rem(14)} />
            }
            onClick={() => setPaused(!paused)}
          >
            {paused ? "Resume" : "Pause"}
          </Button>
        </Group>
      </Group>
      <Group
        justify="space-between"
        gap="xs"
        className="health-observation-bar"
      >
        <Group gap="xs">
          <StatusBadge
            color={stale ? "orange" : paused ? "gray" : data ? "teal" : "gray"}
          >
            {stale
              ? "Stale observations"
              : paused
                ? "Refresh paused"
                : data
                  ? "Auto-refresh · 5 s"
                  : "Connecting"}
          </StatusBadge>
          <Text size="xs" c="dimmed">
            {data
              ? `Snapshot ${observed(data.observed_at_unix_ms)}`
              : "Waiting for the first snapshot"}
          </Text>
        </Group>
        <Text size="xs" c="dimmed">
          Source: admin & gateway
        </Text>
      </Group>
      {query.isError && (
        <Alert
          color="orange"
          icon={<CircleAlert size={rem(17)} />}
          title={
            data
              ? "Showing the last recorded snapshot"
              : "Health observations unavailable"
          }
        >
          {message(query.error)} Current dependency health is unknown; gateway
          traffic may continue.
        </Alert>
      )}
      {paused && !query.isError && (
        <Alert
          color="gray"
          icon={<Pause size={rem(16)} />}
          title="Automatic refresh is paused"
        >
          Statuses below describe the last snapshot. Refresh once or resume to
          get new observations.
        </Alert>
      )}
      {stale && !query.isError && (
        <Alert color="orange" icon={<Clock3 size={rem(16)} />}>
          No new snapshot received for over 15 seconds. Statuses below are last
          recorded observations.
        </Alert>
      )}
      {query.isPending && (
        <Stack role="status" aria-label="Loading system health">
          <Text c="dimmed">Checking system components…</Text>
          <SimpleGrid cols={{ base: 1, sm: 3 }}>
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} height={rem(120)} radius="md" />
            ))}
          </SimpleGrid>
        </Stack>
      )}
      {data && (
        <>
          <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="sm">
            <SummaryCard
              label="Gateway heartbeat"
              value={
                stale
                  ? "Unknown"
                  : data.serving.state === "running"
                    ? "Running"
                    : data.serving.state.replaceAll("_", " ")
              }
              color={stale ? "gray" : "blue"}
              Icon={Activity}
              description={
                stale
                  ? `Last recorded: ${data.serving.state}.`
                  : data.serving.evidence
              }
            >
              <Button
                component={Link}
                to="/uptime"
                variant="subtle"
                size="compact-xs"
                rightSection={<ArrowUpRight size={rem(13)} />}
                className="health-component-link"
              >
                Check upstream reachability
              </Button>
            </SummaryCard>
            <SummaryCard
              label="Monitoring & log delivery"
              value={
                stale
                  ? "Unknown"
                  : data.monitoring.known_data_loss === true
                    ? "Data loss recorded"
                    : healthState(data.monitoring).label.replace(/^./, (c) =>
                        c.toUpperCase(),
                      )
              }
              color={
                stale
                  ? "gray"
                  : data.monitoring.known_data_loss === true
                    ? "red"
                    : healthState(data.monitoring).color
              }
              Icon={Radio}
              description="Monitoring health is separate from traffic serving."
            >
              <StatusBadge
                color={
                  data.monitoring.known_data_loss === true ? "red" : "gray"
                }
              >
                {data.monitoring.known_data_loss === true
                  ? "Known monitoring data loss"
                  : data.monitoring.known_data_loss === false
                    ? "No known monitoring loss"
                    : "Monitoring loss unknown"}
              </StatusBadge>
            </SummaryCard>
            <SummaryCard
              label="Component observations"
              value={
                stale
                  ? "Current health unknown"
                  : !entries.length
                    ? "No observations"
                    : issues
                      ? `${issues} need attention`
                      : "No component alerts"
              }
              color={
                stale
                  ? "gray"
                  : issues
                    ? "orange"
                    : entries.length
                      ? "teal"
                      : "gray"
              }
              Icon={issues || stale ? CircleAlert : Check}
              description={`${healthy} healthy · ${entries.length - healthy - inactive} other · ${inactive} not configured / disabled`}
            >
              <Text size="xs" c="dimmed">
                {entries.length} reported components
                {stale || paused ? " · last recorded" : ""}
              </Text>
            </SummaryCard>
          </SimpleGrid>
          {data.monitoring.known_data_loss === true && (
            <Alert
              color="red"
              icon={<CircleAlert size={rem(16)} />}
              title="Monitoring has lost data"
            >
              Traffic history may be incomplete. Loss remains visible after
              recovery; inspect ClickHouse and monitoring observations below.
            </Alert>
          )}
          <Group justify="space-between" gap="sm" mt="xs">
            <Title order={2}>Components</Title>
            <SegmentedControl
              size="xs"
              aria-label="Filter health components"
              value={filter}
              onChange={setFilter}
              data={[
                { value: "all", label: `All (${entries.length})` },
                { value: "attention", label: `Needs attention (${issues})` },
                { value: "inactive", label: `Not configured (${inactive})` },
              ]}
            />
          </Group>
          {(stale || paused) && (
            <Text size="xs" c="dimmed">
              Component states are from the last recorded snapshot.
            </Text>
          )}
          {!visible.length && (
            <Paper withBorder p="md">
              <Text size="sm">
                {!entries.length
                  ? "No component observations were returned. Current dependency health is unknown."
                  : filter === "attention"
                    ? "No components need attention in this snapshot."
                    : "No components match this filter."}
              </Text>
            </Paper>
          )}
          {groups.map((group) => {
            const rows = visible
              .filter(
                ([name]) =>
                  (components[name]?.group ?? "Other components") === group,
              )
              .sort(
                (a, b) =>
                  componentRank(a[1]) - componentRank(b[1]) ||
                  componentOrder.indexOf(a[0]) - componentOrder.indexOf(b[0]),
              );
            return rows.length ? (
              <section key={group} aria-label={group}>
                <Group gap="xs" mb="xs">
                  <Text size="xs" fw={600} c="dimmed" tt="uppercase">
                    {group}
                  </Text>
                  <Badge variant="light" color="gray">
                    {rows.length}
                  </Badge>
                </Group>
                <SimpleGrid cols={{ base: 1, sm: 2, xl: 3 }} spacing="sm">
                  {rows.map(([name, value]) => (
                    <ComponentCard key={name} name={name} value={value} />
                  ))}
                </SimpleGrid>
              </section>
            ) : null;
          })}
        </>
      )}
    </Stack>
  );
}
