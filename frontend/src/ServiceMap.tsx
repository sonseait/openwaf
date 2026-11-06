import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Badge,
  Button,
  Group,
  Loader,
  NativeSelect,
  Paper,
  Skeleton,
  Stack,
  Tabs,
  Text,
  Title,
  rem,
} from "@mantine/core";
import {
  ArrowUpRight,
  Box,
  ChevronLeft,
  ChevronRight,
  Globe,
  Network,
  RefreshCw,
  Search,
  Server,
  Waypoints,
} from "lucide-react";
import { DataTable } from "./DataTable";
import { ServiceTopology } from "./ServiceTopology";
import { Link } from "react-router-dom";
import { api } from "./api";
import { DiscoveryStatusBadge, Failure, StatusBadge } from "./shared";
import { discoveryReason, sourceLabel, time } from "./format";
import type { CandidatePage, Config, Endpoint, Kind, Source } from "./types";

function sourceIdentity(source?: Source): string {
  if (!source) return "manual";
  switch (source.kind) {
    case "docker_alias":
      return `${source.kind}:${source.container_id}:${source.network}:${source.alias}:${source.port}`;
    case "docker_published":
      return `${source.kind}:${source.container_id}:${source.bind_address}:${source.container_port}:${source.host_port}`;
    case "host_port":
      return `${source.kind}:${source.bind_address}:${source.port}`;
  }
}
export function ServiceMap() {
  const [kind, setKind] = useState<Kind>("docker");
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const config = useQuery({
    queryKey: ["config"],
    queryFn: ({ signal }) => api<Config>("/config", { signal }),
  });
  const cursor = cursors[cursors.length - 1];
  const discovery = useQuery({
    queryKey: ["service-map", kind, cursor],
    queryFn: ({ signal }) =>
      api<CandidatePage>(
        `/discovery/${kind}/candidates?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
        { signal },
      ),
  });
  const refreshing = config.isFetching || discovery.isFetching;
  const active = config.isError ? undefined : config.data?.active;
  const endpoints =
    active?.upstreams.flatMap((upstream) =>
      upstream.endpoints.map((endpoint) => ({
        upstream: upstream.id,
        endpoint,
      })),
    ) ?? [];
  const matched = (
    endpoint: Endpoint,
    source: Source,
    address: string | null,
  ) =>
    endpoint.address === address &&
    sourceIdentity(endpoint.source) === sourceIdentity(source);
  const unprotectedChildren =
    active?.routes.filter(
      (child) =>
        !child.password_protect &&
        active.routes.some(
          (parent) =>
            parent.password_protect &&
            parent.path_match === "prefix" &&
            parent.id !== child.id &&
            (parent.hostname === child.hostname ||
              (parent.hostname.startsWith("*.") &&
                child.hostname.endsWith(parent.hostname.slice(1)))) &&
            (child.path === parent.path ||
              child.path.startsWith(
                parent.path.endsWith("/") ? parent.path : `${parent.path}/`,
              )),
        ),
    ) ?? [];
  const data = discovery.data;
  const restartInventory = () => {
    setCursors([null]);
    if (!cursor) void discovery.refetch();
  };
  return (
    <Stack gap="md" className="service-map-page">
      <Group
        justify="space-between"
        align="flex-start"
        className="page-heading"
      >
        <div>
          <Text className="eyebrow">GATEWAY / TOPOLOGY</Text>
          <Title order={1}>Service map</Title>
          <Text c="dimmed" size="sm" mt="xs">
            Follow each route from gateway to backend.
          </Text>
        </div>
        <Group gap="xs" className="service-map-actions">
          <Button
            variant="default"
            leftSection={<RefreshCw size={rem(14)} />}
            loading={refreshing}
            onClick={() => {
              void config.refetch();
              restartInventory();
            }}
          >
            Reload map
          </Button>
          <Button
            component={Link}
            to="/configuration"
            variant="light"
            rightSection={<ArrowUpRight size={rem(14)} />}
          >
            Configure
          </Button>
        </Group>
      </Group>
      <div
        className="service-map-overview"
        aria-label="Active configuration summary"
      >
        {[
          {
            label: "Routes",
            value: active?.routes.length,
            detail: "Incoming request selectors",
            Icon: Globe,
          },
          {
            label: "Upstreams",
            value: active?.upstreams.length,
            detail: "Configured service pools",
            Icon: Box,
          },
          {
            label: "Endpoints",
            value: active ? endpoints.length : undefined,
            detail: "Configured backend targets",
            Icon: Server,
          },
        ].map(({ label, value, detail, Icon }) => (
          <div className="service-map-stat" key={label}>
            <Icon size={rem(18)} aria-hidden="true" />
            <div>
              <Text size="xs" c="dimmed">
                {label}
              </Text>
              <Text className="service-map-stat-value">{value ?? "—"}</Text>
              <Text size="xs" c="dimmed">
                {detail}
              </Text>
            </div>
          </div>
        ))}
        <div className="service-map-revision">
          <Badge color="gray" variant="outline">
            {active
              ? `Active v${config.data?.active_version}`
              : "Snapshot unavailable"}
          </Badge>
          <Text size="xs" c="dimmed">
            Configuration snapshot · runtime health not measured
          </Text>
        </div>
      </div>
      {config.data?.degraded && (
        <Alert color="orange" title="Configuration out of sync">
          Committed and active versions differ. Paths below use active version{" "}
          {config.data.active_version}.
        </Alert>
      )}
      {!!unprotectedChildren.length && (
        <Alert color="orange" title="Password protection needs review">
          {unprotectedChildren.map((route) => route.id).join(", ")}. These more
          specific routes can win over a password-protected prefix and need
          their own password policy.
        </Alert>
      )}
      <Tabs defaultValue="paths" keepMounted className="service-map-tabs">
        <Tabs.List>
          <Tabs.Tab value="paths" leftSection={<Waypoints size={rem(15)} />}>
            Traffic paths
          </Tabs.Tab>
          <Tabs.Tab value="discovery" leftSection={<Search size={rem(15)} />}>
            Discovery inventory
          </Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="paths" pt="md">
          {config.isPending && (
            <Paper withBorder p="lg">
              <Stack gap="md">
                <Group role="status">
                  <Loader size="xs" />
                  Loading active service map…
                </Group>
                <Skeleton height={30} width="45%" />
                <Skeleton height={240} />
              </Stack>
            </Paper>
          )}
          {config.isError && (
            <Stack>
              <Failure error={config.error} />
              <Button
                variant="default"
                onClick={() => void config.refetch()}
                style={{ alignSelf: "flex-start" }}
              >
                Retry configuration
              </Button>
            </Stack>
          )}
          {active && (
            <Paper withBorder className="service-map-frame">
              <ServiceTopology document={active} />
            </Paper>
          )}
          <Text size="xs" c="dimmed" mt="sm">
            Arrows show configured associations. They do not confirm request
            reachability, Internet exposure, or certificate availability.
          </Text>
        </Tabs.Panel>
        <Tabs.Panel value="discovery" pt="md">
          <Paper withBorder className="service-map-discovery">
            <div className="service-map-discovery-heading">
              <div>
                <Group gap="xs">
                  <Network size={rem(17)} aria-hidden="true" />
                  <Title order={2}>Discovered endpoints</Title>
                </Group>
                <Text size="xs" c="dimmed" mt="xs">
                  Read-only inventory from the local collector.
                </Text>
              </div>
              <NativeSelect
                label="Discovery source"
                data={[
                  { value: "docker", label: "Docker" },
                  { value: "host-ports", label: "Host TCP listeners" },
                ]}
                value={kind}
                onChange={(event) => {
                  setKind(event.currentTarget.value as Kind);
                  setCursors([null]);
                }}
              />
            </div>
            <Stack p="md">
              {discovery.isPending && (
                <Group role="status">
                  <Loader size="xs" />
                  Loading discovery inventory…
                </Group>
              )}
              {discovery.isError && (
                <Stack>
                  <Failure error={discovery.error} />
                  <Button
                    variant="default"
                    onClick={restartInventory}
                    style={{ alignSelf: "flex-start" }}
                  >
                    Retry discovery
                  </Button>
                </Stack>
              )}
              {data && (
                <>
                  <Group justify="space-between" gap="xs">
                    <Group gap="xs">
                      <DiscoveryStatusBadge data={data} />
                      <Text size="xs" c="dimmed">
                        {data.observed_at_unix_ms
                          ? time(data.observed_at_unix_ms)
                          : "No observation timestamp"}
                      </Text>
                    </Group>
                    <Text size="xs" c="dimmed">
                      {data.total} candidates · page {cursors.length} ·{" "}
                      {data.collection_scope.replaceAll("_", " ")}
                    </Text>
                  </Group>
                  {(data.stale || !data.collector_available || data.error) && (
                    <Alert color="orange" title="Discovery needs attention">
                      {data.error
                        ? discoveryReason(data.error)
                        : "Discovery is stale or unavailable."}{" "}
                      Saved upstreams continue using their existing
                      configuration.
                    </Alert>
                  )}
                  {discovery.isError && (
                    <Text size="xs" c="orange">
                      The inventory below is the last cached page; its freshness
                      could not be confirmed.
                    </Text>
                  )}
                  {data.candidates_truncated && (
                    <Alert color="orange" title="Incomplete inventory">
                      A missing endpoint cannot be treated as absent.
                    </Alert>
                  )}
                  <DataTable
                    idAccessor="id"
                    verticalAlign="top"
                    minHeight={rem(180)}
                    records={data.candidates}
                    noRecordsText="No candidate endpoints observed in this snapshot."
                    columns={[
                      {
                        accessor: "address",
                        title: "Endpoint / source",
                        width: rem(350),
                        render: (candidate) => (
                          <Stack gap={rem(4)}>
                            <Text fw={600} size="xs" ff="monospace">
                              {candidate.address ??
                                "No reachable address suggested"}
                            </Text>
                            <Text size="xs" c="dimmed">
                              {sourceLabel(candidate.source)}
                            </Text>
                          </Stack>
                        ),
                      },
                      {
                        accessor: "selectable",
                        title: "Observation",
                        width: rem(220),
                        render: (candidate) => (
                          <Stack gap={rem(4)}>
                            <div>
                              <StatusBadge
                                color={candidate.selectable ? "blue" : "orange"}
                              >
                                {candidate.selectable
                                  ? "Suggested"
                                  : "Unavailable"}
                              </StatusBadge>
                            </div>
                            <Text size="xs" c="dimmed">
                              {candidate.selectable
                                ? "Transport not tested"
                                : (
                                    candidate.unavailable_reason ??
                                    "Unavailable"
                                  ).replaceAll("_", " ")}
                            </Text>
                          </Stack>
                        ),
                      },
                      {
                        accessor: "source",
                        title: "Linked upstream",
                        render: (candidate) => {
                          if (!active)
                            return (
                              <Text size="sm" c="dimmed">
                                Configuration unavailable
                              </Text>
                            );
                          const links = [
                            ...new Set(
                              endpoints
                                .filter((endpoint) =>
                                  matched(
                                    endpoint.endpoint,
                                    candidate.source,
                                    candidate.address,
                                  ),
                                )
                                .map((endpoint) => endpoint.upstream),
                            ),
                          ];
                          return links.length ? (
                            <Group gap={rem(4)}>
                              {links.map((name) => (
                                <Badge
                                  key={name}
                                  variant="light"
                                  color="blue"
                                  tt="none"
                                >
                                  {name}
                                </Badge>
                              ))}
                            </Group>
                          ) : (
                            <Text size="sm" c="dimmed">
                              {endpoints.some(
                                (endpoint) =>
                                  endpoint.endpoint.address ===
                                  candidate.address,
                              )
                                ? "Address matches; source identity differs. Verify the source."
                                : "No matching saved endpoint"}
                            </Text>
                          );
                        },
                      },
                    ]}
                  />
                  <Group
                    justify="space-between"
                    gap="xs"
                    className="service-map-pagination"
                  >
                    <Text size="xs" c="dimmed">
                      Showing {data.candidates.length} on this page. Missing
                      here does not mean missing from the host.
                    </Text>
                    <Group gap="xs">
                      <Button
                        variant="default"
                        leftSection={<ChevronLeft size={rem(14)} />}
                        disabled={cursors.length === 1 || discovery.isFetching}
                        onClick={() =>
                          setCursors((values) => values.slice(0, -1))
                        }
                      >
                        Previous
                      </Button>
                      <Button
                        variant="default"
                        rightSection={<ChevronRight size={rem(14)} />}
                        disabled={
                          !data.next_cursor ||
                          discovery.isFetching ||
                          cursors.length >= 164
                        }
                        onClick={() =>
                          setCursors((values) => [...values, data.next_cursor])
                        }
                      >
                        Next
                      </Button>
                      <Button
                        variant="subtle"
                        disabled={discovery.isFetching}
                        onClick={restartInventory}
                      >
                        Restart inventory
                      </Button>
                    </Group>
                  </Group>
                </>
              )}
              <Text size="xs" c="dimmed">
                Discovery does not publish services or change saved endpoints.
                Test connectivity from Upstreams & discovery.
              </Text>
            </Stack>
          </Paper>
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
