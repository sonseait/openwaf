import {
  Alert,
  Badge,
  Button,
  Code,
  Group,
  Loader,
  Paper,
  Stack,
  Text,
  Title,
} from "@mantine/core";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import dayjs from "dayjs";
import toast from "react-hot-toast";
import { api, queryClient } from "./api";
import { DataTable } from "./DataTable";
import { Failure } from "./shared";
interface Evidence {
  correlation_source?: string;
  sequence_truncated?: boolean;
  recent_events?: {
    started_ms: number;
    completed_ms: number;
    path_hash: string;
    status: number;
    upstream: boolean;
  }[];
  samples: number;
  upstream_404: number;
  gateway_404: number;
  denials: number;
  errors: number;
  capacity_errors: number;
  distinct_paths: number;
  paths_saturated: boolean;
  request_ids: string[];
}
interface Incident {
  id: number;
  revision: number;
  detector: string;
  scope: string;
  route_id: string;
  config_version: number;
  state: "open" | "ack" | "resolved";
  quality: string;
  first_ms: number;
  last_ms: number;
  window_start_ms: number;
  window_end_ms: number;
  evidence: Evidence;
}
interface Diagnostics {
  mode: string;
  quality: string;
  dropped: number;
  pending: number;
  persistence_errors: number;
  keys: number;
  max_keys: number;
  observed_at_unix_ms: number;
  truncated: boolean;
  windows: {
    detector: string;
    route: string;
    scope: string;
    quality: string;
    firing: boolean;
    evidence: Evidence;
  }[];
}
export function AntiAbuse() {
  const [paused, setPaused] = useState(false);
  const [selected, setSelected] = useState<number | null>(null);
  const diagnostics = useQuery({
    queryKey: ["abuse-diagnostics"],
    queryFn: ({ signal }) =>
      api<Diagnostics>("/security/detectors", { signal }),
    refetchInterval: paused ? false : 5000,
  });
  const incidents = useQuery({
    queryKey: ["abuse-incidents"],
    queryFn: ({ signal }) =>
      api<{
        items: Incident[];
        total: number;
        truncated: boolean;
        retention_days: number;
      }>("/security/incidents", { signal }),
    refetchInterval: paused ? false : 5000,
  });
  const action = useMutation({
    mutationFn: ({ incident, state }: { incident: Incident; state: string }) =>
      api(`/security/incidents/${incident.id}`, {
        method: "POST",
        body: { state, expected_revision: incident.revision },
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["abuse-incidents"] });
      toast.success("Incident state saved");
    },
  });
  const current = incidents.data?.items.find((i) => i.id === selected);
  return (
    <Stack>
      <Group justify="space-between">
        <Title order={1}>Abuse observations & incidents</Title>
        <Button variant="light" onClick={() => setPaused(!paused)}>
          {paused ? "Resume observations" : "Pause observations"}
        </Button>
      </Group>
      <Alert>
        Observe only. These detectors describe request pressure and endpoint
        probing evidence; they do not infer fraud or automatically enforce
        policy. Persisted incidents survive restart; unknown, stale or gap data
        cannot automatically resolve an incident.
      </Alert>
      {diagnostics.isPending && (
        <Loader aria-label="Loading detector diagnostics" />
      )}
      {diagnostics.isError && <Failure error={diagnostics.error} />}
      {diagnostics.data && (
        <Paper p="md" withBorder>
          <Stack>
            <Group>
              <Badge color={diagnostics.isError || paused ? "yellow" : "blue"}>
                {paused
                  ? "paused"
                  : diagnostics.isError
                    ? "stale"
                    : "connected"}
              </Badge>
              <Badge>{diagnostics.data.quality}</Badge>
              <Text size="sm">
                Updated{" "}
                {dayjs(diagnostics.data.observed_at_unix_ms).format("HH:mm:ss")}{" "}
                · keys {diagnostics.data.keys}/{diagnostics.data.max_keys} ·
                pending {diagnostics.data.pending} · dropped{" "}
                {diagnostics.data.dropped} · persistence errors{" "}
                {diagnostics.data.persistence_errors}
              </Text>
            </Group>
            {(diagnostics.data.dropped > 0 ||
              diagnostics.data.persistence_errors > 0) && (
              <Alert color="yellow">
                Data gap or persistence degradation. Evidence may be incomplete.
                Pending work is bounded; no automatic recovery from missing
                data.
              </Alert>
            )}
            <DataTable
              aria-label="Detector windows"
              records={(diagnostics.data.windows ?? []).map((w, id) => ({
                ...w,
                id,
              }))}
              columns={[
                { accessor: "detector" },
                { accessor: "route" },
                { accessor: "quality" },
                {
                  accessor: "firing",
                  render: (w) =>
                    w.firing
                      ? "threshold observed"
                      : "warming / below threshold",
                },
                { accessor: "samples", render: (w) => w.evidence.samples },
                {
                  accessor: "correlation",
                  render: (w) => w.evidence.correlation_source ?? "unknown",
                },
                {
                  accessor: "recent_events",
                  render: (w) => (
                    <details>
                      <summary>
                        Recent events ({w.evidence.recent_events?.length ?? 0})
                        {w.evidence.sequence_truncated ? " · truncated" : ""}
                      </summary>
                      <Text size="xs">
                        Ordered by request start; concurrent events do not imply
                        causality. Path values are process-local hashes.
                      </Text>
                      {(w.evidence.recent_events ?? []).map((e, i) => (
                        <Text size="xs" key={i}>
                          {dayjs(e.started_ms).format("HH:mm:ss.SSS")} ·{" "}
                          {e.status} · {e.upstream ? "upstream" : "gateway"} ·{" "}
                          {e.path_hash}
                        </Text>
                      ))}
                    </details>
                  ),
                },
              ]}
              noRecordsText="No observations. Enable detectors on a route and send traffic."
            />
            {diagnostics.data.truncated && (
              <Alert color="yellow">Diagnostics limited to 128 windows.</Alert>
            )}
          </Stack>
        </Paper>
      )}
      <Title order={2}>Persisted incidents</Title>
      {incidents.isPending && <Loader aria-label="Loading incidents" />}
      {incidents.isError && <Failure error={incidents.error} />}
      {action.isError && <Failure error={action.error} />}
      {incidents.data && (
        <>
          <Text size="sm">
            {incidents.data.total} records · at most 1,000 retained · resolved
            history expires after seven days · latest 1,000 shown
          </Text>
          <DataTable
            aria-label="Incidents"
            records={incidents.data.items}
            columns={[
              {
                accessor: "detector",
                render: (i) => (
                  <Button
                    size="compact-xs"
                    variant="subtle"
                    onClick={() => setSelected(i.id)}
                  >
                    {i.detector} #{i.id}
                  </Button>
                ),
              },
              {
                accessor: "route_id",
                title: "Route",
                render: (i) => (
                  <Link to={`/routes/${encodeURIComponent(i.route_id)}`}>
                    {i.route_id}
                  </Link>
                ),
              },
              { accessor: "state", render: (i) => <Badge>{i.state}</Badge> },
              { accessor: "quality" },
              { accessor: "config_version", title: "Version" },
              {
                accessor: "last_ms",
                title: "Last observed",
                render: (i) => dayjs(i.last_ms).format("YYYY-MM-DD HH:mm:ss"),
              },
            ]}
            noRecordsText="No persisted incidents."
          />
          {incidents.data.truncated && (
            <Alert color="yellow">
              Older incidents are outside this bounded list.
            </Alert>
          )}
        </>
      )}
      {current && (
        <Paper p="md" withBorder>
          <Stack>
            <Title order={3}>Incident #{current.id}</Title>
            <Text>
              Version {current.config_version} · {current.scope} · window{" "}
              {dayjs(current.window_start_ms).format("HH:mm:ss")}–
              {dayjs(current.window_end_ms).format("HH:mm:ss")}
            </Text>
            <Code block>{JSON.stringify(current.evidence, null, 2)}</Code>
            <Group>
              {current.evidence.request_ids.map((id) => (
                <Link key={id} to={`/requests/${id}`}>
                  Request {id.slice(0, 8)}
                </Link>
              ))}
            </Group>
            <Text size="sm">
              Request history may be unavailable or expired. Configuration
              version identifies the snapshot; review version history in
              Configuration.
            </Text>
            <Link to="/configuration">Configuration versions</Link>
            <Group>
              {(["ack", "resolved", "open"] as const)
                .filter((s) => s !== current.state)
                .map((state) => (
                  <Button
                    key={state}
                    loading={action.isPending}
                    onClick={() => action.mutate({ incident: current, state })}
                  >
                    {state === "ack"
                      ? "Acknowledge"
                      : state === "resolved"
                        ? "Resolve explicitly"
                        : "Reopen"}
                  </Button>
                ))}
              <Button variant="subtle" onClick={() => setSelected(null)}>
                Close details
              </Button>
            </Group>
          </Stack>
        </Paper>
      )}
    </Stack>
  );
}
