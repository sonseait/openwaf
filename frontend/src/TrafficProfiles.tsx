import { useState } from "react";
import {
  Accordion,
  Alert,
  Badge,
  Button,
  Group,
  Loader,
  NativeSelect,
  Paper,
  SimpleGrid,
  Stack,
  Text,
  Title,
  rem,
} from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useFormContext, useWatch } from "react-hook-form";
import { useDebouncedValue } from "@mantine/hooks";
import { DataTable } from "./DataTable";
import dayjs from "dayjs";
import { api } from "./api";
import { DetailsGrid, Failure } from "./shared";
import { diagnosticTarget, type RouteDiagnostic } from "./route-labels";
import { normalizeDocument } from "./configuration-document";
import { isConfigurationRecommendation } from "./configuration-recommendations";
import type { Document, Route } from "./types";

type Template = Required<
  Pick<
    Route,
    | "profile"
    | "methods"
    | "content"
    | "body"
    | "timeouts"
    | "retry"
    | "admission_class"
    | "waf"
  >
>;
const labels: Record<string, string> = {
  api_crud: "API / CRUD",
  upload: "Upload",
  sse: "SSE",
  websocket: "WebSocket",
  media: "HLS / DASH / video download",
  payment_webhook: "Payment / webhook",
};
export function ProfilePicker({ index }: { index: number }) {
  const { setValue, getValues } = useFormContext<Document>();
  const [selected, setSelected] = useState("api_crud");
  const profiles = useQuery({
    queryKey: ["traffic-profiles"],
    queryFn: ({ signal }) =>
      api<{ templates: Template[] }>("/config/profiles", { signal }),
    staleTime: Infinity,
  });
  return (
    <Stack gap="sm">
      <Title order={3}>Traffic profile template</Title>
      <Text size="sm">
        Copy a versioned template into this draft route. Existing routes stay
        unchanged until you copy and save. Templates set DetectionOnly / PL1 and
        disable retries. Admission class selects a node capacity partition;
        route quotas can be customized below.
      </Text>
      {profiles.isPending && (
        <Group role="status">
          <Loader size="xs" />
          Loading route profiles…
        </Group>
      )}
      {profiles.isError && <Failure error={profiles.error} />}
      {profiles.data && (
        <>
          <NativeSelect
            label="Traffic profile"
            data={(profiles.data.templates ?? []).map((t) => ({
              value: t.profile.kind,
              label: labels[t.profile.kind],
            }))}
            value={selected}
            onChange={(e) => setSelected(e.currentTarget.value)}
          />
          {!profiles.data.templates?.length && (
            <Text>No profile templates available.</Text>
          )}
          <Button
            variant="light"
            disabled={
              !profiles.data.templates?.some((t) => t.profile.kind === selected)
            }
            onClick={() => {
              const template = profiles.data.templates.find(
                (t) => t.profile.kind === selected,
              );
              if (template)
                setValue(
                  `routes.${index}`,
                  {
                    ...getValues(`routes.${index}`),
                    ...structuredClone(template),
                  },
                  { shouldDirty: true },
                );
            }}
          >
            Copy profile into route
          </Button>
        </>
      )}
    </Stack>
  );
}
export function ConfigurationWarnings() {
  const { control } = useFormContext<Document>();
  const values = useWatch({ control }) as Document;
  const [document] = useDebouncedValue(normalizeDocument(values), 600);
  const diagnostics = useQuery({
    queryKey: ["editor-diagnostics", document],
    queryFn: ({ signal }) =>
      api<{ diagnostics: RouteDiagnostic[] }>("/config/diagnostics", {
        method: "POST",
        body: { document },
        signal,
      }),
    retry: false,
    gcTime: 0,
    staleTime: Infinity,
  });
  const entries = diagnostics.data?.diagnostics ?? [];
  const warnings = entries.filter(
    (d) => !isConfigurationRecommendation(d.code),
  );
  const recommendations = entries.filter((d) =>
    isConfigurationRecommendation(d.code),
  );
  return (
    <Accordion variant="default">
      <Accordion.Item value="configuration-warnings">
        <Accordion.Control>
          <Group gap="xs">
            <Text fw={600}>Configuration warnings</Text>
            <Badge
              component="span"
              variant="light"
              color={diagnostics.isError || warnings.length ? "yellow" : "gray"}
              role="status"
              aria-live="polite"
            >
              {diagnostics.isFetching
                ? "Checking…"
                : diagnostics.isError
                  ? "Unavailable"
                  : warnings.length}
            </Badge>
          </Group>
        </Accordion.Control>
        <Accordion.Panel>
          <Stack gap="xs">
            <Text size="xs" c="dimmed">
              Advisory checks for the entire local draft. Changes made in a
              route or upstream dialog are checked after adding them to the
              draft. Saving still runs the full validator.
            </Text>
            {diagnostics.isFetching && (
              <Text role="status">Checking route contracts…</Text>
            )}
            {diagnostics.isError && (
              <Alert color="yellow">
                Configuration warnings unavailable. Complete valid fields and
                check the connection; save still runs the full validator.
              </Alert>
            )}
            {diagnostics.data && !warnings.length && (
              <Text>No configuration warnings.</Text>
            )}
            {warnings.map((d) => (
              <Alert
                key={`${d.path}:${d.code}`}
                color="yellow"
                role="note"
                title={`${diagnosticTarget(d, document)} · ${d.code}`}
              >
                {d.message}
              </Alert>
            ))}
          </Stack>
        </Accordion.Panel>
      </Accordion.Item>
      <Accordion.Item value="configuration-recommendations">
        <Accordion.Control>
          <Group gap="xs">
            <Text fw={600}>Recommendations</Text>
            <Badge component="span" variant="light" color="gray" role="status">
              {diagnostics.isFetching
                ? "Checking…"
                : diagnostics.isError
                  ? "Unavailable"
                  : recommendations.length}
            </Badge>
          </Group>
        </Accordion.Control>
        <Accordion.Panel>
          <Stack gap="xs">
            <Text size="xs" c="dimmed">
              Optional hardening suggestions for the local draft, not
              configuration errors or detected attacks. Choose policies
              appropriate for your application.
            </Text>
            {diagnostics.isError && (
              <Text>
                Recommendations unavailable. Check the connection and complete
                valid fields.
              </Text>
            )}
            {diagnostics.data && !recommendations.length && (
              <Text>No recommendations.</Text>
            )}
            {recommendations.map((d) => (
              <Alert
                key={`${d.path}:${d.code}`}
                color="gray"
                role="note"
                title={`${diagnosticTarget(d, document)} · ${d.code}`}
              >
                {d.message}
              </Alert>
            ))}
          </Stack>
        </Accordion.Panel>
      </Accordion.Item>
    </Accordion>
  );
}
interface Coverage {
  observed_at_unix_ms: number;
  config_version: number;
  source: string;
  scopes: string[];
  reset: string;
  routes: {
    route_id: string;
    profile: Route["profile"];
    counts: number[];
    total: number;
  }[];
}
export function InspectionCoverage({ routeId }: { routeId?: string } = {}) {
  const [paused, setPaused] = useState(false);
  const q = useQuery({
    queryKey: ["inspection-coverage"],
    queryFn: ({ signal }) => api<Coverage>("/config/coverage", { signal }),
    refetchInterval: paused ? false : 10000,
  });
  return (
    <Paper withBorder p="md">
      <Stack>
        <Group justify="space-between">
          <Title order={2}>Actual inspection coverage</Title>
          <Button variant="default" onClick={() => setPaused(!paused)}>
            {paused ? "Resume coverage" : "Pause coverage"}
          </Button>
        </Group>
        <Text size="sm">
          On is an enforcement mode, not a promise that every body was parsed.
          Counts include completed and cancelled requests for the active
          snapshot; reset on apply/restart. Counters do not depend on traffic
          logs. Retired snapshots are excluded.
        </Text>
        {q.isPending && <Text role="status">Loading coverage…</Text>}
        {q.isError && (
          <>
            <Failure error={q.error} />
            <Alert color="yellow">Coverage stale / unavailable.</Alert>
          </>
        )}
        {q.data?.scopes && (
          <>
            <Group>
              <Badge color={paused || q.isError ? "yellow" : "teal"}>
                {paused ? "Paused" : q.isError ? "Stale" : "Connected"}
              </Badge>
            </Group>
            <DetailsGrid
              items={[
                {
                  label: "Observed",
                  value: dayjs(q.data.observed_at_unix_ms).format(
                    "YYYY-MM-DD HH:mm:ss",
                  ),
                },
                { label: "Configuration", value: `v${q.data.config_version}` },
                { label: "Source", value: q.data.source },
              ]}
            />
            <DataTable
              idAccessor="route_id"
              records={q.data.routes.filter(
                (r) => !routeId || r.route_id === routeId,
              )}
              noRecordsText="No active routes."
              columns={[
                { accessor: "route_id", title: "Route" },
                {
                  accessor: "profile",
                  render: (r) =>
                    r.profile
                      ? `${r.profile.kind} v${r.profile.version}`
                      : "Legacy / custom",
                },
                ...q.data.scopes.map((scope, i) => ({
                  accessor: scope,
                  title: scope,
                  render: (r: Coverage["routes"][number]) =>
                    `${r.counts[i]} / ${r.total}`,
                })),
              ]}
            />
          </>
        )}
      </Stack>
    </Paper>
  );
}

export function EffectiveTimeouts({ index }: { index: number }) {
  const { control } = useFormContext<Document>();
  const document = useWatch({ control }) as Document;
  const route = document.routes?.[index];
  if (!route) return null;
  const upstream = document.upstreams?.find((u) => u.id === route.upstream);
  const source = route.timeouts ?? upstream?.timeouts ?? {};
  const connect = source.connect_ms ?? 3000;
  const read = source.read_ms ?? 10000;
  const total = Math.min(
    source.total_ms ?? 30000,
    route.retry?.total_timeout_ms ?? Infinity,
  );
  const items = [
    { label: "TCP connection", value: connect },
    { label: "TLS handshake", value: source.tls_ms ?? connect },
    { label: "Final response headers", value: source.header_ms ?? read },
    { label: "Request body idle", value: route.body?.idle_timeout_ms ?? 30000 },
    {
      label: "Response / WebSocket idle",
      value: source.response_idle_ms ?? read,
    },
    { label: "Upstream write idle", value: source.write_ms ?? 10000 },
    { label: "Absolute request deadline", value: total },
    { label: "Node drain", value: 5000 },
  ];
  return (
    <Paper
      component="section"
      aria-label="Effective timeout contract"
      withBorder
      p="md"
    >
      <Stack gap="md">
        <Stack gap={rem(4)}>
          <Title order={3}>Effective timeout contract</Title>
          <Text size="sm" c="dimmed">
            Current draft values: route overrides → upstream settings →
            defaults. The absolute deadline also respects the total retry
            budget.
          </Text>
        </Stack>
        <SimpleGrid
          component="dl"
          m={0}
          cols={{ base: 2, sm: 3, lg: 4 }}
          spacing="md"
        >
          {items.map(({ label, value }) => (
            <Stack key={label} component="div" gap={rem(4)} miw={0}>
              <Text component="dt" size="xs" c="dimmed">
                {label}
              </Text>
              <Text
                component="dd"
                m={0}
                size="sm"
                fw={600}
                style={{ fontVariantNumeric: "tabular-nums" }}
              >
                {value.toLocaleString("en-US")} ms
              </Text>
            </Stack>
          ))}
        </SimpleGrid>
        <details>
          <summary>Timeout behavior &amp; protocol limits</summary>
          <Stack gap="xs" pt="xs">
            <Text size="sm" c="dimmed">
              Total never resets on traffic or upgrade. Header deadline starts
              when upstream request headers are sent, including upload time.
              WebSocket idle is independent in each direction; send heartbeats
              both ways below the idle limit.
            </Text>
            <Text size="sm" c="dimmed">
              Trailers are unsupported and rejected. HTTP/1.1 supports
              100-continue after header checks; HTTP/2 Expect receives 417. No
              extended CONNECT or gRPC contract. Payment timeout means unknown
              business outcome; reconcile with the backend ledger before
              resubmitting.
            </Text>
          </Stack>
        </details>
      </Stack>
    </Paper>
  );
}
