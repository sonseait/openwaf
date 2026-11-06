import { ModalTabs, ModalSection, ModalTabLayout } from "./ModalTabs";
import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Badge,
  Button,
  Checkbox,
  Code,
  Divider,
  Group,
  Modal,
  NativeSelect,
  NumberInput,
  Paper,
  PasswordInput,
  SimpleGrid,
  Stack,
  Text,
  TextInput,
  Title,
  rem,
} from "@mantine/core";
import { Controller, useForm } from "react-hook-form";
import dayjs from "dayjs";
import toast from "react-hot-toast";
import { api, queryClient } from "./api";
import { DetailsGrid, Failure, StateBadge } from "./shared";
import type { Config } from "./types";
import type {
  EndpointStatus,
  EndpointOperation,
  EndpointPage,
} from "./uptime-state";
import { EndpointTable } from "./EndpointTable";
import { observeConfigVersion } from "./config-cache";
import { UptimeMonitors } from "./UptimeMonitors";

interface Telegram {
  revision: number;
  enabled: boolean;
  chat_id: string;
  topic_id: number | null;
  token_configured: boolean;
  silence_until_unix_ms: number;
}
export function TelegramAlerts() {
  const query = useQuery({
    queryKey: ["telegram"],
    queryFn: ({ signal }) => api<Telegram>("/alerts/telegram", { signal }),
  });
  const outbox = useQuery({
    queryKey: ["telegram-outbox"],
    queryFn: ({ signal }) =>
      api<{
        pending: number;
        capacity: number;
        saturated: boolean;
        items: {
          id: number;
          group: string;
          state: string;
          attempts: number;
          last_error: string | null;
        }[];
      }>("/alerts/telegram/outbox", { signal }),
    refetchInterval: 10000,
  });
  const test = useMutation({
    mutationFn: () => api("/alerts/telegram/test", { method: "POST" }),
    onSuccess: () => {
      toast.success("Test alert queued");
      void outbox.refetch();
    },
  });
  return (
    <Paper withBorder p="md">
      <Stack>
        <Title order={2}>Telegram alerts</Title>
        <Text size="sm">
          One bot, one chat, optional forum topic. Outbound notifications only.
          Repeated events group for 5 minutes; unacknowledged deliveries may
          repeat.
        </Text>
        {query.isPending && <Text>Loading Telegram settings…</Text>}
        {query.isError && <Failure error={query.error} />}
        {query.data && (
          <TelegramForm key={query.data.revision} value={query.data} />
        )}
        <Button
          variant="default"
          onClick={() => test.mutate()}
          loading={test.isPending}
          disabled={!query.data?.enabled}
        >
          Send test alert
        </Button>
        {test.isError && <Failure error={test.error} />}
        <Title order={3}>Recent delivery attempts</Title>
        {outbox.isError && <Failure error={outbox.error} />}
        {outbox.data && (
          <Text size="sm">
            Pending: {outbox.data.pending} / {outbox.data.capacity}
          </Text>
        )}
        {outbox.data?.saturated && (
          <Alert color="red">
            Telegram queue is full. New alerts remain pending evaluation; test
            requests return unavailable until capacity recovers.
          </Alert>
        )}
        <Text size="sm">
          {outbox.data?.items.length === 0 ? "No alerts queued" : null}
        </Text>
        {outbox.data?.items.map((item) => (
          <Stack key={item.id} gap="xs">
            <Group justify="space-between">
              <Text size="sm" fw={500}>
                #{item.id} · {item.group}
              </Text>
              <StateBadge value={item.state} />
            </Group>
            <Text size="sm" c="dimmed">
              Attempts {item.attempts} ·{" "}
              {item.last_error ?? "No delivery error"}
            </Text>
          </Stack>
        ))}
      </Stack>
    </Paper>
  );
}
function TelegramForm({ value }: { value: Telegram }) {
  const form = useForm({
    defaultValues: {
      enabled: value.enabled,
      chat_id: value.chat_id,
      topic_id: value.topic_id ?? undefined,
      token: "",
      silence_hours: 0,
    },
  });
  const save = useMutation({
    mutationFn: (input: {
      enabled: boolean;
      chat_id: string;
      topic_id?: number;
      token: string;
      silence_hours: number;
    }) =>
      api("/alerts/telegram", {
        method: "PUT",
        body: {
          expected_revision: value.revision,
          enabled: input.enabled,
          chat_id: input.chat_id,
          topic_id: input.topic_id ?? null,
          token: input.token || null,
          silence_until_unix_ms: input.silence_hours
            ? Date.now() + input.silence_hours * 3600000
            : 0,
        },
      }),
    onSuccess: () => {
      form.resetField("token");
      toast.success("Telegram settings saved");
      void queryClient.invalidateQueries({ queryKey: ["telegram"] });
    },
  });
  return (
    <form onSubmit={form.handleSubmit((v) => save.mutate(v))}>
      <Stack>
        <Controller
          name="enabled"
          control={form.control}
          render={({ field }) => (
            <Checkbox
              label="Enable Telegram notifications"
              checked={field.value}
              onChange={(e) => field.onChange(e.currentTarget.checked)}
            />
          )}
        />
        <PasswordInput
          label="Bot token"
          autoComplete="off"
          description={
            value.token_configured
              ? "Token stored encrypted. Leave blank to keep it."
              : "Create a bot using BotFather."
          }
          {...form.register("token")}
        />
        <TextInput label="Chat ID" required {...form.register("chat_id")} />
        <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }} spacing="md">
          <Controller
            name="topic_id"
            control={form.control}
            render={({ field }) => (
              <NumberInput
                label="Topic ID (optional)"
                description="Telegram forum topic. Leave blank for the main chat."
                allowDecimal={false}
                min={1}
                value={field.value ?? ""}
                onChange={(v) =>
                  field.onChange(v === "" ? undefined : Number(v))
                }
              />
            )}
          />
          <Controller
            name="silence_hours"
            control={form.control}
            render={({ field }) => (
              <NumberInput
                label="Silence notifications (hours)"
                description={
                  value.silence_until_unix_ms > 0
                    ? `Currently silenced until ${dayjs(value.silence_until_unix_ms).format("YYYY-MM-DD HH:mm")}. Saving 0 ends silence.`
                    : "0 means notifications are active."
                }
                min={0}
                max={168}
                value={field.value}
                onChange={(v) => field.onChange(Number(v))}
              />
            )}
          />
        </SimpleGrid>
        {save.isError && <Failure error={save.error} />}
        <Button type="submit" loading={save.isPending}>
          Save Telegram settings
        </Button>
      </Stack>
    </form>
  );
}
export function EndpointControls({
  paused: parentPaused,
  monitorLayout = false,
}: {
  paused?: boolean;
  monitorLayout?: boolean;
}) {
  const [localPaused, setLocalPaused] = useState(false);
  const paused = parentPaused ?? localPaused;
  const query = useQuery({
    queryKey: ["endpoint-operations", "summary"],
    queryFn: ({ signal }) =>
      api<EndpointPage>("/operations/endpoints?summary=true", { signal }).then(
        (value) => {
          if (
            !Array.isArray(value.endpoints) ||
            !Array.isArray(value.operations)
          )
            throw new Error("Invalid endpoint status response");
          return value;
        },
      ),
    refetchInterval: paused ? false : 5000,
  });
  const version = query.data?.config_version;
  useEffect(() => {
    if (version != null) void observeConfigVersion(queryClient, version);
  }, [version]);
  const [selected, setSelected] = useState<EndpointStatus | null>(null);
  return (
    <>
      {monitorLayout ? (
        <UptimeMonitors
          data={query.data}
          pending={query.isPending}
          error={query.error}
          paused={paused}
          onRetry={() => void query.refetch()}
          onMaintain={setSelected}
        />
      ) : (
        <Paper withBorder p="md">
          <Stack>
            <Group justify="space-between">
              <Title order={2}>Endpoint diagnostics &amp; maintenance</Title>
              <Button
                variant="default"
                onClick={() => setLocalPaused(!localPaused)}
              >
                {paused ? "Resume endpoint refresh" : "Pause endpoint refresh"}
              </Button>
            </Group>
            {(paused || query.isError) && (
              <Badge color="yellow">Endpoint observations stale</Badge>
            )}
            {query.isPending && <Text>Loading endpoint state…</Text>}
            {query.isError && <Failure error={query.error} />}
            <Text size="sm">
              Drain/maintenance stop new admissions and retries. Existing
              requests continue until completion unless explicitly disconnected.
            </Text>
            <EndpointTable
              data={query.data}
              pending={query.isPending}
              stale={paused || query.isError}
              onMaintain={setSelected}
            />
          </Stack>
        </Paper>
      )}
      <Modal
        opened={!!selected}
        onClose={() => setSelected(null)}
        title="Endpoint controls"
        scrollAreaComponent={ModalTabLayout}
        size="lg"
      >
        {selected && query.data && (
          <EndpointForm
            key={selected.key}
            endpoint={selected}
            operation={query.data.operations.find(
              (o) => o.key === selected.key,
            )}
          />
        )}
      </Modal>
    </>
  );
}
function EndpointForm({
  endpoint,
  operation,
}: {
  endpoint: EndpointStatus;
  operation?: EndpointOperation;
}) {
  const form = useForm({
    defaultValues: {
      mode: operation?.mode ?? "active",
      reason: "",
      deadline_minutes: 30,
    },
  });
  const [forceConfirm, setForceConfirm] = useState(false);
  const history = useQuery({
    queryKey: ["endpoint-history", endpoint.key],
    gcTime: 0,
    queryFn: ({ signal }) =>
      api<{
        items: {
          observed_at_unix_ms: number;
          status: {
            reason: string;
            last_check?: {
              addresses: {
                address: string;
                tcp: string;
                tls: string;
                http: string;
                http_status: number | null;
                error: string | null;
                latency_ms: number;
              }[];
            };
          };
        }[];
      }>("/operations/endpoints/history", {
        signal,
        method: "POST",
        body: { key: endpoint.key },
      }),
  });
  const save = useMutation({
    mutationFn: (input: {
      mode: string;
      reason: string;
      deadline_minutes: number;
    }) =>
      api("/operations/endpoints", {
        method: "PUT",
        body: {
          key: endpoint.key,
          expected_revision: operation?.revision ?? 0,
          mode: input.mode,
          reason: input.reason,
          deadline_unix_ms:
            input.mode === "active" || input.deadline_minutes === 0
              ? null
              : Date.now() + input.deadline_minutes * 60000,
        },
      }),
    onSuccess: () => {
      toast.success("Endpoint mode saved");
      void queryClient.invalidateQueries({ queryKey: ["endpoint-operations"] });
    },
  });
  const force = useMutation({
    mutationFn: () =>
      api("/operations/endpoints/force-disconnect", {
        method: "POST",
        body: { key: endpoint.key },
      }),
    onSuccess: () => {
      toast.success("Endpoint requests disconnected");
      setForceConfirm(false);
      void queryClient.invalidateQueries({ queryKey: ["endpoint-operations"] });
    },
  });
  return (
    <Stack>
      <Code>{endpoint.address}</Code>
      <Text>
        {operation?.remaining_leases ?? operation?.active_requests ?? 0}{" "}
        remaining request leases (each H2 stream counts separately)
      </Text>
      {operation?.drained && <Badge color="teal">Drain complete</Badge>}
      {endpoint.expected_downtime && (
        <Alert color="orange" title="Downtime expected">
          {endpoint.single_endpoint
            ? "This upstream has one endpoint."
            : "No healthy active alternative accepts traffic."}{" "}
          Draining it makes new requests unavailable. Existing streams may
          continue until their request deadline; completion time cannot be
          estimated reliably.
        </Alert>
      )}
      {operation?.deadline_unix_ms && (
        <Text c={operation.deadline_exceeded ? "orange" : undefined}>
          Maintenance deadline{" "}
          {dayjs(operation.deadline_unix_ms).format("YYYY-MM-DD HH:mm:ss")} ·{" "}
          {operation.deadline_exceeded ? "exceeded" : "pending"}. No automatic
          disconnect.
        </Text>
      )}
      <ModalTabs label="Endpoint control sections" defaultValue="controls">
        <ModalSection value="controls" label="Maintenance">
          <Text size="sm">
            Returning to active ramps request share over{" "}
            {endpoint.slow_start_ms ?? 0} ms after verified health. Affinity
            cannot override drain/down.
          </Text>
          <form onSubmit={form.handleSubmit((v) => save.mutate(v))}>
            <Stack>
              <Controller
                control={form.control}
                name="mode"
                render={({ field }) => (
                  <NativeSelect
                    label="Admission mode"
                    data={["active", "drain", "maintenance"]}
                    {...field}
                  />
                )}
              />
              <TextInput
                label="Reason"
                required
                maxLength={256}
                {...form.register("reason", { required: true })}
              />
              <Controller
                control={form.control}
                name="deadline_minutes"
                render={({ field }) => (
                  <NumberInput
                    maw={rem(416)}
                    label="Maintenance deadline from now (minutes)"
                    description="0 disables the reminder. Deadline never forces disconnect."
                    min={0}
                    max={10080}
                    allowDecimal={false}
                    value={field.value}
                    onChange={(v) => field.onChange(Number(v))}
                  />
                )}
              />
              <Button type="submit" loading={save.isPending}>
                Save endpoint mode
              </Button>
              {save.isError && <Failure error={save.error} />}
            </Stack>
          </form>
        </ModalSection>
        <ModalSection value="disconnect" label="Disconnect">
          <Checkbox
            label="Disconnect all requests currently using this endpoint"
            checked={forceConfirm}
            onChange={(e) => setForceConfirm(e.currentTarget.checked)}
          />
          <Button
            color="red"
            disabled={!forceConfirm}
            onClick={() => force.mutate()}
            loading={force.isPending}
          >
            Force disconnect
          </Button>
          {force.isError && <Failure error={force.error} />}
        </ModalSection>
        <ModalSection value="history" label="Recent checks">
          <Title order={3}>Recent checks · retained 7 days</Title>
          {history.isPending && <Text>Loading checks…</Text>}
          {history.isError && <Failure error={history.error} />}
          <Text size="sm">
            At most 100 samples. No records means no persisted observations are
            available.
          </Text>
          {history.data?.items.map((v, i) => (
            <Paper withBorder p="sm" key={i}>
              <Text size="sm">
                {dayjs(v.observed_at_unix_ms).format("YYYY-MM-DD HH:mm:ss")} ·{" "}
                {v.status.reason}
              </Text>
              {v.status.last_check?.addresses.map((a, j) => (
                <Text size="xs" key={j}>
                  {a.address} · TCP {a.tcp} · TLS {a.tls} · HTTP {a.http}{" "}
                  {a.http_status} · {a.latency_ms} ms · {a.error}
                </Text>
              ))}
            </Paper>
          ))}
        </ModalSection>
      </ModalTabs>
    </Stack>
  );
}
interface ShadowStatus {
  state: string;
  route_id?: string;
  sampling_percent?: number;
  sampled?: number;
  completed?: number;
  would_block?: number;
  different_decisions?: number;
  dropped?: number;
  started_at_unix_ms?: number;
  duration_ms?: number;
  config_version?: number;
  active_config_version?: number;
  process_epoch?: number;
  ends_at_unix_ms?: number;
  comparison_denominator?: number;
  inspection_scope?: string;
  completed_scopes?: Record<string, number>;
  pending?: number;
  config_changed?: boolean;
  conclusion_limited?: boolean;
}
export function ShadowPolicy({ routeId }: { routeId?: string } = {}) {
  const [paused, setPaused] = useState(false);
  const config = useQuery({
    queryKey: ["config"],
    queryFn: ({ signal }) => api<Config>("/config", { signal }),
  });
  const status = useQuery({
    queryKey: ["shadow"],
    queryFn: ({ signal }) => api<ShadowStatus>("/security/shadow", { signal }),
    refetchInterval: paused ? false : 5000,
  });
  const form = useForm({
    defaultValues: {
      route_id: routeId ?? "",
      sampling_percent: 10,
      duration_minutes: 30,
      paranoia_level: 1,
    },
  });
  const start = useMutation({
    mutationFn: (input: {
      route_id: string;
      sampling_percent: number;
      duration_minutes: number;
      paranoia_level: number;
    }) => {
      const route = config.data?.draft.routes.find(
        (r) => r.id === input.route_id,
      );
      if (!route) throw new Error("Select a configured route");
      return api("/security/shadow", {
        method: "POST",
        body: {
          route_id: route.id,
          sampling_percent: input.sampling_percent,
          duration_ms: input.duration_minutes * 60000,
          policy: {
            ...route.waf,
            mode: "On",
            paranoia_level: input.paranoia_level,
          },
        },
      });
    },
    onSuccess: () => {
      toast.success("Shadow session started");
      void status.refetch();
    },
  });
  const stop = useMutation({
    mutationFn: () => api("/security/shadow", { method: "DELETE" }),
    onSuccess: () => void status.refetch(),
  });
  return (
    <>
      <Paper withBorder p="md">
        <Stack>
          <Group justify="space-between">
            <Title order={2}>Test policy on live traffic</Title>
            <Button variant="default" onClick={() => setPaused(!paused)}>
              {paused ? "Resume shadow refresh" : "Pause shadow refresh"}
            </Button>
          </Group>
          {(paused || status.isError) && (
            <Badge color="yellow">Shadow observations stale</Badge>
          )}
          {status.isPending && (
            <Text role="status">Loading shadow session…</Text>
          )}
          <Text size="sm">
            One shadow session per node; separate bounded workers. Uses the
            selected draft WAF policy and candidate paranoia level. No extra
            upstream requests and no blocking changes. Samples cover requests
            with a primary WAF result (or Off) after contract checks; earlier
            rejects are outside this population.
          </Text>
          {config.isError && <Failure error={config.error} />}
          <form onSubmit={form.handleSubmit((v) => start.mutate(v))}>
            <Stack>
              <Controller
                control={form.control}
                name="route_id"
                rules={{ required: true }}
                render={({ field }) => (
                  <NativeSelect
                    label="Route to sample"
                    data={[
                      { value: "", label: "Select a route" },
                      ...(config.data?.draft.routes.map((r) => ({
                        value: r.id,
                        label: r.id,
                      })) ?? []),
                    ]}
                    {...field}
                  />
                )}
              />
              <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }} spacing="md">
                {(
                  [
                    ["sampling_percent", "Sample traffic (%)", 1, 100],
                    ["duration_minutes", "Session duration (minutes)", 1, 1440],
                    ["paranoia_level", "Candidate paranoia level", 1, 4],
                  ] as const
                ).map(([name, label, min, max]) => (
                  <Controller
                    key={name}
                    name={name}
                    control={form.control}
                    render={({ field }) => (
                      <NumberInput
                        label={label}
                        description={
                          name === "sampling_percent"
                            ? "Share of eligible requests copied to the candidate policy."
                            : name === "duration_minutes"
                              ? "The shadow session stops automatically after this duration."
                              : "1–4. Evaluates the candidate policy without changing the active policy."
                        }
                        min={min}
                        max={max}
                        allowDecimal={false}
                        value={field.value}
                        onChange={(v) => field.onChange(Number(v))}
                      />
                    )}
                  />
                ))}
              </SimpleGrid>
              <Group>
                <Button
                  type="submit"
                  loading={start.isPending}
                  disabled={status.data?.state === "running"}
                >
                  Start shadow test
                </Button>
                <Button
                  variant="default"
                  onClick={() => stop.mutate()}
                  disabled={status.data?.state !== "running"}
                >
                  Stop session
                </Button>
              </Group>
            </Stack>
          </form>
          {start.isError && <Failure error={start.error} />}{" "}
          {stop.isError && <Failure error={stop.error} />}{" "}
          {status.isError && <Failure error={status.error} />}{" "}
          {status.data && (
            <Alert
              color={status.data.dropped ? "yellow" : "blue"}
              title={
                <Group gap="xs">
                  <Text inherit>Shadow</Text>
                  <StateBadge value={status.data.state} />
                </Group>
              }
            >
              <Stack gap="md">
                <DetailsGrid
                  items={[
                    { label: "Sampled", value: status.data.sampled ?? 0 },
                    { label: "Completed", value: status.data.completed ?? 0 },
                    {
                      label: "Would block",
                      value: status.data.would_block ?? 0,
                    },
                    {
                      label: "Different decisions",
                      value: status.data.different_decisions ?? 0,
                    },
                    { label: "Dropped", value: status.data.dropped ?? 0 },
                    { label: "Pending", value: status.data.pending ?? 0 },
                  ]}
                />
                <Divider />
                <DetailsGrid
                  items={[
                    {
                      label: "Candidate config",
                      value: status.data.config_version ?? "Unavailable",
                    },
                    {
                      label: "Active config",
                      value: status.data.active_config_version ?? "Unavailable",
                    },
                    {
                      label: "Process epoch",
                      value: status.data.process_epoch ?? "Unavailable",
                    },
                    {
                      label: "Started",
                      value: status.data.started_at_unix_ms
                        ? dayjs(status.data.started_at_unix_ms).format(
                            "YYYY-MM-DD HH:mm:ss",
                          )
                        : "Unavailable",
                    },
                    {
                      label: "Ends",
                      value: status.data.ends_at_unix_ms
                        ? dayjs(status.data.ends_at_unix_ms).format(
                            "YYYY-MM-DD HH:mm:ss",
                          )
                        : "Unavailable",
                    },
                    {
                      label: "Inspection scope",
                      value: status.data.inspection_scope ?? "Unavailable",
                    },
                    {
                      label: "Comparison denominator",
                      value:
                        status.data.comparison_denominator ?? "Unavailable",
                    },
                  ]}
                />
                <Text size="sm">
                  Comparison uses completed shadow inspections versus actual
                  primary decisions.
                </Text>
                <Divider />
                <Stack gap="sm">
                  <Text fw={600} size="sm">
                    Completed scopes
                  </Text>
                  {Object.keys(status.data.completed_scopes ?? {}).length >
                  0 ? (
                    <DetailsGrid
                      items={Object.entries(
                        status.data.completed_scopes ?? {},
                      ).map(([label, value]) => ({ label, value }))}
                    />
                  ) : (
                    <Text size="sm">No completed samples</Text>
                  )}
                </Stack>
                {(status.data.conclusion_limited ||
                  status.data.config_changed) && (
                  <Text fw={600}>
                    Conclusion limited: missing/dropped samples or active
                    configuration changed. No promotion or automatic apply.
                  </Text>
                )}
                <Text size="xs">
                  Restart resets sessions/counters. Findings contain rule IDs
                  only; no matched data.
                </Text>
              </Stack>
            </Alert>
          )}
        </Stack>
      </Paper>
      <ExclusionLifecycle />
    </>
  );
}

function ExclusionLifecycle() {
  const [paused, setPaused] = useState(false);
  const query = useQuery({
    queryKey: ["exclusion-lifecycle"],
    queryFn: ({ signal }) =>
      api<{
        config_version: number;
        observed_at_unix_ms: number;
        scope: string;
        routes: {
          route_id: string;
          mode: string;
          summary: {
            inspection_offers: number;
            exclusions: {
              rule_id: number;
              target: string | null;
              owner: string | null;
              reason: string;
              state: string;
              expires_at_unix_ms: number | null;
              offered_while_active: number;
            }[];
          };
        }[];
      }>("/security/exclusions", { signal }),
    refetchInterval: paused ? false : 5000,
  });
  return (
    <Paper withBorder p="md">
      <Stack gap="md">
        <Group justify="space-between">
          <Title order={2}>Exclusion lifecycle</Title>
          <Button variant="default" onClick={() => setPaused(!paused)}>
            {paused ? "Resume exclusion refresh" : "Pause exclusion refresh"}
          </Button>
        </Group>
        {query.isPending && <Text role="status">Loading exclusions…</Text>}
        {query.isError && <Failure error={query.error} />}
        {(paused || query.isError) && (
          <Badge color="yellow">Exclusion observations stale</Badge>
        )}
        <Text size="sm">
          Counts cover inspection offers while configured and unexpired, not
          rule matches. Counters reset on apply/restart. Expiry reminders cover
          the next 24 hours. Review the configuration draft to change an
          exclusion; none are renewed automatically.
        </Text>
        {query.data && (
          <DetailsGrid
            items={[
              { label: "Active config", value: query.data.config_version },
              {
                label: "Observed",
                value: dayjs(query.data.observed_at_unix_ms).format(
                  "YYYY-MM-DD HH:mm:ss",
                ),
              },
              { label: "Counter scope", value: query.data.scope },
            ]}
          />
        )}
        {query.data &&
          !query.data.routes.some((r) => r.summary.exclusions.length > 0) && (
            <Text>No active configuration exclusions</Text>
          )}
        {query.data?.routes.map((r) =>
          r.summary.exclusions.map((e, i) => (
            <Stack
              key={`${r.route_id}-${i}`}
              component="article"
              aria-label={`Exclusion ${r.route_id} rule ${e.rule_id}`}
              gap="md"
            >
              <Divider />
              <Group justify="space-between">
                <Title order={3}>Rule {e.rule_id}</Title>
                <Badge color={e.state === "active" ? "blue" : "yellow"}>
                  {e.state.replaceAll("_", " ")}
                </Badge>
              </Group>
              <DetailsGrid
                items={[
                  { label: "Route", value: r.route_id },
                  { label: "Target", value: e.target ?? "Whole route" },
                  { label: "CRS mode", value: <StateBadge value={r.mode} /> },
                  { label: "Owner", value: e.owner || "Unassigned" },
                  { label: "Reason", value: e.reason },
                  {
                    label: "Expires",
                    value: e.expires_at_unix_ms
                      ? dayjs(e.expires_at_unix_ms).format(
                          "YYYY-MM-DD HH:mm:ss",
                        )
                      : "No expiry",
                  },
                  {
                    label: "Offers while active",
                    value: `${e.offered_while_active} / ${r.summary.inspection_offers}`,
                  },
                ]}
              />
            </Stack>
          )),
        )}
      </Stack>
    </Paper>
  );
}
