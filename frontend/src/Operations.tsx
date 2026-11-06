import { ModalTabs, ModalSection, ModalTabLayout } from "./ModalTabs";
import { focusModalError } from "./modal-focus";
import {
  TelegramAlerts,
  EndpointControls,
  ShadowPolicy,
} from "./OperationalControls";
import { ResourceCapacity, type ResourceDiagnostics } from "./ResourceCapacity";
import { InspectionCoverage } from "./TrafficProfiles";
import { CertificateRequests } from "./Certificates";
import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Badge,
  Button,
  Divider,
  Group,
  Loader,
  Modal,
  NativeSelect,
  NumberInput,
  Paper,
  SimpleGrid,
  Stack,
  Text,
  TextInput,
  Title,
  rem,
} from "@mantine/core";
import { DataTable } from "./DataTable";
import { Controller, useFieldArray, useForm } from "react-hook-form";
import { Link } from "react-router-dom";
import dayjs from "dayjs";
import toast from "react-hot-toast";
import { api, queryClient } from "./api";
import { DetailsGrid, Failure, StateBadge } from "./shared";
import type { Config, Route } from "./types";
interface Dependencies extends ResourceDiagnostics {
  observed_at_unix_ms: number;
  config_version: number;
  waf: { queued: number; executing: number; rejected_active_policies: number };
  crowdsec: {
    degraded: boolean;
    last_success_age_ms: number | null;
    checkpoint_status?: string;
    checkpoint_degraded?: boolean;
    checkpoint_recovery?: string;
  } | null;
  tls: {
    revision: number;
    certificates: {
      hostname: string;
      dns_names: string[];
      valid_from_unix_s: number;
      valid_until_unix_s: number;
    }[];
  } | null;
  upstreams: {
    upstream: number;
    endpoint: number;
    available: boolean;
    reason: string;
    checked_at_ms: number | null;
    source: string;
    valid_for_ms: number;
    last_check?: {
      latency_ms: number;
      addresses: {
        tcp: string;
        tls: string;
        http: string;
        error: string | null;
      }[];
    } | null;
  }[];
}
export function Operations({
  page,
}: {
  page: "Security" | "Certificates" | "Uptime" | "Alerts" | "Settings";
}) {
  const [paused, setPaused] = useState(false);
  const status = useQuery({
    queryKey: ["dependencies"],
    queryFn: ({ signal }) =>
      api<Dependencies>("/telemetry/dependencies", { signal }),
    enabled: page !== "Uptime",
    refetchInterval: paused ? false : 5000,
  });
  const certificates = status.data?.tls?.certificates ?? [];
  const warnings = [
    ...(status.data?.crowdsec?.degraded
      ? ["CrowdSec sync degraded. Existing bans retain their original expiry."]
      : []),
    ...(status.data?.crowdsec?.checkpoint_degraded
      ? [
          "CrowdSec checkpoint unavailable; runtime bans keep their original expiry. Restart recovery needs attention.",
        ]
      : []),
    ...(status.data?.upstreams
      .filter((s) => !s.available)
      .map(
        (s) => `Upstream ${s.upstream}, endpoint ${s.endpoint}: ${s.reason}`,
      ) ?? []),
    ...certificates
      .filter(
        (c) =>
          c.valid_until_unix_s * 1000 <
          status.data!.observed_at_unix_ms + 7 * 86400000,
      )
      .map(
        (c) =>
          `Certificate ${c.hostname} expires ${dayjs.unix(c.valid_until_unix_s).format("YYYY-MM-DD HH:mm:ss")}`,
      ),
  ];
  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Title order={1}>{page}</Title>
        <Button variant="default" onClick={() => setPaused(!paused)}>
          {paused ? "Resume health refresh" : "Pause health refresh"}
        </Button>
      </Group>
      {page !== "Uptime" && status.isPending && (
        <Group role="status">
          <Loader size="sm" />
          Loading gateway health…
        </Group>
      )}
      {page !== "Uptime" && status.isError && (
        <>
          <Alert color="yellow">
            Health unavailable; displayed observations may be stale.
          </Alert>
          <Failure error={status.error} />
          <Button onClick={() => void status.refetch()}>Retry health</Button>
        </>
      )}
      {page !== "Uptime" && status.data && (
        <Group gap="md" c="dimmed">
          <Text size="sm">
            {paused ? "Paused observation" : "Last observation"}:{" "}
            {dayjs(status.data.observed_at_unix_ms).format(
              "YYYY-MM-DD HH:mm:ss",
            )}
          </Text>
          <Text size="sm">Active version {status.data.config_version}</Text>
        </Group>
      )}
      {page === "Security" && (
        <>
          <ResourceCapacity
            value={status.data}
            paused={paused}
            stale={status.isError}
          />
          <InspectionCoverage />
          <Paper
            withBorder
            p="md"
            component="section"
            aria-label="Inspection health"
          >
            <Stack gap="md">
              <Title order={2}>Inspection health</Title>
              {status.data && (
                <>
                  <Stack gap="md">
                    <Title order={3}>WAF workers</Title>
                    <DetailsGrid
                      items={[
                        {
                          label: "Queued inspections",
                          value: status.data.waf.queued,
                        },
                        {
                          label: "Executing inspections",
                          value: status.data.waf.executing,
                        },
                        {
                          label: "Rejected admissions in active policies",
                          value: status.data.waf.rejected_active_policies,
                        },
                      ]}
                    />
                  </Stack>
                  <Divider />
                  <Stack gap="md">
                    <Group justify="space-between">
                      <Title order={3}>CrowdSec</Title>
                      <Badge
                        color={
                          status.data.crowdsec?.degraded ||
                          status.data.crowdsec?.checkpoint_degraded
                            ? "yellow"
                            : "gray"
                        }
                      >
                        {status.data.crowdsec
                          ? status.data.crowdsec.degraded
                            ? "CrowdSec degraded"
                            : "CrowdSec synchronized"
                          : "CrowdSec not configured"}
                      </Badge>
                    </Group>
                    <DetailsGrid
                      items={[
                        {
                          label: "Checkpoint",
                          value:
                            status.data.crowdsec?.checkpoint_status ??
                            "Unavailable",
                        },
                        {
                          label: "Recovery",
                          value:
                            status.data.crowdsec?.checkpoint_recovery ??
                            "Unavailable",
                        },
                        {
                          label: "Last successful sync age",
                          value:
                            status.data.crowdsec?.last_success_age_ms != null
                              ? `${status.data.crowdsec.last_success_age_ms} ms`
                              : "Unavailable",
                        },
                      ]}
                    />
                  </Stack>
                </>
              )}
            </Stack>
          </Paper>
          <Policies />
          <ShadowPolicy />
        </>
      )}
      {page === "Certificates" && <CertificateRequests paused={paused} />}
      {page === "Certificates" && (
        <Paper withBorder p="md">
          <Stack>
            <Text>
              Validated listener snapshot · Revision{" "}
              {status.data?.tls?.revision ?? "—"}
            </Text>
            <Text size="sm" c="dimmed">
              Certificate issuance and renewal follow the configured ACME
              schedules. This view reports certificates currently loaded by the
              listener.
            </Text>
            <DataTable
              records={certificates}
              idAccessor="hostname"
              noRecordsText={
                status.data?.tls
                  ? "No certificate loaded"
                  : "TLS listener not configured"
              }
              minHeight={rem(160)}
              columns={[
                { accessor: "hostname", title: "SNI hostname" },
                {
                  accessor: "dns_names",
                  title: "Certificate SANs",
                  render: (c) => c.dns_names.join(", "),
                },
                {
                  accessor: "valid_from_unix_s",
                  title: "Valid from",
                  render: (c) =>
                    dayjs
                      .unix(c.valid_from_unix_s)
                      .format("YYYY-MM-DD HH:mm:ss"),
                },
                {
                  accessor: "valid_until_unix_s",
                  title: "Expires",
                  render: (c) =>
                    dayjs
                      .unix(c.valid_until_unix_s)
                      .format("YYYY-MM-DD HH:mm:ss"),
                },
                {
                  accessor: "health",
                  title: "Health",
                  render: (c) => {
                    const now = status.data!.observed_at_unix_ms / 1000;
                    return c.valid_from_unix_s > now ||
                      c.valid_until_unix_s <= now ? (
                      <StateBadge value="invalid" />
                    ) : c.valid_until_unix_s - now < 7 * 86400 ? (
                      <StateBadge value="expires_soon" />
                    ) : (
                      <StateBadge value="valid" />
                    );
                  },
                },
              ]}
            />
          </Stack>
        </Paper>
      )}
      {page === "Uptime" && <EndpointControls paused={paused} monitorLayout />}
      {page === "Alerts" && <TelegramAlerts />}
      {page === "Uptime" && <UptimeHistory paused={paused} />}
      {page === "Alerts" && (
        <Paper withBorder p="md">
          <Stack>
            <Title order={2}>Current health warnings</Title>
            <Text size="sm" c="dimmed">
              Dependency and certificate observations. Webhook delivery and
              alert rules are scheduled for Phase 5.
            </Text>
            {!status.data ? (
              <Text>Waiting for health observations.</Text>
            ) : warnings.length ? (
              warnings.map((warning) => (
                <Alert color="yellow" key={warning}>
                  {warning}
                </Alert>
              ))
            ) : (
              <Text>No warnings in the current observation.</Text>
            )}
          </Stack>
        </Paper>
      )}
      {page === "Settings" && <Settings />}
    </Stack>
  );
}
function Policies() {
  const config = useQuery({
    queryKey: ["config"],
    queryFn: ({ signal }) => api<Config>("/config", { signal }),
  });
  const [editing, setEditing] = useState<Route | null>(null);
  return (
    <Paper withBorder p="md">
      <Stack>
        <Group justify="space-between">
          <Title order={2}>Route policies · draft</Title>
          <Group>
            <Button
              component={Link}
              to="/configuration?section=global"
              variant="default"
            >
              Global rules
            </Button>
            <Button component={Link} to="/configuration" variant="default">
              Review and apply
            </Button>
          </Group>
        </Group>
        <Text size="sm" c="dimmed">
          Save a policy to the draft, then review and apply its diff. ACL, GeoIP
          and traffic limits remain active when CRS is disabled. An ACL allow
          does not bypass CRS. Global IP, country and rate rules run before
          every route policy.
        </Text>
        {config.isPending && <Text role="status">Loading policies…</Text>}
        {config.isError && <Failure error={config.error} />}
        <DataTable
          records={config.data?.draft.routes ?? []}
          minHeight={rem(140)}
          noRecordsText="No routes configured"
          columns={[
            { accessor: "id", title: "Route" },
            { accessor: "hostname" },
            {
              accessor: "mode",
              title: "CRS mode",
              render: (r) => (
                <StateBadge value={r.waf?.mode ?? "Gateway default"} />
              ),
            },
            {
              accessor: "paranoia",
              title: "Paranoia level",
              render: (r) => r.waf?.paranoia_level ?? "Inherited",
            },
            {
              accessor: "acl",
              title: "ACL deny / allow",
              render: (r) =>
                `${r.access?.deny?.length ?? 0} / ${r.access?.allow?.length ?? 0}`,
            },
            {
              accessor: "edit",
              title: "Actions",
              render: (r) => (
                <Button
                  size="compact-xs"
                  variant="subtle"
                  onClick={() => setEditing(r)}
                  aria-label={`Edit WAF policy ${r.id}`}
                >
                  Edit WAF
                </Button>
              ),
            },
          ]}
        />
        <Modal
          opened={!!editing}
          onClose={() => setEditing(null)}
          title={editing ? `WAF policy · ${editing.id}` : "WAF policy"}
          scrollAreaComponent={ModalTabLayout}
        >
          {editing && config.data && (
            <PolicyEditor
              key={`${editing.id}:${config.data.draft_revision}`}
              route={editing}
              config={config.data}
              done={() => setEditing(null)}
            />
          )}
        </Modal>
      </Stack>
    </Paper>
  );
}
function PolicyEditor({
  route,
  config,
  done,
}: {
  route: Route;
  config: Config;
  done: () => void;
}) {
  const {
    register,
    control,
    handleSubmit,
    formState: { errors },
  } = useForm<{
    mode: "Off" | "DetectionOnly" | "On";
    paranoia_level: number;
    body_limit_bytes: number;
    inspection_timeout_ms: number;
    exclusions: NonNullable<NonNullable<Route["waf"]>["exclusions"]>;
  }>({
    shouldFocusError: false,
    defaultValues: {
      mode: route.waf?.mode ?? "DetectionOnly",
      paranoia_level: route.waf?.paranoia_level ?? 1,
      body_limit_bytes: route.waf?.body_limit_bytes ?? 65536,
      inspection_timeout_ms: route.waf?.inspection_timeout_ms ?? 2000,
      exclusions: route.waf?.exclusions ?? [],
    },
  });
  const exclusions = useFieldArray({ control, name: "exclusions" });
  const save = useMutation({
    mutationFn: (values: {
      mode: "Off" | "DetectionOnly" | "On";
      paranoia_level: number;
      body_limit_bytes: number;
      inspection_timeout_ms: number;
      exclusions: NonNullable<NonNullable<Route["waf"]>["exclusions"]>;
    }) =>
      api("/config/draft", {
        method: "PUT",
        body: {
          expected_revision: config.draft_revision,
          document: {
            ...config.draft,
            routes: config.draft.routes.map((r) =>
              r.id === route.id
                ? {
                    ...r,
                    waf: {
                      ...values,
                      exclusions: values.exclusions.map((e) => ({
                        ...e,
                        owner: e.owner?.trim() || undefined,
                        target: e.target?.trim() || undefined,
                      })),
                    },
                  }
                : r,
            ),
          },
        },
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["config"] });
      toast.success("Policy saved to draft. Review and apply to activate.");
      done();
    },
  });
  return (
    <form
      className="policy-modal-form"
      noValidate
      onSubmit={handleSubmit(
        (values) => save.mutate(values),
        () => focusModalError(".policy-modal-form"),
      )}
    >
      <Stack>
        <ModalTabs label="WAF policy sections" defaultValue="inspection">
          <ModalSection value="inspection" label="Inspection">
            <NativeSelect
              label="CRS mode"
              data={["Off", "DetectionOnly", "On"]}
              {...register("mode")}
            />
            <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }} spacing="md">
              {(
                [
                  ["paranoia_level", "Paranoia level", 4],
                  ["body_limit_bytes", "Body limit (bytes)", 65536],
                  ["inspection_timeout_ms", "Inspection deadline (ms)", 2000],
                ] as const
              ).map(([name, label, max]) => (
                <Controller
                  key={name}
                  name={name}
                  control={control}
                  rules={{ required: true, min: 1, max }}
                  render={({ field }) => (
                    <NumberInput
                      {...field}
                      label={label}
                      description={
                        name === "paranoia_level"
                          ? "Start at 1; higher levels may increase false positives."
                          : name === "body_limit_bytes"
                            ? "Full inspection buffers at most 64 KiB."
                            : "Blocking mode returns 503 when inspection cannot finish in time."
                      }
                      min={1}
                      max={max}
                      allowDecimal={false}
                      value={field.value}
                      onChange={(value) => field.onChange(value)}
                      error={errors[name] ? `Use 1–${max}` : undefined}
                    />
                  )}
                />
              ))}
            </SimpleGrid>
          </ModalSection>
          <ModalSection value="exclusions" label="Rule exclusions">
            <Title order={3}>Scoped rule exclusions</Title>
            {exclusions.fields.map((item, i) => (
              <Stack key={item.id}>
                <Controller
                  control={control}
                  name={`exclusions.${i}.rule_id`}
                  render={({ field }) => (
                    <NumberInput
                      maw={rem(416)}
                      label="Rule ID"
                      min={900000}
                      max={999999}
                      value={field.value}
                      onChange={(v) => field.onChange(Number(v))}
                      required
                    />
                  )}
                />
                <TextInput
                  label="Reason"
                  required
                  maxLength={256}
                  {...register(`exclusions.${i}.reason`, {
                    required: "Reason is required",
                  })}
                  error={errors.exclusions?.[i]?.reason?.message}
                />
                <TextInput
                  label="Exclusion owner"
                  maxLength={128}
                  {...register(`exclusions.${i}.owner`)}
                />
                <TextInput
                  label="Target (optional, e.g. ARGS:search)"
                  {...register(`exclusions.${i}.target`)}
                />
                <Controller
                  control={control}
                  name={`exclusions.${i}.expires_at_unix_ms`}
                  render={({ field }) => (
                    <NumberInput
                      maw={rem(416)}
                      label="Expiry (Unix ms; blank means permanent)"
                      value={field.value ?? ""}
                      onChange={(v) =>
                        field.onChange(v === "" ? undefined : Number(v))
                      }
                    />
                  )}
                />
                <Button
                  variant="subtle"
                  color="red"
                  onClick={() => exclusions.remove(i)}
                >
                  Remove exclusion
                </Button>
              </Stack>
            ))}
            <Button
              variant="light"
              onClick={() =>
                exclusions.append({
                  rule_id: 900000,
                  reason: "",
                  expires_at_unix_ms: Date.now() + 86400000,
                })
              }
              disabled={exclusions.fields.length >= 32}
            >
              Add exclusion
            </Button>
          </ModalSection>
        </ModalTabs>
        {save.isError && <Failure error={save.error} />}
        <Button type="submit" loading={save.isPending}>
          Save policy draft
        </Button>
      </Stack>
    </form>
  );
}
function Settings() {
  const credentials = useQuery({
    queryKey: ["credentials"],
    queryFn: ({ signal }) =>
      api<{ name: string; revision: number; updated_at: string }[]>(
        "/credentials",
        { signal },
      ),
  });
  const audit = useQuery({
    queryKey: ["audit"],
    queryFn: ({ signal }) =>
      api<
        { id: number; action: string; target: string; occurred_at: string }[]
      >("/audit", { signal }),
  });
  return (
    <>
      <Paper withBorder p="md">
        <Stack>
          <Title order={2}>Credential inventory</Title>
          <Text size="sm" c="dimmed">
            Only names and revisions are displayed. Secrets remain encrypted.
          </Text>
          {credentials.isPending && (
            <Text role="status">Loading credentials…</Text>
          )}
          {credentials.isError && <Failure error={credentials.error} />}
          <DataTable
            records={credentials.data ?? []}
            idAccessor="name"
            minHeight={rem(160)}
            noRecordsText="No credentials stored"
            columns={[
              { accessor: "name" },
              { accessor: "revision" },
              {
                accessor: "updated_at",
                title: "Updated",
                render: (r) =>
                  dayjs(r.updated_at).format("YYYY-MM-DD HH:mm:ss"),
              },
            ]}
          />
        </Stack>
      </Paper>
      <Paper withBorder p="md">
        <Stack>
          <Group justify="space-between">
            <Title order={2}>Latest 100 audit entries</Title>
            <Button variant="default" onClick={() => void audit.refetch()}>
              Refresh audit
            </Button>
          </Group>
          {audit.isPending && <Text role="status">Loading audit…</Text>}
          {audit.isError && <Failure error={audit.error} />}
          <DataTable
            records={audit.data ?? []}
            minHeight={rem(160)}
            noRecordsText="No audit entries"
            columns={[
              {
                accessor: "occurred_at",
                title: "Time",
                render: (r) =>
                  dayjs(r.occurred_at).format("YYYY-MM-DD HH:mm:ss"),
              },
              { accessor: "action" },
              { accessor: "target" },
            ]}
          />
        </Stack>
      </Paper>
    </>
  );
}

interface UptimeSample {
  id: number;
  observed_at_unix_ms: number;
  epoch: string;
  config_version: number;
  available: number;
  unavailable: number;
  unknown: number;
}
interface UptimePage {
  observed_at_unix_ms: number;
  from_ms: number;
  to_ms: number;
  interval_ms: number;
  samples: UptimeSample[];
  next_before_id: number | null;
  sampler: {
    degraded: boolean;
    last_success_unix_ms: number;
    failed_samples: number;
    last_error?: string | null;
  };
}
function UptimeHistory({ paused }: { paused: boolean }) {
  const [cursor, setCursor] = useState<{
    before: number;
    from: number;
    to: number;
  } | null>(null);
  const history = useQuery({
    queryKey: ["uptime-history", cursor],
    queryFn: ({ signal }) =>
      api<UptimePage>(
        "/history/uptime?limit=100" +
          (cursor
            ? `&before_id=${cursor.before}&from_ms=${cursor.from}&to_ms=${cursor.to}`
            : ""),
        { signal },
      ),
    refetchInterval: paused || cursor ? false : 10000,
    gcTime: 0,
  });
  const data = history.data;
  return (
    <Paper withBorder p="md">
      <Stack>
        <Title order={2}>Upstream health history</Title>
        <Text size="sm" c="dimmed">
          Gateway snapshot sampled every 10 seconds, retained up to 7 days and
          60,480 samples. Counts describe endpoint eligibility in each active
          configuration. Missing time and gateway downtime are unknown. This is
          not an uptime percentage or an external availability probe.
        </Text>
        {history.isPending && (
          <Text role="status">Loading uptime history…</Text>
        )}
        {history.isError && (
          <>
            <Alert color="yellow">
              Uptime history unavailable; retained rows may be stale.
            </Alert>
            <Failure error={history.error} />
          </>
        )}
        {data && (
          <>
            <Text size="sm">
              Source: gateway active snapshot · Retrieved{" "}
              {dayjs(data.observed_at_unix_ms).format("YYYY-MM-DD HH:mm:ss")}
            </Text>
            <Badge color={data.sampler.degraded ? "yellow" : "green"}>
              {data.sampler.degraded
                ? "Sampler stale/degraded"
                : "Sampler connected"}
            </Badge>
            <Text size="sm">
              Failed sample attempts this process: {data.sampler.failed_samples}{" "}
              · Last persisted:{" "}
              {data.sampler.last_success_unix_ms
                ? dayjs(data.sampler.last_success_unix_ms).format(
                    "YYYY-MM-DD HH:mm:ss",
                  )
                : "Not yet observed"}
            </Text>
          </>
        )}
        {data?.sampler.last_error && (
          <Text size="sm" c="yellow">
            Sampler error: {data.sampler.last_error}
          </Text>
        )}
        <DataTable
          records={data?.samples ?? []}
          minHeight={rem(180)}
          noRecordsText={
            history.isError
              ? "History unavailable"
              : "No uptime samples in this range"
          }
          columns={[
            {
              accessor: "observed_at_unix_ms",
              title: "Sample time",
              render: (r) =>
                dayjs(r.observed_at_unix_ms).format("YYYY-MM-DD HH:mm:ss"),
            },
            { accessor: "config_version", title: "Active version" },
            { accessor: "available", title: "Available endpoints" },
            { accessor: "unavailable", title: "Unavailable endpoints" },
            { accessor: "unknown", title: "Unknown endpoints" },
            {
              accessor: "gap",
              title: "Continuity",
              render: (r, index) => {
                const older = data?.samples[index + 1];
                return older &&
                  (older.epoch !== r.epoch ||
                    r.observed_at_unix_ms - older.observed_at_unix_ms > 15000)
                  ? "Gap / restart — unknown time"
                  : "Sample only";
              },
            },
          ]}
        />
        <Group>
          <Button
            variant="default"
            onClick={() => {
              setCursor(null);
              if (!cursor) void history.refetch();
            }}
          >
            Latest uptime samples
          </Button>
          <Button
            variant="default"
            loading={history.isFetching}
            onClick={() => void history.refetch()}
          >
            Refresh uptime history
          </Button>
          <Button
            disabled={!data?.next_before_id || history.isFetching}
            onClick={() => {
              if (data?.next_before_id)
                setCursor({
                  before: data.next_before_id,
                  from: data.from_ms,
                  to: data.to_ms,
                });
            }}
          >
            Older uptime samples
          </Button>
        </Group>
      </Stack>
    </Paper>
  );
}
