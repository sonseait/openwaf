import { RecordedBodies } from "./RecordedBodies";
import { ModalTabLayout } from "./ModalTabs";
import { requestRouteLabel } from "./route-labels";
import { DataTable } from "./DataTable";
import { RequestFlow } from "./RequestFlow";
import { parseMetadata } from "./request-metadata";
import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Code,
  Divider,
  Paper,
  Tabs,
  Group,
  Modal,
  NumberInput,
  Stack,
  Text,
  TextInput,
  Title,
  rem,
} from "@mantine/core";
import { Controller, useForm } from "react-hook-form";
import { Link, useSearchParams } from "react-router-dom";
import { investigationLink } from "./investigation-state";
import toast from "react-hot-toast";
import { api, queryClient } from "./api";
import {
  BooleanStatusBadge,
  DetailsGrid,
  Failure,
  StateBadge,
  StatusBadge,
} from "./shared";
import {
  ClientMetadata,
  RequestMetadata,
  ResponseMetadata,
  MetadataHeaders,
} from "./RequestMetadata";
import { Activity, Network, ShieldCheck, List } from "lucide-react";
import { time } from "./format";
import type { Config } from "./types";
export interface Decision {
  decision_trace?: { stage: string; result: string; duration_ms?: number }[];
  schema_version: number;
  metadata?: unknown;
  metadata_truncated?: boolean;
  details_truncated?: boolean;
  outcome?: string;
  response_committed?: boolean;
  response_status_observed?: number;
  effective_timeouts?: Record<string, number>;
  route_id?: string;
  application?: {
    application_id: string;
    release_id: string;
    mode: string;
  } | null;
  security_layer?: string;
  security_signals?: {
    status: string;
    coverage: string;
    truncated: boolean;
    entries: {
      source: string;
      reason: string;
      scope: string;
      action: string;
      rule_id: number;
      phase: number;
      severity: number;
    }[];
  };
  body_inspection?: string;
  profile?: { kind: string; version: number };
  waf?: {
    decision: string;
    findings: { rule_id: number; phase: number; severity: number }[];
    truncated: boolean;
    anomaly_score: number | null;
  };
  attempts?: {
    index: number;
    endpoint?: string;
    error?: string;
    duration_ms: number;
    request_started: boolean;
    body_bytes: number;
    retry: boolean;
  }[];
  retry_disabled_reason?: string;
  replay_disabled_reason?: string;
}
export interface RequestRecord {
  request_id?: string;
  details?: string;
  method: string;
  status: number;
  config_version: number | string;
  forwarded: boolean;
  blocked: boolean;
  observed_at_unix_ms?: number | string;
  latency_ms?: number | string;
  route_index?: number | string | null;
  upstream_error?: boolean;
  epoch?: string;
  sequence?: number | string;
}
export function RequestDetails({
  record,
  onClose,
}: {
  record: RequestRecord | null;
  onClose: () => void;
}) {
  return (
    <Modal
      opened={!!record}
      onClose={onClose}
      title="Request details"
      closeButtonProps={{ "aria-label": "Close request details" }}
      size={rem(1100)}
      scrollAreaComponent={ModalTabLayout}
      classNames={{ body: "request-details-body" }}
    >
      {record && (
        <RequestDetailContent
          key={`${record.epoch}:${record.sequence}:${record.request_id}`}
          record={record}
        />
      )}
    </Modal>
  );
}

export function RequestDetailContent({ record }: { record: RequestRecord }) {
  const [params] = useSearchParams();
  const [fallbackTime] = useState(Date.now);
  const [propose, setPropose] = useState(false);
  const [activeTab, setActiveTab] = useState<string | null>("handling");
  let details: Decision | null = null;
  try {
    const parsed: unknown = record.details ? JSON.parse(record.details) : null;
    if (
      parsed &&
      typeof parsed === "object" &&
      !Array.isArray(parsed) &&
      "schema_version" in parsed &&
      typeof parsed.schema_version === "number"
    ) {
      details = parsed as Decision;
    }
  } catch {
    // Older/malformed detail remains explicitly unavailable.
  }
  const metadata = parseMetadata(details?.metadata);
  const findings = Array.isArray(details?.waf?.findings)
    ? details.waf.findings
    : [];
  const attempts = Array.isArray(details?.attempts) ? details.attempts : [];
  return (
    <Stack gap="md">
      <Group>
        {details?.route_id && (
          <Button
            component={Link}
            to={investigationLink(
              `/routes/${encodeURIComponent(details.route_id)}`,
              params,
              {
                version: String(record.config_version),
                route_id: details.route_id,
                start_ms: Math.max(
                  0,
                  Number(record.observed_at_unix_ms ?? fallbackTime) - 3600000,
                ),
                end_ms: Number(record.observed_at_unix_ms ?? fallbackTime) + 1,
              },
            )}
            variant="default"
          >
            Request configuration
          </Button>
        )}
        <Button
          component={Link}
          to={investigationLink("/configuration", params, {
            view: "history",
            version: String(record.config_version),
          })}
          variant="default"
        >
          Config / audit diff · v{record.config_version}
        </Button>
        {record.request_id && (
          <Button
            component={Link}
            to={investigationLink(
              `/requests/${encodeURIComponent(record.request_id)}`,
              params,
            )}
            variant="subtle"
          >
            Request reference link
          </Button>
        )}
      </Group>

      <div className="request-summary">
        <Group gap="sm" mb="sm">
          <Text fw={600}>{record.method}</Text>
          <StatusBadge
            color={
              record.status >= 400 ? "red" : record.status ? "teal" : "gray"
            }
          >
            {record.status ? `HTTP ${record.status}` : "No final response"}
          </StatusBadge>
          <StateBadge
            value={
              record.blocked
                ? "blocked"
                : record.forwarded
                  ? "forwarded"
                  : "handled_locally"
            }
          />
        </Group>
        <Text size="xs" c="dimmed" mb={rem(4)}>
          Request reference
        </Text>
        <Code className="request-reference">
          {record.request_id || "Unavailable for this older record"}
        </Code>
      </div>
      {details?.metadata_truncated && (
        <Alert color="yellow">
          Metadata exceeded the capture budget. Some details were omitted.
        </Alert>
      )}
      {details?.details_truncated && (
        <Alert color="yellow">
          Decision details exceeded the payload limit and are unavailable.
        </Alert>
      )}
      <Tabs
        value={activeTab}
        onChange={setActiveTab}
        keepMounted={false}
        className="modal-section-tabs"
      >
        <Tabs.List
          className="modal-section-tab-list"
          aria-label="Request details sections"
        >
          <Tabs.Tab value="handling" leftSection={<List size={rem(15)} />}>
            Handling
          </Tabs.Tab>
          <Tabs.Tab value="overview" leftSection={<Activity size={rem(15)} />}>
            Overview
          </Tabs.Tab>
          <Tabs.Tab
            value="security"
            leftSection={<ShieldCheck size={rem(15)} />}
          >
            Security
          </Tabs.Tab>
          <Tabs.Tab value="upstream" leftSection={<Network size={rem(15)} />}>
            Upstream
          </Tabs.Tab>
          <Tabs.Tab value="headers" leftSection={<List size={rem(15)} />}>
            Headers
          </Tabs.Tab>
          <Tabs.Tab value="body" leftSection={<List size={rem(15)} />}>
            Body & query
          </Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel
          value="handling"
          pt="md"
          tabIndex={0}
          className="modal-section-panel"
        >
          <RequestFlow record={record} decision={details} />
        </Tabs.Panel>
        <Tabs.Panel
          value="overview"
          pt="md"
          tabIndex={0}
          className="modal-section-panel"
        >
          <Stack gap="md">
            {metadata ? (
              <>
                <ClientMetadata data={metadata} />
                <RequestMetadata data={metadata} />
              </>
            ) : (
              <Alert color="yellow">
                Client and request metadata were not collected for this record
                or are unavailable.
              </Alert>
            )}
            <DetailSection title="Request information">
              <DetailsGrid
                items={[
                  {
                    label: "Observed at",
                    value:
                      record.observed_at_unix_ms != null
                        ? time(Number(record.observed_at_unix_ms))
                        : "Unavailable",
                  },
                  {
                    label: "Latency",
                    value:
                      record.latency_ms != null
                        ? `${record.latency_ms} ms`
                        : "Unavailable",
                  },
                  {
                    label: "Configuration version",
                    value: record.config_version,
                  },
                  {
                    label: "Route",
                    value: requestRouteLabel(record),
                  },
                  {
                    label: "Gateway epoch",
                    value: record.epoch ?? "Unavailable",
                  },
                  {
                    label: "Event sequence",
                    value: record.sequence ?? "Unavailable",
                  },
                ]}
              />
            </DetailSection>
            {details ? (
              <DetailSection title="Response & outcome">
                <DetailsGrid
                  items={[
                    {
                      label: "Outcome",
                      value: (
                        <StateBadge value={details.outcome ?? "completed"} />
                      ),
                    },
                    {
                      label: "Security layer",
                      value:
                        details.security_layer?.replaceAll("_", " ") ??
                        "Unavailable",
                    },
                    {
                      label: "Observed response",
                      value: (
                        <StatusBadge
                          color={
                            details.response_status_observed ? "blue" : "gray"
                          }
                        >
                          Observed status:{" "}
                          {details.response_status_observed ?? "Unknown"}
                        </StatusBadge>
                      ),
                    },
                  ]}
                />
                {metadata && (
                  <div style={{ marginTop: "var(--mantine-spacing-md)" }}>
                    <ResponseMetadata data={metadata} />
                  </div>
                )}
                <Group mt="md">
                  <BooleanStatusBadge
                    value={details.response_committed}
                    trueLabel="Headers entered transport"
                    falseLabel="Headers not entered transport"
                    unknownLabel="Transport state unknown (older record)"
                  />
                </Group>
                <Text size="xs" c="dimmed" mt="sm">
                  This does not prove client receipt or transaction outcome.
                </Text>
              </DetailSection>
            ) : (
              <MissingDetails />
            )}
          </Stack>
        </Tabs.Panel>
        <Tabs.Panel
          value="security"
          pt="md"
          tabIndex={0}
          className="modal-section-panel"
        >
          {details ? (
            <Stack gap="md">
              <DetailSection title="Inspection policy">
                <DetailsGrid
                  items={[
                    {
                      label: "Body inspection",
                      value: (
                        <StateBadge
                          value={details.body_inspection || "not_inspected"}
                        />
                      ),
                    },
                    {
                      label: "Traffic profile",
                      value: details.profile
                        ? `${details.profile.kind} v${details.profile.version}`
                        : "Legacy / custom",
                    },
                    {
                      label: "WAF decision",
                      value: details.waf?.decision ? (
                        <StateBadge value={details.waf.decision} />
                      ) : (
                        "Unavailable"
                      ),
                    },
                    {
                      label: "Anomaly score",
                      value: details.waf?.anomaly_score ?? "Not recorded",
                    },
                  ]}
                />
                <details className="inspection-coverage">
                  <summary>What does this inspection cover?</summary>
                  <Text size="sm" c="dimmed">
                    WAF On enforces inspected inputs. Multipart bodies and
                    headers-query-only streams are not body inspected;
                    not_inspected means inspection did not complete. Response
                    bodies and WebSocket frames are outside coverage.
                  </Text>
                </details>
              </DetailSection>
              <DetailSection title="Security signals">
                {details.security_signals?.status === "collected" ? (
                  <>
                    <Text size="xs" c="dimmed">
                      Completed security observations ·{" "}
                      {details.security_signals.coverage}. CRS actions describe
                      the report decision. Unlisted layers were not collected.
                      Capacity errors are not attack verdicts.
                    </Text>
                    {details.security_signals.entries.length ? (
                      <DataTable
                        aria-label="Security signals"
                        records={details.security_signals.entries.map(
                          (signal, id) => ({ ...signal, id }),
                        )}
                        columns={[
                          { accessor: "source", title: "Source" },
                          { accessor: "reason", title: "Reason" },
                          {
                            accessor: "rule_id",
                            title: "Rule ID",
                            render: (s) =>
                              s.source === "crs" ? s.rule_id : "—",
                          },
                          {
                            accessor: "action",
                            title: "Action",
                            render: (s) => <StateBadge value={s.action} />,
                          },
                          { accessor: "severity", title: "Severity" },
                        ]}
                      />
                    ) : (
                      <Text size="sm" c="dimmed">
                        No recorded signals; this does not prove absence of
                        attacks.
                      </Text>
                    )}
                    {details.security_signals.truncated && (
                      <Alert color="yellow">
                        Signal list incomplete (maximum 16); consult the WAF
                        findings below.
                      </Alert>
                    )}
                  </>
                ) : (
                  <Text size="sm" c="dimmed">
                    Not collected. Older records have no collected security
                    signals.
                  </Text>
                )}
              </DetailSection>
              <DetailSection title="WAF findings" count={findings.length}>
                {findings.length ? (
                  <DataTable
                    aria-label="WAF findings"
                    records={findings.map((finding, index) => ({
                      ...finding,
                      id: index,
                    }))}
                    verticalSpacing="sm"
                    columns={[
                      {
                        accessor: "rule_id",
                        title: "Rule ID",
                        render: (f) => <Code>{f.rule_id}</Code>,
                      },
                      { accessor: "phase", title: "Phase" },
                      { accessor: "severity", title: "Severity" },
                    ]}
                  />
                ) : (
                  <Text size="sm" c="dimmed">
                    No recorded findings. Rules that suppress native logging may
                    not produce findings.
                  </Text>
                )}
                {details.waf?.truncated && (
                  <Alert color="yellow" mt="sm">
                    Findings exceeded the 32-record limit.
                  </Alert>
                )}
              </DetailSection>
              {details.application && (
                <Alert color="blue">
                  Hosted application {details.application.application_id} ·
                  release {details.application.release_id} ·{" "}
                  {details.application.mode}
                </Alert>
              )}
              {details.route_id && (
                <>
                  <Divider />
                  <Button
                    variant="light"
                    fullWidth
                    onClick={() => setPropose(!propose)}
                    aria-expanded={propose}
                  >
                    Suspected false positive / propose exclusion
                  </Button>
                  {propose && (
                    <ExclusionProposal
                      record={record}
                      details={details}
                      onDone={() => setPropose(false)}
                    />
                  )}
                </>
              )}
            </Stack>
          ) : (
            <MissingDetails />
          )}
        </Tabs.Panel>
        <Tabs.Panel
          value="upstream"
          pt="md"
          tabIndex={0}
          className="modal-section-panel"
        >
          {details ? (
            <Stack gap="md">
              <DetailSection title="Upstream attempts" count={attempts.length}>
                <Stack gap="sm">
                  {attempts.map((a) => (
                    <Paper key={a.index} className="request-attempt" p="md">
                      <Group justify="space-between" mb="md">
                        <Text size="sm" fw={600}>
                          Attempt #{a.index}
                        </Text>
                        <Text size="sm" c="dimmed">
                          {a.duration_ms} ms
                        </Text>
                      </Group>
                      <DetailsGrid
                        items={[
                          {
                            label: "Endpoint",
                            value: a.endpoint ?? "No endpoint",
                          },
                          { label: "Body sent", value: `${a.body_bytes} B` },
                        ]}
                      />
                      <Group gap="xs" mt="md">
                        <BooleanStatusBadge
                          value={a.request_started}
                          trueLabel="Request started"
                          falseLabel="Request not started"
                          unknownLabel="Request start unknown"
                        />
                        <BooleanStatusBadge
                          value={a.retry}
                          trueLabel="Retry scheduled"
                          falseLabel="No retry scheduled"
                          unknownLabel="Retry status unknown"
                        />
                      </Group>
                      <Text size="sm" mt="sm" c={a.error ? "red" : "dimmed"}>
                        {a.error ?? "No transport error"}
                      </Text>
                    </Paper>
                  ))}
                  {!attempts.length && (
                    <Text size="sm" c="dimmed">
                      No upstream attempts recorded for this request.
                    </Text>
                  )}
                </Stack>
              </DetailSection>
              <DetailSection title="Retry & replay">
                <DetailsGrid
                  items={[
                    {
                      label: "Retry limitation",
                      value: details.retry_disabled_reason ?? "None recorded",
                    },
                    {
                      label: "Replay limitation",
                      value: details.replay_disabled_reason ?? "None recorded",
                    },
                    {
                      label: "Upstream error",
                      value:
                        record.upstream_error == null
                          ? "Unavailable"
                          : record.upstream_error
                            ? "Yes"
                            : "No",
                    },
                  ]}
                />
              </DetailSection>
              {!!details.effective_timeouts && (
                <DetailSection title="Effective timeouts (ms)">
                  <DetailsGrid
                    items={Object.entries(details.effective_timeouts).map(
                      ([label, value]) => ({
                        label: label.replaceAll("_", " "),
                        value: `${value} ms`,
                      }),
                    )}
                  />
                </DetailSection>
              )}
            </Stack>
          ) : (
            <MissingDetails />
          )}
        </Tabs.Panel>
        <Tabs.Panel
          value="headers"
          pt="md"
          tabIndex={0}
          className="modal-section-panel"
        >
          <MetadataHeaders data={metadata} />
        </Tabs.Panel>
        <Tabs.Panel
          value="body"
          pt="md"
          tabIndex={0}
          className="modal-section-panel"
        >
          <RecordedBodies
            id={record.request_id}
            active={activeTab === "body"}
          />
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}

function DetailSection({
  title,
  count,
  children,
}: {
  title: string;
  count?: number;
  children: React.ReactNode;
}) {
  return (
    <section className="request-detail-section">
      <Group gap="xs" mb="md">
        <Title order={3}>{title}</Title>
        {count != null && <StatusBadge>{count}</StatusBadge>}
      </Group>
      {children}
    </section>
  );
}
function MissingDetails() {
  return (
    <Alert color="yellow">
      Structured details unavailable for this record.
    </Alert>
  );
}
function ExclusionProposal({
  record,
  details,
  onDone,
}: {
  record: RequestRecord;
  details: Decision;
  onDone: () => void;
}) {
  const config = useQuery({
    queryKey: ["config"],
    queryFn: ({ signal }) => api<Config>("/config", { signal }),
  });
  const form = useForm<{
    rule_id: number;
    target: string;
    reason: string;
    owner: string;
    hours: number;
  }>({
    defaultValues: {
      rule_id: details.waf?.findings[0]?.rule_id ?? 0,
      target: "",
      reason: "",
      owner: "",
      hours: 24,
    },
  });
  const save = useMutation({
    mutationFn: async (input: {
      rule_id: number;
      target: string;
      reason: string;
      owner: string;
      hours: number;
    }) => {
      if (!config.data) throw new Error("Configuration unavailable");
      const document = structuredClone(config.data.draft);
      const route = document.routes.find((r) => r.id === details.route_id);
      if (!route) throw new Error("The recorded route no longer exists");
      if (!route.waf)
        throw new Error(
          "Configure an explicit WAF policy for this route before proposing an exception",
        );
      route.waf.exclusions = [
        ...(route.waf.exclusions ?? []),
        {
          rule_id: input.rule_id,
          target: input.target.trim() || undefined,
          reason: input.reason.trim(),
          owner: input.owner.trim() || undefined,
          expires_at_unix_ms:
            input.hours > 0 ? Date.now() + input.hours * 3600000 : undefined,
        },
      ];
      return api("/config/draft", {
        method: "PUT",
        body: { expected_revision: config.data.draft_revision, document },
      });
    },
    onSuccess: () => {
      toast.success(
        "Exclusion saved to draft. Review the diff before applying.",
      );
      void queryClient.invalidateQueries({ queryKey: ["config"] });
      onDone();
    },
  });
  return (
    <form onSubmit={form.handleSubmit((v) => save.mutate(v))}>
      <Stack>
        <Alert color="yellow">
          This proposes an exception in the configuration draft. The current
          policy keeps running until the reviewed draft is applied. Request
          configuration: {record.config_version}; current active:{" "}
          {config.data?.active_version ?? "loading"}.
        </Alert>
        {config.isError && <Failure error={config.error} />}
        <Controller
          control={form.control}
          name="rule_id"
          rules={{ min: 900000, max: 999999 }}
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
          label="Target (optional)"
          description="Use a narrow target such as ARGS:search. Empty removes this rule for the whole route."
          {...form.register("target")}
        />
        <TextInput
          label="Reason"
          required
          maxLength={256}
          {...form.register("reason", { required: true })}
        />
        <TextInput
          label="Exclusion owner"
          maxLength={128}
          {...form.register("owner")}
        />
        <Controller
          control={form.control}
          name="hours"
          render={({ field }) => (
            <NumberInput
              maw={rem(416)}
              label="Expires after (hours)"
              description="Default 24 hours. Set 0 deliberately for a permanent exception."
              min={0}
              max={87600}
              value={field.value}
              onChange={(v) => field.onChange(Number(v))}
            />
          )}
        />
        {save.isError && <Failure error={save.error} />}
        <Group>
          <Button
            type="submit"
            loading={save.isPending}
            disabled={!config.data}
          >
            Save proposal to draft
          </Button>
          <Button
            component={Link}
            to="/configuration?view=review"
            variant="default"
          >
            Review configuration
          </Button>
          <Button
            component={Link}
            to={`/routes/${encodeURIComponent(details.route_id ?? "")}?snapshot=draft`}
            variant="default"
          >
            Test draft with shadow
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
export function RequestLookup() {
  const [id, setId] = useState("");
  const [selected, setSelected] = useState<RequestRecord | null>(null);
  const lookup = useMutation({
    mutationFn: () =>
      api<{ record: RequestRecord }>(
        `/requests/${encodeURIComponent(id.trim())}`,
      ),
    onSuccess: (v) => setSelected(v.record),
  });
  return (
    <Stack>
      <Group align="end">
        <TextInput
          label="Find request by reference ID"
          value={id}
          onChange={(e) => setId(e.currentTarget.value)}
          maxLength={64}
          miw={rem(300)}
        />
        <Button
          onClick={() => lookup.mutate()}
          loading={lookup.isPending}
          disabled={!/^(?:[A-Za-z0-9_]{32}|[A-Za-z0-9_]{64})$/.test(id.trim())}
        >
          Find request
        </Button>
      </Group>
      {lookup.isError && (
        <>
          <Failure error={lookup.error} />
          <Text size="sm">
            A missing reference can reflect retention, lost records or
            unavailable storage; it does not prove the request never existed.
          </Text>
        </>
      )}
      <RequestDetails record={selected} onClose={() => setSelected(null)} />
    </Stack>
  );
}
