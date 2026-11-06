import { useEffect, useRef, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Checkbox,
  Group,
  Loader,
  Paper,
  Select,
  SimpleGrid,
  Stack,
  Text,
  TextInput,
  Title,
  rem,
} from "@mantine/core";
import { useMutation, useQuery } from "@tanstack/react-query";
import { DataTable } from "./DataTable";
import {
  Cable,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  Search,
} from "lucide-react";
import { useForm, useWatch } from "react-hook-form";
import { Link } from "react-router-dom";
import toast from "react-hot-toast";
import { api, ApiError, queryClient } from "./api";
import { DiscoveryStatusBadge, Failure } from "./shared";
import { EndpointControls } from "./OperationalControls";
import { discoveryReason, sourceLabel, time } from "./format";
import type {
  Candidate,
  CandidatePage,
  Config,
  Endpoint,
  Kind,
  Probe,
} from "./types";

export function Discovery() {
  const [source, setSource] = useState<Kind | "manual">("docker");
  return (
    <Stack gap="md">
      <div>
        <Text className="eyebrow">CONNECT / VERIFY / STAGE</Text>
        <Title order={1}>Find your next upstream.</Title>
        <Text c="dimmed" mt="xs">
          Read-only discovery, tested from the gateway's network.
        </Text>
      </div>
      <Paper withBorder p="md">
        <Group justify="space-between" gap="md">
          <div>
            <Text fw={700}>Endpoint sources</Text>
            <Text size="sm" c="dimmed">
              Choose an address deliberately. Ports do not imply HTTP.
            </Text>
          </div>
          <Select
            aria-label="Endpoint source"
            value={source}
            allowDeselect={false}
            data={[
              { value: "docker", label: "Docker" },
              { value: "host-ports", label: "Host TCP ports" },
              { value: "manual", label: "Manual address" },
            ]}
            onChange={(v) => setSource(v as Kind | "manual")}
          />
        </Group>
      </Paper>
      <Picker key={source} source={source} />
      <EndpointControls />
    </Stack>
  );
}
function Picker({ source }: { source: Kind | "manual" }) {
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [candidate, setCandidate] = useState<Candidate | null>(null);
  const [showUnavailable, setShowUnavailable] = useState(false);
  const [notice, setNotice] = useState("");
  const cursor = cursors[cursors.length - 1];
  const inventory = useQuery({
    queryKey: ["candidates", source, cursor],
    enabled: source !== "manual",
    queryFn: ({ signal }) =>
      api<CandidatePage>(
        `/discovery/${source}/candidates?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
        { signal },
      ),
  });
  const refresh = useMutation({
    mutationFn: () =>
      api<{ accepted: boolean; queued: boolean; completed: false }>(
        "/discovery/refresh",
        { method: "POST" },
      ),
    onSuccess: () => {
      setNotice(
        "Refresh queued; collection is not complete yet. Reload the list to check its observation time.",
      );
      setCandidate(null);
    },
  });
  // Reset local pagination as soon as an external inventory revision rejects its cursor.
  if (
    inventory.error instanceof ApiError &&
    inventory.error.status === 409 &&
    cursor
  ) {
    setCursors([null]);
    setCandidate(null);
    setNotice(
      "Inventory changed. Restarted at the first page; select the endpoint again.",
    );
  }
  const data = inventory.data;
  const availableCandidates =
    data?.candidates.filter((c) => c.selectable) ?? [];
  const hiddenCount =
    (data?.candidates.length ?? 0) - availableCandidates.length;
  const reload = () => {
    setCandidate(null);
    setCursors([null]);
    if (!cursor) void inventory.refetch();
  };
  return (
    <Stack gap="md">
      {source !== "manual" && (
        <Paper withBorder p="md">
          <Stack gap="md">
            <Group justify="space-between">
              <Group>
                <Search size={rem(18)} />
                <Text fw={700}>Discovered candidates</Text>
                <Badge variant="light">{data?.total ?? "—"} projected</Badge>
              </Group>
              <Group gap="xs">
                <Checkbox
                  label="Show unavailable"
                  checked={showUnavailable}
                  onChange={(event) =>
                    setShowUnavailable(event.currentTarget.checked)
                  }
                />
                <Button
                  variant="default"
                  size="xs"
                  onClick={reload}
                  loading={inventory.isFetching}
                >
                  Reload list
                </Button>
                <Button
                  variant="light"
                  size="xs"
                  leftSection={<RefreshCw size={rem(14)} />}
                  onClick={() => refresh.mutate()}
                  loading={refresh.isPending}
                >
                  Request refresh
                </Button>
              </Group>
            </Group>
            {notice && (
              <Alert title="Discovery update" role="status">
                {notice}
              </Alert>
            )}
            {refresh.isError && <Failure error={refresh.error} />}
            {inventory.isError && <Failure error={inventory.error} />}
            {inventory.isPending && (
              <Group role="status">
                <Loader size="sm" />
                Reading collector snapshot…
              </Group>
            )}
            {data && (
              <>
                <Group gap="xs">
                  <DiscoveryStatusBadge data={data} />
                  {source === "docker" && (
                    <Badge
                      color={data.docker_events_connected ? "teal" : "orange"}
                    >
                      Events{" "}
                      {data.docker_events_connected
                        ? "connected"
                        : "disconnected"}
                    </Badge>
                  )}
                  <Text size="xs" c="dimmed">
                    Observed {time(data.observed_at_unix_ms)} · collector
                    network namespace
                  </Text>
                </Group>
                {(data.error || data.stale || !data.collector_available) && (
                  <Alert color="orange" title="Source unavailable">
                    {data.error
                      ? discoveryReason(data.error)
                      : "Discovery is stale."}{" "}
                    Saved upstreams keep their configuration. Manual entry
                    remains available.
                  </Alert>
                )}
                {data.candidates_truncated && (
                  <Alert color="orange" title="Incomplete inventory">
                    Projection limit reached. Even after the last page, more
                    endpoints may exist. Use manual entry or reduce source
                    metadata.
                  </Alert>
                )}
                {!showUnavailable && hiddenCount > 0 && (
                  <Text size="sm" c="dimmed" role="status">
                    {hiddenCount} unavailable candidates hidden on this page.
                  </Text>
                )}
                <DataTable
                  idAccessor="id"
                  minHeight={rem(180)}
                  records={
                    showUnavailable ? data.candidates : availableCandidates
                  }
                  noRecordsText={
                    !showUnavailable && hiddenCount > 0
                      ? "No selectable candidates on this page. Enable Show unavailable or try another page."
                      : "No candidate endpoints in this snapshot."
                  }
                  fetching={inventory.isFetching}
                  columns={[
                    {
                      accessor: "address",
                      title: "Suggested endpoint",
                      width: rem(210),
                      render: (c) => (
                        <Text size="sm" ff="monospace">
                          {c.address ?? "Unavailable"}
                        </Text>
                      ),
                    },
                    {
                      accessor: "source",
                      title: "Source / binding",
                      width: rem(300),
                      render: (c) => (
                        <Stack gap={rem(3)}>
                          <Text size="xs">{sourceLabel(c.source)}</Text>
                          <Text size="xs" c="dimmed">
                            {time(c.source.observed_at_unix_ms)}
                          </Text>
                        </Stack>
                      ),
                    },
                    {
                      accessor: "verification",
                      title: "Availability",
                      width: rem(180),
                      render: (c) => (
                        <Text size="xs" c={c.selectable ? "dimmed" : "orange"}>
                          {c.selectable
                            ? "Not tested"
                            : (c.unavailable_reason ?? "Unavailable")}
                        </Text>
                      ),
                    },
                    {
                      accessor: "id",
                      title: "Select",
                      width: rem(90),
                      render: (c) => (
                        <Button
                          size="compact-xs"
                          variant={candidate?.id === c.id ? "filled" : "light"}
                          aria-label={`Choose ${c.address ?? c.id}`}
                          disabled={
                            !c.selectable ||
                            data.stale ||
                            !data.collector_available ||
                            inventory.isFetching ||
                            inventory.isError
                          }
                          onClick={() => setCandidate(c)}
                        >
                          {candidate?.id === c.id ? "Selected" : "Choose"}
                        </Button>
                      ),
                    },
                  ]}
                />
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">
                    Page {cursors.length} · 50 per page · TCP candidates require
                    a protocol test
                  </Text>
                  <Group gap="xs">
                    <Button
                      size="xs"
                      variant="default"
                      leftSection={<ChevronLeft size={rem(14)} />}
                      disabled={
                        cursors.length === 1 ||
                        inventory.isFetching ||
                        inventory.isError
                      }
                      onClick={() => {
                        setCandidate(null);
                        setCursors((v) => v.slice(0, -1));
                      }}
                    >
                      Previous
                    </Button>
                    <Button
                      size="xs"
                      variant="default"
                      rightSection={<ChevronRight size={rem(14)} />}
                      disabled={
                        !data.next_cursor ||
                        inventory.isFetching ||
                        inventory.isError ||
                        cursors.length >= 328
                      }
                      onClick={() => {
                        setCandidate(null);
                        setCursors((v) => [...v, data.next_cursor]);
                      }}
                    >
                      Next
                    </Button>
                  </Group>
                </Group>
              </>
            )}
          </Stack>
        </Paper>
      )}
      {source === "manual" || candidate ? (
        <EndpointEditor
          key={`${source}:${candidate?.id ?? "manual"}:${data?.revision ?? ""}`}
          source={source}
          candidate={candidate}
          usable={
            source === "manual" ||
            (!!data &&
              !inventory.isError &&
              !data.stale &&
              data.collector_available)
          }
        />
      ) : (
        <Paper withBorder p="md" className="empty-selection">
          <Cable size={rem(28)} />
          <Title order={3} mt="sm">
            Choose a candidate to continue
          </Title>
          <Text c="dimmed" size="sm" mt="xs">
            Select its exact network, alias or published binding, then choose
            HTTP or HTTPS.
          </Text>
        </Paper>
      )}
    </Stack>
  );
}
interface EndpointForm {
  address: string;
  protocol: "" | "http" | "https";
  sni: string;
}
function EndpointEditor({
  source,
  candidate,
  usable,
}: {
  source: Kind | "manual";
  candidate: Candidate | null;
  usable: boolean;
}) {
  const form = useForm<EndpointForm>({
    defaultValues: { address: candidate?.address ?? "", protocol: "", sni: "" },
  });
  const [verified, setVerified] = useState<{
    key: string;
    endpoint: Endpoint;
    report: Probe;
  } | null>(null);
  form.register("protocol", { required: "Choose a protocol" });
  const values = useWatch({ control: form.control });
  const fingerprint = JSON.stringify(values);
  const current = useRef(fingerprint);
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const invalidate = () => {
    generation.current++;
    controller.current?.abort();
    setVerified(null);
    test.reset();
    current.current = JSON.stringify(form.getValues());
  };
  useEffect(() => () => controller.current?.abort(), []);
  const test = useMutation({
    mutationFn: async (input: EndpointForm) => {
      controller.current?.abort();
      controller.current = new AbortController();
      const signal = controller.current.signal;
      const key = JSON.stringify(input);
      const run = ++generation.current;
      setVerified(null);
      let endpoint: Endpoint;
      if (source === "manual")
        endpoint = {
          address: input.address.trim(),
          protocol: input.protocol as "http" | "https",
          tls_server_name:
            input.protocol === "https" ? input.sni.trim() || null : null,
        };
      else {
        const selected = await api<{ endpoint: Endpoint }>(
          "/discovery/select",
          {
            method: "POST",
            signal,
            body: {
              source,
              candidate_id: candidate?.id,
              protocol: input.protocol,
              ...(input.protocol === "https" && input.sni.trim()
                ? { tls_server_name: input.sni.trim() }
                : {}),
            },
          },
        );
        endpoint = selected.endpoint;
      }
      const report = await api<Probe>("/upstreams/test", {
        method: "POST",
        body: endpoint,
        signal,
      });
      if (
        !signal.aborted &&
        run === generation.current &&
        key === current.current
      )
        setVerified({ key, endpoint, report });
    },
  });
  const addressField = form.register("address", {
    required: "Address is required",
    maxLength: 300,
  });
  const sniField = form.register("sni", { maxLength: 253 });
  const result = verified?.key === fingerprint && usable ? verified : null;
  return (
    <Paper withBorder p="md">
      <Stack gap="md">
        <div>
          <Text className="eyebrow">01 / VERIFY ENDPOINT</Text>
          <Title order={2}>Test before you stage.</Title>
          {candidate && (
            <Text size="sm" c="dimmed" mt="xs">
              {sourceLabel(candidate.source)}
            </Text>
          )}
        </div>
        <form onSubmit={form.handleSubmit((v) => test.mutate(v))}>
          <Stack>
            <SimpleGrid cols={{ base: 1, sm: 3 }}>
              <TextInput
                label="Endpoint address"
                placeholder="service.internal:8080"
                description="Explicit host:port or [IPv6]:port"
                readOnly={source !== "manual"}
                {...addressField}
                onChange={(e) => {
                  void addressField.onChange(e);
                  invalidate();
                }}
                error={form.formState.errors.address?.message}
              />
              <Select
                label="Protocol"
                placeholder="Choose HTTP or HTTPS"
                data={[
                  { value: "http", label: "HTTP" },
                  { value: "https", label: "HTTPS (verified TLS)" },
                ]}
                value={values.protocol || null}
                onChange={(v) => {
                  form.setValue(
                    "protocol",
                    (v ?? "") as EndpointForm["protocol"],
                    { shouldValidate: true },
                  );
                  invalidate();
                }}
                error={form.formState.errors.protocol?.message}
              />
              <TextInput
                label="TLS server name (SNI)"
                description="Optional DNS name; certificate must match"
                disabled={values.protocol !== "https"}
                {...sniField}
                onChange={(e) => {
                  void sniField.onChange(e);
                  invalidate();
                }}
              />
            </SimpleGrid>
            <Group>
              <Button
                type="submit"
                loading={test.isPending}
                disabled={!usable}
                leftSection={<Cable size={rem(16)} />}
              >
                Test from gateway
              </Button>
              <Text size="xs" c="dimmed">
                3 s network deadline · HEAD / · no redirect following
              </Text>
            </Group>
          </Stack>
        </form>
        {test.isError && <Failure error={test.error} />}
        {result && (
          <>
            <Alert
              color={result.report.available ? "teal" : "red"}
              title={
                result.report.available
                  ? "HTTP transport available"
                  : "Endpoint unavailable"
              }
              role="status"
            >
              {result.report.error ??
                `Resolved target: ${result.report.endpoint}. HTTP ${result.report.http_status ?? "—"} · ${result.report.latency_ms} ms.`}{" "}
              A transport result does not establish application health; HTTP
              error statuses may still be reachable.
            </Alert>
            <SimpleGrid cols={{ base: 2, sm: 4 }}>
              {(["dns", "tcp", "tls", "http"] as const).map((step) => (
                <Paper withBorder p="sm" key={step}>
                  <Group justify="space-between">
                    <Text fw={700} tt="uppercase" size="sm">
                      {step}
                    </Text>
                    <Badge
                      size="xs"
                      color={
                        result.report[step].state === "failed"
                          ? "red"
                          : result.report[step].state === "passed"
                            ? "teal"
                            : "gray"
                      }
                    >
                      {result.report[step].state.replace("_", " ")}
                    </Badge>
                  </Group>
                  <Text size="xs" mt="xs">
                    {result.report[step].latency_ms ?? "—"} ms
                  </Text>
                  {result.report[step].error && (
                    <Text size="xs" c="red">
                      {result.report[step].error}
                    </Text>
                  )}
                </Paper>
              ))}
            </SimpleGrid>
            {result.report.available && (
              <StageEndpoint endpoint={result.endpoint} />
            )}
          </>
        )}
      </Stack>
    </Paper>
  );
}
function StageEndpoint({ endpoint }: { endpoint: Endpoint }) {
  const config = useQuery({
    queryKey: ["config"],
    queryFn: ({ signal }) => api<Config>("/config", { signal }),
  });
  const form = useForm<{
    upstream: string;
    route: string;
    hostname: string;
    path: string;
    match: "prefix" | "exact";
  }>({
    defaultValues: {
      upstream: "",
      route: "",
      hostname: "",
      path: "/",
      match: "prefix",
    },
  });
  const match = useWatch({ control: form.control, name: "match" });
  const [saved, setSaved] = useState(false);
  const [reloadRequired, setReloadRequired] = useState(false);
  const save = useMutation({
    mutationFn: async (input: {
      upstream: string;
      route: string;
      hostname: string;
      path: string;
      match: "prefix" | "exact";
    }) => {
      if (!config.data || config.isError)
        throw new Error("Reload configuration before saving.");
      const document = structuredClone(config.data.draft);
      if (document.upstreams.some((u) => u.id === input.upstream))
        throw new Error(
          "Upstream ID already exists. Choose a new ID; existing pools are preserved.",
        );
      if (document.routes.some((r) => r.id === input.route))
        throw new Error("Route ID already exists. Choose a new ID.");
      document.upstreams.push({ id: input.upstream, endpoints: [endpoint] });
      document.routes.push({
        id: input.route,
        hostname: input.hostname.trim(),
        path: input.path,
        path_match: input.match,
        methods: [],
        upstream: input.upstream,
      });
      const checked = await api<{ valid: boolean; error: string | null }>(
        "/config/validate",
        { method: "POST", body: { document } },
      );
      if (!checked.valid)
        throw new Error(
          `Configuration rejected: ${checked.error ?? "invalid document"}`,
        );
      try {
        await api("/config/draft", {
          method: "PUT",
          body: { expected_revision: config.data.draft_revision, document },
        });
      } catch (error) {
        setReloadRequired(true);
        throw error;
      }
    },
    onSuccess: () => {
      setSaved(true);
      toast.success("Draft saved. Review before applying.");
      void queryClient.invalidateQueries({ queryKey: ["config"] });
    },
  });
  const idRules = {
    required: "ID is required",
    pattern: {
      value: /^[a-z0-9_-]{1,64}$/,
      message: "Use 1–64 lowercase letters, digits, _ or -",
    },
  };
  return (
    <Stack>
      <div>
        <Text className="eyebrow">02 / STAGE CONFIGURATION</Text>
        <Title order={3}>Add an upstream and route</Title>
        <Text size="sm" c="dimmed">
          Creates a new single-endpoint pool and a route for all HTTP methods.
          Existing pools, routes and settings are preserved. Saving does not
          change traffic.
        </Text>
      </div>
      {config.isPending && <Loader size="sm" />}
      {config.isError && <Failure error={config.error} />}
      <form onSubmit={form.handleSubmit((v) => save.mutate(v))}>
        <Stack>
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            <TextInput
              label="New upstream ID"
              {...form.register("upstream", idRules)}
              error={form.formState.errors.upstream?.message}
              disabled={saved || save.isPending}
            />
            <TextInput
              label="New route ID"
              {...form.register("route", idRules)}
              error={form.formState.errors.route?.message}
              disabled={saved || save.isPending}
            />
            <TextInput
              label="Hostname"
              placeholder="app.example.com"
              {...form.register("hostname", {
                required: "Hostname is required",
                maxLength: 253,
              })}
              error={form.formState.errors.hostname?.message}
              disabled={saved || save.isPending}
            />
            <TextInput
              label="Path"
              {...form.register("path", {
                required: "Path is required",
                pattern: { value: /^\//, message: "Start with /" },
              })}
              error={form.formState.errors.path?.message}
              disabled={saved || save.isPending}
            />
            <Select
              label="Path match"
              data={["prefix", "exact"]}
              value={match}
              allowDeselect={false}
              onChange={(v) => form.setValue("match", v as "prefix" | "exact")}
              disabled={saved || save.isPending}
            />
          </SimpleGrid>
          {save.isError && <Failure error={save.error} />}
          <Group>
            <Button
              type="submit"
              loading={save.isPending}
              disabled={
                saved ||
                reloadRequired ||
                !config.data ||
                config.isError ||
                config.isFetching
              }
            >
              Validate & save draft
            </Button>
            {(save.isError || config.isError) && (
              <Button
                variant="default"
                onClick={async () => {
                  const fresh = await config.refetch();
                  if (fresh.isSuccess) setReloadRequired(false);
                }}
              >
                Reload current configuration
              </Button>
            )}
            {saved && (
              <Button
                component={Link}
                to="/configuration?view=review"
                variant="light"
              >
                Review & apply →
              </Button>
            )}
          </Group>
          <Text size="xs" c="dimmed">
            Based on draft revision {config.data?.draft_revision ?? "—"}. A
            conflict requires reloading and reviewing current state.
          </Text>
        </Stack>
      </form>
    </Stack>
  );
}
