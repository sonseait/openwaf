import { useSearchParams } from "react-router-dom";
import { investigationParams } from "./investigation-state";
import { parseRequestDetails } from "./route-labels";
import { object } from "./request-metadata";
import { useMemo, useState } from "react";
import {
  Badge,
  Button,
  Grid,
  Group,
  NativeSelect,
  Paper,
  Box,
  Stack,
  Text,
  TextInput,
  Title,
  rem,
} from "@mantine/core";
import { useForm, useWatch } from "react-hook-form";
import { DataTable } from "./DataTable";
import { Filter, RotateCcw } from "lucide-react";
import {
  RequestDetails,
  RequestLookup,
  type RequestRecord,
} from "./RequestDetails";
import type { TrafficLog } from "./telemetry-state";
import { trafficColumns, trafficRecord } from "./traffic-table";
import { matchesLivePathPrefix } from "./live-traffic-filter";

export function TrafficFeed({ logs }: { logs: TrafficLog[] }) {
  const [params] = useSearchParams();
  const scope = investigationParams(params).toString();
  const [selected, setSelected] = useState<RequestRecord | null>(null);
  const form = useForm({
    defaultValues: {
      method: "",
      decision: "",
      status: "",
      reference: "",
      host: "",
      pathPrefix: "",
      country: "",
    },
  });
  const filters = useWatch({ control: form.control });
  const records = useMemo(
    () =>
      logs
        .map(trafficRecord)
        .filter((record) => matchesScope(record, new URLSearchParams(scope)))
        .filter(
          (record) =>
            (!filters.host?.trim() ||
              record.host
                .toLowerCase()
                .includes(filters.host.trim().toLowerCase())) &&
            matchesLivePathPrefix(record.path, filters.pathPrefix ?? "") &&
            (!filters.country?.trim() ||
              record.country === filters.country.trim().toUpperCase()) &&
            (!filters.method || record.method === filters.method) &&
            (!filters.decision ||
              (filters.decision === "blocked"
                ? record.blocked
                : filters.decision === "forwarded"
                  ? record.forwarded
                  : !record.blocked && !record.forwarded)) &&
            (!filters.status ||
              Math.floor(record.status / 100).toString() === filters.status) &&
            (!filters.reference ||
              record.request_id
                ?.toLowerCase()
                .includes(filters.reference.trim().toLowerCase())),
        )
        .slice()
        .reverse(),
    [
      logs,
      filters.method,
      filters.decision,
      filters.status,
      filters.reference,
      filters.host,
      filters.pathPrefix,
      filters.country,
      scope,
    ],
  );
  const filtered = Object.values(filters).some(Boolean);
  return (
    <Stack gap="md">
      <Paper withBorder style={{ overflow: "hidden" }}>
        <Group justify="space-between" p="md">
          <div>
            <Title order={2}>Live request feed</Title>
            <Text size="sm" c="dimmed" mt={rem(4)}>
              Newest first · {logs.length.toLocaleString()} / 1,000 retained
              {scope ? " · URL investigation filters also apply" : ""}
            </Text>
          </div>
          <Badge variant="light" color="gray">
            {records.length.toLocaleString()} shown
          </Badge>
        </Group>
        <Box
          component="form"
          p="md"
          bg="var(--console-muted)"
          style={{ borderBlock: "1px solid var(--console-border)" }}
          aria-label="Filter live requests"
          onSubmit={(e) => e.preventDefault()}
        >
          <Grid gutter="md" align="flex-end">
            <Grid.Col span={{ base: 12, sm: 2.4, xl: 1.2 }}>
              <TextInput
                label="Host contains"
                placeholder="app.example.test"
                maxLength={253}
                {...form.register("host")}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 12, sm: 4, xl: 2 }}>
              <TextInput
                label="Path prefix"
                placeholder="/api/"
                maxLength={2048}
                {...form.register("pathPrefix")}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 6, sm: 4, xl: 1.8 }}>
              <TextInput
                label="Country code"
                placeholder="VN"
                maxLength={2}
                styles={{ input: { textTransform: "uppercase" } }}
                {...form.register("country")}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 6, sm: 4, xl: 2 }}>
              <NativeSelect
                label="HTTP method"
                data={[
                  { value: "", label: "All methods" },
                  "GET",
                  "POST",
                  "PUT",
                  "PATCH",
                  "DELETE",
                  "HEAD",
                  "OPTIONS",
                  "CONNECT",
                  "TRACE",
                ]}
                {...form.register("method")}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 6, sm: 4, xl: 2 }}>
              <NativeSelect
                label="Decision"
                data={[
                  { value: "", label: "All decisions" },
                  { value: "blocked", label: "Blocked" },
                  { value: "forwarded", label: "Forwarded" },
                  { value: "local", label: "Local response" },
                ]}
                {...form.register("decision")}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 6, sm: 4, xl: 2 }}>
              <NativeSelect
                label="Response status"
                data={[
                  { value: "", label: "All statuses" },
                  { value: "0", label: "No final response" },
                  ...[1, 2, 3, 4, 5].map((i) => ({
                    value: String(i),
                    label: `${i}xx`,
                  })),
                ]}
                {...form.register("status")}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 6, sm: 4, xl: 2 }}>
              <TextInput
                label="Reference contains"
                placeholder="Request ID"
                maxLength={128}
                leftSection={<Filter size={rem(14)} aria-hidden="true" />}
                {...form.register("reference")}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 12, sm: 4, xl: 2 }}>
              <Button
                fullWidth
                variant="default"
                leftSection={<RotateCcw size={rem(14)} />}
                onClick={() => form.reset()}
                disabled={!filtered}
              >
                Reset filters
              </Button>
            </Grid.Col>
          </Grid>
        </Box>
        <DataTable
          withTableBorder={false}
          idAccessor={(record) => `${record.epoch}:${record.sequence}`}
          records={records}
          onRowClick={({ record }) => setSelected(record)}
          noRecordsText={
            filtered
              ? "No retained requests match these filters."
              : "No live requests received"
          }
          minHeight={rem(280)}
          columns={trafficColumns(setSelected)}
        />
        <Text size="xs" c="dimmed" p="md">
          Filters apply to retained live records. Origin is the request scheme
          and host observed by the gateway. Path is before rewriting, without
          query values. Missing metadata is shown as unavailable; truncated
          paths end with an ellipsis. Country code comes from gateway GeoIP.
          Path prefix matching is literal and case-sensitive; /api also matches
          /apix. Clear the prefix to show all paths. Body size counts request
          payload bytes received; incomplete reads are marked. Route names come
          from each recorded request, including its configuration version.
          Client IPs, headers, bodies and matched data are omitted from this
          table.
        </Text>
      </Paper>
      <RequestLookup />
      <RequestDetails record={selected} onClose={() => setSelected(null)} />
    </Stack>
  );
}

function matchesScope(
  record: ReturnType<typeof trafficRecord>,
  params: URLSearchParams,
): boolean {
  const details = parseRequestDetails(record.details);
  const client = object(object(details?.metadata)?.client);
  const action = params.get("action");
  const start = Number(params.get("start_ms"));
  const end = Number(params.get("end_ms"));
  const timestamp = Number(record.observed_at_unix_ms);
  const findings = object(details?.waf)?.findings;
  return (
    (!start || timestamp >= start) &&
    (!end || timestamp < end) &&
    (!params.has("route_id") || details?.route_id === params.get("route_id")) &&
    (!params.has("config_version") ||
      Number(record.config_version) === Number(params.get("config_version"))) &&
    (!params.has("host") ||
      record.host.toLowerCase().includes(params.get("host")!.toLowerCase())) &&
    (!params.has("path") || record.path.includes(params.get("path")!)) &&
    (!params.has("country") ||
      record.country === params.get("country")!.toUpperCase()) &&
    (!params.has("client_ip") || client?.ip === params.get("client_ip")) &&
    (!params.has("layer") || details?.security_layer === params.get("layer")) &&
    (!params.has("rule_id") ||
      (Array.isArray(findings) &&
        findings.some(
          (f) => object(f)?.rule_id === Number(params.get("rule_id")),
        ))) &&
    (!params.has("status_class") ||
      Math.floor(record.status / 100) === Number(params.get("status_class"))) &&
    (!action ||
      (action === "blocked"
        ? record.blocked
        : action === "forwarded"
          ? record.forwarded
          : !record.blocked && !record.forwarded))
  );
}
