import { Alert, Code, Stack, Text, Title } from "@mantine/core";
import { DataTable } from "./DataTable";
import { DetailsGrid } from "./shared";
import { time } from "./format";
import { object, type Fields, type Metadata } from "./request-metadata";
function string(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}
function number(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? value
    : null;
}
const missing = "Not collected / unavailable";
function label(value: unknown) {
  return string(value)?.replaceAll("_", " ") ?? missing;
}
function bytes(value: unknown) {
  const n = number(value);
  if (n === null) return missing;
  if (n < 1024) return `${n.toLocaleString("en-US")} B`;
  const unit = n < 1048576 ? "KiB" : "MiB";
  return `${(n / (unit === "KiB" ? 1024 : 1048576)).toFixed(2)} ${unit} (${n.toLocaleString("en-US")} B)`;
}
function complete(value: unknown) {
  return value === true
    ? "Complete"
    : value === false
      ? "Incomplete / not fully observed"
      : missing;
}
export function ClientMetadata({ data }: { data: Metadata }) {
  const c = data.client;
  const code = string(c.country_code);
  const country =
    code && /^[A-Z]{2}$/.test(code)
      ? `${new Intl.DisplayNames(["en"], { type: "region" }).of(code)} (${code})`
      : missing;
  return (
    <section className="request-detail-section">
      <Title order={3} mb="md">
        Client
      </Title>
      <DetailsGrid
        items={[
          { label: "Client IP", value: string(c.ip) ?? missing },
          { label: "Connection peer IP", value: string(c.peer_ip) ?? missing },
          {
            label: "Connection peer port",
            value: number(c.peer_port) ?? missing,
          },
          { label: "Client IP source", value: label(c.ip_source) },
          { label: "Country", value: country },
          { label: "GeoIP status", value: label(c.geoip_status) },
          { label: "GeoIP source", value: label(c.geoip_source) },
          {
            label: "TLS version",
            value:
              string(c.tls_version) ??
              "Unavailable (plain HTTP or not collected)",
          },
          {
            label: "TLS cipher",
            value:
              string(c.tls_cipher) ??
              "Unavailable (plain HTTP or not collected)",
          },
        ]}
      />
      <Text size="xs" c="dimmed" mt="md">
        User agent
      </Text>
      <Text size="sm" style={{ overflowWrap: "anywhere" }}>
        {string(c.user_agent) ?? missing}
      </Text>
      {c.user_agent_truncated === true && (
        <Text size="xs" c="orange">
          User agent truncated.
        </Text>
      )}
      <Text size="xs" c="dimmed" mt="sm">
        Location is an IP-based country estimate; city and coordinates are not
        collected.
      </Text>
    </section>
  );
}
export function RequestMetadata({ data }: { data: Metadata }) {
  const r = data.request;
  return (
    <section className="request-detail-section">
      <Title order={3} mb="md">
        Request
      </Title>
      <DetailsGrid
        items={[
          { label: "Method", value: string(r.method) ?? missing },
          { label: "Scheme", value: string(r.scheme) ?? missing },
          { label: "HTTP version", value: string(r.http_version) ?? missing },
          { label: "Host", value: string(r.host) ?? missing },
          {
            label: "Query string",
            value:
              r.query === "[REDACTED]"
                ? "Present · redacted"
                : r.query === null
                  ? "None"
                  : missing,
          },
          {
            label: "Declared request body",
            value: bytes(r.body_declared_bytes),
          },
          {
            label: "Received request body",
            value: bytes(r.body_received_bytes),
          },
          { label: "Request body read", value: complete(r.body_read_complete) },
          {
            label: "Started at",
            value:
              number(data.root.started_at_unix_ms) !== null
                ? time(Number(data.root.started_at_unix_ms))
                : missing,
          },
        ]}
      />
      <Text size="xs" c="dimmed" mt="md">
        Original path (without query)
      </Text>
      <Code block style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
        {string(r.path) ?? missing}
      </Code>
      {r.path_truncated === true && (
        <Text size="xs" c="orange">
          Path truncated.
        </Text>
      )}
      <Text size="xs" c="dimmed" mt="sm">
        Body sizes count payload bytes, excluding HTTP framing. Declared length
        can be absent for chunked requests. Body contents are not stored.
      </Text>
    </section>
  );
}
export function ResponseMetadata({ data }: { data: Metadata }) {
  const r = data.response;
  return (
    <DetailsGrid
      items={[
        {
          label: "Declared response body",
          value: bytes(r.body_declared_bytes),
        },
        { label: "Response body written", value: bytes(r.body_sent_bytes) },
        {
          label: "Upstream response body received",
          value: bytes(r.upstream_body_received_bytes),
        },
        {
          label: "Upstream body read",
          value: complete(r.upstream_body_complete),
        },
        { label: "Response completion", value: complete(r.completed) },
        {
          label: "Finished at",
          value:
            number(data.root.completed_at_unix_ms) !== null
              ? time(Number(data.root.completed_at_unix_ms))
              : missing,
        },
      ]}
    />
  );
}
function Headers({ title, value }: { title: string; value: unknown }) {
  const h = object(value);
  const entries = Array.isArray(h?.entries)
    ? h.entries
        .slice(0, 24)
        .map(object)
        .filter((v): v is Fields => v !== null)
    : null;
  return (
    <section className="request-detail-section">
      <Title order={3} mb="sm">
        {title}
      </Title>
      {!entries ? (
        <Text c="dimmed" size="sm">
          Headers not collected / unavailable.
        </Text>
      ) : (
        <>
          <Text size="xs" c="dimmed" mb="sm">
            {entries.length} shown of {number(h?.total) ?? "unknown"} headers.
            Sensitive and unrecognized values are redacted.
          </Text>
          {h?.truncated === true && (
            <Alert color="yellow" mb="sm">
              Header capture limited: {number(h.omitted) ?? "unknown"} omitted;
              some names or values may be truncated.
            </Alert>
          )}
          {entries.length ? (
            <DataTable
              disableScroll
              aria-label={title}
              records={entries.map((entry, index): Fields & { id: number } => ({
                ...entry,
                id: index,
              }))}
              defaultColumnProps={{
                cellsStyle: () => ({ overflowWrap: "anywhere" }),
              }}
              styles={{ table: { tableLayout: "fixed" } }}
              columns={[
                {
                  accessor: "name",
                  title: "Name",
                  width: "35%",
                  render: (entry) => (
                    <Text component="code" size="sm">
                      {string(entry.name) ?? missing}
                    </Text>
                  ),
                },
                {
                  accessor: "value",
                  title: "Value",
                  render: (entry) => (
                    <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>
                      {entry.redacted === true
                        ? "[REDACTED]"
                        : (string(entry.value) ?? missing)}
                      {entry.truncated === true && (
                        <Text
                          component="span"
                          display="block"
                          size="xs"
                          c="orange"
                        >
                          Truncated
                        </Text>
                      )}
                    </Text>
                  ),
                },
              ]}
            />
          ) : (
            <Text size="sm" c="dimmed">
              No headers.
            </Text>
          )}
        </>
      )}
    </section>
  );
}
export function MetadataHeaders({ data }: { data: Metadata | null }) {
  return (
    <Stack gap="md">
      <Headers title="Request headers" value={data?.request.headers} />
      <Headers title="Response headers" value={data?.response.headers} />
    </Stack>
  );
}
