import { Badge, Button, Text, rem } from "@mantine/core";
import type { DataTableColumn } from "mantine-datatable";
import dayjs from "dayjs";
import type { TrafficLog } from "./telemetry-state";
import type { RequestRecord } from "./RequestDetails";
import { parseRequestDetails, requestRouteLabel } from "./route-labels";
import { object } from "./request-metadata";

// ClickHouse serializes UInt64 values as strings; SSE uses numbers.
export type TrafficRecord = Omit<
  TrafficLog,
  | "sequence"
  | "observed_at_unix_ms"
  | "latency_ms"
  | "config_version"
  | "route_index"
> & {
  sequence: number | string;
  observed_at_unix_ms: number | string;
  latency_ms: number | string;
  config_version: number | string;
  route_index: number | string | null;
};

export function trafficRecord(record: TrafficRecord) {
  const details = parseRequestDetails(record.details);
  const metadata = object(details?.metadata);
  const request = object(metadata?.request);
  const client = object(metadata?.client);
  const scheme = request?.scheme;
  const host = request?.host;
  const country = client?.country_code;
  const bodyBytes = request?.body_received_bytes;
  return {
    ...record,
    route: requestRouteLabel(record, details),
    host: typeof host === "string" ? host : "",
    origin:
      (scheme === "http" || scheme === "https") &&
      typeof host === "string" &&
      host
        ? `${scheme}://${host}`
        : "Unavailable",
    path:
      typeof request?.path === "string" && request.path
        ? request.path.split("?")[0]
        : "Unavailable",
    pathTruncated: request?.path_truncated === true,
    country:
      typeof country === "string" && /^[A-Z]{2}$/.test(country)
        ? country
        : null,
    bodyBytes:
      typeof bodyBytes === "number" &&
      Number.isSafeInteger(bodyBytes) &&
      bodyBytes >= 0
        ? bodyBytes
        : null,
    bodyComplete: request?.body_read_complete === true,
  };
}

type TableRecord = ReturnType<typeof trafficRecord>;

export function trafficColumns(
  select: (record: RequestRecord) => void,
): DataTableColumn<TableRecord>[] {
  return [
    {
      accessor: "observed_at_unix_ms",
      title: "Time",
      width: rem(125),
      render: (record) => {
        const timestamp = dayjs(Number(record.observed_at_unix_ms));
        if (!timestamp.isValid()) return "Unavailable";
        return (
          <time
            data-event-id={`${record.epoch}:${record.sequence}`}
            dateTime={timestamp.toISOString()}
            title={timestamp.format("YYYY-MM-DD HH:mm:ss.SSS Z")}
          >
            {timestamp.format("HH:mm:ss.SSS")}
          </time>
        );
      },
    },
    {
      accessor: "request_id",
      title: "Reference",
      width: rem(150),
      render: (record) => (
        <Button
          variant="subtle"
          size="compact-xs"
          aria-label={`View request ${record.request_id || `${record.epoch}:${record.sequence}`}`}
          onClick={() => select(record)}
        >
          {record.request_id?.slice(0, 12) || "Details"}
        </Button>
      ),
    },
    { accessor: "method", title: "Method", width: rem(85) },
    {
      accessor: "origin",
      title: "Origin",
      width: rem(220),
      render: (record) => (
        <Text size="sm" truncate maw={rem(220)} title={record.origin}>
          {record.origin}
        </Text>
      ),
    },
    {
      accessor: "path",
      title: "Path",
      width: rem(280),
      render: (record) => (
        <Text
          size="sm"
          truncate
          maw={rem(280)}
          title={`${record.path}${record.pathTruncated ? " (truncated at gateway)" : ""}`}
        >
          {record.path}
          {record.pathTruncated && "…"}
        </Text>
      ),
    },
    {
      accessor: "country",
      title: "Country (code)",
      width: rem(125),
      render: (record) => record.country ?? "Unavailable",
    },
    {
      accessor: "bodyBytes",
      title: "Body size",
      width: rem(145),
      render: (record) => (
        <Text
          size="sm"
          title="Request payload bytes received by the gateway; excludes HTTP framing. An incomplete read may contain only part of the body."
        >
          {record.bodyBytes === null
            ? "Unavailable"
            : `${record.bodyBytes.toLocaleString()} B${record.bodyComplete ? "" : " (partial)"}`}
        </Text>
      ),
    },
    {
      accessor: "status",
      title: "Status",
      width: rem(80),
      render: (record) => (
        <Badge
          variant="light"
          color={
            record.status >= 500
              ? "red"
              : record.status >= 400
                ? "orange"
                : record.status === 0
                  ? "gray"
                  : "teal"
          }
        >
          {record.status || "—"}
        </Badge>
      ),
    },
    {
      accessor: "blocked",
      title: "Decision",
      width: rem(120),
      render: (record) => (
        <Text size="sm" c={record.blocked ? "orange" : undefined}>
          {record.blocked
            ? "Blocked"
            : record.forwarded
              ? "Forwarded"
              : "Local"}
        </Text>
      ),
    },
    { accessor: "latency_ms", title: "Latency (ms)", width: rem(110) },
    { accessor: "config_version", title: "Version", width: rem(80) },
    {
      accessor: "route",
      title: "Route",
      width: rem(180),
      render: (record) => (
        <Text size="sm" truncate maw={rem(180)} title={record.route}>
          {record.route}
        </Text>
      ),
    },
  ];
}
