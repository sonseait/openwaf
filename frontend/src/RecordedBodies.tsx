import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Code,
  Group,
  Loader,
  Paper,
  Stack,
  Text,
  Title,
} from "@mantine/core";
import { api } from "./api";
import { Failure, StateBadge } from "./shared";

interface Side {
  status: string;
  reason?: string | null;
  content_type?: string | null;
  bytes?: number;
  content?: string | null;
}
interface Bodies {
  request: Side;
  response: Side;
  query?: Side;
  persistence?: string;
}
function displayBody(side: Side) {
  if (!side.content) return "";
  if (side.content_type?.includes("json")) {
    try {
      const pretty = JSON.stringify(JSON.parse(side.content), null, 2);
      if (pretty.length <= 262144) return pretty;
    } catch {
      // Render malformed stored content as text, never as markup.
    }
  }
  return side.content;
}
export function RecordedBodies({
  id,
  active,
}: {
  id?: string;
  active: boolean;
}) {
  const result = useQuery({
    queryKey: ["recorded-bodies", id],
    queryFn: ({ signal }) =>
      api<Bodies>(`/requests/${encodeURIComponent(id!)}/body`, { signal }),
    enabled: active && !!id,
    gcTime: 0,
    retry: false,
    refetchInterval: (query) =>
      active &&
      (query.state.data?.persistence === "pending" ||
        [
          query.state.data?.request.status,
          query.state.data?.response.status,
          query.state.data?.query?.status,
        ].includes("pending"))
        ? 2000
        : false,
  });
  if (!id)
    return (
      <Alert color="yellow">
        Body and query recording were not collected for this older record.
      </Alert>
    );
  if (result.isPending)
    return (
      <Group>
        <Loader size="sm" />
        <Text>Loading recorded data…</Text>
      </Group>
    );
  if (result.isError)
    return (
      <Stack>
        <Failure error={result.error} />
        <Button variant="light" size="xs" onClick={() => void result.refetch()}>
          Retry loading recorded data
        </Button>
      </Stack>
    );
  return (
    <Stack>
      <Button
        variant="light"
        size="xs"
        onClick={() => void result.refetch()}
        loading={result.isFetching}
      >
        Refresh recorded data
      </Button>
      <Text size="sm" c="dimmed">
        Recorded bodies and query strings are redacted and retained for 7 days.
        Response capture describes data prepared by the gateway, not
        confirmation of client receipt.
      </Text>
      {result.data.persistence &&
        !["written", "not_required"].includes(result.data.persistence) && (
          <Alert color="yellow">
            History persistence: {result.data.persistence.replaceAll("_", " ")}.
            A live copy may be temporary.
          </Alert>
        )}
      {(["request", "response", "query"] as const).map((direction) => {
        const side = result.data[direction] ?? {
          status: "unavailable",
          reason: "not_collected",
        };
        return (
          <Paper key={direction} withBorder p="md">
            <Stack gap="sm">
              <Group justify="space-between">
                <Title order={4}>
                  {direction === "request"
                    ? "Request body"
                    : direction === "response"
                      ? "Response body"
                      : "Query string"}
                </Title>
                <StateBadge value={side.status} />
              </Group>
              <Text size="sm" c="dimmed">
                {side.content_type || "Content type unavailable"}
                {side.bytes == null ? "" : ` · ${side.bytes} B observed`}
              </Text>
              {side.reason && (
                <Text size="sm">{side.reason.replaceAll("_", " ")}</Text>
              )}
              {side.content != null ? (
                <Code
                  block
                  style={{
                    whiteSpace: "pre-wrap",
                    overflowWrap: "anywhere",
                    maxHeight: 480,
                    overflow: "auto",
                  }}
                >
                  {displayBody(side)}
                </Code>
              ) : (
                <Text size="sm" c="dimmed">
                  {side.status === "empty"
                    ? direction === "query"
                      ? "No query string."
                      : "No body."
                    : "No recorded content available."}
                </Text>
              )}
            </Stack>
          </Paper>
        );
      })}
    </Stack>
  );
}
