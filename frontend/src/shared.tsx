import {
  Alert,
  Badge,
  Group,
  Paper,
  SimpleGrid,
  Stack,
  Text,
  rem,
} from "@mantine/core";
import type { ReactNode } from "react";
import { AlertTriangle, CircleCheck, CircleOff, Clock3 } from "lucide-react";
import { ApiError, message } from "./api";
import type { CandidatePage, Diff } from "./types";

export function StatusBadge({
  children,
  color = "gray",
}: {
  children: ReactNode;
  color?: string;
}) {
  const lightText = color === "yellow" ? "dark-6" : `${color}-9`;
  return (
    <Badge
      component="span"
      variant="light"
      color={color}
      c={`light-dark(var(--mantine-color-${lightText}), var(--mantine-color-${color}-3))`}
      radius="sm"
      tt="none"
    >
      {children}
    </Badge>
  );
}

export function BooleanStatusBadge({
  value,
  trueLabel,
  falseLabel,
  unknownLabel = "Unknown",
  trueColor = "blue",
  falseColor = "gray",
}: {
  value?: boolean | null;
  trueLabel: string;
  falseLabel: string;
  unknownLabel?: string;
  trueColor?: string;
  falseColor?: string;
}) {
  return (
    <StatusBadge
      color={value === true ? trueColor : value === false ? falseColor : "gray"}
    >
      {value === true ? trueLabel : value === false ? falseLabel : unknownLabel}
    </StatusBadge>
  );
}

export function StateBadge({ value }: { value?: string | null }) {
  const state = value ?? "unknown";
  const colors: Record<string, string> = {
    healthy: "teal",
    available: "teal",
    valid: "teal",
    passed: "teal",
    delivered: "teal",
    running: "blue",
    observed: "blue",
    active: "blue",
    completed: "blue",
    forwarded: "blue",
    queued: "blue",
    sent: "teal",
    failed: "red",
    error: "red",
    unavailable: "red",
    invalid: "red",
    blocked: "red",
    down: "red",
    absolute_timeout: "red",
    degraded: "yellow",
    pending: "yellow",
    retrying: "yellow",
    drain: "yellow",
    maintenance: "yellow",
    expires_soon: "yellow",
    Off: "yellow",
    DetectionOnly: "blue",
    On: "blue",
  };
  const label =
    state === "DetectionOnly" ? "Detection only" : state.replaceAll("_", " ");
  return (
    <StatusBadge color={colors[state] ?? "gray"}>
      {label.charAt(0).toUpperCase() + label.slice(1)}
    </StatusBadge>
  );
}

export function DetailsGrid({
  items,
}: {
  items: { label: string; value: ReactNode }[];
}) {
  return (
    <SimpleGrid
      component="dl"
      m={0}
      cols={{ base: 1, sm: 2, lg: 3 }}
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
            fw={500}
            style={{ overflowWrap: "anywhere" }}
          >
            {value}
          </Text>
        </Stack>
      ))}
    </SimpleGrid>
  );
}

export function DiscoveryStatusBadge({
  data,
}: {
  data?: Pick<CandidatePage, "collector_available" | "stale" | "error">;
}) {
  const { label, color, Icon } = !data?.collector_available
    ? { label: "Unavailable", color: "orange", Icon: CircleOff }
    : data.stale
      ? { label: "Stale", color: "orange", Icon: Clock3 }
      : data.error
        ? { label: "Degraded", color: "orange", Icon: AlertTriangle }
        : { label: "Fresh", color: "teal", Icon: CircleCheck };
  return (
    <Badge
      color={color}
      variant="light"
      radius="sm"
      tt="none"
      c={
        color === "orange"
          ? "light-dark(#9a400d, var(--mantine-color-orange-3))"
          : `light-dark(var(--mantine-color-${color}-9), var(--mantine-color-${color}-3))`
      }
      leftSection={
        <Icon size={rem(12)} color="currentColor" aria-hidden="true" />
      }
    >
      {label}
    </Badge>
  );
}

export function Failure({ error }: { error: unknown }) {
  return (
    <Alert
      color="red"
      icon={<AlertTriangle size={rem(18)} />}
      title="Action needs attention"
      role="alert"
    >
      {message(error)}
      {error instanceof ApiError &&
        error.retryAfter &&
        ` Retry after ${error.retryAfter} seconds.`}
    </Alert>
  );
}
export function Difference({ diff }: { diff?: Partial<Diff> | null }) {
  const changeList = (value: unknown) =>
    Array.isArray(value) && value.every((item) => typeof item === "string")
      ? value.join(", ") || "none"
      : "unavailable";
  const changeState = (value: unknown) =>
    value === true ? "changed" : value === false ? "unchanged" : "unavailable";
  return (
    <Paper withBorder p="md">
      <Stack gap="xs">
        {(["routes", "upstreams"] as const).map((kind) => (
          <Group key={kind} gap="xs">
            <Text size="sm" fw={600}>
              {kind}
            </Text>
            {(["added", "changed", "removed"] as const).map((action) => (
              <Badge
                key={action}
                variant="light"
                color={action === "removed" ? "red" : "teal"}
              >
                {action}: {changeList(diff?.[kind]?.[action])}
              </Badge>
            ))}
          </Group>
        ))}
        <Text size="sm" c="dimmed">
          Global rules: {changeState(diff?.global_rules_changed)}
        </Text>
        <Text size="sm" c="dimmed">
          Trusted proxies: {changeState(diff?.trusted_proxies_changed)}
        </Text>
        <Text size="sm" c="dimmed">
          Global error pages: {changeState(diff?.error_pages_changed)}
        </Text>
      </Stack>
    </Paper>
  );
}
