import { requestRouteLabel } from "./route-labels";
import {
  Alert,
  Badge,
  Group,
  Paper,
  Stack,
  Text,
  ThemeIcon,
  Title,
  rem,
} from "@mantine/core";
import {
  ArrowRight,
  Ban,
  Check,
  CircleAlert,
  Clock3,
  Minus,
} from "lucide-react";
import type { CSSProperties } from "react";
import type { Decision, RequestRecord } from "./RequestDetails";

// Use explicit recorded results; an unfamiliar result must never imply success.
const resultColors: Record<string, string> = {
  passed: "teal",
  matched: "teal",
  authenticated: "teal",
  cleared: "teal",
  solved: "teal",
  login_succeeded: "teal",
  served: "teal",
  blocked: "red",
  denied: "red",
  rejected: "red",
  failed: "red",
  error: "red",
  unavailable: "red",
  method_not_allowed: "red",
  required: "orange",
  enabled: "orange",
  stopped: "orange",
  interrupted: "orange",
  standalone: "blue",
  redirected_to_https: "blue",
};

const explanations: Record<string, string> = {
  application:
    "The static application target returned this status locally. Check the release, path, HTTP method and artifact availability.",
  waf: "The WAF stopped this request. Matched rule IDs are shown below; matched payload data is redacted.",
  route_maintenance:
    "Route maintenance returns a local 503 with Retry-After before challenge, authentication and upstream forwarding. Existing requests keep their original configuration.",
  challenge:
    "Browser proof-of-work is required before application access. Clearance does not bypass ACL, rate limits or WAF.",
  ddos_global: "The shared HTTP flood budget across all routes was exhausted.",
  ddos_route: "The shared HTTP flood budget for this route was exhausted.",
  ddos_global_capacity:
    "Global HTTP flood protection was unavailable. The gateway refused the request.",
  ddos_route_capacity:
    "Route HTTP flood protection was unavailable. The gateway refused the request.",
  global_acl: "The client IP did not pass the global IP access policy.",
  global_geoip:
    "The global country policy rejected the request, or GeoIP was unavailable.",
  global_rate_limit:
    "The client exhausted its shared request allowance across routes.",
  global_rate_limit_capacity:
    "The global rate limiter could not admit another client. The request was refused without bypassing the limit.",
  acl: "The client IP did not pass this route's IP access policy.",
  geoip: "The country policy rejected the request, or GeoIP was unavailable.",
  rate_limit: "The client exhausted this route's request rate allowance.",
  crowdsec:
    "The client matched an unexpired ban in the local CrowdSec snapshot.",
  body_limit:
    "Request body or framing validation stopped processing. Check the HTTP status and recorded outcome.",
  content_contract: "The request did not meet this route's content contract.",
  routing:
    "The gateway could not select a valid route or rejected routing metadata.",
  framing: "The gateway rejected invalid or ambiguous HTTP framing.",
  waf_capacity:
    "No inspection capacity was available. The gateway refused to bypass the WAF.",
  waf_unavailable:
    "WAF inspection could not complete. The gateway refused to bypass protection.",
  forward_auth:
    "The external authentication step denied access or was unavailable.",
  password_protect:
    "This route requires a valid password session. See the outcome for login, CSRF or capacity failures.",
  cors: "The request did not pass the route's CORS policy.",
};
export function RequestFlow({
  record,
  decision,
}: {
  record: RequestRecord;
  decision: Decision | null;
}) {
  const trace = Array.isArray(decision?.decision_trace)
    ? decision.decision_trace
        .slice(0, 16)
        .filter(
          (s) =>
            s && typeof s.stage === "string" && typeof s.result === "string",
        )
    : [];
  const rules = Array.isArray(decision?.waf?.findings)
    ? decision.waf.findings.slice(0, 16)
    : [];
  const layer = decision?.security_layer;
  const stopped = !record.forwarded && record.status >= 400;
  return (
    <Paper withBorder p="md" radius="md" aria-label="Request decision flow">
      <Stack gap="sm">
        <Title order={3}>
          {record.blocked
            ? "Why was this request blocked?"
            : stopped
              ? "Why was this request stopped?"
              : "How was this request handled?"}
        </Title>
        <Text size="sm" c="dimmed">
          {stopped
            ? (layer && explanations[layer]) ||
              "The gateway recorded a security rejection. Consult the decision layer and outcome."
            : record.forwarded
              ? "The request reached an upstream. An application error status alone does not mean the WAF blocked it."
              : decision?.application
                ? "The gateway served a hosted application release locally after security checks."
                : "The gateway handled this request locally. Consult the recorded outcome."}
        </Text>
        <Group gap="xs">
          <Badge variant="light">Config {record.config_version}</Badge>
          <Badge variant="light">Route: {requestRouteLabel(record)}</Badge>
          {layer && (
            <Badge variant="light" color={record.blocked ? "red" : "gray"}>
              Decision: {layer}
            </Badge>
          )}
        </Group>
        {trace.length ? (
          <ol
            className="decision-flow"
            role="list"
            aria-label="Recorded checkpoints"
          >
            {trace.map((step, index) => {
              const color = Object.hasOwn(resultColors, step.result)
                ? resultColors[step.result]
                : "gray";
              const Icon =
                color === "teal"
                  ? Check
                  : color === "red"
                    ? Ban
                    : color === "orange"
                      ? CircleAlert
                      : color === "blue"
                        ? ArrowRight
                        : Minus;
              const duration =
                typeof step.duration_ms === "number" &&
                Number.isFinite(step.duration_ms) &&
                step.duration_ms >= 0
                  ? step.duration_ms > 0 && step.duration_ms < 0.001
                    ? "<0.001 ms"
                    : `${step.duration_ms.toLocaleString(undefined, { maximumFractionDigits: 3 })} ms`
                  : "Timing not collected";
              return (
                <li
                  key={`${index}:${step.stage}`}
                  className="decision-flow-step"
                  style={
                    {
                      "--flow-color": `light-dark(var(--mantine-color-${color}-9), var(--mantine-color-${color}-3))`,
                      "--flow-tint": `light-dark(var(--mantine-color-${color}-0), var(--mantine-color-${color}-light))`,
                    } as CSSProperties
                  }
                >
                  <div className="decision-flow-step-heading">
                    <ThemeIcon
                      color={color}
                      variant="light"
                      size={rem(26)}
                      radius="md"
                      c="var(--flow-color)"
                    >
                      <Icon size={rem(14)} aria-hidden="true" />
                    </ThemeIcon>
                    <Text size="sm" fw={600} className="decision-flow-stage">
                      {step.stage.replaceAll("_", " ")}
                    </Text>
                    <Text
                      span
                      size="xs"
                      c="dimmed"
                      className="decision-flow-index"
                      aria-hidden="true"
                    >
                      {String(index + 1).padStart(2, "0")}
                    </Text>
                  </div>
                  <div className="decision-flow-step-footer">
                    <Badge
                      className="decision-flow-result"
                      variant="light"
                      size="md"
                      color={color}
                      c="var(--flow-color)"
                      tt="none"
                      fw={500}
                      radius="sm"
                    >
                      {step.result.replaceAll("_", " ")}
                    </Badge>
                    <Text
                      span
                      size="xs"
                      c="dimmed"
                      className="decision-flow-duration"
                    >
                      <Clock3 size={rem(12)} aria-hidden="true" />
                      {duration}
                    </Text>
                  </div>
                </li>
              );
            })}
          </ol>
        ) : (
          <Text size="xs" c="dimmed">
            Step-by-step evidence was not collected for this older record.
          </Text>
        )}
        <Alert
          color={record.blocked ? "red" : "blue"}
          title={
            record.forwarded
              ? "Upstream reached"
              : "No upstream forwarding recorded"
          }
        >
          {decision?.outcome ?? "Outcome unavailable"}
          {stopped && layer
            ? ` · Stopped at ${layer.replaceAll("_", " ")}`
            : ""}
        </Alert>
        {rules.length > 0 && (
          <Group gap="xs" aria-label="Matched WAF rules">
            {rules.map((rule, i) => (
              <Badge
                key={`${i}:${rule.rule_id}`}
                color="orange"
                variant="light"
              >
                Rule {rule.rule_id} · phase {rule.phase}
              </Badge>
            ))}
          </Group>
        )}
        {decision?.body_inspection && (
          <Text size="xs" c="dimmed">
            Inspection scope: {decision.body_inspection.replaceAll("_", " ")}.
            Steps after the recorded stop were not evaluated.
          </Text>
        )}
      </Stack>
    </Paper>
  );
}
