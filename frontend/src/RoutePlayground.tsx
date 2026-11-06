import {
  Alert,
  Badge,
  Button,
  Code,
  Group,
  Loader,
  NativeSelect,
  Paper,
  SimpleGrid,
  Stack,
  Text,
  TextInput,
  Title,
  rem,
} from "@mantine/core";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { useRef } from "react";
import { DataTable } from "./DataTable";
import { api } from "./api";
import { Failure } from "./shared";
import type { Config } from "./types";

interface Simulation {
  config_version: number;
  hostname: string;
  path: string;
  method: string;
  candidates: {
    route_id: string;
    host_matches: boolean;
    path_matches: boolean;
    method_matches: boolean;
    selected: boolean;
  }[];
  effective: {
    route_id: string;
    upstream: string;
    application?: { application_id: string; release_id: string; mode: string };
    rewritten_path: string;
    acl_permits_ip: boolean;
    global_rules?: {
      acl_permits_ip: boolean;
      geo_policy: boolean;
      rate_limit: unknown;
      ddos?: unknown;
      challenge?: unknown;
    };
    waf_mode: string | null;
    maintenance?: { message: string; retry_after_seconds: number } | null;
    password_protected: boolean;
    forward_auth: boolean;
    geo_policy: boolean;
    rate_limit: unknown;
    ddos?: unknown;
    challenge?: unknown;
    redirect: { url: string; status: number } | null;
  } | null;
  limitations: string[];
}
interface Inputs {
  scheme: "http" | "https";
  source: "active" | "draft";
  hostname: string;
  path: string;
  method: string;
  client_ip: string;
}
export function RoutePlayground() {
  const config = useQuery({
    queryKey: ["config"],
    queryFn: ({ signal }) => api<Config>("/config", { signal }),
  });
  const form = useForm<Inputs>({
    defaultValues: {
      source: "active",
      scheme: "https",
      hostname: "",
      path: "/",
      method: "GET",
      client_ip: "127.0.0.1",
    },
  });
  const generation = useRef(0);
  const simulate = useMutation({
    mutationFn: async (input: Inputs) => {
      const run = ++generation.current;
      const { source, ...request } = input;
      const document = source === "draft" ? config.data?.draft : undefined;
      if (
        source === "draft" &&
        (!document || config.isError || config.isFetching)
      )
        throw new Error("Reload the saved draft before simulating it.");
      const result = await api<Simulation>("/config/playground", {
        method: "POST",
        body: { source, document, request },
      });
      return {
        result,
        current: run === generation.current,
        source,
        draftRevision: config.data?.draft_revision,
      };
    },
  });
  const result = simulate.data?.current ? simulate.data.result : null;
  const changed = () => {
    generation.current++;
    simulate.reset();
  };
  return (
    <Stack gap="md">
      <div>
        <Text className="eyebrow">GATEWAY / ROUTING TOOLS</Text>
        <Title order={1}>Route playground</Title>
        <Text c="dimmed">
          Understand which route wins before sending any traffic.
        </Text>
      </div>
      <Alert color="blue">
        Read-only simulation. No upstream calls, configuration changes, WAF
        execution or live rate-limit consumption.
      </Alert>
      <Paper withBorder p="md">
        <form
          onSubmit={form.handleSubmit((input) => simulate.mutate(input))}
          onChange={changed}
        >
          <Stack>
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <NativeSelect
                label="Configuration source"
                data={[
                  { value: "active", label: "Active gateway snapshot" },
                  { value: "draft", label: "Saved draft" },
                ]}
                {...form.register("source")}
              />
              <NativeSelect
                label="Request scheme"
                data={["https", "http"]}
                {...form.register("scheme")}
              />
              <TextInput
                label="Hostname"
                placeholder="app.example.com"
                {...form.register("hostname", {
                  required: "Enter a hostname",
                  maxLength: 300,
                })}
                error={form.formState.errors.hostname?.message}
              />
              <TextInput
                label="Path"
                description="Path only; do not include query values."
                {...form.register("path", {
                  required: true,
                  maxLength: 2048,
                  validate: (v) =>
                    (v.startsWith("/") && !v.includes("?")) ||
                    "Enter a path without a query",
                })}
                error={form.formState.errors.path?.message}
              />
              <TextInput
                label="HTTP method"
                {...form.register("method", {
                  required: true,
                  pattern: {
                    value: /^[A-Z-]{1,32}$/,
                    message: "Use an uppercase HTTP method",
                  },
                })}
                error={form.formState.errors.method?.message}
              />
              <TextInput
                label="Simulated client IP"
                description="Evaluates IP ACL only; this is not a trusted forwarded header."
                {...form.register("client_ip", {
                  required: "Enter an IP address",
                  maxLength: 45,
                })}
                error={form.formState.errors.client_ip?.message}
              />
            </SimpleGrid>
            <Group>
              <Button
                type="submit"
                loading={simulate.isPending}
                disabled={
                  config.isPending || config.isError || config.isFetching
                }
              >
                Simulate routing
              </Button>
              <Button
                variant="default"
                onClick={() => {
                  changed();
                  void config.refetch();
                }}
              >
                Reload configuration
              </Button>
            </Group>
          </Stack>
        </form>
      </Paper>
      {config.isPending && <Loader aria-label="Loading configuration" />}
      {config.isError && <Failure error={config.error} />}
      {simulate.isError && <Failure error={simulate.error} />}
      {result && (
        <Stack gap="md" aria-live="polite">
          <Paper withBorder p="md">
            <Stack gap="sm">
              <Group>
                <Title order={2}>
                  {result.effective
                    ? `Selected route: ${result.effective.route_id}`
                    : "No matching route"}
                </Title>
                <Badge>
                  {simulate.data?.source === "draft"
                    ? `Saved draft revision ${simulate.data.draftRevision}`
                    : `Active version ${result.config_version}`}
                </Badge>
              </Group>
              <Text size="sm">
                Normalized request:{" "}
                <Code>
                  {result.method} {result.hostname}
                  {result.path}
                </Code>
              </Text>
              {result.effective && (
                <>
                  <Text>
                    Target:{" "}
                    {result.effective.maintenance && (
                      <Badge color="yellow">
                        Maintenance: local 503 · Retry-After{" "}
                        {result.effective.maintenance.retry_after_seconds}s
                      </Badge>
                    )}
                    {result.effective.application
                      ? `Application ${result.effective.application.application_id.slice(0, 12)} · release ${result.effective.application.release_id.slice(0, 12)}`
                      : result.effective.redirect
                        ? `Redirect ${result.effective.redirect.status} → ${result.effective.redirect.url}`
                        : result.effective.upstream}
                  </Text>
                  <Text>
                    Rewritten path:{" "}
                    <Code>{result.effective.rewritten_path}</Code>
                  </Text>
                  <Group gap="xs">
                    <Badge
                      color={result.effective.acl_permits_ip ? "teal" : "red"}
                    >
                      Combined IP ACL:{" "}
                      {result.effective.acl_permits_ip ? "permits" : "denies"}
                    </Badge>
                    <Badge>
                      WAF:{" "}
                      {result.effective.waf_mode ?? "inherits startup mode"}
                    </Badge>
                    <Badge>
                      Password:{" "}
                      {result.effective.password_protected ? "required" : "off"}
                    </Badge>
                    <Badge>
                      ForwardAuth:{" "}
                      {result.effective.forward_auth ? "configured" : "off"}
                    </Badge>
                    {result.effective.global_rules && (
                      <Badge
                        color={
                          result.effective.global_rules.acl_permits_ip
                            ? "teal"
                            : "red"
                        }
                      >
                        Global IP ACL:{" "}
                        {result.effective.global_rules.acl_permits_ip
                          ? "permits"
                          : "denies"}
                      </Badge>
                    )}
                    {result.effective.global_rules?.geo_policy && (
                      <Badge>Global GeoIP: not evaluated</Badge>
                    )}
                    {!!result.effective.global_rules?.rate_limit && (
                      <Badge>Global rate limit: not evaluated</Badge>
                    )}
                    {!!result.effective.global_rules?.ddos && (
                      <Badge>Global HTTP flood budget: not evaluated</Badge>
                    )}
                    {!!result.effective.global_rules?.challenge && (
                      <Badge>Global challenge: not evaluated</Badge>
                    )}
                    {!!result.effective.challenge && (
                      <Badge>Route challenge: not evaluated</Badge>
                    )}
                    {!!result.effective.ddos && (
                      <Badge>Route HTTP flood budget: not evaluated</Badge>
                    )}
                    {result.effective.geo_policy && (
                      <Badge>GeoIP: not evaluated</Badge>
                    )}
                    {!!result.effective.rate_limit && (
                      <Badge>Rate limit: not evaluated</Badge>
                    )}
                  </Group>
                </>
              )}
            </Stack>
          </Paper>
          <Paper withBorder p="md">
            <Title order={3} mb="sm">
              Route precedence
            </Title>
            <Text c="dimmed" size="sm" mb="sm">
              Exact host → most specific wildcard → exact path → longest prefix
              → specific method. All candidates are ordered by the gateway
              matcher.
            </Text>
            <DataTable
              aria-label="Route precedence"
              records={result.candidates}
              idAccessor="route_id"
              minHeight={rem(100)}
              noRecordsText="No configured routes."
              columns={[
                { accessor: "route_id", title: "Route" },
                {
                  accessor: "host_matches",
                  title: "Host",
                  render: (c) => (c.host_matches ? "Matches" : "Miss"),
                },
                {
                  accessor: "path_matches",
                  title: "Path",
                  render: (c) => (c.path_matches ? "Matches" : "Miss"),
                },
                {
                  accessor: "method_matches",
                  title: "Method",
                  render: (c) => (c.method_matches ? "Matches" : "Miss"),
                },
                {
                  accessor: "selected",
                  title: "Result",
                  render: (c) =>
                    c.selected
                      ? "Selected"
                      : c.host_matches && c.path_matches && c.method_matches
                        ? "Lower precedence"
                        : "Not eligible",
                },
              ]}
            />
          </Paper>
          <Alert color="gray" title="Simulation limits">
            {result.limitations.join(" ")}
          </Alert>
        </Stack>
      )}
    </Stack>
  );
}
