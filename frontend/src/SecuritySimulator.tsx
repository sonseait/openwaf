import {
  Alert,
  Button,
  Code,
  Group,
  Loader,
  NativeSelect,
  Paper,
  Stack,
  Text,
  Textarea,
  TextInput,
  Title,
} from "@mantine/core";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { api } from "./api";
import type { Config } from "./types";
import { Failure } from "./shared";
interface Input {
  source: "active" | "draft" | "compare";
  hostname: string;
  path: string;
  method: string;
  client_ip: string;
  headers: string;
  body: string;
}
export function SecuritySimulator() {
  const config = useQuery({
    queryKey: ["config"],
    queryFn: ({ signal }) => api<Config>("/config", { signal }),
  });
  const form = useForm<Input>({
    defaultValues: {
      source: "compare",
      hostname: "",
      path: "/",
      method: "GET",
      client_ip: "192.0.2.1",
      headers: "[]",
      body: "",
    },
  });
  const simulation = useMutation({
    mutationFn: (input: Input) => {
      const { source, headers, ...request } = input;
      return api<{
        config_version: number;
        live_state_mutated: boolean;
        outputs: Record<string, unknown>;
      }>("/security/simulate", {
        method: "POST",
        body: {
          source,
          expected_active_version: config.data?.active_version,
          expected_draft_revision: config.data?.draft_revision,
          request: { ...request, headers: JSON.parse(headers) },
        },
      });
    },
  });
  return (
    <Stack>
      <Title order={1}>Security simulator</Title>
      <Alert>
        Isolated execution. No upstream/auth requests, live quota changes,
        detector observations or incident writes. Payload is not stored or
        logged. Output explicitly marks unsupported layers. Use the route
        playground for routing candidate explanations.
      </Alert>
      {config.isPending && (
        <Loader aria-label="Loading simulator configuration" />
      )}
      {config.isError && <Failure error={config.error} />}{" "}
      {config.data && (
        <Text>
          Active version {config.data.active_version} · saved draft revision{" "}
          {config.data.draft_revision}. Unsaved editor changes are excluded.
        </Text>
      )}
      <Paper p="md" withBorder>
        <form onSubmit={form.handleSubmit((input) => simulation.mutate(input))}>
          <Stack>
            <NativeSelect
              label="Configuration source"
              data={[
                { value: "compare", label: "Compare active and saved draft" },
                { value: "active", label: "Active exact version" },
                { value: "draft", label: "Saved draft exact revision" },
              ]}
              {...form.register("source")}
            />
            <TextInput
              label="Hostname"
              {...form.register("hostname", { required: true, maxLength: 253 })}
            />
            <TextInput
              label="Raw path and query"
              {...form.register("path", { required: true, maxLength: 8192 })}
            />
            <TextInput
              label="Method (exact uppercase)"
              {...form.register("method", { required: true, maxLength: 32 })}
            />
            <TextInput
              label="Client IP for stateless ACL"
              {...form.register("client_ip", { required: true })}
            />
            <Textarea
              label='Headers as JSON pairs, e.g. [["content-type","application/json"]]'
              {...form.register("headers", { maxLength: 16384 })}
              minRows={2}
            />
            <Textarea
              label="Request body (maximum 64 KiB UTF-8)"
              {...form.register("body", {
                validate: (v) =>
                  new TextEncoder().encode(v).length <= 65536 ||
                  "Body exceeds 64 KiB",
              })}
              error={form.formState.errors.body?.message}
              minRows={5}
            />
            <Group>
              <Button
                type="submit"
                loading={simulation.isPending}
                disabled={!config.data}
              >
                Run isolated simulation
              </Button>
              <Button
                type="button"
                variant="light"
                onClick={() => {
                  form.setValue("body", "");
                  form.setValue("headers", "[]");
                  simulation.reset();
                }}
              >
                Clear payload and result
              </Button>
              <Button
                type="button"
                variant="subtle"
                onClick={() => void config.refetch()}
              >
                Refresh versions
              </Button>
            </Group>
          </Stack>
        </form>
      </Paper>
      {simulation.isError && <Failure error={simulation.error} />}
      {simulation.data && (
        <Paper p="md" withBorder>
          <Title order={2}>Simulation outputs</Title>
          <Code block>{JSON.stringify(simulation.data, null, 2)}</Code>
        </Paper>
      )}
    </Stack>
  );
}
