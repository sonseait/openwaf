import {
  Alert,
  Button,
  Switch,
  Grid,
  Group,
  NativeSelect,
  NumberInput,
  Stack,
  Text,
  TextInput,
  rem,
} from "@mantine/core";
import {
  Controller,
  useFieldArray,
  useFormContext,
  useWatch,
} from "react-hook-form";
import { Plus } from "lucide-react";
import type { Document } from "../types";
import { Section, Optional, Remove } from "./shared";
import { ModalTabs, ModalSection } from "../ModalTabs";
import { TIMEOUT_HELP } from "./timeouts";
function Endpoints({ index }: { index: number }) {
  const {
    control,
    setValue,
    formState: { errors },
  } = useFormContext<Document>();
  const name = `upstreams.${index}.endpoints` as const;
  const list = useFieldArray({
    control,
    name,
    rules: {
      validate: (endpoints) =>
        endpoints.length > 0 || "Add at least one endpoint",
    },
  });
  const values = useWatch({ control, name });
  return (
    <Stack>
      {errors.upstreams?.[index]?.endpoints?.root?.message && (
        <Alert color="red">
          {errors.upstreams[index]?.endpoints?.root?.message}
        </Alert>
      )}
      {list.fields.map((item, i) => (
        <Stack className="config-item" pb="xs" key={item.id}>
          <Group justify="space-between">
            <Text size="sm" fw={600}>
              Endpoint {i + 1}
            </Text>
            <Remove label="Remove endpoint" onClick={() => list.remove(i)} />
          </Group>
          <Grid gutter="md" align="flex-start">
            <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
              <Controller
                control={control}
                name={`${name}.${i}.address`}
                rules={{
                  required: "Endpoint address is required",
                }}
                render={({ field, fieldState }) => (
                  <TextInput
                    {...field}
                    label="Endpoint address"
                    error={fieldState.error?.message}
                    disabled={!!values?.[i]?.source}
                    required
                    withAsterisk={false}
                    value={field.value ?? ""}
                    onChange={(event) =>
                      field.onChange(event.currentTarget.value || "")
                    }
                  />
                )}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 12, sm: 6, lg: 4 }} miw={0}>
              <Controller
                control={control}
                name={`${name}.${i}.weight`}
                render={({ field, fieldState }) => (
                  <NumberInput
                    {...field}
                    label="Endpoint weight"
                    description="Default 1. Used by weighted round-robin and least-active requests."
                    error={fieldState.error?.message}
                    maw={rem(416)}
                    min={1}
                    max={1000}
                    allowDecimal={false}
                    allowNegative={false}
                    value={field.value ?? ""}
                    onChange={(value) =>
                      field.onChange(value === "" ? undefined : value)
                    }
                  />
                )}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
              <Controller
                control={control}
                name={`${name}.${i}.protocol`}
                rules={{ required: "Protocol is required" }}
                render={({ field, fieldState }) => (
                  <NativeSelect
                    {...field}
                    label="Protocol"
                    error={fieldState.error?.message}
                    disabled={!!values?.[i]?.source}
                    data={["http", "https"]}
                    value={field.value ?? ""}
                    onChange={(event) => {
                      field.onChange(event.currentTarget.value || undefined);
                      if (event.currentTarget.value === "http") {
                        setValue(`${name}.${i}.tls_verify`, true, {
                          shouldDirty: true,
                        });
                        setValue(`${name}.${i}.tls_server_name`, null, {
                          shouldDirty: true,
                        });
                      }
                    }}
                  />
                )}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
              <Controller
                control={control}
                name={`${name}.${i}.tls_server_name`}
                render={({ field, fieldState }) => (
                  <TextInput
                    {...field}
                    label="TLS server name (SNI)"
                    description="SNI and hostname used for HTTPS verification."
                    error={fieldState.error?.message}
                    disabled={!!values?.[i]?.source}
                    withAsterisk={false}
                    value={field.value ?? ""}
                    onChange={(event) =>
                      field.onChange(event.currentTarget.value || undefined)
                    }
                  />
                )}
              />
            </Grid.Col>
          </Grid>
          {values?.[i]?.protocol === "https" && (
            <Controller
              control={control}
              name={`${name}.${i}.tls_verify`}
              render={({ field }) => (
                <Switch
                  label="Verify upstream TLS certificate and hostname"
                  description="Enabled by default. Disabling allows an untrusted server to impersonate this upstream."
                  checked={field.value ?? true}
                  onChange={(event) =>
                    field.onChange(event.currentTarget.checked)
                  }
                />
              )}
            />
          )}
          {values?.[i]?.source && (
            <Group>
              <Text size="xs" c="dimmed">
                Discovery source: {values[i].source?.kind}. Editing this
                endpoint requires detaching its discovery source.
              </Text>
              <Button
                size="compact-xs"
                variant="light"
                onClick={() =>
                  setValue(`${name}.${i}.source`, undefined, {
                    shouldDirty: true,
                  })
                }
              >
                Use as manual endpoint
              </Button>
            </Group>
          )}
        </Stack>
      ))}
      <Button
        variant="light"
        data-add-endpoint
        leftSection={<Plus size={rem(14)} />}
        onClick={() =>
          list.append({ address: "", protocol: "http", tls_server_name: null })
        }
      >
        Add endpoint
      </Button>
    </Stack>
  );
}
export function UpstreamEditor({ index }: { index: number }) {
  const p = `upstreams.${index}` as const;
  const { control } = useFormContext<Document>();
  return (
    <ModalTabs label="Upstream settings" defaultValue="endpoints">
      <ModalSection value="endpoints" label="Endpoints">
        <Controller
          control={control}
          name={`${p}.id`}
          rules={{ required: "Upstream ID is required" }}
          render={({ field, fieldState }) => (
            <TextInput
              {...field}
              data-autofocus
              label="Upstream ID"
              error={fieldState.error?.message}
              required
              withAsterisk={false}
              value={field.value ?? ""}
              onChange={(event) =>
                field.onChange(event.currentTarget.value || "")
              }
            />
          )}
        />
        <Endpoints index={index} />
      </ModalSection>
      <ModalSection value="balancing" label="Balancing & sessions">
        <Optional
          name={`${p}.balancing`}
          title="Customize load balancing"
          initial={{ algorithm: "round_robin", slow_start_ms: 0 }}
        >
          <Section title="Request balancing">
            <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
              <Controller
                control={control}
                name={`${p}.balancing.algorithm`}
                rules={{
                  required: "Balancing algorithm is required",
                }}
                render={({ field, fieldState }) => (
                  <NativeSelect
                    {...field}
                    label="Balancing algorithm"
                    error={fieldState.error?.message}
                    data={[
                      "round_robin",
                      "weighted_round_robin",
                      "least_active_requests",
                    ]}
                    value={field.value ?? ""}
                    onChange={(event) =>
                      field.onChange(event.currentTarget.value || undefined)
                    }
                  />
                )}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 12, sm: 6, lg: 4 }} miw={0}>
              <Controller
                control={control}
                name={`${p}.balancing.slow_start_ms`}
                rules={{
                  required: "Recovery slow start (ms) is required",
                }}
                render={({ field, fieldState }) => (
                  <NumberInput
                    {...field}
                    label="Recovery slow start (ms)"
                    description="Ramps request share after health recovery or maintenance. H2 streams count separately; connections are not requests."
                    error={fieldState.error?.message}
                    maw={rem(416)}
                    min={0}
                    max={300000}
                    allowDecimal={false}
                    allowNegative={false}
                    value={field.value ?? ""}
                    onChange={(value) =>
                      field.onChange(value === "" ? undefined : value)
                    }
                  />
                )}
              />
            </Grid.Col>
          </Section>
        </Optional>
        <Optional
          name={`${p}.affinity`}
          title="Enable sticky sessions"
          initial={{ lifetime_seconds: 3600, fallback: "rebalance" }}
        >
          <Text size="sm">
            Requires gateway HTTPS. Signed host-only cookies expire within one
            day. Drain/down always overrides affinity; this cannot recover
            application session state.
          </Text>
          <Section title="Session affinity">
            <Grid.Col span={{ base: 12, sm: 6, lg: 4 }} miw={0}>
              <Controller
                control={control}
                name={`${p}.affinity.lifetime_seconds`}
                rules={{
                  required: "Affinity cookie lifetime (seconds) is required",
                }}
                render={({ field, fieldState }) => (
                  <NumberInput
                    {...field}
                    label="Affinity cookie lifetime (seconds)"
                    error={fieldState.error?.message}
                    maw={rem(416)}
                    min={1}
                    max={86400}
                    allowDecimal={false}
                    allowNegative={false}
                    value={field.value ?? ""}
                    onChange={(value) =>
                      field.onChange(value === "" ? undefined : value)
                    }
                  />
                )}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
              <Controller
                control={control}
                name={`${p}.affinity.fallback`}
                rules={{
                  required: "Unavailable sticky endpoint is required",
                }}
                render={({ field, fieldState }) => (
                  <NativeSelect
                    {...field}
                    label="Unavailable sticky endpoint"
                    description="Rebalance chooses a healthy endpoint; reject returns 503. Tampered/expired cookies start a new binding."
                    error={fieldState.error?.message}
                    data={["rebalance", "reject"]}
                    value={field.value ?? ""}
                    onChange={(event) =>
                      field.onChange(event.currentTarget.value || undefined)
                    }
                  />
                )}
              />
            </Grid.Col>
          </Section>
        </Optional>
      </ModalSection>
      <ModalSection value="timeouts" label="Timeouts">
        <Section title="Connection timeouts (ms)">
          {(
            [
              "connect",
              "read",
              "write",
              "idle",
              "total",
              "tls",
              "header",
              "response_idle",
            ] as const
          ).map((key) => (
            <Grid.Col key={key} span={{ base: 12, sm: 6, lg: 4 }} miw={0}>
              <Controller
                key={key}
                control={control}
                name={`${p}.timeouts.${key}_ms`}
                render={({ field, fieldState }) => (
                  <NumberInput
                    {...field}
                    label={`${key[0].toUpperCase()}${key.slice(1)} timeout (ms)`}
                    description={TIMEOUT_HELP[`${key}_ms`]}
                    error={fieldState.error?.message}
                    maw={rem(416)}
                    min={1}
                    allowDecimal={false}
                    allowNegative={false}
                    value={field.value ?? ""}
                    onChange={(value) =>
                      field.onChange(value === "" ? undefined : value)
                    }
                  />
                )}
              />
            </Grid.Col>
          ))}
        </Section>
      </ModalSection>
      <ModalSection value="health" label="Health checks">
        <Optional
          name={`${p}.health`}
          title="Customize active health checks"
          initial={{
            path: "/",
            host: null,
            interval_ms: 2000,
            timeout_ms: 3000,
            status_min: 200,
            status_max: 399,
            healthy_threshold: 1,
            unhealthy_threshold: 1,
          }}
        >
          <Section title="HTTP health check">
            <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
              <Controller
                control={control}
                name={`${p}.health.method`}
                render={({ field }) => (
                  <NativeSelect
                    {...field}
                    label="Health HTTP method"
                    description="Use GET for services that do not support HEAD. Only response headers are read."
                    data={["HEAD", "GET"]}
                    value={field.value ?? "HEAD"}
                  />
                )}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
              <Controller
                control={control}
                name={`${p}.health.path`}
                rules={{
                  required: "Health path is required",
                }}
                render={({ field, fieldState }) => (
                  <TextInput
                    {...field}
                    label="Health path"
                    error={fieldState.error?.message}
                    required
                    withAsterisk={false}
                    value={field.value ?? ""}
                    onChange={(event) =>
                      field.onChange(event.currentTarget.value || "")
                    }
                  />
                )}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
              <Controller
                control={control}
                name={`${p}.health.host`}
                render={({ field, fieldState }) => (
                  <TextInput
                    {...field}
                    label="Health Host header"
                    error={fieldState.error?.message}
                    withAsterisk={false}
                    value={field.value ?? ""}
                    onChange={(event) =>
                      field.onChange(event.currentTarget.value || undefined)
                    }
                  />
                )}
              />
            </Grid.Col>
            {(
              [
                [
                  "interval_ms",
                  "Check interval (ms)",
                  250,
                  30000,
                  "Time between active health probes; 250–30,000 ms.",
                ],
                [
                  "timeout_ms",
                  "Check timeout (ms)",
                  100,
                  10000,
                  "Deadline for one health probe; 100–10,000 ms.",
                ],
                [
                  "status_min",
                  "Minimum HTTP status",
                  200,
                  599,
                  "Lowest accepted HTTP status, inclusive.",
                ],
                [
                  "status_max",
                  "Maximum HTTP status",
                  200,
                  599,
                  "Highest accepted HTTP status, inclusive.",
                ],
                [
                  "healthy_threshold",
                  "Recovery threshold",
                  1,
                  10,
                  "Consecutive successful probes required to recover.",
                ],
                [
                  "unhealthy_threshold",
                  "Failure threshold",
                  1,
                  10,
                  "Consecutive failed probes required to become unhealthy.",
                ],
              ] as const
            ).map(([key, label, min, max, description]) => (
              <Grid.Col key={key} span={{ base: 12, sm: 6, lg: 4 }} miw={0}>
                <Controller
                  key={key}
                  control={control}
                  name={`${p}.health.${key}`}
                  rules={{
                    required: `${label} is required`,
                  }}
                  render={({ field, fieldState }) => (
                    <NumberInput
                      {...field}
                      label={label}
                      description={description}
                      error={fieldState.error?.message}
                      maw={rem(416)}
                      min={min}
                      max={max}
                      allowDecimal={false}
                      allowNegative={false}
                      value={field.value ?? ""}
                      onChange={(value) =>
                        field.onChange(value === "" ? undefined : value)
                      }
                    />
                  )}
                />
              </Grid.Col>
            ))}
          </Section>
        </Optional>
      </ModalSection>
    </ModalTabs>
  );
}
