import {
  Button,
  Checkbox,
  Divider,
  Grid,
  NativeSelect,
  NumberInput,
  Stack,
  Text,
  Textarea,
  TextInput,
  rem,
} from "@mantine/core";
import {
  Controller,
  useFieldArray,
  useFormContext,
  useWatch,
} from "react-hook-form";
import { EffectiveTimeouts, ProfilePicker } from "../TrafficProfiles";
import type { Document, RetryPolicy } from "../types";
import { Section, Optional, Remove } from "./shared";
import { ModalTabs, ModalSection } from "../ModalTabs";
import { TIMEOUT_HELP } from "./timeouts";
import { MiddlewareEditor } from "./MiddlewareEditor";
import { PasswordProtectEditor } from "./PasswordProtectEditor";
import { RecordBodyEditor } from "./RecordBodyEditor";
import { MaintenanceEditor } from "./MaintenanceEditor";
import { AccessEditor } from "./AccessEditor";
import { ErrorPagesEditor } from "./ErrorPagesEditor";
function Exclusions({ base }: { base: `routes.${number}.waf` }) {
  const { control } = useFormContext<Document>();
  const list = useFieldArray({ control, name: `${base}.exclusions` });
  return (
    <Stack>
      <Text size="sm" fw={600}>
        Rule exclusions
      </Text>
      {list.fields.map((item, i) => (
        <Grid key={item.id} gutter="md" align="flex-start">
          <Grid.Col span={{ base: 12, sm: 6, lg: 4 }} miw={0}>
            <Controller
              control={control}
              name={`${base}.exclusions.${i}.rule_id`}
              rules={{ required: "Rule ID is required" }}
              render={({ field, fieldState }) => (
                <NumberInput
                  {...field}
                  label="Rule ID"
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
          <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
            <Controller
              control={control}
              name={`${base}.exclusions.${i}.reason`}
              rules={{ required: "Reason is required" }}
              render={({ field, fieldState }) => (
                <TextInput
                  {...field}
                  label="Reason"
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
              name={`${base}.exclusions.${i}.owner`}
              render={({ field, fieldState }) => (
                <TextInput
                  {...field}
                  label="Exclusion owner"
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
          <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
            <Controller
              control={control}
              name={`${base}.exclusions.${i}.target`}
              render={({ field, fieldState }) => (
                <TextInput
                  {...field}
                  label="Excluded target"
                  description="Optional, e.g. ARGS:search. Empty excludes the entire rule on this route."
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
          <Grid.Col span={{ base: 12, sm: 6, lg: 4 }} miw={0}>
            <Controller
              control={control}
              name={`${base}.exclusions.${i}.expires_at_unix_ms`}
              render={({ field, fieldState }) => (
                <NumberInput
                  {...field}
                  label="Expiry (Unix ms)"
                  description="Empty means a deliberate permanent exception."
                  error={fieldState.error?.message}
                  maw={rem(416)}
                  min={0}
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
            <Remove label="Remove exclusion" onClick={() => list.remove(i)} />
          </Grid.Col>
        </Grid>
      ))}
      <Button
        variant="light"
        size="compact-xs"
        onClick={() =>
          list.append({
            rule_id: 0,
            reason: "",
            expires_at_unix_ms: Date.now() + 86400000,
          })
        }
      >
        Add exclusion
      </Button>
    </Stack>
  );
}
function RetryFields({ base }: { base: `routes.${number}` }) {
  const { control, setValue } = useFormContext<Document>();
  const policy = useWatch({ control, name: `${base}.retry` });
  return (
    <Stack>
      <Optional
        name={`${base}.body`}
        title="Customize request body handling"
        initial={{
          max_body_bytes: 65536,
          inspection: "full",
          idle_timeout_ms: 30000,
        }}
      >
        <Section title="Request body">
          <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
            <Controller
              control={control}
              name={`${base}.body.max_body_bytes`}
              rules={{
                required: "Maximum request body (bytes) is required",
              }}
              render={({ field, fieldState }) => (
                <NumberInput
                  {...field}
                  label="Maximum request body (bytes)"
                  description="Total request body limit. Full inspection supports at most 64 KiB; larger bodies need streaming scope."
                  error={fieldState.error?.message}
                  min={1}
                  max={2147483648}
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
              name={`${base}.body.inspection`}
              rules={{
                required: "Body inspection is required",
              }}
              render={({ field, fieldState }) => (
                <NativeSelect
                  {...field}
                  label="Body inspection"
                  error={fieldState.error?.message}
                  data={["full", "headers-query-only"]}
                  value={field.value ?? ""}
                  onChange={(event) =>
                    field.onChange(event.currentTarget.value || undefined)
                  }
                />
              )}
            />
          </Grid.Col>
          <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
            <Controller
              control={control}
              name={`${base}.body.idle_timeout_ms`}
              rules={{
                required: "Client body idle timeout (ms) is required",
              }}
              render={({ field, fieldState }) => (
                <NumberInput
                  {...field}
                  label="Client body idle timeout (ms)"
                  description="Maximum wait between chunks of the client request body."
                  error={fieldState.error?.message}
                  min={1}
                  max={120000}
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
        <Text size="sm">
          All multipart requests stream with body inspection skipped. Headers
          and query protections remain. Full inspection is limited to 64 KiB;
          larger non-multipart streams require headers-query-only.
        </Text>
      </Optional>
      <Divider />
      <Optional
        name={`${base}.retry`}
        title="Customize retry and replay"
        initial={{
          mode: "disabled",
          max_attempts: 1,
          methods: ["GET", "HEAD", "OPTIONS"],
          idempotency_scope: "endpoint",
          retry_on: ["connect_failure", "connect_timeout", "connection_reset"],
          replay: { mode: "none" },
          backoff_base_ms: 100,
          backoff_max_ms: 1000,
        }}
      >
        <Section title="Retry policy">
          <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
            <Controller
              control={control}
              name={`${base}.retry.mode`}
              render={({ field }) => (
                <NativeSelect
                  label="Retry authorization"
                  data={["disabled", "connect-only", "safe", "idempotent"]}
                  value={field.value}
                  onChange={(e) => {
                    const mode = e.currentTarget.value as RetryPolicy["mode"];
                    field.onChange(mode);
                    if (mode === "disabled")
                      setValue(`${base}.retry.max_attempts`, 1, {
                        shouldDirty: true,
                      });
                  }}
                />
              )}
            />
          </Grid.Col>
          {(policy?.mode === "safe" || policy?.mode === "idempotent") && (
            <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
              {policy?.mode === "safe" && (
                <Controller
                  control={control}
                  name={`${base}.retry.methods`}
                  render={({ field, fieldState }) => (
                    <Textarea
                      {...field}
                      label="Safe methods"
                      description="GET, HEAD, OPTIONS by default. PUT/DELETE require an explicit backend safety contract."
                      error={fieldState.error?.message}
                      autosize
                      minRows={2}
                      value={field.value?.join("\n") ?? ""}
                      onChange={(event) =>
                        field.onChange(event.currentTarget.value.split("\n"))
                      }
                    />
                  )}
                />
              )}
              {policy?.mode === "idempotent" && (
                <>
                  <Controller
                    control={control}
                    name={`${base}.retry.idempotency_scope`}
                    rules={{
                      required: "Backend deduplication scope is required",
                    }}
                    render={({ field, fieldState }) => (
                      <NativeSelect
                        {...field}
                        label="Backend deduplication scope"
                        error={fieldState.error?.message}
                        data={["endpoint", "pool"]}
                        value={field.value ?? ""}
                        onChange={(event) =>
                          field.onChange(event.currentTarget.value || undefined)
                        }
                      />
                    )}
                  />
                  <Text size="sm">
                    Backend must enforce Idempotency-Key deduplication. Missing
                    or invalid keys forward once. Pool scope requires shared
                    deduplication across all endpoints.
                  </Text>
                </>
              )}
            </Grid.Col>
          )}
          <Grid.Col span={12} miw={0}>
            <Controller
              control={control}
              name={`${base}.retry.retry_on`}
              render={({ field, fieldState }) => (
                <Textarea
                  {...field}
                  label="Retry transport failures"
                  description="connect_failure, connect_timeout, connection_reset, request_write_timeout, response_header_timeout, per_try_timeout — one per line"
                  error={fieldState.error?.message}
                  autosize
                  minRows={2}
                  value={field.value?.join("\n") ?? ""}
                  onChange={(event) =>
                    field.onChange(event.currentTarget.value.split("\n"))
                  }
                />
              )}
            />
          </Grid.Col>
        </Section>
        <Section title="Retry budgets">
          <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
            <Controller
              control={control}
              name={`${base}.retry.max_attempts`}
              rules={{
                required: "Maximum attempts (includes first) is required",
              }}
              render={({ field, fieldState }) => (
                <NumberInput
                  {...field}
                  label="Maximum attempts (includes first)"
                  description="Includes the original request. 1 means no retry."
                  error={fieldState.error?.message}
                  disabled={policy?.mode === "disabled"}
                  min={1}
                  max={5}
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
              name={`${base}.retry.per_try_timeout_ms`}
              render={({ field, fieldState }) => (
                <NumberInput
                  {...field}
                  label="Per-attempt timeout through final headers (ms)"
                  description="Deadline per attempt until final response headers. Blank inherits the route deadline."
                  error={fieldState.error?.message}
                  min={1}
                  max={86400000}
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
              name={`${base}.retry.total_timeout_ms`}
              render={({ field, fieldState }) => (
                <NumberInput
                  {...field}
                  label="Total request deadline (ms)"
                  description="Deadline across all attempts. Blank inherits the route/upstream total timeout."
                  error={fieldState.error?.message}
                  min={1}
                  max={86400000}
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
        <Section title="Retry backoff">
          <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
            <Controller
              control={control}
              name={`${base}.retry.backoff_base_ms`}
              rules={{
                required: "Jitter base (ms) is required",
              }}
              render={({ field, fieldState }) => (
                <NumberInput
                  {...field}
                  label="Jitter base (ms)"
                  description="Base delay for jittered retry backoff. 0 starts retries without delay."
                  error={fieldState.error?.message}
                  min={0}
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
              name={`${base}.retry.backoff_max_ms`}
              rules={{
                required: "Jitter cap (ms) is required",
              }}
              render={({ field, fieldState }) => (
                <NumberInput
                  {...field}
                  label="Jitter cap (ms)"
                  description="Upper bound for retry backoff; must be at least the base delay."
                  error={fieldState.error?.message}
                  min={0}
                  max={30000}
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
        <Section title="Body replay">
          <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
            <Controller
              control={control}
              name={`${base}.retry.replay.mode`}
              render={({ field }) => (
                <NativeSelect
                  label="Body replay storage"
                  data={["none", "memory", "disk"]}
                  value={field.value}
                  onChange={(e) => {
                    const mode = e.currentTarget
                      .value as RetryPolicy["replay"]["mode"];
                    field.onChange(mode);
                    setValue(
                      `${base}.retry.replay.max_body_size_bytes`,
                      mode === "none"
                        ? undefined
                        : mode === "memory"
                          ? 65536
                          : 536870912,
                      { shouldDirty: true },
                    );
                  }}
                />
              )}
            />
          </Grid.Col>
          {policy?.replay.mode !== "none" && (
            <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
              <Controller
                control={control}
                name={`${base}.retry.replay.max_body_size_bytes`}
                rules={{
                  required: "Replay capture cap (bytes) is required",
                }}
                render={({ field, fieldState }) => (
                  <NumberInput
                    {...field}
                    label="Replay capture cap (bytes)"
                    error={fieldState.error?.message}
                    min={1}
                    max={
                      policy?.replay.mode === "memory" ? 1048576 : 2147483648
                    }
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
          )}
        </Section>
        <Text size="sm">
          Replay storage never authorizes a retry. Upload/streaming routes
          should use connect-only and replay none. Disk capture tees the
          original stream; incomplete or over-cap captures forward once without
          replay. HTTP status responses never trigger retries.
        </Text>
      </Optional>
    </Stack>
  );
}
export function RouteEditor({ index }: { index: number }) {
  const p = `routes.${index}` as const;
  const { control } = useFormContext<Document>();
  const upstreams = useWatch({ control, name: "upstreams" });
  const application = useWatch({ control, name: `${p}.application` });
  return (
    <ModalTabs label="Route settings" defaultValue="routing">
      <ModalSection value="routing" label="Routing">
        {application ? (
          <Text size="sm">
            Managed application {application.application_id.slice(0, 12)} ·
            release {application.release_id.slice(0, 12)}. Change domain and
            release in Applications; protection settings remain editable below.
          </Text>
        ) : (
          <Stack gap="md">
            <Section title="Route matching" hideLegend>
              <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
                <Controller
                  control={control}
                  name={`${p}.id`}
                  rules={{ required: "Route ID is required" }}
                  render={({ field, fieldState }) => (
                    <TextInput
                      {...field}
                      label="Route ID"
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
                  name={`${p}.hostname`}
                  rules={{ required: "Hostname is required" }}
                  render={({ field, fieldState }) => (
                    <TextInput
                      {...field}
                      data-autofocus
                      label="Hostname"
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
                  name={`${p}.path`}
                  rules={{ required: "Path is required" }}
                  render={({ field, fieldState }) => (
                    <TextInput
                      {...field}
                      label="Path"
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
                  name={`${p}.path_match`}
                  rules={{
                    required: "Path matching is required",
                  }}
                  render={({ field, fieldState }) => (
                    <NativeSelect
                      {...field}
                      label="Path matching"
                      error={fieldState.error?.message}
                      data={["prefix", "exact"]}
                      value={field.value ?? ""}
                      onChange={(event) =>
                        field.onChange(event.currentTarget.value || undefined)
                      }
                    />
                  )}
                />
              </Grid.Col>
              <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
                <Controller
                  control={control}
                  name={`${p}.methods`}
                  render={({ field, fieldState }) => (
                    <Textarea
                      {...field}
                      label="HTTP methods"
                      description="One per line. Leave empty for all methods."
                      error={fieldState.error?.message}
                      autosize
                      minRows={2}
                      value={field.value?.join("\n") ?? ""}
                      onChange={(event) =>
                        field.onChange(event.currentTarget.value.split("\n"))
                      }
                    />
                  )}
                />
              </Grid.Col>
              <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
                <Controller
                  control={control}
                  name={`${p}.upstream`}
                  render={({ field, fieldState }) => (
                    <NativeSelect
                      {...field}
                      label="Upstream pool"
                      error={fieldState.error?.message}
                      data={["", ...upstreams.map((u) => u.id).filter(Boolean)]}
                      value={field.value ?? ""}
                      onChange={(event) =>
                        field.onChange(event.currentTarget.value || undefined)
                      }
                    />
                  )}
                />
              </Grid.Col>
            </Section>
            <Optional
              name={`${p}.redirect`}
              title="Redirect requests"
              initial={{ url: "https://", status: 302, http_only: false }}
            >
              <Section title="Redirect">
                <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
                  <Controller
                    control={control}
                    name={`${p}.redirect.url`}
                    rules={{
                      required: "Destination URL is required",
                    }}
                    render={({ field, fieldState }) => (
                      <TextInput
                        {...field}
                        label="Destination URL"
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
                    name={`${p}.redirect.status`}
                    control={control}
                    render={({ field }) => (
                      <NativeSelect
                        label="Redirect status"
                        data={["301", "302", "303", "307", "308"]}
                        value={field.value}
                        onChange={(e) =>
                          field.onChange(Number(e.currentTarget.value))
                        }
                      />
                    )}
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
                  <Controller
                    control={control}
                    name={`${p}.redirect.http_only`}
                    render={({ field, fieldState }) => (
                      <Checkbox
                        name={field.name}
                        ref={field.ref}
                        onBlur={field.onBlur}
                        label="Only redirect HTTP (use upstream for HTTPS)"
                        error={fieldState.error?.message}
                        checked={field.value === true}
                        onChange={(event) =>
                          field.onChange(event.currentTarget.checked)
                        }
                      />
                    )}
                  />
                </Grid.Col>
                {(["preserve_path", "preserve_query"] as const).map((key) => (
                  <Grid.Col span={{ base: 12, sm: 6 }} key={key}>
                    <Controller
                      control={control}
                      name={`${p}.redirect.${key}`}
                      render={({ field }) => (
                        <Checkbox
                          name={field.name}
                          ref={field.ref}
                          onBlur={field.onBlur}
                          label={
                            key === "preserve_path"
                              ? "Preserve request path"
                              : "Preserve query parameters"
                          }
                          description={
                            key === "preserve_path"
                              ? "Destination URL must have a root path."
                              : "Destination URL must not contain a query."
                          }
                          checked={field.value === true}
                          onChange={(e) =>
                            field.onChange(e.currentTarget.checked)
                          }
                        />
                      )}
                    />
                  </Grid.Col>
                ))}
              </Section>
            </Optional>
          </Stack>
        )}
        <MaintenanceEditor index={index} />
      </ModalSection>
      <ModalSection value="middleware" label="Middleware">
        <MiddlewareEditor index={index} />
      </ModalSection>
      <ModalSection value="access" label="Access & auth">
        <AccessEditor base={`${p}.access`} />
        <PasswordProtectEditor index={index} />
      </ModalSection>
      <ModalSection value="waf" label="WAF">
        <Optional
          name={`${p}.waf`}
          title="Customize WAF policy"
          initial={{
            mode: "DetectionOnly",
            paranoia_level: 1,
            body_limit_bytes: 65536,
            inspection_timeout_ms: 2000,
            exclusions: [],
          }}
        >
          <Text size="xs" c="dimmed">
            Without an override, the gateway WAF policy applies. ACL allow
            entries still pass through WAF inspection.
          </Text>
          <Section title="WAF inspection">
            <Grid.Col span={12}>
              <Controller
                control={control}
                name={`${p}.waf.mode`}
                rules={{ required: "WAF mode is required" }}
                render={({ field, fieldState }) => (
                  <NativeSelect
                    {...field}
                    label="WAF mode"
                    error={fieldState.error?.message}
                    data={["DetectionOnly", "On", "Off"]}
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
                name={`${p}.waf.paranoia_level`}
                rules={{
                  required: "Paranoia level is required",
                }}
                render={({ field, fieldState }) => (
                  <NumberInput
                    {...field}
                    label="Paranoia level"
                    description="1–4. Start at 1; higher levels may increase false positives."
                    error={fieldState.error?.message}
                    maw={rem(416)}
                    min={1}
                    max={4}
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
            <Grid.Col span={{ base: 12, sm: 6, lg: 4 }} miw={0}>
              <Controller
                control={control}
                name={`${p}.waf.body_limit_bytes`}
                rules={{
                  required: "Body limit (bytes) is required",
                }}
                render={({ field, fieldState }) => (
                  <NumberInput
                    {...field}
                    label="Body limit (bytes)"
                    description="Maximum body buffered for full WAF inspection; up to 65,536 bytes (64 KiB)."
                    error={fieldState.error?.message}
                    maw={rem(416)}
                    min={1}
                    max={65536}
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
            <Grid.Col span={{ base: 12, sm: 6, lg: 4 }} miw={0}>
              <Controller
                control={control}
                name={`${p}.waf.inspection_timeout_ms`}
                rules={{
                  required: "Inspection deadline (ms) is required",
                }}
                render={({ field, fieldState }) => (
                  <NumberInput
                    {...field}
                    label="Inspection deadline (ms)"
                    description="Maximum inspection time. Blocking mode returns 503 if inspection cannot finish."
                    error={fieldState.error?.message}
                    maw={rem(416)}
                    min={1}
                    max={2000}
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
          <Exclusions base={`${p}.waf`} />
        </Optional>
      </ModalSection>
      <ModalSection value="responses" label="Responses">
        <Section title="Response security headers">
          <Grid.Col span={{ base: 12, sm: 6, lg: 4 }} miw={0}>
            <Controller
              control={control}
              name={`${p}.security_headers.hsts_max_age`}
              render={({ field, fieldState }) => (
                <NumberInput
                  {...field}
                  label="HSTS max age (seconds)"
                  description="How long browsers require HTTPS. 0 clears HSTS; blank omits the header."
                  error={fieldState.error?.message}
                  maw={rem(416)}
                  min={0}
                  max={63072000}
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
              name={`${p}.security_headers.content_security_policy`}
              render={({ field, fieldState }) => (
                <TextInput
                  {...field}
                  label="Content Security Policy"
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
          <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
            <Controller
              control={control}
              name={`${p}.security_headers.referrer_policy`}
              render={({ field, fieldState }) => (
                <NativeSelect
                  {...field}
                  label="Referrer policy"
                  error={fieldState.error?.message}
                  data={[
                    "",
                    ...[
                      "no-referrer",
                      "same-origin",
                      "strict-origin",
                      "strict-origin-when-cross-origin",
                    ],
                  ]}
                  value={field.value ?? ""}
                  onChange={(event) =>
                    field.onChange(event.currentTarget.value || undefined)
                  }
                />
              )}
            />
          </Grid.Col>
          <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
            <Controller
              control={control}
              name={`${p}.security_headers.frame_options`}
              render={({ field, fieldState }) => (
                <NativeSelect
                  {...field}
                  label="Frame options"
                  error={fieldState.error?.message}
                  data={["", ...["DENY", "SAMEORIGIN"]]}
                  value={field.value ?? ""}
                  onChange={(event) =>
                    field.onChange(event.currentTarget.value || undefined)
                  }
                />
              )}
            />
          </Grid.Col>
          <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
            <Controller
              control={control}
              name={`${p}.security_headers.hsts_include_subdomains`}
              render={({ field, fieldState }) => (
                <Checkbox
                  name={field.name}
                  ref={field.ref}
                  onBlur={field.onBlur}
                  label="HSTS include subdomains"
                  error={fieldState.error?.message}
                  checked={field.value === true}
                  onChange={(event) =>
                    field.onChange(event.currentTarget.checked)
                  }
                />
              )}
            />
          </Grid.Col>
          <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
            <Controller
              control={control}
              name={`${p}.security_headers.nosniff`}
              render={({ field, fieldState }) => (
                <Checkbox
                  name={field.name}
                  ref={field.ref}
                  onBlur={field.onBlur}
                  label="Prevent content type sniffing"
                  error={fieldState.error?.message}
                  checked={field.value === true}
                  onChange={(event) =>
                    field.onChange(event.currentTarget.checked)
                  }
                />
              )}
            />
          </Grid.Col>
        </Section>
        <ErrorPagesEditor name={`${p}.error_pages`} />
      </ModalSection>
      <ModalSection value="traffic" label="Traffic & capacity">
        {!application && <ProfilePicker index={index} />}
        <Optional
          name={`${p}.profile`}
          title="Profile metadata"
          initial={{ kind: "api_crud", version: 1 }}
        >
          <Grid gutter="md" align="flex-start">
            <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
              <Controller
                control={control}
                name={`${p}.profile.kind`}
                rules={{
                  required: "Profile kind is required",
                }}
                render={({ field, fieldState }) => (
                  <NativeSelect
                    {...field}
                    label="Profile kind"
                    error={fieldState.error?.message}
                    data={[
                      "api_crud",
                      "upload",
                      "sse",
                      "websocket",
                      "media",
                      "payment_webhook",
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
                name={`${p}.profile.version`}
                rules={{
                  required: "Template version (metadata only) is required",
                }}
                render={({ field, fieldState }) => (
                  <NumberInput
                    {...field}
                    label="Template version (metadata only)"
                    error={fieldState.error?.message}
                    maw={rem(416)}
                    min={1}
                    max={65535}
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
          </Grid>
        </Optional>
        <Controller
          control={control}
          name={`${p}.admission_class`}
          render={({ field, fieldState }) => (
            <NativeSelect
              {...field}
              label="Admission class"
              description="Selects a separate node capacity partition; classes do not borrow slots."
              error={fieldState.error?.message}
              data={["", ...["api", "upload", "stream", "critical"]]}
              value={field.value ?? ""}
              onChange={(event) =>
                field.onChange(event.currentTarget.value || undefined)
              }
            />
          )}
        />
        <Optional
          name={`${p}.admission`}
          title="Customize admission quotas"
          initial={{ requests: 64, streams: 8, uploads: 4, per_client: 32 }}
        >
          <Text size="sm">
            Immediate admission with no waiting queue. The critical class has a
            separate node capacity partition. A client behind NAT shares its
            per-client quota. Defaults: 64 concurrent requests per route, 32 per
            client. Node and class budgets still apply.
          </Text>
          <Section title="Route concurrency limits">
            <Grid.Col span={{ base: 12, sm: 6, lg: 4 }} miw={0}>
              <Controller
                control={control}
                name={`${p}.admission.requests`}
                render={({ field, fieldState }) => (
                  <NumberInput
                    {...field}
                    label="Concurrent requests"
                    description="Maximum simultaneous requests admitted on this route."
                    error={fieldState.error?.message}
                    maw={rem(416)}
                    min={1}
                    max={128}
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
            <Grid.Col span={{ base: 12, sm: 6, lg: 4 }} miw={0}>
              <Controller
                control={control}
                name={`${p}.admission.streams`}
                render={({ field, fieldState }) => (
                  <NumberInput
                    {...field}
                    label="Concurrent long-lived streams"
                    description="Maximum simultaneous long-lived streams. 0 disables stream admission."
                    error={fieldState.error?.message}
                    maw={rem(416)}
                    min={0}
                    max={128}
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
            <Grid.Col span={{ base: 12, sm: 6, lg: 4 }} miw={0}>
              <Controller
                control={control}
                name={`${p}.admission.uploads`}
                render={({ field, fieldState }) => (
                  <NumberInput
                    {...field}
                    label="Concurrent uploads"
                    description="Maximum simultaneous uploads. 0 disables upload admission."
                    error={fieldState.error?.message}
                    maw={rem(416)}
                    min={0}
                    max={128}
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
            <Grid.Col span={{ base: 12, sm: 6, lg: 4 }} miw={0}>
              <Controller
                control={control}
                name={`${p}.admission.per_client`}
                render={({ field, fieldState }) => (
                  <NumberInput
                    {...field}
                    label="Concurrent requests per client IP"
                    description="Shared by requests from the same client IP, including clients behind NAT."
                    error={fieldState.error?.message}
                    maw={rem(416)}
                    min={1}
                    max={128}
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
          name={`${p}.content`}
          title="Strict content contract"
          initial={{
            media_types: ["application/json"],
            require_type_for_body: true,
          }}
        >
          <Controller
            control={control}
            name={`${p}.content.media_types`}
            render={({ field, fieldState }) => (
              <Textarea
                {...field}
                label="Allowed request media types"
                description="Exact lower-case types, one per line. Empty rejects any Content-Type. Parameters are parsed. Compressed request bodies are rejected; identity only."
                error={fieldState.error?.message}
                autosize
                minRows={2}
                value={field.value?.join("\n") ?? ""}
                onChange={(event) =>
                  field.onChange(event.currentTarget.value.split("\n"))
                }
              />
            )}
          />
          <Controller
            control={control}
            name={`${p}.content.require_type_for_body`}
            render={({ field, fieldState }) => (
              <Checkbox
                name={field.name}
                ref={field.ref}
                onBlur={field.onBlur}
                label="Require Content-Type for a nonempty or chunked body"
                error={fieldState.error?.message}
                checked={field.value === true}
                onChange={(event) =>
                  field.onChange(event.currentTarget.checked)
                }
              />
            )}
          />
        </Optional>
      </ModalSection>
      <ModalSection value="timeouts" label="Timeouts">
        <EffectiveTimeouts index={index} />
        <Divider />
        <Optional
          name={`${p}.timeouts`}
          title="Route timeout override"
          initial={{
            total_ms: 30000,
            connect_ms: 3000,
            read_ms: 10000,
            write_ms: 10000,
            idle_ms: 30000,
          }}
        >
          {(
            [
              {
                title: "Connection setup",
                fields: [
                  ["connect_ms", "TCP connection"],
                  ["tls_ms", "TLS handshake"],
                ],
              },
              {
                title: "Upstream response",
                fields: [
                  ["read_ms", "Read timeout"],
                  ["header_ms", "Final response headers"],
                  ["response_idle_ms", "Response idle"],
                  ["write_ms", "Upstream write idle"],
                ],
              },
              {
                title: "Request lifecycle",
                fields: [
                  ["total_ms", "Absolute request deadline"],
                  ["idle_ms", "Connection keep-alive idle"],
                ],
              },
            ] as const
          ).map(({ title, fields }) => (
            <Section key={title} title={`${title} (ms)`}>
              {fields.map(([timeout, label]) => (
                <Grid.Col key={timeout} span={{ base: 12, sm: 6 }} miw={0}>
                  <Controller
                    control={control}
                    name={`${p}.timeouts.${timeout}`}
                    rules={{
                      required: !(
                        ["tls_ms", "header_ms", "response_idle_ms"] as string[]
                      ).includes(timeout)
                        ? `Route ${timeout} (ms) is required`
                        : false,
                    }}
                    render={({ field, fieldState }) => (
                      <NumberInput
                        {...field}
                        label={`${label} (ms)`}
                        description={TIMEOUT_HELP[timeout]}
                        error={fieldState.error?.message}
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
          ))}
        </Optional>
      </ModalSection>
      <ModalSection value="retries" label="Body & retries">
        <RecordBodyEditor base={p} />
        <RetryFields base={p} />
      </ModalSection>
    </ModalTabs>
  );
}
