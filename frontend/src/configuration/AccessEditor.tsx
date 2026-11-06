import {
  Alert,
  Grid,
  NativeSelect,
  NumberInput,
  Stack,
  Text,
  Textarea,
  rem,
} from "@mantine/core";
import { Controller, useFormContext, useWatch } from "react-hook-form";
import type { Document } from "../types";
import { Section, Optional } from "./shared";

export function AccessEditor({
  base,
}: {
  base: "global_rules" | `routes.${number}.access`;
}) {
  const { control } = useFormContext<Document>();
  const globalChallenge = useWatch({ control, name: "global_rules.challenge" });
  return (
    <Stack>
      {base !== "global_rules" && globalChallenge && (
        <Alert color="blue">
          Global browser challenge is enabled for this route. The route option
          adds a separate requirement; turning it off does not disable global
          challenge.
        </Alert>
      )}
      <Optional
        name={`${base}.challenge`}
        title="Browser challenge (JavaScript proof-of-work)"
        initial={{ difficulty: 12, clearance_seconds: 900 }}
        // Preserve an explicit disabled policy through save/reopen.
        disabledValue={null}
      >
        <Text size="sm" c="dimmed">
          Requires HTTPS at the gateway, JavaScript and cookies. Browsers
          without clearance must solve a proof-of-work before accessing
          {base === "global_rules" ? " any route." : " this route."}
          {base !== "global_rules" &&
            " Global challenge still applies independently."}{" "}
          Does not verify human identity. APIs, uploads and WebSocket clients
          need prior browser clearance; POST requests are never replayed. Open a
          GET URL on the route first. Configuration apply or restart requires
          verification again.
        </Text>
        <Section title="Browser verification">
          <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
            <Controller
              control={control}
              name={`${base}.challenge.difficulty`}
              rules={{
                required: "Proof difficulty is required",
                min: { value: 8, message: "Minimum is 8" },
                max: { value: 20, message: "Maximum is 20" },
              }}
              render={({ field, fieldState }) => (
                <NumberInput
                  {...field}
                  label="Proof difficulty (bits)"
                  description="8–20 zero bits. Each extra bit doubles average browser work."
                  error={fieldState.error?.message}
                  min={8}
                  max={20}
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
              name={`${base}.challenge.clearance_seconds`}
              rules={{
                required: "Challenge clearance lifetime is required",
                min: { value: 60, message: "Minimum is 60" },
                max: { value: 86400, message: "Maximum is 86,400" },
              }}
              render={({ field, fieldState }) => (
                <NumberInput
                  {...field}
                  label="Challenge clearance lifetime (seconds)"
                  description="60–86,400 seconds. Bound to this hostname, client IP and configuration version."
                  error={fieldState.error?.message}
                  min={60}
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
        </Section>
      </Optional>
      <Optional
        name={`${base}.ddos`}
        title="DDoS protection (HTTP flood)"
        initial={{ per_second: 1000, burst: 2000 }}
      >
        <Text size="sm" c="dimmed">
          Shared by all client IPs{" "}
          {base === "global_rules" ? "across all routes" : "on this route"}.
          Requests exceeding the budget receive 429 before WAF or upstream work.
          Per-IP limits continue to apply. This protects HTTP capacity; network
          flood protection requires your network provider or CDN.
        </Text>
        <Section title="HTTP flood budget">
          {(["per_second", "burst"] as const).map((key) => (
            <Grid.Col key={key} span={{ base: 12, sm: 6 }} miw={0}>
              <Controller
                control={control}
                name={`${base}.ddos.${key}`}
                rules={{
                  required: "HTTP flood budget is required",
                  min: { value: 1, message: "Minimum is 1" },
                  max: { value: 10000, message: "Maximum is 10,000" },
                }}
                render={({ field, fieldState }) => (
                  <NumberInput
                    {...field}
                    label={
                      key === "per_second"
                        ? "Total requests per second"
                        : "Total burst capacity"
                    }
                    description={
                      key === "per_second"
                        ? "Token refill rate shared by all clients."
                        : "Maximum tokens available for a short burst."
                    }
                    error={fieldState.error?.message}
                    min={1}
                    max={10000}
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
      <Section title="IP access lists">
        <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
          <Controller
            control={control}
            name={`${base}.allow`}
            render={({ field, fieldState }) => (
              <Textarea
                {...field}
                label="Allowed CIDRs"
                description="One IP network per line."
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
            name={`${base}.deny`}
            render={({ field, fieldState }) => (
              <Textarea
                {...field}
                label="Denied CIDRs"
                description="Deny takes precedence over allow."
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
      <Optional
        name={`${base}.geo`}
        title="Country filtering"
        initial={{ allow: [], deny: [], unknown: "deny" }}
      >
        <Section title="GeoIP">
          <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
            <Controller
              control={control}
              name={`${base}.geo.allow`}
              render={({ field, fieldState }) => (
                <Textarea
                  {...field}
                  label="Allowed country codes"
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
              name={`${base}.geo.deny`}
              render={({ field, fieldState }) => (
                <Textarea
                  {...field}
                  label="Denied country codes"
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
              name={`${base}.geo.unknown`}
              rules={{
                required: "Unknown country is required",
              }}
              render={({ field, fieldState }) => (
                <NativeSelect
                  {...field}
                  label="Unknown country"
                  error={fieldState.error?.message}
                  data={["deny", "allow"]}
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
      <Optional
        name={`${base}.rate_limit`}
        title="Rate limiting"
        initial={{ per_second: 100, burst: 200 }}
      >
        <Section title="Rate limit">
          <Grid.Col span={{ base: 12, sm: 6, lg: 4 }} miw={0}>
            <Controller
              control={control}
              name={`${base}.rate_limit.per_second`}
              rules={{
                required: "Requests per second is required",
              }}
              render={({ field, fieldState }) => (
                <NumberInput
                  {...field}
                  label="Requests per second"
                  description="Token refill rate per client IP within this policy scope."
                  error={fieldState.error?.message}
                  maw={rem(416)}
                  min={1}
                  max={10000}
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
              name={`${base}.rate_limit.burst`}
              rules={{
                required: "Burst capacity is required",
              }}
              render={({ field, fieldState }) => (
                <NumberInput
                  {...field}
                  label="Burst capacity"
                  description="Maximum token capacity for short request bursts."
                  error={fieldState.error?.message}
                  maw={rem(416)}
                  min={1}
                  max={10000}
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
    </Stack>
  );
}
