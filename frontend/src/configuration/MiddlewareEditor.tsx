import {
  Button,
  Checkbox,
  Grid,
  NativeSelect,
  NumberInput,
  Stack,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import {
  Controller,
  useFieldArray,
  useFormContext,
  useWatch,
  type FieldPath,
} from "react-hook-form";
import type { Document } from "../types";
import { AntiAbuseEditor } from "./AntiAbuseEditor";
import { Optional, Remove, Section } from "./shared";

function StringField({
  name,
  label,
  description,
  list = false,
  optional = false,
}: {
  name: FieldPath<Document>;
  label: string;
  description?: string;
  list?: boolean;
  optional?: boolean;
}) {
  const { control } = useFormContext<Document>();
  return (
    <Grid.Col span={{ base: 12, sm: 6 }} miw={0}>
      <Controller
        control={control}
        name={name}
        render={({ field, fieldState }) =>
          list ? (
            <Textarea
              name={field.name}
              ref={field.ref}
              onBlur={field.onBlur}
              label={label}
              description={description ?? "One per line."}
              error={fieldState.error?.message}
              minRows={2}
              autosize
              value={Array.isArray(field.value) ? field.value.join("\n") : ""}
              onChange={(e) =>
                field.onChange(e.currentTarget.value.split("\n"))
              }
            />
          ) : (
            <TextInput
              name={field.name}
              ref={field.ref}
              onBlur={field.onBlur}
              label={label}
              description={description}
              error={fieldState.error?.message}
              value={typeof field.value === "string" ? field.value : ""}
              onChange={(e) =>
                field.onChange(
                  e.currentTarget.value || (optional ? undefined : ""),
                )
              }
            />
          )
        }
      />
    </Grid.Col>
  );
}
function CheckField({
  name,
  label,
}: {
  name: FieldPath<Document>;
  label: string;
}) {
  const { control } = useFormContext<Document>();
  return (
    <Grid.Col span={{ base: 12, sm: 6 }}>
      <Controller
        control={control}
        name={name}
        render={({ field }) => (
          <Checkbox
            name={field.name}
            ref={field.ref}
            onBlur={field.onBlur}
            label={label}
            checked={field.value === true}
            onChange={(e) => field.onChange(e.currentTarget.checked)}
          />
        )}
      />
    </Grid.Col>
  );
}
function NumberField({
  name,
  label,
  min,
  max,
}: {
  name: FieldPath<Document>;
  label: string;
  min: number;
  max: number;
}) {
  const { control } = useFormContext<Document>();
  return (
    <Grid.Col span={{ base: 12, sm: 6 }}>
      <Controller
        control={control}
        name={name}
        render={({ field, fieldState }) => (
          <NumberInput
            name={field.name}
            ref={field.ref}
            onBlur={field.onBlur}
            label={label}
            error={fieldState.error?.message}
            value={typeof field.value === "number" ? field.value : ""}
            min={min}
            max={max}
            allowNegative={false}
            allowDecimal={false}
            onChange={field.onChange}
          />
        )}
      />
    </Grid.Col>
  );
}
function HeaderEditor({
  base,
  direction,
}: {
  base:
    | `routes.${number}.middleware.request_headers`
    | `routes.${number}.middleware.response_headers`;
  direction: string;
}) {
  const { control } = useFormContext<Document>();
  const rows = useFieldArray({ control, name: `${base}.set` });
  return (
    <Stack gap="sm">
      <Section title={`${direction} headers`}>
        <Grid.Col span={12}>
          <Text size="xs" c="dimmed">
            Set replaces existing values. Reserved transport, identity and
            credential headers cannot be changed here. Keep secrets outside
            route configuration.
          </Text>
        </Grid.Col>
        {rows.fields.map((row, i) => (
          <Grid.Col span={12} key={row.id}>
            <Grid align="flex-start">
              <StringField
                name={`${base}.set.${i}.name`}
                label={`${direction} header name ${i + 1}`}
              />
              <StringField
                name={`${base}.set.${i}.value`}
                label={`${direction} header value ${i + 1}`}
              />
              <Grid.Col span={12}>
                <Remove
                  label={`Remove ${direction.toLowerCase()} header ${i + 1}`}
                  onClick={() => rows.remove(i)}
                />
              </Grid.Col>
            </Grid>
          </Grid.Col>
        ))}
        <Grid.Col span={12}>
          <Button
            type="button"
            variant="light"
            size="xs"
            disabled={rows.fields.length >= 32}
            onClick={() => rows.append({ name: "", value: "" })}
          >
            Add {direction.toLowerCase()} header
          </Button>
        </Grid.Col>
        <StringField
          name={`${base}.remove`}
          label={`${direction} headers to remove`}
          list
        />
      </Section>
    </Stack>
  );
}
export function MiddlewareEditor({ index }: { index: number }) {
  const { control } = useFormContext<Document>();
  const p = `routes.${index}.middleware` as const;
  const upstreams = useWatch({ control, name: "upstreams" }) ?? [];
  return (
    <Stack gap="md">
      <Optional
        name={p}
        title="Configure route middleware"
        initial={{
          request_headers: { set: [], remove: [] },
          response_headers: { set: [], remove: [] },
        }}
      >
        <Optional
          name={`${p}.rewrite`}
          title="Rewrite upstream path"
          initial={{}}
        >
          <Section title="Path rewrite">
            <Grid.Col span={12}>
              <Text size="xs" c="dimmed">
                Routing, WAF and authentication use the original URL. Strip then
                add a prefix, or replace the entire path. Query parameters are
                preserved.
              </Text>
            </Grid.Col>
            <StringField
              name={`${p}.rewrite.strip_prefix`}
              optional
              label="Strip path prefix"
              description="Matches a complete path segment, e.g. /grafana."
            />
            <StringField
              name={`${p}.rewrite.add_prefix`}
              optional
              label="Add path prefix"
              description="Applied after stripping, e.g. /internal."
            />
            <StringField
              name={`${p}.rewrite.replace_path`}
              optional
              label="Replace path"
              description="Use instead of strip/add, e.g. /index.html."
            />
          </Section>
        </Optional>
        <HeaderEditor base={`${p}.request_headers`} direction="Request" />
        <HeaderEditor base={`${p}.response_headers`} direction="Response" />
        <Optional
          name={`${p}.cors`}
          title="Configure CORS"
          initial={{
            origins: [],
            methods: ["GET", "HEAD", "POST"],
            allowed_headers: [],
            exposed_headers: [],
            credentials: false,
            max_age_seconds: 600,
          }}
        >
          <Section title="Cross-origin access">
            <Grid.Col span={12}>
              <Text size="xs" c="dimmed">
                Allowed preflight requests receive 204 after security checks,
                without contacting the application or authentication service.
                Actual requests still require authentication.
              </Text>
            </Grid.Col>
            <StringField
              name={`${p}.cors.origins`}
              label="Allowed origins"
              description="Exact origins such as https://app.example.org, without a trailing slash. * requires credentials disabled."
              list
            />
            <StringField
              name={`${p}.cors.methods`}
              label="CORS allowed methods"
              list
            />
            <StringField
              name={`${p}.cors.allowed_headers`}
              label="CORS allowed request headers"
              list
            />
            <StringField
              name={`${p}.cors.exposed_headers`}
              label="CORS exposed response headers"
              list
            />
            <CheckField
              name={`${p}.cors.credentials`}
              label="Allow browser credentials"
            />
            <NumberField
              name={`${p}.cors.max_age_seconds`}
              label="Preflight cache age (seconds)"
              min={0}
              max={86400}
            />
          </Section>
        </Optional>
        <Optional
          name={`${p}.forward_auth`}
          title="Require ForwardAuth"
          initial={{
            upstream: "",
            path: "/",
            timeout_ms: 2000,
            request_headers: ["cookie", "authorization"],
            response_headers: [
              "remote-user",
              "remote-groups",
              "remote-email",
              "remote-name",
            ],
            response_cookies: [],
            redirect_origins: [],
          }}
        >
          <Section title="Application authentication">
            <Grid.Col span={12}>
              <Text size="xs" c="dimmed">
                Use a trusted authentication service with a healthy endpoint.
                Errors and timeouts deny access. Only the selected identity
                headers and cookies are accepted from it.
              </Text>
            </Grid.Col>
            <Grid.Col span={{ base: 12, sm: 6 }}>
              <Controller
                control={control}
                name={`${p}.forward_auth.upstream`}
                rules={{ required: "Select an authentication upstream" }}
                render={({ field, fieldState }) => (
                  <NativeSelect
                    {...field}
                    value={field.value ?? ""}
                    label="Authentication upstream"
                    error={fieldState.error?.message}
                    data={[
                      { value: "", label: "Select upstream" },
                      ...upstreams
                        .filter((u) => u.id)
                        .map((u) => ({ value: u.id, label: u.id })),
                    ]}
                  />
                )}
              />
            </Grid.Col>
            <StringField
              name={`${p}.forward_auth.path`}
              label="Authentication check path"
              description="GET endpoint, e.g. /api/authz/forward-auth. Original method and URL are sent in forwarded headers."
            />
            <NumberField
              name={`${p}.forward_auth.timeout_ms`}
              label="Authentication timeout (ms)"
              min={100}
              max={5000}
            />
            <StringField
              name={`${p}.forward_auth.request_headers`}
              label="Headers sent to authentication service"
              list
            />
            <StringField
              name={`${p}.forward_auth.response_headers`}
              label="Verified identity headers"
              description="Client values are removed. Only the authentication service may populate these headers."
              list
            />
            <StringField
              name={`${p}.forward_auth.identity_headers`}
              label="Headers approved for principal quotas"
              description="Explicit subset of verified response headers. Only successful ForwardAuth responses can provide quota identity."
              list
            />
            <StringField
              name={`${p}.forward_auth.response_cookies`}
              label="Authentication cookie names to accept"
              list
            />
            <StringField
              name={`${p}.forward_auth.redirect_origins`}
              label="Allowed login redirect origins"
              description="Exact origins, e.g. https://auth.example.org. Relative redirects are also allowed."
              list
            />
          </Section>
        </Optional>
        <AntiAbuseEditor index={index} />
      </Optional>
    </Stack>
  );
}
