import {
  Alert,
  Button,
  Checkbox,
  Grid,
  JsonInput,
  NativeSelect,
  NumberInput,
  Stack,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import { Controller, useFormContext, type FieldPath } from "react-hook-form";
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api } from "../api";
import type { Document } from "../types";
import { Failure } from "../shared";
import { Optional, Section } from "./shared";
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
        render={({ field }) => (
          <NumberInput
            label={label}
            value={typeof field.value === "number" ? field.value : 0}
            min={min}
            max={max}
            allowDecimal={false}
            allowNegative={false}
            onChange={field.onChange}
          />
        )}
      />
    </Grid.Col>
  );
}
function SchemaText({
  value,
  onChange,
  onBlur,
  error,
}: {
  value: unknown;
  onChange: (v: unknown) => void;
  onBlur: () => void;
  error?: string;
}) {
  const [text, setText] = useState(() => JSON.stringify(value, null, 2));
  return (
    <JsonInput
      label="Reviewed JSON schema"
      formatOnBlur
      autosize
      minRows={5}
      error={error}
      value={text}
      onBlur={onBlur}
      onChange={(v) => {
        setText(v);
        try {
          onChange(JSON.parse(v));
        } catch {
          onChange(null);
        }
      }}
    />
  );
}
function SchemaField({
  name,
}: {
  name: `routes.${number}.middleware.api_schema.schema`;
}) {
  const { control } = useFormContext<Document>();
  return (
    <Controller
      control={control}
      name={name}
      rules={{ validate: (v) => v !== null || "Valid JSON schema required" }}
      render={({ field, fieldState }) => (
        <SchemaText
          value={field.value}
          onChange={field.onChange}
          onBlur={field.onBlur}
          error={fieldState.error?.message}
        />
      )}
    />
  );
}
export function AntiAbuseEditor({ index }: { index: number }) {
  const { control, setValue, register } = useFormContext<Document>();
  const p = `routes.${index}.middleware` as const;
  const [schemaEpoch, setSchemaEpoch] = useState(0);
  const [openapi, setOpenapi] = useState("");
  const [path, setPath] = useState("/");
  const [method, setMethod] = useState("POST");
  const imported = useMutation({
    mutationFn: () =>
      api<{ policy: { mode: "observe"; schema: Record<string, unknown> } }>(
        "/config/import-schema",
        {
          method: "POST",
          body: { document: JSON.parse(openapi), path, method },
        },
      ),
    onSuccess: (result) => {
      setValue(`${p}.api_schema`, result.policy, { shouldDirty: true });
      setValue(
        `routes.${index}.content`,
        { media_types: ["application/json"], require_type_for_body: true },
        { shouldDirty: true },
      );
      setValue(
        `routes.${index}.body`,
        { inspection: "full", max_body_bytes: 65536, idle_timeout_ms: 30000 },
        { shouldDirty: true },
      );
      setOpenapi("");
      setSchemaEpoch((n) => n + 1);
    },
  });
  return (
    <Stack>
      <Optional
        name={`${p}.identity_rate_limit`}
        title="Verified identity quota"
        initial={{
          header: "remote-user",
          per_second: 10,
          burst: 20,
          require_identity: false,
        }}
      >
        <Section title="Principal token bucket">
          <Grid.Col span={12}>
            <Text size="sm">
              Requires successful ForwardAuth and an explicitly approved
              identity header. IP/global protections still apply. Missing
              identity falls back to those protections unless required here.
              Capacity returns 503.
            </Text>
          </Grid.Col>
          <Grid.Col span={12}>
            <TextInput
              label="Approved principal header"
              {...register(`${p}.identity_rate_limit.header`)}
            />
          </Grid.Col>
          <NumberField
            name={`${p}.identity_rate_limit.per_second`}
            label="Sustained requests / second"
            min={1}
            max={10000}
          />
          <NumberField
            name={`${p}.identity_rate_limit.burst`}
            label="Burst requests"
            min={1}
            max={10000}
          />
          <Grid.Col span={12}>
            <Controller
              control={control}
              name={`${p}.identity_rate_limit.require_identity`}
              render={({ field }) => (
                <Checkbox
                  label="Require verified principal (403 when missing)"
                  checked={field.value === true}
                  onChange={(e) => field.onChange(e.currentTarget.checked)}
                />
              )}
            />
          </Grid.Col>
        </Section>
      </Optional>
      <Optional
        name={`${p}.detectors`}
        title="Observe endpoint probing and route pressure"
        initial={{
          window_seconds: 60,
          min_samples: 100,
          requests_per_second: 20,
          distinct_paths: 32,
          upstream_404_percent: 50,
        }}
      >
        <Section title="Observe-only detectors">
          <Grid.Col span={12}>
            <Alert>
              No automatic ban, challenge or policy change. Endpoint probing
              requires distinct paths, rate and upstream 404s; gateway 404s are
              separate evidence. Flood reports aggregate completion pressure and
              denial/error sources.
            </Alert>
          </Grid.Col>
          <NumberField
            name={`${p}.detectors.window_seconds`}
            label="Window seconds"
            min={10}
            max={3600}
          />
          <NumberField
            name={`${p}.detectors.min_samples`}
            label="Minimum samples"
            min={1}
            max={1000000}
          />
          <NumberField
            name={`${p}.detectors.requests_per_second`}
            label="Window request rate threshold"
            min={1}
            max={100000}
          />
          <NumberField
            name={`${p}.detectors.distinct_paths`}
            label="Distinct path threshold"
            min={2}
            max={64}
          />
          <NumberField
            name={`${p}.detectors.upstream_404_percent`}
            label="Upstream 404 percent"
            min={1}
            max={100}
          />
        </Section>
      </Optional>
      <Optional
        name={`${p}.api_schema`}
        title="JSON structural schema"
        initial={{
          mode: "observe",
          schema: {
            type: "object",
            properties: {},
            additionalProperties: true,
          },
        }}
      >
        <Section title="Bounded request schema">
          <Grid.Col span={12}>
            <Alert>
              Requires full inspection and a JSON-only content contract, at most
              64 KiB. Supported: type, properties, required,
              additionalProperties (boolean), items, min/maxLength,
              min/maxItems. Other keywords are rejected. Responses,
              authorization and business rules are outside coverage.
            </Alert>
          </Grid.Col>
          <Grid.Col span={12}>
            <Controller
              control={control}
              name={`${p}.api_schema.mode`}
              render={({ field }) => (
                <NativeSelect
                  label="Schema enforcement"
                  data={[
                    { value: "observe", label: "Observe (default)" },
                    {
                      value: "block",
                      label: "Block invalid requests (explicit)",
                    },
                  ]}
                  value={field.value ?? "observe"}
                  onChange={field.onChange}
                />
              )}
            />
          </Grid.Col>
          <Grid.Col span={12}>
            <SchemaField key={schemaEpoch} name={`${p}.api_schema.schema`} />
          </Grid.Col>
        </Section>
      </Optional>
      <details>
        <summary>
          Import selected OpenAPI request schema into this route
        </summary>
        <Stack mt="sm">
          <Text size="sm">
            Paste OpenAPI 3.x (maximum 256 KiB). Select a required JSON request
            body. Import fills the draft form in observe mode with a full JSON
            body contract; review, save, validate and apply through
            configuration.
          </Text>
          <Textarea
            label="OpenAPI document JSON"
            value={openapi}
            onChange={(e) => setOpenapi(e.currentTarget.value.slice(0, 262144))}
            minRows={4}
          />
          <TextInput
            label="OpenAPI path"
            value={path}
            onChange={(e) => setPath(e.currentTarget.value)}
          />
          <TextInput
            label="OpenAPI method"
            value={method}
            onChange={(e) => setMethod(e.currentTarget.value)}
          />
          {imported.isError && <Failure error={imported.error} />}{" "}
          {imported.isSuccess && (
            <Alert>
              Imported into this form. Unsupported OpenAPI parameters, responses
              and security are not simulated or enforced.
            </Alert>
          )}
          <Button
            type="button"
            loading={imported.isPending}
            disabled={!openapi}
            onClick={() => imported.mutate()}
          >
            Import and review schema
          </Button>
        </Stack>
      </details>
    </Stack>
  );
}
