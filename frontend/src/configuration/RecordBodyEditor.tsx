import { Alert, Checkbox, Stack, Text, Textarea } from "@mantine/core";
import { Controller, useFormContext } from "react-hook-form";
import type { Document } from "../types";
import { Section } from "./shared";

export function RecordBodyEditor({ base }: { base: `routes.${number}` }) {
  const { control } = useFormContext<Document>();
  return (
    <Section title="Body & query recording">
      <Stack>
        <Text size="sm" c="dimmed">
          Opt in separately for this route. Complete UTF-8 JSON, URL-encoded
          forms and query strings up to 64 KiB each are redacted and retained
          for 7 days. Changes take effect after applying the configuration.
        </Text>
        {(
          ["request_enabled", "response_enabled", "query_enabled"] as const
        ).map((name) => (
          <Controller
            key={name}
            control={control}
            name={`${base}.record_body.${name}`}
            render={({ field }) => (
              <Checkbox
                ref={field.ref}
                name={field.name}
                onBlur={field.onBlur}
                checked={field.value ?? false}
                onChange={(event) =>
                  field.onChange(event.currentTarget.checked)
                }
                label={
                  name === "request_enabled"
                    ? "Record request body"
                    : name === "response_enabled"
                      ? "Record response body"
                      : "Record query string"
                }
              />
            )}
          />
        ))}
        <Controller
          control={control}
          name={`${base}.record_body.redact_fields`}
          rules={{
            validate: (values) =>
              !values ||
              (values.length <= 64 &&
                values.every(
                  (name) => new TextEncoder().encode(name).length <= 128,
                )) ||
              "Use at most 64 field names, each up to 128 bytes.",
          }}
          render={({ field, fieldState }) => (
            <Textarea
              ref={field.ref}
              name={field.name}
              onBlur={field.onBlur}
              label="Additional fields to redact"
              description="One name per line, case-insensitive. Applies to JSON keys, form fields and query parameters, including repeated names."
              value={(field.value ?? []).join("\n")}
              onChange={(event) =>
                field.onChange(event.currentTarget.value.split("\n"))
              }
              error={fieldState.error?.message}
              minRows={3}
            />
          )}
        />
        <Alert color="yellow" title="Review sensitive fields before enabling">
          Passwords, tokens, secrets, API keys, authorization, cookies and CSRF
          tokens with standard field names are always redacted. Add your
          application&apos;s sensitive field names; secrets inside free-form
          values cannot be detected automatically. Body capture skips files,
          compressed bodies and streams; query recording is independent. Turning
          recording off keeps existing captures until expiry.
        </Alert>
      </Stack>
    </Section>
  );
}
