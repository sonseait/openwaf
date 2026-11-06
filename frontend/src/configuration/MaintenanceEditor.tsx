import {
  Checkbox,
  NumberInput,
  Stack,
  Text,
  Textarea,
  rem,
} from "@mantine/core";
import { useController, useFormContext } from "react-hook-form";
import type { Document } from "../types";

function messageError(value: string) {
  if (!value.trim()) return "Maintenance message is required";
  if (new TextEncoder().encode(value).length > 512)
    return "Use at most 512 UTF-8 bytes";
  if (
    [...value].some((c) => {
      const code = c.codePointAt(0)!;
      return (code < 32 && c !== "\n") || (code >= 127 && code <= 159);
    })
  )
    return "Control characters are not allowed";
}

export function MaintenanceEditor({ index }: { index: number }) {
  const { control } = useFormContext<Document>();
  // Control the nullable policy as one field so clearing a saved policy does
  // not fall back to RHF defaults or traverse null through registered children.
  const {
    field: { name, ref, onBlur, value: policy, onChange: changePolicy },
    fieldState,
  } = useController({
    control,
    name: `routes.${index}.maintenance`,
    rules: {
      validate: (value) => {
        if (!value) return true;
        return (
          messageError(value.message) ??
          (Number.isInteger(value.retry_after_seconds) &&
          value.retry_after_seconds >= 1 &&
          value.retry_after_seconds <= 86400
            ? true
            : "Use an integer retry interval from 1 to 86400 seconds")
        );
      },
    },
  });
  return (
    <Stack gap="sm">
      <Checkbox
        label="Enable route maintenance"
        checked={policy != null}
        onChange={(event) =>
          changePolicy(
            event.currentTarget.checked
              ? {
                  message:
                    "We are performing scheduled maintenance. Please try again shortly.",
                  retry_after_seconds: 300,
                }
              : null,
          )
        }
      />
      {policy && (
        <>
          <Text size="sm" c="dimmed">
            After saving and applying, new requests to this route receive a
            local maintenance page (503) before challenge or authentication.
            Other routes and existing requests continue. Endpoint modes are
            managed separately.
          </Text>
          <Textarea
            ref={ref}
            name={`${name}.message`}
            onBlur={onBlur}
            value={policy.message}
            onChange={(event) =>
              changePolicy({ ...policy, message: event.currentTarget.value })
            }
            label="Maintenance message"
            description="Plain text, up to 512 UTF-8 bytes. Line breaks are supported."
            autosize
            minRows={2}
            maxRows={6}
            required
            withAsterisk={false}
            error={fieldState.error ? messageError(policy.message) : undefined}
          />
          <NumberInput
            name={`${name}.retry_after_seconds`}
            onBlur={onBlur}
            value={policy.retry_after_seconds ?? ""}
            onChange={(value) =>
              changePolicy({
                ...policy,
                retry_after_seconds: value === "" ? undefined : Number(value),
              })
            }
            label="Retry after (seconds)"
            description="Retry-After response header; maintenance stays on until you disable and apply it."
            min={1}
            max={86400}
            allowDecimal={false}
            allowNegative={false}
            maw={rem(416)}
            required
            withAsterisk={false}
            error={
              !messageError(policy.message)
                ? fieldState.error?.message
                : undefined
            }
          />
        </>
      )}
    </Stack>
  );
}
