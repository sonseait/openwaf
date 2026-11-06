import type { ReactNode } from "react";
import {
  Button,
  Checkbox,
  Fieldset,
  Grid,
  Group,
  Stack,
  Text,
  VisuallyHidden,
  rem,
} from "@mantine/core";
import { useController, useFormContext, type FieldPath } from "react-hook-form";
import { ChevronDown, Trash2 } from "lucide-react";
import type { Document } from "../types";
export function EditorGroup({
  title,
  description,
  open = false,
  children,
}: {
  title: string;
  description: string;
  open?: boolean;
  children: ReactNode;
}) {
  return (
    <details className="editor-group" open={open || undefined}>
      <Group
        component="summary"
        justify="space-between"
        wrap="nowrap"
        gap="md"
        mih={rem(44)}
        py={rem(6)}
        c="var(--mantine-color-text)"
      >
        <Stack gap={rem(4)}>
          <Text component="strong" size="sm" fw={600}>
            {title}
          </Text>
          <Text component="span" size="xs" c="dimmed">
            {description}
          </Text>
        </Stack>
        <ChevronDown size={rem(16)} aria-hidden="true" />
      </Group>
      <Stack gap="md" pt="xs" pb="md">
        {children}
      </Stack>
    </details>
  );
}
export function Section({
  title,
  children,
  hideLegend = false,
}: {
  title: string;
  children: ReactNode;
  hideLegend?: boolean;
}) {
  return (
    <Fieldset
      variant="unstyled"
      legend={hideLegend ? <VisuallyHidden>{title}</VisuallyHidden> : title}
    >
      <Grid gutter="md" align="flex-start">
        {children}
      </Grid>
    </Fieldset>
  );
}
export function Optional({
  name,
  title,
  initial,
  disabledValue,
  children,
}: {
  name: string;
  title: string;
  initial: unknown;
  disabledValue?: unknown;
  children: ReactNode;
}) {
  const { control, setValue } = useFormContext<Document>();
  // Register the optional object itself as a field. Otherwise removing a saved
  // object makes RHF diff its nested defaults against null/undefined and throw.
  const { field } = useController({
    control,
    name: name as FieldPath<Document>,
  });
  const value = field.value;
  return (
    <Stack gap="sm">
      <Checkbox
        label={title}
        checked={value != null}
        onChange={(e) =>
          setValue(
            name as FieldPath<Document>,
            (e.currentTarget.checked
              ? structuredClone(initial)
              : disabledValue) as never,
            { shouldDirty: true },
          )
        }
      />
      {value != null && children}
    </Stack>
  );
}
export function Remove({
  label,
  onClick,
}: {
  label: string;
  onClick: () => void;
}) {
  return (
    <Button
      type="button"
      variant="subtle"
      color="red"
      size="compact-xs"
      leftSection={<Trash2 size={rem(14)} aria-hidden="true" />}
      onClick={onClick}
    >
      {label}
    </Button>
  );
}
