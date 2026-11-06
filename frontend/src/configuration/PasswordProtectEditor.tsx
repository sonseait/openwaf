import {
  Alert,
  Button,
  Group,
  NumberInput,
  PasswordInput,
  Stack,
  Text,
  rem,
} from "@mantine/core";
import { useMutation } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import {
  useController,
  useForm,
  useFormContext,
  useWatch,
} from "react-hook-form";
import { api } from "../api";
import { Failure } from "../shared";
import type { Document } from "../types";

export function PasswordProtectEditor({ index }: { index: number }) {
  const { control, setValue, getValues } = useFormContext<Document>();
  const route = useWatch({ control, name: `routes.${index}` });
  // Register the nullable policy as one controlled field. Tracking only its
  // children makes RHF traverse null when a saved policy is removed.
  const {
    field: { name, ref, onBlur, value: policy, onChange: changePolicy },
    fieldState: policyState,
  } = useController({
    control,
    name: `routes.${index}.password_protect`,
    rules: {
      validate: (value) =>
        !value ||
        (Number.isInteger(value.session_seconds) &&
          value.session_seconds >= 300 &&
          value.session_seconds <= 86400) ||
        "Use a session lifetime between 300 and 86400 seconds",
    },
  });
  const form = useForm<{ password: string; confirm: string }>({
    defaultValues: { password: "", confirm: "" },
  });
  const generation = useRef(0);
  const request = useRef<AbortController | null>(null);
  useEffect(
    () => () => {
      generation.current++;
      request.current?.abort();
    },
    [],
  );
  const protect = useMutation({
    mutationFn: async () => {
      const password = form.getValues("password");
      form.reset();
      request.current?.abort();
      request.current = new AbortController();
      const id = route.id;
      const run = ++generation.current;
      try {
        const result = await api<{ sealed_verifier: string }>(
          "/config/password-verifier",
          {
            method: "POST",
            body: { route_id: id, password },
            signal: request.current.signal,
          },
        );
        if (
          run !== generation.current ||
          getValues(`routes.${index}.id`) !== id
        )
          throw new Error(
            "Route changed. Set the password again for its current ID.",
          );
        setValue(
          `routes.${index}.password_protect`,
          {
            sealed_verifier: result.sealed_verifier,
            session_seconds: route.password_protect?.session_seconds ?? 43200,
          },
          { shouldDirty: true },
        );
      } finally {
        form.reset();
      }
    },
  });
  return (
    <Stack>
      <Alert
        color={route.password_protect ? "teal" : "gray"}
        title={
          route.password_protect
            ? "Password protection configured in this form"
            : "No password protection configured"
        }
      >
        OpenWAF serves a password-only login page over HTTPS. Save and apply to
        activate changes. Changing the password signs out existing visitors on
        their next request.
      </Alert>
      <Text size="sm" c="dimmed">
        For a whole application, use a prefix route at / with all methods. More
        specific routes have their own protection; configure them too. Direct
        access to the backend must be restricted separately.
      </Text>
      {route.password_protect && (
        <>
          <NumberInput
            name={name}
            ref={ref}
            onBlur={onBlur}
            value={policy?.session_seconds ?? ""}
            onChange={(v) =>
              changePolicy({
                ...policy,
                session_seconds: v === "" ? undefined : Number(v),
              })
            }
            label="Password session lifetime (seconds)"
            description="5 minutes to 24 hours. Sessions end after every configuration apply/rollback or gateway restart."
            min={300}
            max={86400}
            allowDecimal={false}
            error={policyState.error?.message}
            maw={rem(416)}
          />
          <Button
            variant="subtle"
            color="red"
            disabled={protect.isPending}
            onClick={() => {
              generation.current++;
              changePolicy(null);
              protect.reset();
            }}
          >
            Remove password protection from draft
          </Button>
        </>
      )}
      <Group
        align="flex-start"
        grow
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            event.preventDefault();
            event.stopPropagation();
            if (!protect.isPending)
              void form.handleSubmit(() => protect.mutate())();
          }
        }}
      >
        <PasswordInput
          label={
            route.password_protect
              ? "New application password"
              : "Application password"
          }
          autoComplete="new-password"
          disabled={protect.isPending}
          {...form.register("password", {
            required: "Enter a password",
            validate: (v) =>
              (new TextEncoder().encode(v).length >= 12 &&
                new TextEncoder().encode(v).length <= 128) ||
              "Use 12–128 bytes",
          })}
          error={form.formState.errors.password?.message}
        />
        <PasswordInput
          label="Confirm application password"
          autoComplete="new-password"
          disabled={protect.isPending}
          {...form.register("confirm", {
            validate: (v) =>
              v === form.getValues("password") || "Passwords do not match",
          })}
          error={form.formState.errors.confirm?.message}
        />
      </Group>
      <Group>
        <Button
          variant="light"
          loading={protect.isPending}
          disabled={!/^[a-z0-9_-]{1,64}$/.test(route.id)}
          onClick={() => void form.handleSubmit(() => protect.mutate())()}
        >
          {route.password_protect
            ? "Replace password in draft"
            : "Set password in draft"}
        </Button>
      </Group>
      {protect.isError && <Failure error={protect.error} />}
      {protect.isSuccess && (
        <Text size="sm" role="status" c="teal">
          Encrypted verifier staged. Save and apply the configuration to
          activate it.
        </Text>
      )}
    </Stack>
  );
}
