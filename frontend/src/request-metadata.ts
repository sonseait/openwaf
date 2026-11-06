export type Fields = Record<string, unknown>;
export function object(value: unknown): Fields | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Fields)
    : null;
}
export function parseMetadata(value: unknown) {
  const root = object(value);
  const client = object(root?.client),
    request = object(root?.request),
    response = object(root?.response);
  return root && client && request && response
    ? { root, client, request, response }
    : null;
}
export type Metadata = NonNullable<ReturnType<typeof parseMetadata>>;
