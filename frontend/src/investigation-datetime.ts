import dayjs from "dayjs";

export function toPickerDateTime(milliseconds: string): string | null {
  if (!milliseconds) return null;
  const date = dayjs(Number(milliseconds));
  return date.isValid() ? date.format("YYYY-MM-DD HH:mm:ss") : null;
}

export function fromPickerDateTime(value: string | null): string {
  if (!value) return "";
  const date = dayjs(value);
  return date.isValid() ? String(date.valueOf()) : "";
}
