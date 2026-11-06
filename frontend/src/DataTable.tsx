import { rem } from "@mantine/core";
import {
  DataTable as MantineDataTable,
  type DataTableProps as MantineDataTableProps,
} from "mantine-datatable";

export type DataTableProps<T> = MantineDataTableProps<T> & {
  /** Expand to fit content without internal scrolling; overrides height/maxHeight. */
  disableScroll?: boolean;
};

// Keep package behavior and props available, with consistent console defaults.
export function DataTable<T>({
  disableScroll = false,
  height = "auto",
  maxHeight = `max(${rem(240)}, min(${rem(420)}, 60dvh))`,
  scrollAreaProps,
  styles,
  ...props
}: DataTableProps<T>) {
  return (
    <MantineDataTable
      withTableBorder
      fz="sm"
      horizontalSpacing="sm"
      verticalSpacing={rem(6)}
      highlightOnHover
      borderRadius="sm"
      {...props}
      height={disableScroll ? "auto" : height}
      maxHeight={disableScroll ? "none" : maxHeight}
      scrollAreaProps={{
        ...scrollAreaProps,
        mah: disableScroll ? "none" : maxHeight,
        ...(disableScroll && {
          scrollbars: false,
          offsetScrollbars: false,
          style: [
            scrollAreaProps?.style,
            { height: "auto", maxHeight: "none", overflow: "visible" },
          ],
        }),
        viewportProps: {
          tabIndex: disableScroll ? undefined : 0,
          ...scrollAreaProps?.viewportProps,
          // The package caps its outer box; let the auto-height viewport
          // inherit the ScrollArea cap so records scroll inside that box.
          style: {
            maxHeight: "inherit",
            ...scrollAreaProps?.viewportProps?.style,
            ...(disableScroll && {
              height: "auto",
              maxHeight: "none",
              overflowX: "visible",
              overflowY: "visible",
            }),
          },
        },
      }}
      styles={{
        ...styles,
        root: [
          styles?.root,
          disableScroll ? { overflow: "visible" } : undefined,
        ],
        header: [{ background: "var(--console-surface)" }, styles?.header],
        footer: [{ background: "var(--console-surface)" }, styles?.footer],
      }}
    />
  );
}
