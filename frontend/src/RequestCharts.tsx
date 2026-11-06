import { memo, useEffect, useRef } from "react";
import { Box, Group, Text, useComputedColorScheme, rem } from "@mantine/core";
import { scaleLinear, scaleTime } from "d3-scale";
import { line } from "d3-shape";
import dayjs from "dayjs";
import { DataTable } from "./DataTable";

export interface ChartPoint {
  time: number;
  values: (number | null)[];
}
export interface ChartSeries {
  label: string;
  color: string;
}

// React owns the shell; D3 draws into a single bounded Canvas. Updates and
// resizes coalesce into one animation frame, with no transitions or point nodes.
export const RequestChart = memo(function RequestChart({
  points,
  series,
  label,
  unit,
  fractionDigits = 1,
}: {
  points: ChartPoint[];
  series: ChartSeries[];
  label: string;
  unit: string;
  fractionDigits?: number;
}) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const theme = useComputedColorScheme("light");
  useEffect(() => {
    const element = canvas.current;
    if (!element) return;
    let frame = 0;
    const draw = () => {
      const context = element.getContext("2d");
      if (!context) return;
      const { width, height } = element.getBoundingClientRect();
      if (width <= 0 || height <= 0) return;
      const style = getComputedStyle(element);
      const fontSize = Number.parseFloat(style.fontSize);
      const unit = fontSize / 12;
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      element.width = Math.round(width * ratio);
      element.height = Math.round(height * ratio);
      context.scale(ratio, ratio);
      const margin = {
        left: 52 * unit,
        right: 18 * unit,
        top: 18 * unit,
        bottom: 32 * unit,
      };
      const first = points[0]?.time ?? Date.now();
      const last = points.at(-1)?.time ?? first;
      const x = scaleTime()
        .domain([
          new Date(first === last ? first - 1000 : first),
          new Date(last),
        ])
        .range([margin.left, width - margin.right]);
      const maximum = Math.max(
        1,
        ...points.map((point) =>
          Math.max(0, ...point.values.map((v) => v ?? 0)),
        ),
      );
      const y = scaleLinear()
        .domain([0, maximum])
        .nice(4)
        .range([height - margin.bottom, margin.top]);
      const text = style.color;
      context.font = `${style.fontSize} ${style.fontFamily}`;
      context.textAlign = "right";
      for (const tick of y
        .ticks(4)
        .filter((value) => fractionDigits !== 0 || Number.isInteger(value))) {
        context.strokeStyle = style.borderTopColor;
        context.beginPath();
        context.moveTo(margin.left, y(tick));
        context.lineTo(width - margin.right, y(tick));
        context.stroke();
        context.fillStyle = text;
        context.fillText(
          tick.toLocaleString(undefined, {
            notation: fractionDigits === 0 ? "standard" : "compact",
            maximumFractionDigits: fractionDigits,
          }),
          margin.left - 8 * unit,
          y(tick) + 4 * unit,
        );
      }
      context.textAlign = "center";
      for (const tick of x.ticks(width < 500 * unit ? 3 : 6)) {
        context.fillStyle = text;
        const label = dayjs(tick).format("HH:mm:ss");
        const halfWidth = context.measureText(label).width / 2;
        context.fillText(
          label,
          Math.max(halfWidth, Math.min(width - halfWidth, x(tick))),
          height - 9 * unit,
        );
      }
      series.forEach((item, index) => {
        const path = line<ChartPoint>()
          .defined(
            (point) =>
              point.values[index] != null &&
              Number.isFinite(point.values[index]),
          )
          .x((point) => x(point.time))
          .y((point) => y(point.values[index] ?? 0))
          .context(context);
        context.strokeStyle = item.color;
        context.lineWidth = 2 * unit;
        context.setLineDash([]);
        context.beginPath();
        path(points);
        context.stroke();
        // An isolated observation must remain visible without joining a gap.
        context.setLineDash([]);
        points.forEach((point, i) => {
          const value = point.values[index];
          if (value == null || !Number.isFinite(value)) return;
          if (
            points[i - 1]?.values[index] != null ||
            points[i + 1]?.values[index] != null
          )
            return;
          context.fillStyle = item.color;
          context.beginPath();
          context.arc(x(point.time), y(value), 3 * unit, 0, Math.PI * 2);
          context.fill();
        });
      });
    };
    const schedule = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(draw);
    };
    const observer = new ResizeObserver(schedule);
    observer.observe(element);
    document.fonts.addEventListener("loadingdone", schedule);
    schedule();
    return () => {
      observer.disconnect();
      document.fonts.removeEventListener("loadingdone", schedule);
      cancelAnimationFrame(frame);
    };
  }, [points, series, theme, fractionDigits]);
  const recent = points
    .filter((point) => point.values.some((v) => v != null))
    .slice(-10);
  return (
    <figure className="request-chart">
      <canvas ref={canvas} role="img" aria-label={label} />
      <figcaption>
        <Group gap="md" mt="sm" fz="xs">
          {series.map((item, index) => (
            <Group key={item.label} component="span" gap={rem(6)} wrap="nowrap">
              <Box
                component="span"
                w={rem(12)}
                h={rem(3)}
                bg={item.color}
                aria-hidden="true"
              />
              {item.label}:{" "}
              <strong>
                {recent.at(-1)?.values[index]?.toLocaleString(undefined, {
                  maximumFractionDigits: fractionDigits,
                }) ?? "—"}
              </strong>
            </Group>
          ))}
          <span>{unit}</span>
        </Group>
        {!recent.length && <p>No observations available in this window.</p>}
        <details className="chart-data">
          <summary>View latest chart values</summary>
          <Text size="xs" c="dimmed" mt="sm" mb="xs">
            Latest 10 observations · {unit}
          </Text>
          <DataTable
            aria-label={`Latest 10 observations · ${unit}`}
            records={recent.map((point, index) => ({
              ...point,
              id: `${point.time}:${index}`,
            }))}
            fz="xs"
            tabularNums
            noRecordsText="No observations available in this window."
            minHeight={rem(100)}
            columns={[
              {
                accessor: "time",
                title: "Time",
                width: rem(110),
                render: (point) => dayjs(point.time).format("HH:mm:ss"),
              },
              ...series.map((item, index) => ({
                accessor: `series-${index}`,
                title: item.label,
                textAlign: "right" as const,
                render: (point: ChartPoint) =>
                  point.values[index]?.toLocaleString(undefined, {
                    maximumFractionDigits: fractionDigits,
                  }) ?? "Gap",
              })),
            ]}
          />
        </details>
      </figcaption>
    </figure>
  );
});
