import { cn } from "@/lib/utils";

export function ShieldMark({
  className,
  inverted = false,
}: {
  className?: string;
  inverted?: boolean;
}) {
  return (
    <svg
      viewBox="0 0 36 40"
      fill="none"
      aria-hidden="true"
      className={cn("h-9 w-auto", className)}
    >
      <path
        d="M18 2.5 33 8.1v13.5c0 8.9-6.1 14.9-15 17.9-8.9-3-15-9-15-17.9V8.1L18 2.5Z"
        fill={inverted ? "#F8F7F4" : "#191D35"}
        stroke={inverted ? "#F8F7F4" : "#171717"}
        strokeWidth="2.2"
        strokeLinejoin="round"
      />
      <path
        d="M11.6 19.7 16 24l8.7-9.1"
        stroke={inverted ? "#191D35" : "#C9F45A"}
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="29.8" cy="7.9" r="4.1" fill="#B67AE8" stroke="#171717" strokeWidth="1.8" />
    </svg>
  );
}

export function Brand({
  className,
  inverted = false,
  compact = false,
}: {
  className?: string;
  inverted?: boolean;
  compact?: boolean;
}) {
  return (
    <span className={cn("inline-flex items-center gap-2.5", className)}>
      <ShieldMark inverted={inverted} className={compact ? "h-7" : "h-[34px]"} />
      <span
        className={cn(
          "text-[21px] font-semibold tracking-[-0.045em]",
          inverted ? "text-[#F8F7F4]" : "text-[#171717]",
        )}
      >
        AgentShield
      </span>
    </span>
  );
}
