import type {
  ButtonHTMLAttributes,
  HTMLAttributes,
  PropsWithChildren,
  ReactNode,
} from "react";

export type ButtonVariant = "primary" | "secondary" | "quiet";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  readonly variant?: ButtonVariant;
}

export function Button({
  type = "button",
  variant = "secondary",
  className = "",
  ...props
}: ButtonProps) {
  const classes = ["e4m-button", `e4m-button--${variant}`, className]
    .filter(Boolean)
    .join(" ");
  return <button {...props} className={classes} type={type} />;
}

export type StatusTone =
  | "neutral"
  | "information"
  | "positive"
  | "warning"
  | "critical";

export interface StatusBadgeProps extends PropsWithChildren {
  readonly tone?: StatusTone;
  readonly className?: string;
}

export function StatusBadge({
  tone = "neutral",
  className = "",
  children,
}: StatusBadgeProps) {
  const classes = ["status-badge", `status-badge--${tone}`, className]
    .filter(Boolean)
    .join(" ");
  return <span className={classes}>{children}</span>;
}

export interface SectionHeadingProps extends HTMLAttributes<HTMLDivElement> {
  readonly eyebrow?: string;
  readonly title: string;
  readonly description?: ReactNode;
  readonly headingId: string;
}

export function SectionHeading({
  eyebrow,
  title,
  description,
  headingId,
  className = "",
  ...props
}: SectionHeadingProps) {
  return (
    <div {...props} className={["section-heading", className].filter(Boolean).join(" ")}>
      {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
      <h2 id={headingId}>{title}</h2>
      {description ? <div className="section-heading__description">{description}</div> : null}
    </div>
  );
}

export function VisuallyHidden({ children }: PropsWithChildren) {
  return <span className="visually-hidden">{children}</span>;
}
