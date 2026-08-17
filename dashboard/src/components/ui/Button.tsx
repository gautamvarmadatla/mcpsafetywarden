import { forwardRef, useEffect, useState, type ButtonHTMLAttributes } from "react";

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "quiet";
  size?: "sm" | "md";
  loading?: boolean;
};

const Button = forwardRef<HTMLButtonElement, Props>(function Button(
  { variant = "secondary", size = "md", loading = false, className = "", children, onClick, ...rest },
  ref
) {
  const [showSpin, setShowSpin] = useState(false);

  useEffect(() => {
    if (!loading) {
      setShowSpin(false);
      return;
    }
    const t = setTimeout(() => setShowSpin(true), 150);
    return () => clearTimeout(t);
  }, [loading]);

  const cls = [
    "btn",
    variant === "primary" ? "primary" : variant === "quiet" ? "quiet" : "",
    size === "sm" ? "sm" : "",
    showSpin ? "is-loading" : "",
    className,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <button
      ref={ref}
      type="button"
      className={cls}
      aria-busy={loading || undefined}
      onClick={(e) => {
        if (loading) return;
        onClick?.(e);
      }}
      {...rest}
    >
      <span className="spin" />
      {children}
    </button>
  );
});

export default Button;
