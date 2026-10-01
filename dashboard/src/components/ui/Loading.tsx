export function Spinner({ className }: { className?: string }) {
  return (
    <div
      className={`animate-spin rounded-full border-2 border-border border-t-primary h-5 w-5 ${className ?? ""}`}
    />
  );
}

export function PageLoading() {
  return (
    <div className="flex items-center justify-center h-64">
      <Spinner className="h-8 w-8" />
    </div>
  );
}

export function Empty({ message = "No data" }: { message?: string }) {
  return (
    <div className="flex items-center justify-center h-32 text-sm text-muted-foreground">
      {message}
    </div>
  );
}
