export function VisuallyHidden({ children }: { children: React.ReactNode }) {
  return (
    <span
      style={{
        border: 0,
        clip: "rect(0 0 0 0)",
        height: 1,
        margin: -1,
        overflow: "hidden",
        padding: 0,
        position: "absolute",
        width: 1
      }}
    >
      {children}
    </span>
  );
}
