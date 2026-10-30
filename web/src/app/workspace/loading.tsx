import { LoadingState } from "@/components/workspace/ui";

export default function WorkspaceLoading() {
  return (
    <div className="ws-stack">
      <div className="ws-skeleton" style={{ width: 240, height: 34 }} />
      <div className="ws-skeleton" style={{ width: 460, height: 14 }} />
      <LoadingState rows={4} />
      <LoadingState rows={2} />
    </div>
  );
}
