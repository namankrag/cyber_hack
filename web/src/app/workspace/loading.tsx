import { LoadingState } from "@/components/workspace/ui";

export default function WorkspaceLoading() {
  return (
    <div className="ws-stack">
      <div className="ws-skeleton ws-loading-title" />
      <div className="ws-skeleton ws-loading-sub" />
      <LoadingState rows={4} />
      <LoadingState rows={2} />
    </div>
  );
}
