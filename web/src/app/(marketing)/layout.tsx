import "../marketing-core.css";
import "../marketing-sections.css";
import "../marketing-hiw.css";
import "../marketing-lab.css";
import "../marketing-docs.css";
import "../marketing-responsive.css";

// Marketing-only styles. Workspace routes (`/workspace/*`) never load these:
// global CSS is code-split per route in production builds, so keeping these
// imports in the marketing group layout (and not-found) keeps the workspace
// bundle to globals.css + tokens.css + workspace.css.
export default function MarketingLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return children;
}
