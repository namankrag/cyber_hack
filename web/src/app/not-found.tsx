import Link from "next/link";
import "./marketing-core.css";
import "./marketing-sections.css";
import "./marketing-hiw.css";
import "./marketing-lab.css";
import "./marketing-docs.css";
import "./marketing-responsive.css";
import { ArrowLeft } from "lucide-react";
import { Brand } from "@/components/marketing/logo";

export default function NotFound() {
  return (
    <div className="site">
      <main id="main" className="not-found-main">
        <div className="wrap not-found-inner">
          <Brand />
          <p className="kicker">
            <span className="kicker-mark" /> Error 404
          </p>
          <h1 className="display display-lg">
            This page took
            <br />
            a <span className="serif-accent">wrong turn.</span>
          </h1>
          <p className="lede">
            The page you&apos;re looking for doesn&apos;t exist or has moved.
            Head back to the homepage and pick up where you left off.
          </p>
          <Link href="/" className="btn btn-primary btn-lg">
            <ArrowLeft className="h-4 w-4" /> Back to home
          </Link>
        </div>
      </main>
    </div>
  );
}
