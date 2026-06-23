import React from "react";
import Layout from "@theme/Layout";
import Link from "@docusaurus/Link";
import useBaseUrl from "@docusaurus/useBaseUrl";

const publicToolUrl = "/tools/risk-navigator.html";

const toolSections = [
  {
    image: "/img/tool/risk-navigator-prioritization.png",
    title: "Prioritize vulnerable libraries",
    copy: "Start from the ranked library view to compare CVSS, EPSS, KEV, affected projects, upgrade effort, safe versions, and amplifier paths in one place.",
    alt: "Risk Navigator library prioritization table with detail pane",
  },
  {
    image: "/img/tool/risk-navigator-backpatch.png",
    title: "Find OSERA patch candidates",
    copy: "Use the backpatch priority calculator to separate routine upgrades from cases where fork, backpatch, or amplifier work can reduce migration risk.",
    alt: "Risk Navigator backpatch priority calculator view",
  },
  {
    image: "/img/tool/risk-navigator-openrewrite-cart.png",
    title: "Generate remediation bundles",
    copy: "Add Maven dependencies to the OpenRewrite cart, tune target versions, and generate YAML or impact prompts for repeatable remediation planning.",
    alt: "Risk Navigator OpenRewrite cart panel",
  },
];

function ToolSectionCard({ image, title, copy, alt }) {
  const imageSrc = useBaseUrl(image);
  return (
    <article className="rn-tool-card">
      <div className="rn-tool-shot">
        <img src={imageSrc} alt={alt} loading="lazy" />
      </div>
      <div className="rn-tool-copy">
        <h3>{title}</h3>
        <p>{copy}</p>
      </div>
    </article>
  );
}

export default function Home() {
  return (
    <Layout
      title="OSERA Risk Navigator"
      description="Dependency-risk prioritization for open source supply resiliency"
    >
      <main>
        <section className="rn-hero">
          <div className="rn-wrap rn-hero-grid">
            <div>
              <h1>Prioritize dependency risk with an open, reproducible snapshot.</h1>
              <p className="rn-sub">
                Risk Navigator turns vulnerability intelligence and dependency inventory into an
                interactive decision surface for remediation planning, backpatch candidates,
                amplifier upgrades, and OpenRewrite-ready upgrade bundles.
              </p>
              <div className="rn-cta">
                <a className="rn-btn rn-primary" href={publicToolUrl}>Launch the tool</a>
                <Link className="rn-btn rn-primary" to="/docs/home">Read the docs</Link>
                <Link className="rn-btn rn-ghost" to="/docs/spec">Review the spec</Link>
              </div>
            </div>
            <div className="rn-diagram" aria-label="Risk Navigator flow">
              <div className="rn-node rn-input">Vulnerability signals</div>
              <div className="rn-node rn-input">Dependency inventory</div>
              <div className="rn-arrow">→</div>
              <div className="rn-node rn-core">Risk Navigator dataset</div>
              <div className="rn-arrow">→</div>
              <div className="rn-node rn-output">Prioritized fixes</div>
              <div className="rn-node rn-output">OpenRewrite cart</div>
            </div>
          </div>
        </section>

        <section className="rn-section rn-tool-section">
          <div className="rn-wrap">
            <div className="rn-section-head">
              <div>
                <div className="rn-eyebrow">Inside the tool</div>
                <h2>From exposure signal to remediation plan.</h2>
              </div>
              <p>
                The hosted demo uses the OSERA sample dataset, so the same views can be explored
                directly from GitHub Pages.
              </p>
            </div>
            <div className="rn-tool-grid">
              {toolSections.map(section => (
                <ToolSectionCard key={section.title} {...section} />
              ))}
            </div>
          </div>
        </section>

        <section className="rn-section">
          <div className="rn-wrap">
            <div className="rn-eyebrow">What it helps answer</div>
            <div className="rn-cards">
              <article>
                <h2>Where is the exposure?</h2>
                <p>Slice vulnerable libraries by CVSS, EPSS, KEV, namespace, project reference, and project group.</p>
              </article>
              <article>
                <h2>What moves first?</h2>
                <p>Rank patch, minor, major, backpatch, framework, and amplifier remediation options by impact and effort.</p>
              </article>
              <article>
                <h2>Where is OSERA needed?</h2>
                <p>Surface cases where downstream patch ownership or backpatch work can defer risky migrations.</p>
              </article>
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
}
