const lightCodeTheme = require("prism-react-renderer").themes.github;
const darkCodeTheme = require("prism-react-renderer").themes.nightOwl;

const isGitHubPages = process.env.GITHUB_PAGES === "true";

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: "OSERA Risk Navigator",
  tagline: "Dependency-risk prioritization for open source supply resiliency",
  favicon: "img/favicon.ico",
  url: isGitHubPages ? "https://finos-backpatch.github.io" : "https://risk-navigator.finos.org",
  baseUrl: isGitHubPages ? "/risk-navigator/" : "/",
  organizationName: "finos-backpatch",
  projectName: "risk-navigator",
  onBrokenLinks: "throw",
  markdown: {
    hooks: {
      onBrokenMarkdownLinks: "warn",
    },
  },

  presets: [
    [
      "classic",
      {
        docs: {
          path: "../docs",
          routeBasePath: "docs",
          sidebarPath: require.resolve("./sidebars.js"),
          editUrl: ({ docPath }) => `https://github.com/finos-backpatch/risk-navigator/edit/main/docs/${docPath}`,
        },
        blog: false,
        theme: {
          customCss: require.resolve("./src/css/custom.css"),
        },
      },
    ],
  ],

  themeConfig: {
    colorMode: {
      defaultMode: "light",
      respectPrefersColorScheme: false,
    },
    navbar: {
      title: "\u00b7 OSERA Risk Navigator",
      logo: {
        alt: "FINOS",
        src: "img/finos-logo-white.png",
      },
      items: [
        { to: "/", label: "Overview", position: "right" },
        { to: "/docs/home", label: "Docs", position: "right" },
        {
          href: "https://github.com/finos-backpatch/risk-navigator",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    footer: {
      style: "dark",
      logo: {
        alt: "FINOS",
        src: "img/finos-logo-white.png",
        href: "https://www.finos.org/",
      },
      links: [
        {
          title: "Project",
          items: [
            { label: "Overview", to: "/" },
            { label: "Docs", to: "/docs/home" },
            { label: "GitHub", href: "https://github.com/finos-backpatch/risk-navigator" },
          ],
        },
        {
          title: "FINOS",
          items: [
            { label: "FINOS", href: "https://www.finos.org/" },
            { label: "Community", href: "https://community.finos.org/" },
            { label: "OSERA", href: "https://github.com/finos-backpatch/community" },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} FINOS.`,
    },
    prism: {
      theme: lightCodeTheme,
      darkTheme: darkCodeTheme,
    },
  },
};

module.exports = config;
