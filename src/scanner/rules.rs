/// A stable scanner rule. IDs are part of the SARIF output and must not change.
pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub short_description: &'static str,
    pub help: &'static str,
    pub severity: &'static str,
    pub asi: &'static [&'static str],
    pub help_uri: &'static str,
    pub remediation: &'static str,
}

pub const SHELL_EXECUTION: &str = "recon/shell-execution";
pub const MCP_UNPINNED_PACKAGE: &str = "recon/mcp-unpinned-package";
pub const MCP_REMOTE_CVE: &str = "recon/mcp-remote-cve-2025-6514";
pub const MCP_SECRET_IN_ENV: &str = "recon/mcp-secret-in-env";
pub const MCP_FILESYSTEM_ROOT: &str = "recon/mcp-filesystem-root";
pub const MCP_SHELL_WITHOUT_APPROVAL: &str = "recon/mcp-shell-without-approval";
pub const AGENT_CLOUD_SPEND: &str = "recon/agent-cloud-spend";

const OWASP_ASI: &str =
    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/";
const AZGUARD_GUARD: &str = "https://github.com/cdobratz/AzGuard#agent-guard";

pub const AZGUARD_REMEDIATION: &str = "Use least-privilege cloud roles and run `azguard guard` before billable commands. See https://github.com/cdobratz/AzGuard#agent-guard";

pub fn catalog() -> &'static [Rule] {
    &RULES
}

pub fn by_id(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|rule| rule.id == id)
}

const RULES: [Rule; 7] = [
    Rule {
        id: SHELL_EXECUTION,
        name: "shell-execution",
        short_description: "Shell or code execution call",
        help: "This line spawns a process or runs a shell. Database calls such as db.Exec, tx.Exec, stmt.Exec, and conn.Query are not shell execution. Confirm an agent cannot reach this call without a human approval step.",
        severity: "high",
        asi: &["ASI05"],
        help_uri: OWASP_ASI,
        remediation: "",
    },
    Rule {
        id: MCP_UNPINNED_PACKAGE,
        name: "mcp-unpinned-package",
        short_description: "Unpinned npx or uvx package",
        help: "npx or uvx is launching a package without an exact version pin. An unpinned package can change between runs (agentic supply chain). Pin it, for example `npx -y pkg@1.2.3` or `uvx 'pkg==1.2.3'`. A tag of @latest is not a pin.",
        severity: "high",
        asi: &["ASI04"],
        help_uri: OWASP_ASI,
        remediation: "",
    },
    Rule {
        id: MCP_REMOTE_CVE,
        name: "mcp-remote-cve-2025-6514",
        short_description: "Vulnerable mcp-remote version",
        help: "mcp-remote versions 0.0.5 through 0.1.15 are affected by CVE-2025-6514, a command-injection vulnerability. Upgrade to mcp-remote 0.1.16 or later.",
        severity: "high",
        asi: &["ASI05"],
        help_uri: "https://nvd.nist.gov/vuln/detail/cve-2025-6514",
        remediation: "",
    },
    Rule {
        id: MCP_SECRET_IN_ENV,
        name: "mcp-secret-in-env",
        short_description: "Secret stored in MCP env",
        help: "An MCP server env entry holds a literal secret. Pass the secret by reference from the process environment or a secret store instead of writing it into the MCP config.",
        severity: "high",
        asi: &["ASI03"],
        help_uri: OWASP_ASI,
        remediation: "",
    },
    Rule {
        id: MCP_FILESYSTEM_ROOT,
        name: "mcp-filesystem-root",
        short_description: "MCP filesystem root is / or ~",
        help: "An MCP filesystem root is `/` or `~`, which exposes the whole machine or the home directory to the agent. Restrict the root to a specific project directory.",
        severity: "high",
        asi: &["ASI02"],
        help_uri: OWASP_ASI,
        remediation: "",
    },
    Rule {
        id: MCP_SHELL_WITHOUT_APPROVAL,
        name: "mcp-shell-without-approval",
        short_description: "Shell or exec tool without approval",
        help: "A shell or exec tool is available to the agent and the config does not require an approval step. Set requireApproval (or an equivalent approval flag) before the agent can run commands.",
        severity: "high",
        asi: &["ASI02", "ASI05"],
        help_uri: OWASP_ASI,
        remediation: "",
    },
    Rule {
        id: AGENT_CLOUD_SPEND,
        name: "agent-cloud-spend",
        short_description: "Agent can spend cloud money",
        help: "This agent or MCP server can create cloud resources or spend cloud money. It has cloud credentials, a cloud CLI or IaC apply command, a cloud write tool, or a Stripe live secret key.",
        severity: "high",
        asi: &["ASI02"],
        help_uri: AZGUARD_GUARD,
        remediation: AZGUARD_REMEDIATION,
    },
];
