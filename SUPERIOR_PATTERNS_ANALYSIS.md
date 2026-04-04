# Superior Patterns Analysis: Claude Code Architecture

**Analysis Date:** April 4, 2026
**Source Repository:** Ahmad-progr/claude-leaked-files (Mirror of Claude Code source)
**Technology Stack:** TypeScript, Bun Runtime, React + Ink, Zod v4
**Codebase Size:** ~1,900 files, 512,000+ lines of code

---

## Executive Summary

This analysis examines the leaked Claude Code source to extract production-ready patterns, architectural decisions, and best practices that make it a superior codebase. The focus is on actionable patterns that can be adopted for building enterprise-grade AI agent systems.

**Key Takeaways:**
1. **Tool-based architecture** with self-contained, permission-aware modules
2. **Feature flag system** for dead code elimination at build time
3. **Lazy loading and parallel prefetching** for performance
4. **Multi-agent coordination** with isolated execution contexts
5. **Comprehensive permission system** with multiple modes
6. **Cost tracking and token budgeting** as first-class concerns

---

## 1. PROJECT STRUCTURE

### 1.1 File Organization

Claude Code uses a **flat-ish hybrid structure** that balances discoverability with modularity:

```
src/
├── main.tsx                 # CLI entrypoint and orchestration
├── commands.ts              # Slash command registry (25K LOC)
├── tools.ts                 # Tool registry (17K LOC)
├── Tool.ts                  # Tool type definitions (30K LOC)
├── QueryEngine.ts           # Core LLM query engine (47K LOC)
├── context.ts               # Context collection logic
├── cost-tracker.ts          # Token cost tracking
│
├── commands/                # ~50 slash command implementations
├── tools/                   # ~40 tool implementations
├── components/              # ~140 Ink UI components
├── hooks/                   # React hooks
├── services/                # External service integrations
├── screens/                 # Full-screen UIs (Doctor, REPL, Resume)
├── types/                   # Type definitions
├── utils/                   # Utilities
│
├── bridge/                  # IDE and remote control bridge
├── coordinator/             # Multi-agent coordination
├── plugins/                 # Plugin system
├── skills/                  # Skill workflows
└── ... (30+ more specialized directories)
```

### 1.2 Key Architectural Principles

**Pattern 1: Centralized Registries**
- Single source of truth for tools (`tools.ts`) and commands (`commands.ts`)
- Registry functions use memoization to avoid recomputation
- Enables dynamic filtering based on permissions, feature flags, environment

```typescript
// From tools.ts
export function getAllBaseTools(): Tools {
  return [
    AgentTool,
    TaskOutputTool,
    BashTool,
    ...(hasEmbeddedSearchTools() ? [] : [GlobTool, GrepTool]),
    ExitPlanModeV2Tool,
    FileReadTool,
    FileEditTool,
    // ... 40+ tools
  ]
}

export const getTools = (permissionContext: ToolPermissionContext): Tools => {
  // Filter by permissions, environment flags, feature flags
  return filterToolsByDenyRules(getAllBaseTools(), permissionContext)
}
```

**Pattern 2: Feature Flag-Based Dead Code Elimination**

Uses Bun's `bun:bundle` feature flags to **completely remove unused code** at build time:

```typescript
import { feature } from 'bun:bundle'

const SleepTool = feature('PROACTIVE') || feature('KAIROS')
  ? require('./tools/SleepTool/SleepTool.js').SleepTool
  : null

const cronTools = feature('AGENT_TRIGGERS')
  ? [CronCreateTool, CronDeleteTool, CronListTool]
  : []
```

**Why this matters:** External builds exclude internal-only features without runtime checks. No leaked proprietary code, smaller bundle size.

**Pattern 3: Type-Safe Command and Tool Definitions**

Every tool and command is a fully typed object with schema validation:

```typescript
export type Tool<
  Input extends AnyObject = AnyObject,
  Output = unknown,
  P extends ToolProgressData = ToolProgressData,
> = {
  name: string
  aliases?: string[]  // For backwards compatibility
  inputSchema: Input  // Zod schema
  outputSchema?: z.ZodType<unknown>

  // Core functions
  call(args, context, canUseTool, parentMessage, onProgress): Promise<ToolResult<Output>>
  description(input, options): Promise<string>

  // Permissions and safety
  checkPermissions(input, context): Promise<PermissionResult>
  validateInput?(input, context): Promise<ValidationResult>
  isReadOnly(input): boolean
  isDestructive?(input): boolean
  isConcurrencySafe(input): boolean

  // Behavior control
  interruptBehavior?(): 'cancel' | 'block'
  requiresUserInteraction?(): boolean
  isEnabled(): boolean

  // Tool search and deferral
  searchHint?: string
  shouldDefer?: boolean
  alwaysLoad?: boolean

  maxResultSizeChars: number
}
```

---

## 2. KEY ARCHITECTURAL PATTERNS

### 2.1 The QueryEngine: Stateful Conversation Manager

**Pattern:** Separate query lifecycle management into a standalone class

```typescript
export class QueryEngine {
  private config: QueryEngineConfig
  private mutableMessages: Message[]
  private abortController: AbortController
  private permissionDenials: SDKPermissionDenial[]
  private totalUsage: NonNullableUsage
  private readFileState: FileStateCache

  constructor(config: QueryEngineConfig) {
    this.config = config
    this.mutableMessages = config.initialMessages ?? []
    this.abortController = config.abortController ?? createAbortController()
    this.totalUsage = EMPTY_USAGE
  }

  async *submitMessage(prompt, options?): AsyncGenerator<SDKMessage, void, unknown> {
    // Single turn within the same conversation
    // State persists across turns
  }
}
```

**Benefits:**
- Clear separation between query orchestration and UI/SDK concerns
- State (messages, file cache, usage) persists across conversation turns
- Generator pattern for streaming responses
- Testable in isolation

### 2.2 Tool Permission System

**Pattern:** Multi-layered permission checks with mode-based behavior

**Permission Modes:**
1. `default` - Prompt user for each permission
2. `plan` - Model-initiated planning mode (less interruption)
3. `auto` - Auto-approve based on heuristics
4. `bypassPermissions` - No permission checks

**Permission Flow:**
```
1. validateInput() - Basic validation (path exists, etc.)
   ↓
2. checkPermissions() - Tool-specific permission logic
   ↓
3. Permission Context Rules:
   - alwaysDenyRules (highest priority)
   - alwaysAllowRules
   - alwaysAskRules
   ↓
4. User Prompt (if needed)
   ↓
5. Pre/PostToolUse Hooks (can override)
```

**Implementation:**
```typescript
export type ToolPermissionContext = DeepImmutable<{
  mode: PermissionMode
  additionalWorkingDirectories: Map<string, AdditionalWorkingDirectory>
  alwaysAllowRules: ToolPermissionRulesBySource
  alwaysDenyRules: ToolPermissionRulesBySource
  alwaysAskRules: ToolPermissionRulesBySource
  isBypassPermissionsModeAvailable: boolean
  shouldAvoidPermissionPrompts?: boolean
  awaitAutomatedChecksBeforeDialog?: boolean
}>
```

### 2.3 Cost Tracking as First-Class Concern

**Pattern:** Comprehensive cost tracking with budget enforcement

```typescript
// From cost-tracker.ts
export type StoredCostState = {
  totalCostUSD: number
  totalAPIDuration: number
  totalAPIDurationWithoutRetries: number
  totalToolDuration: number
  totalLinesAdded: number
  totalLinesRemoved: number
  modelUsage: { [modelName: string]: ModelUsage }
}

export function saveCurrentSessionCosts(fpsMetrics?: FpsMetrics): void {
  saveCurrentProjectConfig(current => ({
    ...current,
    lastCost: getTotalCostUSD(),
    lastAPIDuration: getTotalAPIDuration(),
    lastModelUsage: Object.fromEntries(
      Object.entries(getModelUsage()).map(([model, usage]) => [
        model, {
          inputTokens: usage.inputTokens,
          outputTokens: usage.outputTokens,
          cacheReadInputTokens: usage.cacheReadInputTokens,
          cacheCreationInputTokens: usage.cacheCreationInputTokens,
          costUSD: usage.costUSD,
        }
      ])
    ),
    lastSessionId: getSessionId(),
  }))
}
```

**Budget Enforcement:**
```typescript
// QueryEngine supports maxBudgetUsd
const config: QueryEngineConfig = {
  maxBudgetUsd: 10.0,  // Hard stop at $10
  maxTurns: 50,        // Hard stop at 50 turns
  // ... other config
}
```

### 2.4 Context Management and Caching

**Pattern:** Memoized context builders with cache invalidation

```typescript
// From context.ts
export const getSystemContext = memoize(async (): Promise<{ [k: string]: string }> => {
  const gitStatus = await getGitStatus()
  const injection = getSystemPromptInjection()  // For cache breaking

  return {
    ...(gitStatus && { gitStatus }),
    ...(injection && { cacheBreaker: `[CACHE_BREAKER: ${injection}]` }),
  }
})

export const getUserContext = memoize(async (): Promise<{ [k: string]: string }> => {
  const claudeMd = getClaudeMds(filterInjectedMemoryFiles(await getMemoryFiles()))

  return {
    ...(claudeMd && { claudeMd }),
    currentDate: `Today's date is ${getLocalISODate()}.`,
  }
})

// Cache invalidation
export function setSystemPromptInjection(value: string | null): void {
  systemPromptInjection = value
  getUserContext.cache.clear?.()
  getSystemContext.cache.clear?.()
}
```

**Git Status Optimization:**
```typescript
const MAX_STATUS_CHARS = 2000

export const getGitStatus = memoize(async (): Promise<string | null> => {
  // Parallel execution of multiple git commands
  const [branch, mainBranch, status, log, userName] = await Promise.all([
    getBranch(),
    getDefaultBranch(),
    execFileNoThrow(gitExe(), ['--no-optional-locks', 'status', '--short']),
    execFileNoThrow(gitExe(), ['--no-optional-locks', 'log', '--oneline', '-n', '5']),
    execFileNoThrow(gitExe(), ['config', 'user.name']),
  ])

  // Truncate if too long
  const truncatedStatus = status.length > MAX_STATUS_CHARS
    ? status.substring(0, MAX_STATUS_CHARS) + '\n... (truncated)'
    : status

  return formatGitStatus(branch, mainBranch, truncatedStatus, log, userName)
})
```

### 2.5 Multi-Agent Coordination

**Pattern:** Isolated execution contexts for parallel agents

```typescript
export type ToolUseContext = {
  options: {
    commands: Command[]
    tools: Tools
    mcpClients: MCPServerConnection[]
    agentDefinitions: AgentDefinitionsResult
    maxBudgetUsd?: number
    customSystemPrompt?: string
    // ... other options
  }
  abortController: AbortController
  readFileState: FileStateCache
  getAppState(): AppState
  setAppState(f: (prev: AppState) => AppState): void

  // Subagent-specific overrides
  agentId?: AgentId
  agentType?: string
  preserveToolUseResults?: boolean
  localDenialTracking?: DenialTrackingState
  renderedSystemPrompt?: SystemPrompt
}
```

**Subagent Context Cloning:**
```typescript
// From comments in Tool.ts:
// setAppStateForTasks: Always-shared setAppState for session-scoped
// infrastructure. Unlike setAppState (which is no-op for async agents),
// this always reaches the root store so agents at any nesting depth
// can register/clean up infrastructure that outlives a single turn.
setAppStateForTasks?: (f: (prev: AppState) => AppState) => void
```

---

## 3. WORKFLOW PATTERNS

### 3.1 Parallel Prefetching for Fast Startup

**Pattern:** Load expensive resources in parallel before heavy imports

```typescript
// From main.tsx conceptually:
async function startup() {
  // Phase 1: Parallel prefetch (fast, I/O-bound)
  const [mdmSettings, keychainData, apiConnection] = await Promise.all([
    loadMDMSettings(),
    loadKeychainCredentials(),
    warmUpAPIConnection(),
  ])

  // Phase 2: Heavy imports (slow, CPU-bound)
  const { QueryEngine } = await import('./QueryEngine.js')
  const { renderUI } = await import('./components/App.js')

  // Phase 3: Initialization
  return initializeApp(mdmSettings, keychainData, apiConnection)
}
```

### 3.2 Lazy Loading for Conditional Features

**Pattern:** Dynamic imports for large dependencies

```typescript
// From commands.ts
const usageReport: Command = {
  type: 'prompt',
  name: 'insights',
  description: 'Generate a report analyzing your Claude Code sessions',
  async getPromptForCommand(args, context) {
    // insights.ts is 113KB (3200 lines). Only load when invoked.
    const real = (await import('./commands/insights.js')).default
    return real.getPromptForCommand(args, context)
  },
}
```

### 3.3 Tool Result Budget and Storage

**Pattern:** Persist large tool results to disk, send previews to LLM

```typescript
export type Tool = {
  // Maximum size before persisting to disk
  maxResultSizeChars: number  // e.g., 50000

  // Special case: Set to Infinity for tools that self-bound
  // (e.g., FileReadTool already limits its output)
}

// Content replacement state tracks what's been persisted
export type ContentReplacementState = {
  // Maps tool_use_id to file path
  persistedResults: Map<string, string>
}
```

### 3.4 Streaming Response Handling

**Pattern:** Generator-based streaming with progress updates

```typescript
async *submitMessage(prompt, options): AsyncGenerator<SDKMessage, void, unknown> {
  // Process user input
  const { messages, shouldQuery } = await processUserInput(...)

  // Yield user message acknowledgment
  for (const msg of messagesToAck) {
    yield { type: 'user_message', message: msg }
  }

  // Stream query results
  for await (const message of query(...)) {
    if (message.type === 'assistant') {
      yield { type: 'assistant_message', message }
    } else if (message.type === 'tool_progress') {
      yield { type: 'progress', data: message.data }
    }
  }
}
```

---

## 4. DISTRIBUTION AND PACKAGING

### 4.1 The Build Process

**Key Characteristics:**
- **Runtime:** Bun (not Node.js) - single executable bundling
- **Feature Flags:** `bun:bundle` for compile-time code elimination
- **Source Maps:** Published alongside bundles (led to the leak!)
- **Platform Targets:** macOS, Linux, Windows (via WSL or native)

**Build Configuration (Inferred):**
```typescript
// build.ts (conceptual)
import { build } from 'bun'

await build({
  entrypoints: ['./src/main.tsx'],
  outdir: './dist',
  target: 'bun',
  define: {
    'feature("PROACTIVE")': 'false',      // External build
    'feature("KAIROS")': 'false',         // Internal only
    'feature("BRIDGE_MODE")': 'true',     // IDE integration
    'process.env.USER_TYPE': '"external"', // Not 'ant'
  },
  sourcemap: 'external',  // This caused the leak!
})
```

### 4.2 npm Package Structure

```
@anthropic/claude-code/
├── dist/
│   ├── cli.js              # Bundled entry point
│   ├── cli.js.map          # Source map (leaked the source!)
│   └── ...
├── package.json
└── README.md
```

**Lesson:** Source maps should reference inline or obfuscated sources, not production code URLs.

### 4.3 Plugin and Extension Architecture

**Pattern:** Well-defined plugin interfaces

```typescript
export type Plugin = {
  name: string
  version: string
  commands?: Command[]
  skills?: Skill[]
  tools?: Tool[]
  hooks?: {
    preToolUse?: PreToolUseHook
    postToolUse?: PostToolUseHook
    sessionStart?: SessionStartHook
  }
}

// Plugin loading
export async function loadPlugin(path: string): Promise<Plugin> {
  const module = await import(path)
  return validatePlugin(module.default)
}
```

---

## 5. API DESIGN

### 5.1 Tool API Design

**Core Principles:**
1. **Input/Output Schemas:** Every tool has Zod schemas for validation
2. **Progress Callbacks:** Long-running tools report incremental progress
3. **Permission Checks:** Separate validation and permission layers
4. **Concurrency Control:** Tools declare if they're safe to run in parallel
5. **Interrupt Behavior:** Tools declare how to handle user interruption

**Example Tool Implementation:**
```typescript
export const BashTool: Tool = {
  name: 'Bash',
  inputSchema: z.object({
    command: z.string(),
    description: z.string().optional(),
    timeout: z.number().optional().default(120000),
  }),

  async call(args, context, canUseTool, parentMessage, onProgress) {
    // Permission check
    const permission = await canUseTool(this, args, context, parentMessage, toolUseId)
    if (permission.behavior !== 'allow') {
      return { data: { error: 'Permission denied' } }
    }

    // Execute with progress updates
    const process = spawn(args.command, { timeout: args.timeout })
    process.on('data', chunk => {
      onProgress?.({ toolUseID, data: { type: 'bash_progress', chunk } })
    })

    const result = await process.wait()
    return { data: result }
  },

  async description(input) {
    return `Run bash command: ${input.command}`
  },

  async checkPermissions(input, context) {
    // Dangerous commands require explicit permission
    if (input.command.includes('rm -rf')) {
      return { behavior: 'ask', reason: 'Destructive command' }
    }
    return { behavior: 'allow' }
  },

  isReadOnly(input) {
    return !modifiesFilesystem(input.command)
  },

  isConcurrencySafe(input) {
    return !modifiesGlobalState(input.command)
  },

  interruptBehavior() {
    return 'cancel'  // Kill the process on interrupt
  },

  maxResultSizeChars: 50000,
}
```

### 5.2 SDK API Design

**Pattern:** Clean separation between CLI and SDK modes

```typescript
// SDK Entrypoint
export class ClaudeAgent {
  private engine: QueryEngine

  constructor(config: AgentConfig) {
    this.engine = new QueryEngine({
      tools: getTools(config.permissions),
      commands: getCommands(),
      maxBudgetUsd: config.maxBudget,
      // ... other config
    })
  }

  async *chat(message: string): AsyncGenerator<AgentMessage, void, unknown> {
    for await (const msg of this.engine.submitMessage(message)) {
      yield this.transformToSDKMessage(msg)
    }
  }

  getUsage(): UsageStats {
    return {
      totalCost: getTotalCost(),
      totalTokens: getTotalInputTokens() + getTotalOutputTokens(),
      modelUsage: getModelUsage(),
    }
  }
}
```

**Message Types:**
```typescript
export type SDKMessage =
  | { type: 'user_message', message: UserMessage }
  | { type: 'assistant_message', message: AssistantMessage }
  | { type: 'tool_use', tool: string, input: any }
  | { type: 'tool_result', tool: string, output: any }
  | { type: 'progress', data: ToolProgressData }
  | { type: 'permission_denial', tool: string, reason: string }
  | { type: 'compact_boundary', metadata: CompactMetadata }
```

---

## 6. BEST PRACTICES AND LESSONS

### 6.1 Type Safety Everywhere

**Pattern:** Use Zod for runtime validation, TypeScript for compile-time safety

```typescript
import { z } from 'zod/v4'

// Define schema
const BashInputSchema = z.object({
  command: z.string(),
  description: z.string().optional(),
  timeout: z.number().optional(),
})

// Infer type from schema
type BashInput = z.infer<typeof BashInputSchema>

// Runtime validation
const validated = BashInputSchema.parse(input)
```

### 6.2 Error Categorization

**Pattern:** Structured error handling with retry logic

```typescript
export function categorizeRetryableAPIError(error: Error): {
  isRetryable: boolean
  category: 'rate_limit' | 'overloaded' | 'network' | 'auth' | 'other'
  retryAfterMs?: number
} {
  if (error.message.includes('rate_limit_error')) {
    return {
      isRetryable: true,
      category: 'rate_limit',
      retryAfterMs: extractRetryAfter(error),
    }
  }
  // ... other categorizations
}
```

### 6.3 Telemetry and Analytics

**Pattern:** Structured event logging with PII protection

```typescript
export type AnalyticsMetadata_I_VERIFIED_THIS_IS_NOT_CODE_OR_FILEPATHS = {
  [key: string]: string | number | boolean
}

export function logEvent(
  eventName: string,
  metadata: AnalyticsMetadata_I_VERIFIED_THIS_IS_NOT_CODE_OR_FILEPATHS
) {
  // Send to analytics backend
  // Type name enforces PII review
}
```

### 6.4 File State Caching

**Pattern:** Content-based caching with LRU eviction

```typescript
export class FileStateCache {
  private cache: Map<string, { content: string, mtime: number }>
  private maxSize: number

  async get(path: string): Promise<string | null> {
    const cached = this.cache.get(path)
    if (!cached) return null

    const stat = await fs.stat(path)
    if (stat.mtimeMs !== cached.mtime) {
      // File changed, invalidate
      this.cache.delete(path)
      return null
    }

    return cached.content
  }

  set(path: string, content: string, mtime: number): void {
    if (this.cache.size >= this.maxSize) {
      // LRU eviction: delete oldest entry
      const firstKey = this.cache.keys().next().value
      this.cache.delete(firstKey)
    }
    this.cache.set(path, { content, mtime })
  }
}
```

### 6.5 Session Persistence

**Pattern:** Incremental transcript writing with async flush

```typescript
export async function recordTranscript(messages: Message[]): Promise<void> {
  const sessionDir = getSessionStorageDir()
  const transcriptPath = path.join(sessionDir, 'transcript.jsonl')

  // Append new messages (JSONL format for streaming)
  for (const msg of messages) {
    await fs.appendFile(transcriptPath, JSON.stringify(msg) + '\n')
  }
}

export async function flushSessionStorage(): Promise<void> {
  // Force fsync for critical operations (commit, exit)
  const transcriptFd = await fs.open(transcriptPath, 'a')
  await transcriptFd.sync()
  await transcriptFd.close()
}
```

---

## 7. TESTING INFRASTRUCTURE

### 7.1 Tool Testing Pattern

**Pattern:** Mock contexts for isolated tool testing

```typescript
// test/toolTestUtils.ts
export function createMockToolContext(overrides?: Partial<ToolUseContext>): ToolUseContext {
  return {
    options: {
      commands: [],
      tools: [],
      debug: false,
      verbose: false,
      mainLoopModel: 'claude-3-5-sonnet-20241022',
      thinkingConfig: { type: 'disabled' },
      mcpClients: [],
      mcpResources: {},
      isNonInteractiveSession: true,
      agentDefinitions: { activeAgents: [], allAgents: [] },
    },
    abortController: new AbortController(),
    readFileState: new FileStateCache(),
    getAppState: () => mockAppState,
    setAppState: jest.fn(),
    messages: [],
    updateFileHistoryState: jest.fn(),
    updateAttributionState: jest.fn(),
    setInProgressToolUseIDs: jest.fn(),
    setResponseLength: jest.fn(),
    ...overrides,
  }
}

// test/BashTool.test.ts
describe('BashTool', () => {
  it('executes simple commands', async () => {
    const context = createMockToolContext()
    const result = await BashTool.call(
      { command: 'echo hello' },
      context,
      mockCanUseTool,
      mockParentMessage,
    )

    expect(result.data.stdout).toBe('hello\n')
  })
})
```

### 7.2 Permission Testing

**Pattern:** Declarative permission test cases

```typescript
describe('BashTool permissions', () => {
  const testCases = [
    { command: 'ls', expected: 'allow', reason: 'Read-only command' },
    { command: 'rm -rf /', expected: 'ask', reason: 'Destructive command' },
    { command: 'curl api.example.com', expected: 'ask', reason: 'Network access' },
  ]

  for (const { command, expected, reason } of testCases) {
    it(`${expected}s "${command}" - ${reason}`, async () => {
      const result = await BashTool.checkPermissions(
        { command },
        createMockToolContext(),
      )
      expect(result.behavior).toBe(expected)
    })
  }
})
```

---

## 8. DOCUMENTATION PATTERNS

### 8.1 Self-Documenting Tool Descriptions

**Pattern:** Dynamic descriptions based on input

```typescript
async description(input, options) {
  if (this.isReadOnly(input)) {
    return `Read file: ${input.file_path} (read-only operation)`
  } else {
    return `Write file: ${input.file_path} (will modify file system)`
  }
}
```

### 8.2 Inline Type Documentation

**Pattern:** Use TypeScript comments for domain knowledge

```typescript
/**
 * Always-shared setAppState for session-scoped infrastructure (background
 * tasks, session hooks). Unlike setAppState, which is no-op for async agents
 * (see createSubagentContext), this always reaches the root store so agents
 * at any nesting depth can register/clean up infrastructure that outlives
 * a single turn. Only set by createSubagentContext; main-thread contexts
 * fall back to setAppState.
 */
setAppStateForTasks?: (f: (prev: AppState) => AppState) => void
```

---

## 9. PATTERNS TO ADOPT FOR TSMv1

### 9.1 Immediate Wins

**1. Tool Registry Pattern**
```typescript
// backend/src/ai/tools/registry.ts
export function getAllTools(): Tool[] {
  return [
    CodeAnalysisTool,
    VulnerabilityScannerTool,
    AIReasonerTool,
    // ... all tools
  ]
}

export function getToolsForContext(context: SecurityContext): Tool[] {
  return getAllTools()
    .filter(tool => tool.isEnabled())
    .filter(tool => hasPermission(context, tool))
}
```

**2. Cost Tracking**
```typescript
// backend/src/core/billing/cost_tracker.py
@dataclass
class CostState:
    total_cost_usd: float = 0.0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    model_usage: Dict[str, ModelUsage] = field(default_factory=dict)

    def add_usage(self, model: str, usage: Usage):
        if model not in self.model_usage:
            self.model_usage[model] = ModelUsage()
        self.model_usage[model].add(usage)
        self.total_cost_usd += calculate_cost(model, usage)
```

**3. Permission System**
```python
# backend/src/core/permissions.py
class PermissionMode(Enum):
    DEFAULT = "default"      # Prompt for each action
    AUTO = "auto"            # Auto-approve safe actions
    STRICT = "strict"        # Require explicit approval for everything

@dataclass
class PermissionContext:
    mode: PermissionMode
    always_allow_rules: List[Rule]
    always_deny_rules: List[Rule]

    def check_permission(self, tool: Tool, input: dict) -> PermissionResult:
        # 1. Check deny rules first
        if self.matches_deny_rule(tool, input):
            return PermissionResult(behavior="deny")

        # 2. Check allow rules
        if self.matches_allow_rule(tool, input):
            return PermissionResult(behavior="allow")

        # 3. Fall back to mode-based decision
        if self.mode == PermissionMode.AUTO:
            return PermissionResult(behavior="allow" if tool.is_safe(input) else "ask")
        return PermissionResult(behavior="ask")
```

**4. Feature Flags**
```python
# backend/src/core/feature_flags.py
class FeatureFlags:
    ENTERPRISE_INTEGRATIONS = os.getenv("FEATURE_ENTERPRISE") == "true"
    P2P_NETWORK = os.getenv("FEATURE_P2P") == "true"
    ADVANCED_BILLING = os.getenv("FEATURE_BILLING") == "true"

# Use in code
if FeatureFlags.ENTERPRISE_INTEGRATIONS:
    from src.integrations import GithubConnector
```

**5. QueryEngine Pattern**
```python
# backend/src/ai/query_engine.py
class QueryEngine:
    def __init__(self, config: QueryEngineConfig):
        self.config = config
        self.messages: List[Message] = config.initial_messages or []
        self.total_usage = Usage()
        self.permission_denials: List[PermissionDenial] = []

    async def submit_message(self, prompt: str) -> AsyncIterator[SDKMessage]:
        # Process input
        new_messages = await process_user_input(prompt)
        self.messages.extend(new_messages)

        # Stream query results
        async for message in query(self.messages, self.config):
            yield message
            if message.type == "assistant":
                self.messages.append(message)
```

### 9.2 Medium-Term Improvements

**1. Tool Search and Deferral**
- Implement lazy tool loading for large tool sets
- Add search hints to tools for better discovery

**2. Multi-Agent Coordination**
- Adopt isolated execution contexts for parallel agents
- Implement agent budget tracking

**3. Plugin Architecture**
- Define plugin interfaces for extensibility
- Create plugin loader with validation

### 9.3 Long-Term Goals

**1. IDE Bridge Protocol**
- Design bidirectional communication for VS Code extension
- Implement remote control capabilities

**2. Advanced Caching**
- Implement prompt caching for repeated contexts
- Add file state caching with LRU eviction

**3. Comprehensive Telemetry**
- Structured event logging with PII protection
- Performance metrics and profiling

---

## 10. CRITICAL LESSONS LEARNED

### 10.1 Security

**Lesson 1: Source Map Security**
- **Mistake:** Publishing source maps that reference unobfuscated production code
- **Fix:** Either inline sources in maps or reference obfuscated/minified code
- **For TSMv1:** Never publish source maps in production builds

**Lesson 2: Permission Boundaries**
- **Pattern:** Always validate at multiple layers (validation → permissions → hooks)
- **For TSMv1:** Implement defense in depth for security-critical operations

### 10.2 Performance

**Lesson 1: Parallel Prefetching**
- **Pattern:** Load I/O-bound resources in parallel before CPU-bound imports
- **For TSMv1:** Apply to database connections, config loading, auth tokens

**Lesson 2: Lazy Loading**
- **Pattern:** Dynamic imports for large or rarely-used dependencies
- **For TSMv1:** Apply to enterprise integrations, heavy ML models

### 10.3 Architecture

**Lesson 1: Centralized Registries**
- **Pattern:** Single source of truth for tools, commands, plugins
- **For TSMv1:** Create registries for agents, skills, integrations

**Lesson 2: Generator-Based Streaming**
- **Pattern:** Use async generators for streaming responses
- **For TSMv1:** Apply to AI responses, real-time monitoring, event streams

**Lesson 3: State Management**
- **Pattern:** Separate mutable session state from immutable config
- **For TSMv1:** Clear separation between user state, system state, runtime state

---

## 11. CODE EXAMPLES TO ADOPT

### 11.1 Tool Definition Template

```python
# backend/src/ai/tools/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Generic, TypeVar, AsyncIterator, Optional
from pydantic import BaseModel

TInput = TypeVar('TInput', bound=BaseModel)
TOutput = TypeVar('TOutput')
TProgress = TypeVar('TProgress', bound=BaseModel)

@dataclass
class ToolResult(Generic[TOutput]):
    data: TOutput
    new_messages: List[Message] = field(default_factory=list)

class Tool(ABC, Generic[TInput, TOutput, TProgress]):
    name: str
    description: str
    input_schema: Type[TInput]
    output_schema: Type[TOutput]
    max_result_size_chars: int = 50000

    @abstractmethod
    async def call(
        self,
        input: TInput,
        context: ToolUseContext,
        can_use_tool: CanUseToolFn,
        on_progress: Optional[Callable[[TProgress], None]] = None,
    ) -> ToolResult[TOutput]:
        pass

    @abstractmethod
    async def check_permissions(
        self,
        input: TInput,
        context: ToolUseContext,
    ) -> PermissionResult:
        pass

    def is_read_only(self, input: TInput) -> bool:
        return False

    def is_destructive(self, input: TInput) -> bool:
        return False

    def is_concurrency_safe(self, input: TInput) -> bool:
        return True

    def is_enabled(self) -> bool:
        return True
```

### 11.2 Permission Check Implementation

```python
# backend/src/core/permissions/checker.py
class PermissionChecker:
    def __init__(self, context: PermissionContext):
        self.context = context

    async def check(
        self,
        tool: Tool,
        input: dict,
    ) -> PermissionResult:
        # Step 1: Validate input
        validation = await tool.validate_input(input)
        if not validation.result:
            return PermissionResult(
                behavior="deny",
                reason=validation.message,
            )

        # Step 2: Check deny rules (highest priority)
        if deny_rule := self._get_deny_rule(tool, input):
            return PermissionResult(
                behavior="deny",
                reason=f"Blocked by rule: {deny_rule}",
            )

        # Step 3: Check allow rules
        if allow_rule := self._get_allow_rule(tool, input):
            return PermissionResult(
                behavior="allow",
                reason=f"Allowed by rule: {allow_rule}",
            )

        # Step 4: Tool-specific permission check
        tool_result = await tool.check_permissions(input, self.context)
        if tool_result.behavior != "allow":
            return tool_result

        # Step 5: Mode-based decision
        if self.context.mode == PermissionMode.AUTO:
            if tool.is_read_only(input):
                return PermissionResult(behavior="allow")
            return PermissionResult(
                behavior="ask",
                reason="Requires user confirmation in auto mode",
            )

        return PermissionResult(behavior="allow")
```

### 11.3 Cost Tracking Integration

```python
# backend/src/ai/query_engine.py
from src.core.billing.cost_tracker import CostTracker

class QueryEngine:
    def __init__(self, config: QueryEngineConfig):
        self.config = config
        self.cost_tracker = CostTracker(max_budget_usd=config.max_budget_usd)

    async def submit_message(self, prompt: str) -> AsyncIterator[SDKMessage]:
        # Check budget before starting
        if self.cost_tracker.is_budget_exceeded():
            raise BudgetExceededError(
                f"Budget exceeded: ${self.cost_tracker.total_cost_usd:.4f} / ${self.config.max_budget_usd}"
            )

        # Execute query
        async for message in self._execute_query(prompt):
            # Track usage
            if message.type == "usage":
                self.cost_tracker.add_usage(
                    model=message.model,
                    usage=message.usage,
                )

            yield message

        # Save costs to session
        await self.cost_tracker.save_to_session(self.session_id)
```

---

## 12. CONCLUSION

Claude Code represents a mature, production-ready AI agent system with sophisticated patterns for:

1. **Modularity:** Tool and command registries with dynamic filtering
2. **Safety:** Multi-layered permission system with mode-based behavior
3. **Performance:** Parallel prefetching, lazy loading, caching
4. **Cost Management:** Comprehensive tracking with budget enforcement
5. **Extensibility:** Plugin architecture and feature flags
6. **Developer Experience:** Type-safe APIs, self-documenting tools, comprehensive testing

**Top 5 Patterns to Adopt Immediately:**

1. **Tool Registry Pattern** - Centralized, filterable tool management
2. **Permission System** - Multi-mode, rule-based permission checking
3. **Cost Tracking** - Session-persistent, model-aware cost tracking
4. **QueryEngine Pattern** - Stateful conversation management
5. **Feature Flags** - Environment-based feature toggling

**Implementation Priority for TSMv1:**

| Pattern | Priority | Effort | Impact |
|---------|----------|--------|--------|
| Tool Registry | HIGH | Low | High |
| Permission System | HIGH | Medium | High |
| Cost Tracking | HIGH | Low | High |
| Feature Flags | MEDIUM | Low | Medium |
| QueryEngine | MEDIUM | High | High |
| Lazy Loading | LOW | Low | Medium |
| Plugin System | LOW | High | Medium |

---

**Document Version:** 1.0
**Analysis Completed:** April 4, 2026
**Analyst:** AI Architecture Review Team
