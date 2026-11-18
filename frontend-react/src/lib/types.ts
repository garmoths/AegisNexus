/**
 * Types for the AegisNexus HTTP API (`/api/v2`). They mirror the Pydantic
 * response models in `modules/<module>/schemas.py` and `app/routers/*`.
 */

export type Role = 'free' | 'premium' | 'corporate' | 'admin'

/** Every error response: `{detail, error: {code, status, request_id}}` (see app/errors.py). */
export interface ApiErrorBody {
  detail: string | Array<{ loc: (string | number)[]; msg: string; type: string }>
  error?: { code: string; status: number; request_id: string }
}

export interface Me {
  email: string
  full_name: string | null
  role: Role
}

export interface LoginResponse {
  email: string
  role: Role
  is_active: boolean
}

export interface RegisterResponse {
  email: string
  api_key: string
  role: Role
  message: string
}

// ── Phishing detector ────────────────────────────────────────────────────

export type ScanStatus = 'complete' | 'analyzing' | 'queued' | 'running' | 'retrying' | 'failed' | 'timeout' | 'expired'

/** Verdict produced by the scoring pipeline; its detail fields evolve with the scorer. */
export interface ScanResult {
  status: ScanStatus
  job_id?: string
  job_state?: string
  url?: string
  risk_score?: number
  safety_score?: number
  score?: number
  risk_level?: string
  is_safe?: boolean
  sources?: unknown[]
  details?: unknown[]
  message?: string
  error?: string
  [key: string]: unknown
}

export interface PhishingRow {
  id: number
  url: string | null
  domain: string | null
  target: string
  status: string
  submission_time: string | null
  phish_id?: string | null
}

export interface Paged<T> {
  data: T[]
  page: number
  total_pages: number
  total: number
}

export interface ScanHistoryRow {
  url: string
  risk_score: number
  safety_score: number
  risk_level: string
  checked_at: string | null
  is_safe: boolean
}

export interface PhishingStats {
  stats: { total_urls: number; phishing_count?: number; safe_count?: number; today_scans?: number; [key: string]: unknown }
  module: string
}

// ── Honeypot / IOC ───────────────────────────────────────────────────────

export interface IOCStatistics {
  status: 'success'
  stats: { total_iocs: number; high_risk_count: number; medium_risk_count: number; low_risk_count: number; last_update: string }
  total_records: number
  today_added: number
  weekly_growth: { date: string; count: number }[]
  risk_distribution: { range: string; count: number; percentage: number }[]
  top_threats: { type: string; count: number }[]
  source_breakdown: { source: string; count: number }[]
  last_updated: string
}

export interface IOCRow {
  id?: number
  value: string
  type: string
  threat_type: string
  risk_score: number
  confidence?: number
  source: string
  detection_count: number | null
  first_seen?: string | null
  last_seen?: string | null
}

export interface IOCSearchResult {
  status: 'success'
  query: string
  found: number
  results: IOCRow[]
}

// ── Workspace ────────────────────────────────────────────────────────────

export interface WatchItem {
  id: number
  kind: string
  value: string
  last_checked_at: string | null
  last_error: string | null
  last_result: Record<string, unknown> | null
}

export interface UserNotification {
  id: number
  title: string
  detail: { value?: string; risk_score?: number; [key: string]: unknown } | null
  read_at: string | null
  created_at: string | null
}

export interface Report {
  id: number
  user_description: string
  attack_type: string | null
  risk_score: number | null
  protection_plan: string | null
  ai_analysis: Record<string, unknown> | null
  status: 'open' | 'in_progress' | 'resolved'
  action_steps: { text: string; done: boolean }[]
  pdf_status: string
  has_pdf: boolean
  created_at: string | null
  message?: string
}

export interface AdminUser {
  id: number
  email: string
  full_name: string | null
  role: Role
  is_active: boolean
  created_at: string | null
}

export interface SmsAnalysis {
  risk_score: number
  category: string
  confidence: number
  action: 'BLOCK' | 'WARN' | 'MONITOR' | 'ALLOW' | string
  indicators: string[]
  urls: { url: string; is_suspicious: boolean; reason: string; in_ioc_db: boolean; ioc_risk_score: number | null }[]
  explanation: string
  analyzed_at: string
}

// ── Operations (admin) ───────────────────────────────────────────────────

export interface TaskState {
  state: string
  task_id?: string
  started_at?: string
  finished_at?: string
  last_success_at?: string
  last_error?: string
}

export interface Operations {
  broker: { available: boolean; queues: Record<string, { waiting: number; consumers: number }>; error?: string }
  workers: { hostname: string; seen_at: string }[]
  outbox_pending: number
  ioc_last_seen: string | null
  tasks: Record<string, TaskState>
}

export interface Feedback {
  id: number
  report_id: number | null
  url: string | null
  expected_verdict: 'safe' | 'dangerous' | 'uncertain'
  reason: string
  status: string
  review_note: string | null
  created_at: string | null
}

// ── Discovery crawler (/api/v2/crawler) ──────────────────────────────────

export interface CrawlConfig {
  enabled: boolean
  browser_enabled: boolean
  daily_limit: number
  browser_limit: number
  excluded_hosts: string[]
}

export interface CrawlOverview {
  settings: CrawlConfig
  counts: Record<string, number>
  today_crawled: number
  today_browser: number
  worker: { state: string; [key: string]: unknown } | null
  certstream: { state: string; [key: string]: unknown } | null
  mode: string
}

export interface CrawlCandidate {
  id: number
  url: string
  host: string
  source: string
  reason: string
  state: string
  risk: number | null
  coverage: string
  attempts: number
  depth: number
  last_error: string | null
  created_at: string
  updated_at: string
  next_attempt_at: string | null
}

export interface CrawlEvidence { code: string; group?: string; label?: string; detail?: string; weight?: number }

export interface CrawlObservation {
  id: number
  final_url: string
  http_status: number
  live: boolean
  truncated: boolean
  fetched_at: string
  has_screenshot: boolean
  features: {
    title?: string
    brands: string[]
    forms: { fields: string[]; target_host: string | null; external: boolean; method: string }[]
    redirects: string[]
    links: string[]
    scripts: string[]
    trackers: string[]
    favicon_url: string | null
    [key: string]: unknown
  }
  assessment: { coverage: string; risk?: number; evidence: CrawlEvidence[]; [key: string]: unknown }
}

export interface CrawlDetail extends CrawlCandidate {
  fresh: boolean
  observations: CrawlObservation[]
  reviews: { decision: string; note: string; actor: string; created_at: string }[]
}

export interface CrawlRelated { candidate_id: number; url: string; reasons: string[]; [key: string]: unknown }

export interface CrawlSource {
  id: number
  name: string
  url: string
  kind: 'url_list' | 'ct_json' | 'certstream' | string
  enabled: boolean
  last_checked_at: string | null
  last_error: string | null
  added_count: number
}
