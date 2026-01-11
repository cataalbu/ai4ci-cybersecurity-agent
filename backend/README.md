# Backend Threat Intel (AbuseIPDB)

Required env vars:
- `ABUSEIPDB_API_KEY` (required to enable)
- `ABUSEIPDB_BASE_URL` (default `https://api.abuseipdb.com/api/v2`)
- `ABUSEIPDB_MAX_AGE_DAYS` (default `90`)
- `ABUSEIPDB_TIMEOUT_SECONDS` (default `5`)
- `ABUSEIPDB_CACHE_TTL_SECONDS` (default `86400`)
- `ABUSEIPDB_RETRIES` (default `2`)

Example:
```
curl "http://localhost:8000/api/threat-intel/ip/8.8.8.8?max_age_days=30&verbose=true"
```

# Jira Cloud Integration

Create a Jira API token:
1. Go to https://id.atlassian.com/manage-profile/security/api-tokens
2. Create an API token and copy it.
3. Use the email address of your Jira account with the token.

Required env vars (enable integration when all are set):
- `JIRA_BASE_URL` (e.g., `https://your-domain.atlassian.net`)
- `JIRA_EMAIL`
- `JIRA_API_TOKEN`
- `JIRA_PROJECT_KEY`

Optional env vars:
- `JIRA_ISSUE_TYPE` (default `Incident`, falls back to `Task` if missing in Jira)
- `JIRA_DEFAULT_PRIORITY` (default none)
- `JIRA_LABELS` (comma-separated list, e.g. `ai-agent,network-defense`)
- `JIRA_TIMEOUT_SECONDS` (default `10`)
- `JIRA_RETRIES` (default `2`)

Notes:
- Jira ticket descriptions use the LLM incident summary stored in the database (`summary` field).
- Endpoint: `POST /api/incidents/{id}/jira/` (or `POST /api/incidents/{id}/escalate/jira/`)

# Slack Incident Notifications

Create a Slack App:
1. Go to https://api.slack.com/apps and create a new app.
2. Add the OAuth scope: `chat:write`.
3. Install the app to your workspace and copy the Bot User OAuth token.
4. Add the bot to the target channel (Channel settings → Integrations → Add apps).
5. Copy the channel ID (Channel details → About).

Required env vars (enable integration when all are set):
- `SLACK_ENABLED` (set to `true` to enable; defaults to `false`)
- `SLACK_BOT_TOKEN` (Bot User OAuth token, `xoxb-...`)
- `SLACK_CHANNEL_ID` (channel ID, e.g. `C0123456789`)

Optional env vars:
- `SLACK_ICON_EMOJI` (e.g. `:shield:`)
- `SLACK_BOT_NAME` (e.g. `NDR Bot`)
