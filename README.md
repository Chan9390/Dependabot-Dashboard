## Dependabot Dashboard

A simple Python script to dump Dependabot alerts from all GitHub orgs and repos to PostgresDB.

Requires the following env variables to execute:
- `DB_USER`
- `DB_PASSWORD`
- `DB_HOST`
- `GH_HOST`
- `GH_TOKEN` (needs full repo access to query internal repos)

The script needs to be run everyday to visualize metrics over time.

**Note:** The script is tested on GitHub Enterprise Server. It's not tested on public GitHub.com or GitHub Enterprise Cloud.