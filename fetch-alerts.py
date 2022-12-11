from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
import json
from github import Github
import psycopg2
from datetime import date, datetime
import os

db_user = os.environ["DB_USER"]
db_password = os.environ["DB_PASSWORD"]
db_host = os.environ["DB_HOST"]
host = os.environ["GH_HOST"]
gh_token = os.environ["GH_TOKEN"]

connection = psycopg2.connect(user=db_user,
                                      password=db_password,
                                      host=db_host,
                                      port="5432",
                                      database="dependabot")

def initialize_db():
    try:
        cursor = connection.cursor()

        postgres_create_table = """ 
            create table if not exists dependabot_alerts(
                snapshot timestamp,
                gh_repo varchar(100),
                gh_org varchar(30),
                created_at timestamp,
                fixed_at timestamp,
                alert_number int,
                state varchar(10),
                dismissed_at timestamp,
                dismiss_reason varchar(300),
                dismisser varchar(30),
                vuln_ghsa_id varchar(30),
                vuln_severity varchar(15),
                vuln_summary text,
                vuln_package varchar(100),
                fix_pr_number int,
                fix_pr_title text,
                fix_merged_at timestamp
            );
            """
        cursor.execute(postgres_create_table)

        connection.commit()
        count = cursor.rowcount
    except (Exception, psycopg2.Error) as error:
        print("Failed to initialize dependabot_alerts table: ", error)

def insert_into_db(alert, gh_org, gh_repo):
    try:
        snapshot_date = date.today()
        snapshot_timestamp = datetime.strptime(
                str(snapshot_date), "%Y-%m-%d").strftime("%Y-%m-%dT00:00:00Z")
        repo = gh_org + "/" + gh_repo
        org = gh_org
        created_at = alert.get("createdAt")
        fixed_at = alert.get("fixedAt")

        alert_number = alert.get("number")
        state = alert.get("state")
        dismissed_at = alert.get("dismissedAt")
        dismiss_reason = alert.get("dismissReason")
        dismisser = None

        if alert.get("dismisser") is not None:
            dismisser = alert.get("dismisser").get("login")
        
        vuln_ghsa_id = alert.get("securityVulnerability").get("advisory").get("ghsaId")
        vuln_severity = alert.get("securityVulnerability").get("severity")
        vuln_summary = alert.get("securityVulnerability").get("advisory").get("summary")
        vuln_package = alert.get("securityVulnerability").get("package").get("name")

        fix_pr_number = None
        fix_pr_title = None
        fix_merged_at = None

        if alert.get("dependabotUpdate") is not None:
            if alert.get("dependabotUpdate").get("pullRequest") is not None:
                fix_pr_number = alert.get("dependabotUpdate").get("pullRequest").get("number")
                fix_pr_title = alert.get("dependabotUpdate").get("pullRequest").get("title")
                fix_merged_at = alert.get("dependabotUpdate").get("pullRequest").get("mergedAt")

        if state == "FIXED" or state == "DISMISSED":
            tmp_now = datetime.strptime(
                str(snapshot_date), "%Y-%m-%d")
            if fixed_at is not None:
                tmp_fixed_at = datetime.strptime(fixed_at, "%Y-%m-%dT%H:%M:%SZ")
                if tmp_fixed_at >= tmp_now:
                    state = "OPEN"
            if dismissed_at is not None:
                tmp_dismissed_at = datetime.strptime(dismissed_at, "%Y-%m-%dT%H:%M:%SZ")
                if tmp_dismissed_at >= tmp_now:
                    state = "OPEN"

        insert_query = """
            insert into dependabot_alerts (
                snapshot,
                gh_repo,
                gh_org,
                created_at,
                fixed_at,
                alert_number,
                state,
                dismissed_at,
                dismiss_reason,
                dismisser,
                vuln_ghsa_id,
                vuln_severity,
                vuln_summary,
                vuln_package,
                fix_pr_number,
                fix_pr_title,
                fix_merged_at
            ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        """

        db_values = (snapshot_timestamp, repo, org, created_at, fixed_at, alert_number, state, dismissed_at, dismiss_reason,
                         dismisser, vuln_ghsa_id, vuln_severity, vuln_summary, vuln_package, fix_pr_number, fix_pr_title, fix_merged_at)
        cursor = connection.cursor()
        cursor.execute(insert_query, db_values)
        connection.commit()
    except (Exception, psycopg2.Error) as error:
        print("Error when inserting into table: ", error)
        print("DEBUG: ", str(alert))

def get_repos(host, gh_token):
    g = Github(base_url=host + "/api/v3", login_or_token=gh_token)
    repos = []

    # Add orgs that you need to ignore
    blacklisted_orgs = ['test-org']

    for org in g.get_organizations():
        if org.login not in blacklisted_orgs:
            for repo in org.get_repos():
                if not repo.archived:
                    repos.append(repo.full_name)

    return repos


def get_alerts(host, gh_token, gh_org, gh_repo):
    # Handle pagination
    headers = {
        "Authorization": "Bearer " + gh_token,
        "Accept": "application/vnd.github.v4.idl"
    }

    # Select your transport with a defined url endpoint
    transport = AIOHTTPTransport(url=host+"/api/graphql", headers=headers)
    # Create a GraphQL client using the defined transport
    client = Client(transport=transport, fetch_schema_from_transport=True)

    # Provide a GraphQL query
    query = gql(
        """
        {
        repository(name: "%s", owner: "%s") {
            vulnerabilityAlerts(first:100) {
            pageInfo {
                startCursor
                hasNextPage
                endCursor
            }
            nodes {
                createdAt
                fixedAt
                number
                dependabotUpdate {
                pullRequest {
                    number
                    title
                    mergedAt
                }
                }
                state
                dismissedAt
                dismisser {
                    login
                }
                dismissReason
                securityVulnerability {
                severity
                advisory {
                    ghsaId
                    summary
                }
                package {
                    name
                }
                }
            }
            }
        }
        }

    """ % (gh_repo, gh_org)
    )

    while True:
        # Execute the query on the transport
        result = client.execute(query)

        for alert in result.get("repository").get("vulnerabilityAlerts").get("nodes"):
            print(json.dumps(alert))
            insert_into_db(alert, gh_org, gh_repo)

        nextpage = result.get("repository").get(
            "vulnerabilityAlerts").get("pageInfo").get("hasNextPage")
        if not nextpage:
            break

        endcursor = result.get("repository").get(
            "vulnerabilityAlerts").get("pageInfo").get("endCursor")
        query = gql(
            """
        {
        repository(name: "%s", owner: "%s") {
            vulnerabilityAlerts(first:100, after:"%s") {
            pageInfo {
                startCursor
                hasNextPage
                endCursor
            }
            nodes {
                createdAt
                fixedAt
                number
                dependabotUpdate {
                pullRequest {
                    number
                    title
                    mergedAt
                }
                }
                state
                dismissedAt
                dismisser {
                    login
                }
                dismissReason
                securityVulnerability {
                severity
                advisory {
                    ghsaId
                    summary
                }
                package {
                    name
                }
                }
            }
            }
        }
        }
    """ % (gh_repo, gh_org, endcursor)
        )

    return []


initialize_db()
repos = get_repos(host=host, gh_token=gh_token)

for repo in repos:
    print("[+] Analyzing " + repo)
    org = repo.split("/")[0]
    repo_name = repo.split("/")[1]

    get_alerts(host, gh_token, org, repo_name)
