import asyncio
from typing import Annotated
import os
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth.providers.bearer import BearerAuthProvider, RSAKeyPair
from mcp import ErrorData, McpError
from mcp.server.auth.provider import AccessToken
from mcp.types import TextContent, INVALID_PARAMS, INTERNAL_ERROR
from pydantic import BaseModel, Field, AnyUrl

import markdownify
import httpx
import readabilipy
from github import Github
import re
from datetime import datetime

# --- Load environment variables ---
load_dotenv()

TOKEN = os.environ.get("AUTH_TOKEN")
MY_NUMBER = os.environ.get("MY_NUMBER")
GITHUB_PAT = os.environ.get("GITHUB_PAT")

assert TOKEN is not None, "Please set AUTH_TOKEN in your .env file"
assert MY_NUMBER is not None, "Please set MY_NUMBER in your .env file"
assert GITHUB_PAT is not None, "Please set GITHUB_PAT in your .env file"

# --- Auth Provider ---
class SimpleBearerAuthProvider(BearerAuthProvider):
    def __init__(self, token: str):
        k = RSAKeyPair.generate()
        super().__init__(public_key=k.public_key, jwks_uri=None, issuer=None, audience=None)
        self.token = token

    async def load_access_token(self, token: str) -> AccessToken | None:
        if token == self.token:
            return AccessToken(
                token=token,
                client_id="puch-client",
                scopes=["*"],
                expires_at=None,
            )
        return None

# --- Rich Tool Description model ---
class RichToolDescription(BaseModel):
    description: str
    use_when: str
    side_effects: str | None = None

# --- Fetch Utility Class ---
class Fetch:
    USER_AGENT = "Puch/1.0 (Autonomous)"

    @classmethod
    async def fetch_url(
        cls,
        url: str,
        user_agent: str,
        force_raw: bool = False,
    ) -> tuple[str, str]:
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(
                    url,
                    follow_redirects=True,
                    headers={"User-Agent": user_agent},
                    timeout=30,
                )
            except httpx.HTTPError as e:
                raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Failed to fetch {url}: {e!r}"))

            if response.status_code >= 400:
                raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Failed to fetch {url} - status code {response.status_code}"))

            page_raw = response.text

        content_type = response.headers.get("content-type", "")
        is_page_html = "text/html" in content_type

        if is_page_html and not force_raw:
            return cls.extract_content_from_html(page_raw), ""

        return (
            page_raw,
            f"Content type {content_type} cannot be simplified to markdown, but here is the raw content:\n",
        )

    @staticmethod
    def extract_content_from_html(html: str) -> str:
        """Extract and convert HTML content to Markdown format."""
        ret = readabilipy.simple_json.simple_json_from_html_string(html, use_readability=True)
        if not ret or not ret.get("content"):
            return "<error>Page failed to be simplified from HTML</error>"
        content = markdownify.markdownify(ret["content"], heading_style=markdownify.ATX)
        return content

    @staticmethod
    async def google_search_links(query: str, num_results: int = 5) -> list[str]:
        """
        Perform a scoped DuckDuckGo search and return a list of job posting URLs.
        (Using DuckDuckGo because Google blocks most programmatic scraping.)
        """
        ddg_url = f"https://html.duckduckgo.com/html/?q={query.replace(' ', '+')}"
        links = []

        async with httpx.AsyncClient() as client:
            resp = await client.get(ddg_url, headers={"User-Agent": Fetch.USER_AGENT})
            if resp.status_code != 200:
                return ["<error>Failed to perform search.</error>"]

        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.find_all("a", class_="result__a", href=True):
            href = a["href"]
            if "http" in href:
                links.append(href)
            if len(links) >= num_results:
                break

        return links or ["<error>No results found.</error>"]

# --- MCP Server Setup ---
mcp = FastMCP(
    "Job Finder MCP Server",
    auth=SimpleBearerAuthProvider(TOKEN),
)

# --- Tool: help ---
HelpDescription = RichToolDescription(
    description="Get a list of all available tools and what they do.",
    use_when="The user asks for help, or asks what you can do.",
    side_effects="None",
)

@mcp.tool(description=HelpDescription.model_dump_json())
async def help() -> str:
    """
    Returns a list of all available tools.
    """
    tool_list = []
    for tool_name, tool in mcp.tools.items():
        if tool_name in ['validate', 'help']:
            continue
        
        try:
            description_json = tool.description
            description_model = RichToolDescription.model_validate_json(description_json)
            
            tool_info = f"### {tool_name}\n"
            tool_info += f"**Description:** {description_model.description}\n"
            tool_info += f"**Use When:** {description_model.use_when}\n"
            if description_model.side_effects:
                tool_info += f"**Side Effects:** {description_model.side_effects}"
            
            tool_list.append(tool_info)
        except Exception as e:
            print(f"Could not parse description for tool {tool_name}: {e}")

    return "\n\n---\n\n".join(tool_list)

# --- Tool: validate (required by Puch) ---
@mcp.tool
async def validate() -> str:
    return MY_NUMBER


# --- Tool: job_finder (now smart!) ---
JobFinderDescription = RichToolDescription(
    description="Smart job tool: analyze descriptions, fetch URLs, or search jobs based on free text.",
    use_when="Use this to evaluate job descriptions or search for jobs using freeform goals.",
    side_effects="Returns insights, fetched job descriptions, or relevant job links.",
)

@mcp.tool(description=JobFinderDescription.model_dump_json())
async def job_finder(
    user_goal: Annotated[str, Field(description="The user's goal (can be a description, intent, or freeform query)")],
    job_description: Annotated[str | None, Field(description="Full job description text, if available.")] = None,
    job_url: Annotated[AnyUrl | None, Field(description="A URL to fetch a job description from.")] = None,
    raw: Annotated[bool, Field(description="Return raw HTML content if True")] = False,
) -> str:
    """
    Handles multiple job discovery methods: direct description, URL fetch, or freeform search query.
    """
    if job_description:
        return (
            f"📝 **Job Description Analysis**\n\n"
            f"---\n{job_description.strip()}\n---\n\n"
            f"User Goal: **{user_goal}**\n\n"
            f"💡 Suggestions:\n- Tailor your resume.\n- Evaluate skill match.\n- Consider applying if relevant."
        )

    if job_url:
        content, _ = await Fetch.fetch_url(str(job_url), Fetch.USER_AGENT, force_raw=raw)
        return (
            f"🔗 **Fetched Job Posting from URL**: {job_url}\n\n"
            f"---\n{content.strip()}\n---\n\n"
            f"User Goal: **{user_goal}**"
        )

    if "look for" in user_goal.lower() or "find" in user_goal.lower():
        links = await Fetch.google_search_links(user_goal)
        return (
            f"🔍 **Search Results for**: _{user_goal}_\n\n" +
            "\n".join(f"- {link}" for link in links)
        )

    raise McpError(ErrorData(code=INVALID_PARAMS, message="Please provide either a job description, a job URL, or a search query in user_goal."))




# --- Tool: create_github_issue ---
CreateGithubIssueDescription = RichToolDescription(
    description="Create a GitHub issue in a repository.",
    use_when="Use this to create a GitHub issue with a title and body.",
    side_effects="Creates a new issue in the specified GitHub repository.",
)

@mcp.tool(description=CreateGithubIssueDescription.model_dump_json())
async def create_github_issue(
    repo_url: Annotated[str, Field(description="The URL of the GitHub repository (e.g., 'https://github.com/owner/repo')")],
    title: Annotated[str, Field(description="The title of the issue.")],
    body: Annotated[str, Field(description="The body of the issue.")],
    repo_file_path: Annotated[str | None, Field(description="The path to a file within the GitHub repository to include in the issue body.")] = None,
) -> str:
    """
    Creates a new issue in a GitHub repository.
    """
    try:
        g = Github(GITHUB_PAT)
        if not repo_url.startswith("https://github.com/"):
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Invalid GitHub repository URL"))
        repo_name = repo_url.replace("https://github.com/", "").rstrip('/')
        print(f"Repository name: {repo_name}") # Debug print
        repo = g.get_repo(repo_name)

        issue_body = body
        file_content_to_add = None
        file_path_used = None

        # 1. Try to use repo_file_path if provided by AI
        if repo_file_path:
            print(f"Attempting to fetch file from repository (AI provided path): {repo_file_path}")
            try:
                file_obj = repo.get_contents(repo_file_path)
                if file_obj:
                    file_content_to_add = file_obj.decoded_content.decode('utf-8')
                    file_path_used = repo_file_path
                    print(f"Successfully fetched file from AI provided path: {repo_file_path}")
                else:
                    print(f"File object not returned for AI provided path: {repo_file_path}")
            except Exception as e:
                print(f"Error fetching file from AI provided path {repo_file_path} from GitHub: {e}")
                # Don't raise an error yet, try fallback
                file_content_to_add = None # Reset in case of partial success/error

        # 2. If no file content yet, try fallback based on title/body
        if file_content_to_add is None:
            potential_filenames = []
            text_to_search = f"{title} {body}"

            MAX_FILENAME_LENGTH = 100
            # Regex to find strings that look like file paths (e.g., file.txt, path/to/file.py)
            # It looks for words containing at least one dot, or paths with slashes.
            # It tries to avoid matching URLs or very long strings.
            filename_pattern = r'\b(?:[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*\.[a-zA-Z0-9]{1,5})\b'
            common_no_ext_filenames = ["Dockerfile", "LICENSE", "Makefile", "CONTRIBUTING", "README"] # Added README
            no_ext_pattern = r'\b(?:' + '|'.join(re.escape(f) for f in common_no_ext_filenames) + r')\b'

            for match in re.finditer(filename_pattern, text_to_search):
                filename = match.group(0)
                if len(filename) <= MAX_FILENAME_LENGTH and not filename.startswith("http"):
                    potential_filenames.append(filename)

            for match in re.finditer(no_ext_pattern, text_to_search):
                filename = match.group(0)
                if len(filename) <= MAX_FILENAME_LENGTH:
                    potential_filenames.append(filename)

            potential_filenames = sorted(list(set(potential_filenames)), key=len) # Sort by length to try shorter, more common ones first

            for potential_file in potential_filenames:
                print(f"Attempting fallback file read for: {potential_file}")
                try:
                    file_obj = repo.get_contents(potential_file)
                    if file_obj:
                        file_content_to_add = file_obj.decoded_content.decode('utf-8')
                        file_path_used = potential_file
                        print(f"Successfully included fallback file: {potential_file}")
                        break # Stop after the first successful fallback
                    else:
                        print(f"Fallback file object not returned for: {potential_file}")
                except Exception as e:
                    print(f"Error fetching fallback file {potential_file} from GitHub: {e}")
                    # Continue to next potential file

        # 3. Append file content if found (either from AI or fallback)
        if file_content_to_add:
            issue_body += f"\n\n---\nFile: {file_path_used}\n---\n\n" + "```\n" + file_content_to_add + "\n```"

        issue = repo.create_issue(title=title, body=issue_body)
        return f"Successfully created issue #{issue.number}: {issue.html_url}"
    except Exception as e:
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Failed to create GitHub issue: {e}"))



# --- Tool: get_repo_file_for_modification ---
GetRepoFileForModificationDescription = RichToolDescription(
    description="Identifies and retrieves the content of a relevant file from a GitHub repository based on a user's request for code changes.",
    use_when="Use this when a user wants to make code changes but doesn't specify the exact file, or when the AI needs to determine the most relevant file to modify.",
    side_effects="Returns the content of the identified file, or an error if no relevant file can be found.",
)

@mcp.tool(description=GetRepoFileForModificationDescription.model_dump_json())
async def get_repo_file_for_modification(
    repo_url: Annotated[str, Field(description="The URL of the GitHub repository (e.g., 'https://github.com/owner/repo')")],
    user_request: Annotated[str, Field(description="A natural language description of the code changes the user wants to make.")],
    target_file_path: Annotated[str | None, Field(description="Optional: The specific file path to retrieve. If provided, the tool will attempt to read this file directly. If not, it will try to infer the relevant file from the user_request.")] = None,
) -> str:
    """
    Identifies and retrieves the content of a relevant file from a GitHub repository for modification.
    """
    try:
        g = Github(GITHUB_PAT)
        if not repo_url.startswith("https://github.com/"):
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Invalid GitHub repository URL"))
        repo_name = repo_url.replace("https://github.com/", "").rstrip('/')
        repo = g.get_repo(repo_name)

        file_to_read = target_file_path

        if file_to_read is None:
            # Fallback: Infer file from user_request
            print(f"Attempting to infer target file from user request: {user_request}")
            potential_filenames = []
            text_to_search = user_request

            MAX_FILENAME_LENGTH = 100
            filename_pattern = r'\b(?:[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*\.[a-zA-Z0-9]{1,5})\b'
            common_no_ext_filenames = ["Dockerfile", "LICENSE", "Makefile", "CONTRIBUTING", "README"]
            no_ext_pattern = r'\b(?:' + '|'.join(re.escape(f) for f in common_no_ext_filenames) + r')\b'

            for match in re.finditer(filename_pattern, text_to_search):
                filename = match.group(0)
                if len(filename) <= MAX_FILENAME_LENGTH and not filename.startswith("http"):
                    potential_filenames.append(filename)

            for match in re.finditer(no_ext_pattern, text_to_search):
                filename = match.group(0)
                if len(filename) <= MAX_FILENAME_LENGTH:
                    potential_filenames.append(filename)

            potential_filenames = sorted(list(set(potential_filenames)), key=len)

            if not potential_filenames:
                raise McpError(ErrorData(code=INVALID_PARAMS, message="No specific file path provided or inferable from the request. Please specify the file to modify."))

            # Try to read the first potential filename found, with case variations
            found_file_content = None
            for inferred_file_name in potential_filenames:
                # Generate case variations for the inferred filename
                case_variations = [inferred_file_name]
                if '.' in inferred_file_name:
                    parts = inferred_file_name.split('/')
                    last_part = parts[-1]
                    if '.' in last_part:
                        name_ext_parts = last_part.split('.')
                        name = '.'.join(name_ext_parts[:-1])
                        ext = name_ext_parts[-1]
                        # Common variations for name and extension
                        case_variations.append(inferred_file_name.replace(last_part, name.lower() + '.' + ext.lower()))
                        case_variations.append(inferred_file_name.replace(last_part, name.upper() + '.' + ext.upper()))
                        case_variations.append(inferred_file_name.replace(last_part, name.capitalize() + '.' + ext.lower()))
                        case_variations.append(inferred_file_name.replace(last_part, name.upper() + '.' + ext.lower())) # README.md
                        case_variations.append(inferred_file_name.replace(last_part, name.lower() + '.' + ext.upper())) # readme.MD
                else: # For files without extensions like Dockerfile, README
                    case_variations.append(inferred_file_name.lower())
                    case_variations.append(inferred_file_name.upper())
                    case_variations.append(inferred_file_name.capitalize())

                # Remove duplicates and try them
                case_variations = list(set(case_variations))

                for variation in case_variations:
                    print(f"Attempting to read inferred file (variation): {variation}")
                    try:
                        file_obj = repo.get_contents(variation)
                        if file_obj:
                            file_content = file_obj.decoded_content.decode('utf-8')
                            return f"File: {variation}\n\n```\n{file_content}\n```"
                        else:
                            print(f"File object not returned for inferred file (variation): {variation}")
                    except Exception as e:
                        print(f"Error fetching inferred file (variation) {variation} from GitHub: {e}")
                        # Continue to next variation if 404, otherwise re-raise
                        if "404" not in str(e) and "Not Found" not in str(e):
                            raise # Re-raise if it's not a 404 error

            # If no file found after trying all variations
            raise McpError(ErrorData(code=INVALID_PARAMS, message=f"File '{file_to_read}' not found in repository '{repo_name}' after trying case variations. Please check the path (including case-sensitivity) and ensure it's relative to the repository root."))

        # If target_file_path was provided, read it directly
        try:
            file_obj = repo.get_contents(file_to_read)
            if file_obj:
                file_content = file_obj.decoded_content.decode('utf-8')
                return f"File: {file_to_read}\n\n```\n{file_content}\n```"
            else:
                raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"File object not returned for: {file_to_read}"))
        except Exception as e:
            if "404" in str(e) or "Not Found" in str(e):
                raise McpError(ErrorData(code=INVALID_PARAMS, message=f"File '{file_to_read}' not found in repository '{repo_name}'. Please check the path (including case-sensitivity) and ensure it's relative to the repository root."))
            else:
                raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Failed to read file '{file_to_read}' from repository: {e}"))

    except Exception as e:
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Failed to get repository file for modification: {e}"))



# --- Tool: close_github_issue ---
CloseGithubIssueDescription = RichToolDescription(
    description="Close a GitHub issue.",
    use_when="Use this to close a GitHub issue.",
    side_effects="Closes an issue in the specified GitHub repository.",
)

@mcp.tool(description=CloseGithubIssueDescription.model_dump_json())
async def close_github_issue(
    repo_url: Annotated[str, Field(description="The URL of the GitHub repository (e.g., 'https://github.com/owner/repo')")],
    issue_number: Annotated[int, Field(description="The number of the issue to close.")],
) -> str:
    """
    Closes a GitHub issue.
    """
    try:
        g = Github(GITHUB_PAT)
        if not repo_url.startswith("https://github.com/"):
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Invalid GitHub repository URL"))
        repo_name = repo_url.replace("https://github.com/", "").rstrip('/')
        repo = g.get_repo(repo_name)
        issue = repo.get_issue(number=issue_number)
        issue.edit(state="closed")
        return f"Successfully closed issue #{issue.number} in {repo_name}."
    except Exception as e:
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Failed to close GitHub issue: {e}"))


# --- Tool: comment_on_github_issue ---
CommentOnGithubIssueDescription = RichToolDescription(
    description="Add a comment to a GitHub issue.",
    use_when="Use this to add a comment to a GitHub issue.",
    side_effects="Adds a comment to an issue in the specified GitHub repository.",
)

@mcp.tool(description=CommentOnGithubIssueDescription.model_dump_json())
async def comment_on_github_issue(
    repo_url: Annotated[str, Field(description="The URL of the GitHub repository (e.g., 'https://github.com/owner/repo')")],
    issue_number: Annotated[int, Field(description="The number of the issue to comment on.")],
    body: Annotated[str, Field(description="The body of the comment.")],
) -> str:
    """
    Adds a comment to a GitHub issue.
    """
    try:
        g = Github(GITHUB_PAT)
        if not repo_url.startswith("https://github.com/"):
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Invalid GitHub repository URL"))
        repo_name = repo_url.replace("https://github.com/", "").rstrip('/')
        repo = g.get_repo(repo_name)
        issue = repo.get_issue(number=issue_number)
        comment = issue.create_comment(body)
        return f"Successfully added comment to issue #{issue.number} in {repo_name}: {comment.html_url}"
    except Exception as e:
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Failed to comment on GitHub issue: {e}"))


# --- Tool: get_github_issue ---
GetGithubIssueDescription = RichToolDescription(
    description="Get information about a GitHub issue.",
    use_when="Use this to get information about a GitHub issue.",
    side_effects="Fetches information about an issue from the specified GitHub repository.",
)

@mcp.tool(description=GetGithubIssueDescription.model_dump_json())
async def get_github_issue(
    repo_url: Annotated[str, Field(description="The URL of the GitHub repository (e.g., 'https://github.com/owner/repo')")],
    issue_number: Annotated[int, Field(description="The number of the issue to get.")],
) -> str:
    """
    Gets information about a GitHub issue.
    """
    try:
        g = Github(GITHUB_PAT)
        if not repo_url.startswith("https://github.com/"):
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Invalid GitHub repository URL"))
        repo_name = repo_url.replace("https://github.com/", "").rstrip('/')
        repo = g.get_repo(repo_name)
        issue = repo.get_issue(number=issue_number)
        return f"Issue #{issue.number}: {issue.title}\n\n{issue.body}"
    except Exception as e:
        raise McpError(ErrorData(code=INTERNAL_ERROR, message=f"Failed to get GitHub issue: {e}"))


# --- Tool: create_pull_request_with_content ---
# --- Tool: create_pull_request_with_content ---
# --- Enhanced Tool: create_pull_request_with_content ---
CreatePullRequestWithContentDescription = RichToolDescription(
    description="Creates a new branch, commits changes to a specified file, and opens a pull request with the new content. Includes diagnostic information if it fails.",
    use_when="Use this after you have identified the file to modify and have the complete new content for that file.",
    side_effects="Creates a new branch and a pull request in the specified GitHub repository, or provides manual instructions if automated creation fails.",
)

@mcp.tool(description=CreatePullRequestWithContentDescription.model_dump_json())
async def create_pull_request_with_content(
    repo_url: Annotated[str, Field(description="The URL of the GitHub repository (e.g., 'https://github.com/owner/repo')")],
    file_path: Annotated[str, Field(description="The path to the file to be modified within the repository.")],
    new_file_content: Annotated[str, Field(description="The complete new content of the file after modifications.")],
    commit_message: Annotated[str, Field(description="The commit message for the changes.")],
    pr_title: Annotated[str, Field(description="The title of the pull request.")],
    pr_body: Annotated[str, Field(description="The body of the pull request.")],
    base_branch: Annotated[str, Field(description="The base branch to create the PR against (e.g., 'main' or 'master'). Defaults to 'main'.")] = "main",
    new_branch_name: Annotated[str | None, Field(description="The name of the new branch to create for these changes. If not provided, a unique name will be generated.")] = None,
) -> str:
    """
    Creates a new branch, commits changes to a specified file, and opens a pull request.
    If automated creation fails, provides manual instructions.
    """
    try:
        g = Github(GITHUB_PAT)
        if not repo_url.startswith("https://github.com/"):
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Invalid GitHub repository URL"))
        repo_name = repo_url.replace("https://github.com/", "").rstrip('/')
        
        # First, verify we can access the repository
        try:
            repo = g.get_repo(repo_name)
            print(f"✅ Successfully accessed repository: {repo_name}")
        except Exception as e:
            print(f"❌ Error accessing repository '{repo_name}': {e}")
            return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Cannot access repository: {e}")

        # Check if we have push access by trying to get user permissions
        user_can_push = False
        try:
            current_user = g.get_user()
            permissions = repo.get_collaborator_permission(current_user.login)
            print(f"📋 User permissions for repository: {permissions}")
            if permissions in ['admin', 'write', 'maintain']:
                user_can_push = True
            else:
                print(f"⚠️ Insufficient permissions: {permissions}")
        except Exception as e:
            print(f"⚠️ Could not check permissions (might still work for public repos): {e}")
            # For public repos, we might still be able to fork and create PR
            try:
                # Test if we can at least read the repo content
                repo.get_contents("", ref=base_branch)
                print("✅ Can read repository contents")
                user_can_push = False  # We'll need to fork
            except Exception as read_e:
                print(f"❌ Cannot even read repository: {read_e}")
                return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"No repository access: {read_e}")

        # Get available branches
        try:
            branches = list(repo.get_branches())
            branch_names = [branch.name for branch in branches]
            print(f"📂 Available branches: {branch_names}")
            
            if base_branch not in branch_names:
                if base_branch == "main" and "master" in branch_names:
                    base_branch = "master"
                    print(f"🔄 Switched base branch from 'main' to 'master'")
                elif base_branch == "master" and "main" in branch_names:
                    base_branch = "main"
                    print(f"🔄 Switched base branch from 'master' to 'main'")
                else:
                    return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Base branch '{base_branch}' not found. Available: {branch_names}")
        except Exception as e:
            print(f"❌ Error checking branches: {e}")
            return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Cannot check branches: {e}")

        # If we don't have push access, try to fork the repository
        if not user_can_push:
            try:
                print("🍴 Attempting to fork repository...")
                current_user = g.get_user()
                forked_repo = current_user.create_fork(repo)
                print(f"✅ Successfully forked to: {forked_repo.html_url}")
                repo = forked_repo  # Use the forked repo for changes
                time.sleep(2)  # Give GitHub a moment to set up the fork
            except Exception as e:
                print(f"❌ Could not fork repository: {e}")
                return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Cannot fork repository: {e}")

        # Generate branch name if not provided
        if new_branch_name is None:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            new_branch_name = f"feature/mcp-pr-{timestamp}"

        # Get base branch reference
        try:
            base_ref = repo.get_git_ref(f"heads/{base_branch}")
            base_sha = base_ref.object.sha
            print(f"📍 Base branch '{base_branch}' SHA: {base_sha}")
        except Exception as e:
            print(f"❌ Error getting base branch reference: {e}")
            return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Cannot get base branch reference: {e}")

        # Create new branch
        try:
            print(f"🌟 Creating new branch: {new_branch_name}")
            new_ref = repo.create_git_ref(f"refs/heads/{new_branch_name}", base_sha)
            print(f"✅ Successfully created branch: {new_branch_name}")
        except Exception as e:
            print(f"❌ Error creating branch '{new_branch_name}': {e}")
            if "already exists" in str(e).lower():
                # Try with milliseconds
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")[:-3]
                new_branch_name = f"feature/mcp-pr-{timestamp}"
                try:
                    new_ref = repo.create_git_ref(f"refs/heads/{new_branch_name}", base_sha)
                    print(f"✅ Successfully created branch with new name: {new_branch_name}")
                except Exception as e2:
                    return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Cannot create branch after retry: {e2}")
            else:
                return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Cannot create branch: {e}")

        # Get/Create file content
        file_exists = True
        try:
            contents = repo.get_contents(file_path, ref=base_branch)
            print(f"✅ Found existing file: {file_path}")
        except Exception as e:
            if "404" in str(e):
                print(f"📝 File '{file_path}' doesn't exist, will create it")
                file_exists = False
                contents = None
            else:
                print(f"❌ Error checking file: {e}")
                return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Cannot check file: {e}")

        # Update or create file
        try:
            if file_exists:
                repo.update_file(
                    path=file_path,
                    message=commit_message,
                    content=new_file_content,
                    sha=contents.sha,
                    branch=new_branch_name
                )
                print(f"✅ Updated file: {file_path}")
            else:
                repo.create_file(
                    path=file_path,
                    message=commit_message,
                    content=new_file_content,
                    branch=new_branch_name
                )
                print(f"✅ Created file: {file_path}")
        except Exception as e:
            print(f"❌ Error modifying file: {e}")
            return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Cannot modify file: {e}")

        # Create pull request
        try:
            # If we forked, create PR from fork to original
            original_repo = g.get_repo(repo_name) if not user_can_push else repo
            head_ref = f"{repo.owner.login}:{new_branch_name}" if not user_can_push else new_branch_name
            
            pull = original_repo.create_pull(
                title=pr_title,
                body=pr_body,
                head=head_ref,
                base=base_branch
            )
            print(f"✅ Successfully created pull request: {pull.html_url}")
            return f"✅ Successfully created pull request: {pull.html_url}"
        except Exception as e:
            print(f"❌ Error creating pull request: {e}")
            # Even if PR creation fails, we can provide the manual steps since we have the branch
            return generate_manual_pr_instructions(
                repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch,
                f"Branch created but PR failed: {e}",
                branch_created=True,
                branch_name=new_branch_name,
                forked_repo_url=repo.html_url if not user_can_push else None
            )

    except McpError:
        raise  # Re-raise MCP errors as-is
    except Exception as e:
        print(f"💥 Unexpected error: {e}")
        return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Unexpected error: {e}")


def generate_manual_pr_instructions(repo_url: str, file_path: str, new_file_content: str, 
                                  commit_message: str, pr_title: str, pr_body: str, 
                                  base_branch: str, error_msg: str, branch_created: bool = False,
                                  branch_name: str = None, forked_repo_url: str = None) -> str:
    """Generate manual instructions for creating a pull request."""
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    suggested_branch = branch_name or f"feature/manual-pr-{timestamp}"
    
    instructions = f"""
🤖 **AUTOMATED PR CREATION FAILED**

❌ **Error**: {error_msg}

📋 **MANUAL PULL REQUEST INSTRUCTIONS**

{'✅ **Good news**: A branch was already created for you!' if branch_created else ''}
{'🍴 **Fork created**: ' + forked_repo_url if forked_repo_url else ''}

**Option 1: Using GitHub Web Interface**
1. 🌐 Go to: {repo_url}
2. 🍴 Click "Fork" (if you don't have write access)
3. 📝 Navigate to `{file_path}` (create if it doesn't exist)
4. ✏️ Edit the file with the content below
5. 💾 Commit with message: `{commit_message}`
6. 🌿 Create branch: `{suggested_branch}`
7. 🔄 Create Pull Request with title: `{pr_title}`

**Option 2: Using Git CLI**
```bash
# Clone the repository (or your fork)
git clone {repo_url}
cd {repo_url.split('/')[-1].replace('.git', '')}

# Create and switch to new branch
git checkout -b {suggested_branch}

# Create/edit the file
cat > {file_path} << 'EOF'
{new_file_content}
EOF

# Commit and push
git add {file_path}
git commit -m "{commit_message}"
git push origin {suggested_branch}

# Then create PR via GitHub web interface
```

**📄 FILE CONTENT TO USE:**
```
{new_file_content}
```

**📝 PR DETAILS:**
- **Title**: {pr_title}
- **Description**: {pr_body}
- **Base Branch**: {base_branch}
- **Head Branch**: {suggested_branch}

**🔧 TROUBLESHOOTING TIPS:**
1. Ensure your GitHub PAT has `repo` scope for private repos or `public_repo` for public repos
2. Check if you have write access to the repository
3. Verify the repository URL is correct
4. Try forking the repository if you don't have direct write access

**⚠️ COMMON PAT PERMISSION ISSUES:**
- Go to GitHub Settings → Developer Settings → Personal Access Tokens
- Ensure your token has appropriate scopes:
  - `repo` (full control of private repositories)
  - `public_repo` (access to public repositories) 
  - `workflow` (if updating GitHub Actions)
"""
    
    return instructions

@mcp.tool(description=CreatePullRequestWithContentDescription.model_dump_json())
async def create_pull_request_with_content(
    repo_url: Annotated[str, Field(description="The URL of the GitHub repository (e.g., 'https://github.com/owner/repo')")],
    file_path: Annotated[str, Field(description="The path to the file to be modified within the repository.")],
    new_file_content: Annotated[str, Field(description="The complete new content of the file after modifications.")],
    commit_message: Annotated[str, Field(description="The commit message for the changes.")],
    pr_title: Annotated[str, Field(description="The title of the pull request.")],
    pr_body: Annotated[str, Field(description="The body of the pull request.")],
    base_branch: Annotated[str, Field(description="The base branch to create the PR against (e.g., 'main' or 'master'). Defaults to 'main'.")] = "main",
    new_branch_name: Annotated[str | None, Field(description="The name of the new branch to create for these changes. If not provided, a unique name will be generated.")] = None,
    merge_strategy: Annotated[str, Field(description="How to handle existing content: 'replace' (default), 'append', 'prepend', or 'smart-merge'.")] = "replace",
) -> str:
    """
    Creates a new branch, commits changes to a specified file, and opens a pull request.
    If automated creation fails, provides manual instructions.
    """
    try:
        g = Github(GITHUB_PAT)
        if not repo_url.startswith("https://github.com/"):
            raise McpError(ErrorData(code=INVALID_PARAMS, message="Invalid GitHub repository URL"))
        repo_name = repo_url.replace("https://github.com/", "").rstrip('/')
        
        # First, verify we can access the repository
        try:
            repo = g.get_repo(repo_name)
            print(f"✅ Successfully accessed repository: {repo_name}")
        except Exception as e:
            print(f"❌ Error accessing repository '{repo_name}': {e}")
            return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Cannot access repository: {e}")

        # Check if we have push access
        user_can_push = False
        try:
            current_user = g.get_user()
            permissions = repo.get_collaborator_permission(current_user.login)
            print(f"📋 User permissions for repository: {permissions}")
            if permissions in ['admin', 'write', 'maintain']:
                user_can_push = True
            else:
                print(f"⚠️ Insufficient permissions: {permissions}")
        except Exception as e:
            print(f"⚠️ Could not check permissions (might still work for public repos): {e}")
            try:
                repo.get_contents("", ref=base_branch)
                print("✅ Can read repository contents")
                user_can_push = False
            except Exception as read_e:
                print(f"❌ Cannot even read repository: {read_e}")
                return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"No repository access: {read_e}")

        # Get available branches
        try:
            branches = list(repo.get_branches())
            branch_names = [branch.name for branch in branches]
            print(f"📂 Available branches: {branch_names}")
            
            if base_branch not in branch_names:
                if base_branch == "main" and "master" in branch_names:
                    base_branch = "master"
                    print(f"🔄 Switched base branch from 'main' to 'master'")
                elif base_branch == "master" and "main" in branch_names:
                    base_branch = "main"
                    print(f"🔄 Switched base branch from 'master' to 'main'")
                else:
                    return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Base branch '{base_branch}' not found. Available: {branch_names}")
        except Exception as e:
            print(f"❌ Error checking branches: {e}")
            return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Cannot check branches: {e}")

        # If we don't have push access, try to fork the repository
        if not user_can_push:
            try:
                print("🍴 Attempting to fork repository...")
                current_user = g.get_user()
                forked_repo = current_user.create_fork(repo)
                print(f"✅ Successfully forked to: {forked_repo.html_url}")
                repo = forked_repo
                time.sleep(5)  # Increased delay for fork propagation
            except Exception as e:
                print(f"❌ Could not fork repository: {e}")
                return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Cannot fork repository: {e}")

        # Generate branch name if not provided
        if new_branch_name is None:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            new_branch_name = f"feature/mcp-pr-{timestamp}"

        # Get base branch reference
        try:
            base_ref = repo.get_git_ref(f"heads/{base_branch}")
            base_sha = base_ref.object.sha
            print(f"📍 Base branch '{base_branch}' SHA: {base_sha}")
        except Exception as e:
            print(f"❌ Error getting base branch reference: {e}")
            return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Cannot get base branch reference: {e}")

        # Create new branch with retry logic and verification
        max_retries = 3
        retry_delay = 3  # seconds
        branch_created = False

        for attempt in range(max_retries):
            try:
                print(f"🌟 Creating new branch (attempt {attempt + 1}): {new_branch_name}")
                new_ref = repo.create_git_ref(f"refs/heads/{new_branch_name}", base_sha)
                print(f"✅ Successfully created branch: {new_branch_name}")
                
                # Verify branch exists
                time.sleep(retry_delay)
                repo.get_branch(new_branch_name)
                print(f"✅ Verified branch exists: {new_branch_name}")
                branch_created = True
                break
            except Exception as e:
                if attempt == max_retries - 1:
                    return generate_manual_pr_instructions(
                        repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch,
                        f"Failed to create/verify branch after {max_retries} attempts: {e}"
                    )
                print(f"⚠️ Branch creation/verification failed (attempt {attempt + 1}), retrying...")
                time.sleep(retry_delay)

        # Get existing file content and merge according to strategy
        file_exists = True
        old_content = ""
        try:
            contents = repo.get_contents(file_path, ref=base_branch)
            print(f"✅ Found existing file: {file_path}")
            old_content = contents.decoded_content.decode('utf-8')
        except Exception as e:
            if "404" in str(e):
                print(f"📝 File '{file_path}' doesn't exist, will create it")
                file_exists = False
                contents = None
            else:
                print(f"❌ Error checking file: {e}")
                return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Cannot check file: {e}")

        # Apply merge strategy
        final_content = new_file_content
        if file_exists:
            if merge_strategy == "append":
                final_content = old_content + "\n\n" + new_file_content
            elif merge_strategy == "prepend":
                final_content = new_file_content + "\n\n" + old_content
            elif merge_strategy == "smart-merge":
                final_content = smart_merge_content(old_content, new_file_content, file_path)
            # else "replace" is the default
            
            # Generate diff for PR body
            diff = generate_diff(old_content, final_content)
            pr_body += f"\n\n### Changes:\n```diff\n{diff}\n```"

        # Update or create file with retry logic
        for attempt in range(max_retries):
            try:
                if file_exists:
                    repo.update_file(
                        path=file_path,
                        message=commit_message,
                        content=final_content,
                        sha=contents.sha,
                        branch=new_branch_name
                    )
                    print(f"✅ Updated file: {file_path}")
                else:
                    repo.create_file(
                        path=file_path,
                        message=commit_message,
                        content=final_content,
                        branch=new_branch_name
                    )
                    print(f"✅ Created file: {file_path}")
                break
            except Exception as e:
                if attempt == max_retries - 1:
                    return generate_manual_pr_instructions(repo_url, file_path, final_content, commit_message, pr_title, pr_body, base_branch, f"Cannot modify file after {max_retries} attempts: {e}")
                print(f"⚠️ Error modifying file (attempt {attempt + 1}), retrying...")
                time.sleep(retry_delay)

        # Create pull request
        try:
            # If we forked, create PR from fork to original
            original_repo = g.get_repo(repo_name) if not user_can_push else repo
            head_ref = f"{repo.owner.login}:{new_branch_name}" if not user_can_push else new_branch_name
            
            pull = original_repo.create_pull(
                title=pr_title,
                body=pr_body,
                head=head_ref,
                base=base_branch
            )
            print(f"✅ Successfully created pull request: {pull.html_url}")
            return f"✅ Successfully created pull request: {pull.html_url}"
        except Exception as e:
            print(f"❌ Error creating pull request: {e}")
            return generate_manual_pr_instructions(
                repo_url, file_path, final_content, commit_message, pr_title, pr_body, base_branch,
                f"Branch created but PR failed: {e}",
                branch_created=True,
                branch_name=new_branch_name,
                forked_repo_url=repo.html_url if not user_can_push else None
            )

    except McpError:
        raise
    except Exception as e:
        print(f"💥 Unexpected error: {e}")
        return generate_manual_pr_instructions(repo_url, file_path, new_file_content, commit_message, pr_title, pr_body, base_branch, f"Unexpected error: {e}")

def smart_merge_content(old_content: str, new_content: str, file_path: str) -> str:
    """
    Intelligently merge old and new content based on file type and patterns.
    """
    # Get file extension for type-specific handling
    file_ext = file_path.split('.')[-1].lower() if '.' in file_path else ''
    
    # Handle common file types differently
    if file_ext in ['md', 'markdown', 'txt']:
        # For documentation files, append with separator
        return old_content + "\n\n---\n\n" + new_content
    elif file_ext in ['py', 'js', 'java', 'c', 'cpp', 'go', 'rs']:
        # For code files, look for specific patterns
        if "def " in new_content or "function " in new_content or "class " in new_content:
            # If adding new functions/classes, append at end
            return old_content + "\n\n" + new_content
        else:
            # Otherwise prepend
            return new_content + "\n\n" + old_content
    elif file_ext in ['yaml', 'yml', 'json', 'toml']:
        # For config files, better to replace completely
        return new_content
    elif file_ext in ['html', 'xml']:
        # For markup, look for closing tags
        if "</body>" in old_content and "</body>" in new_content:
            return old_content.replace("</body>", new_content + "\n</body>")
        elif "</html>" in old_content and "</html>" in new_content:
            return old_content.replace("</html>", new_content + "\n</html>")
        else:
            return old_content + "\n" + new_content
    else:
        # Default append behavior
        return old_content + "\n\n" + new_content


def generate_diff(old_content: str, new_content: str) -> str:
    """
    Generate a unified diff between old and new content.
    """
    from difflib import unified_diff
    
    diff = unified_diff(
        old_content.splitlines(keepends=True),
        new_content.splitlines(keepends=True),
        fromfile='original',
        tofile='modified',
        lineterm=''
    )
    return ''.join(diff)


# Add import for time if not already imported
import time
# --- Run MCP Server ---

async def main():
    print("🚀 Starting MCP server on http://0.0.0.0:8086")
    await mcp.run_async("streamable-http", host="0.0.0.0", port=8086)

if __name__ == "__main__":
    asyncio.run(main())
