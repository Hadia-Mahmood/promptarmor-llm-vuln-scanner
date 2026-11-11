"""
GitHub Uploader for PromptArmor.
Uploads the local project directly to your GitHub account using GitHub REST API.
Zero external pip dependencies required.
"""

import os
import sys
import json
import base64
import urllib.request
import urllib.error

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

# Files to upload
FILES_TO_UPLOAD = [
    "app.py",
    "scanner.py",
    "targets.py",
    "probes.py",
    "requirements.txt",
    "README.md",
    ".gitignore",
    os.path.join("static", "index.html")
]

def make_request(url, token, data=None, method="GET"):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "PromptArmor-Uploader",
        "Content-Type": "application/json"
    }
    payload = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=payload, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8")), resp.getcode()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        try:
            err_json = json.loads(body)
            err_msg = err_json.get("message", body)
        except Exception:
            err_msg = body
        return {"error": err_msg}, e.code
    except Exception as e:
        return {"error": str(e)}, 500


def upload_project(token: str, repo_name: str = "promptarmor-llm-vuln-scanner", is_private: bool = False):
    token = token.strip()
    if not token:
        print("[!] Error: GitHub Personal Access Token is required.")
        return False

    print("\n[1/3] Verifying GitHub user credentials...")
    user_info, code = make_request("https://api.github.com/user", token)
    if code != 200:
        print(f"[!] Authentication failed (HTTP {code}): {user_info.get('error')}")
        print("    Ensure your token is valid and has the 'repo' scope enabled.")
        return False

    username = user_info.get("login")
    print(f"[*] Authenticated as GitHub user: @{username}")

    print(f"\n[2/3] Checking repository '{repo_name}'...")
    repo_url = f"https://api.github.com/repos/{username}/{repo_name}"
    repo_data, code = make_request(repo_url, token)

    if code == 404:
        print(f"[*] Repository does not exist. Creating new repository '{repo_name}'...")
        create_payload = {
            "name": repo_name,
            "description": "PromptArmor: Automated LLM Vulnerability Scanner & AI Governance Auditor (OWASP Top 10 for LLMs)",
            "private": is_private,
            "has_issues": True,
            "has_projects": True,
            "has_wiki": True
        }
        repo_data, code = make_request("https://api.github.com/user/repos", token, data=create_payload, method="POST")
        if code not in [200, 201]:
            print(f"[!] Failed to create repository (HTTP {code}): {repo_data.get('error')}")
            return False
        print(f"[*] Repository created: {repo_data.get('html_url')}")
    elif code == 200:
        print(f"[*] Found existing repository: {repo_data.get('html_url')}")
    else:
        print(f"[!] Unexpected error checking repository (HTTP {code}): {repo_data.get('error')}")
        return False

    html_url = repo_data.get("html_url")

    print("\n[3/3] Uploading project files...")
    success_count = 0

    for rel_path in FILES_TO_UPLOAD:
        full_path = os.path.join(PROJECT_DIR, rel_path)
        if not os.path.exists(full_path):
            print(f"[-] Skipping missing file: {rel_path}")
            continue

        with open(full_path, "rb") as f:
            content_bytes = f.read()
        content_b64 = base64.b64encode(content_bytes).decode("utf-8")

        # Normalize path for GitHub API (forward slashes)
        api_file_path = rel_path.replace("\\", "/")
        file_url = f"https://api.github.com/repos/{username}/{repo_name}/contents/{api_file_path}"

        # Check if file exists to get its SHA for update
        existing, get_code = make_request(file_url, token)
        sha = existing.get("sha") if get_code == 200 else None

        commit_payload = {
            "message": f"Upload {api_file_path} via PromptArmor Uploader",
            "content": content_b64
        }
        if sha:
            commit_payload["sha"] = sha

        put_res, put_code = make_request(file_url, token, data=commit_payload, method="PUT")
        if put_code in [200, 201]:
            print(f"[+] Successfully uploaded: {api_file_path}")
            success_count += 1
        else:
            print(f"[!] Failed to upload {api_file_path} (HTTP {put_code}): {put_res.get('error')}")

    print("\n" + "="*60)
    print(f"🎉 Upload Complete! {success_count}/{len(FILES_TO_UPLOAD)} files pushed successfully.")
    print(f"🔗 View your repository online at: {html_url}")
    print("="*60 + "\n")
    return True


if __name__ == "__main__":
    print("\n--- PromptArmor GitHub Uploader ---")
    if len(sys.argv) > 1:
        token_input = sys.argv[1]
        repo_name_input = sys.argv[2] if len(sys.argv) > 2 else "promptarmor-llm-vuln-scanner"
    else:
        token_input = input("Enter your GitHub Personal Access Token (PAT): ").strip()
        repo_name_input = input("Enter repository name [default: promptarmor-llm-vuln-scanner]: ").strip()
        if not repo_name_input:
            repo_name_input = "promptarmor-llm-vuln-scanner"

    upload_project(token_input, repo_name_input)
