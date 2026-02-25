"""
Service for managing interactions with Jira, providing functions to create issues, list projects and issue types, and manage comments on issues. This module includes logic to handle authentication with Jira using either API tokens or bearer tokens, to construct appropriate API requests to the Jira REST API, and to process the responses received from Jira. The service ensures that the base URL for Jira is properly configured and validated, and it provides error handling for various scenarios that may arise when interacting with the Jira API.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import base64
import logging
import os
from typing import Any, Dict, List, Literal, Optional

import httpx

from config import config
from services.common.http_client import create_async_client
from services.common.url_utils import is_safe_http_url

logger = logging.getLogger(__name__)

Credentials = Optional[Dict[str, Any]]


class JiraError(Exception):
    pass


class JiraService:
    def __init__(self, timeout: Optional[float] = None) -> None:
        self.base_url = (os.getenv("JIRA_BASE_URL") or "").strip().rstrip("/")
        self.email = (os.getenv("JIRA_EMAIL") or "").strip() or None
        self.api_token = (os.getenv("JIRA_API_TOKEN") or "").strip() or None
        self.bearer = (os.getenv("JIRA_BEARER_TOKEN") or "").strip() or None
        self.timeout = float(timeout or config.DEFAULT_TIMEOUT)
        self._client = create_async_client(self.timeout)

    def _resolve_base_url(self, credentials: Credentials = None) -> str:
        scoped = credentials or {}
        url = scoped.get("base_url") or scoped.get("baseUrl") or self.base_url or ""
        return str(url).strip().rstrip("/")

    def _auth_headers(self, credentials: Credentials = None) -> Dict[str, str]:
        scoped = credentials or {}
        bearer = (
            scoped.get("bearer")
            or scoped.get("bearer_token")
            or scoped.get("bearerToken")
            or self.bearer
            or ""
        ).strip()
        if bearer:
            return {"Authorization": f"Bearer {bearer}"}

        email = (scoped.get("email") or self.email or "").strip()
        api_token = (scoped.get("api_token") or scoped.get("apiToken") or self.api_token or "").strip()
        if email and api_token:
            token = base64.b64encode(f"{email}:{api_token}".encode()).decode()
            return {"Authorization": f"Basic {token}"}

        raise JiraError("No Jira credentials configured")

    def _headers(self, credentials: Credentials = None) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            **self._auth_headers(credentials),
        }

    def _build_url(self, path: str, credentials: Credentials = None) -> str:
        base_url = self._resolve_base_url(credentials)
        if not is_safe_http_url(base_url):
            raise JiraError("JIRA_BASE_URL not configured or invalid")
        return f"{base_url}{path}"

    async def _request(
        self,
        method: Literal["GET", "POST"],
        path: str,
        credentials: Credentials = None,
        params: Optional[Dict[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = self._build_url(path, credentials)
        headers = self._headers(credentials)
        try:
            if method == "GET":
                response = await self._client.get(url, headers=headers, params=params)
            else:
                response = await self._client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            return response.json() if response.content else {}
        except httpx.HTTPStatusError as exc:
            logger.warning("Jira %s failed: %s %s", method, exc.response.status_code, exc.response.text[:240])
            raise JiraError(f"Jira API error: {exc.response.status_code}") from exc
        except JiraError:
            raise
        except Exception as exc:
            logger.exception("Unexpected Jira %s error", method)
            raise JiraError("Failed to contact Jira API") from exc

    async def _get(self, path: str, credentials: Credentials = None, params: Optional[Dict[str, Any]] = None) -> Any:
        return await self._request("GET", path, credentials, params=params)

    async def _post(self, path: str, payload: Dict[str, Any], credentials: Credentials = None) -> Any:
        return await self._request("POST", path, credentials, payload=payload)

    async def create_issue(
        self,
        project_key: str,
        summary: str,
        description: Optional[str] = None,
        issue_type: str = "Task",
        credentials: Credentials = None,
    ) -> Dict[str, Any]:
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": description or "",
                "issuetype": {"name": issue_type},
            }
        }
        data = await self._post("/rest/api/2/issue", payload, credentials)
        key = data.get("key")
        base_url = self._resolve_base_url(credentials)
        return {
            "key": key,
            "url": f"{base_url}/browse/{key}" if key else None,
            "raw": data,
        }

    async def list_projects(self, credentials: Credentials = None) -> List[Dict[str, str]]:
        data = await self._get("/rest/api/2/project", credentials)
        return [
            {"key": key, "name": str(p.get("name") or key).strip()}
            for p in (data or [])
            if (key := str(p.get("key") or "").strip())
        ]

    async def list_issue_types(self, project_key: str, credentials: Credentials = None) -> List[str]:
        project = await self._get(f"/rest/api/2/project/{project_key}", credentials)
        issue_types = project.get("issueTypes") if isinstance(project, dict) else []
        return [
            name
            for it in (issue_types or [])
            if (name := str(it.get("name") or "").strip())
        ]

    async def add_comment(self, issue_key: str, text: str, credentials: Credentials = None) -> Dict[str, Any]:
        return await self._post(f"/rest/api/2/issue/{issue_key}/comment", {"body": text}, credentials)

    async def list_comments(self, issue_key: str, credentials: Credentials = None) -> List[Dict[str, Any]]:
        data = await self._get(f"/rest/api/2/issue/{issue_key}/comment", credentials)
        comments = data.get("comments") if isinstance(data, dict) else []
        return [
            {
                "id": str(item.get("id") or ""),
                "author": _extract_display_name(item.get("author")),
                "body": str(item.get("body") or ""),
                "created": item.get("created"),
            }
            for item in (comments or [])
            if isinstance(item, dict)
        ]


def _extract_display_name(author: Any) -> str:
    if not isinstance(author, dict):
        return "jira"
    return str(author.get("displayName") or author.get("name") or "jira")


jira_service = JiraService()
