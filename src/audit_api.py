import logging
from typing import Dict, Optional, List, Any, Annotated
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from pydantic import BaseModel, Field
from datetime import datetime
from .auth import get_current_user, requires_permission
from .audit import AuditLogService
from .dependencies import get_audit_service

logger = logging.getLogger(__name__)


# Define request and response models
class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    actor_id: Optional[int] = None
    actor_type: str
    action_type: str
    resource_type: str
    resource_id: Optional[str] = None
    status: str
    details: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None
    ip_address: Optional[str] = None


# Create the router
router = APIRouter(
    tags=["audit"],
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)


# API Endpoints
@router.get("/logs", response_model=List[AuditLogResponse])
async def get_audit_logs(
    current_user: Annotated[Dict[str, Any], Depends(requires_permission("log:read"))],
    audit_service: Annotated[AuditLogService, Depends(get_audit_service)],
    request: Request = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    actor_id: Optional[int] = None,
    actor_type: Optional[str] = None,
    action_type: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
):
    """
    Get audit logs with optional filtering.

    Args:
        current_user: The authenticated user with log:read permission
        audit_service: The audit log service
        request: FastAPI request object
        start_time: Filter logs after this time
        end_time: Filter logs before this time
        actor_id: Filter logs by actor ID
        actor_type: Filter logs by actor type
        action_type: Filter logs by action type
        resource_type: Filter logs by resource type
        resource_id: Filter logs by resource ID
        status: Filter logs by status
        limit: Maximum number of logs to return (max 1000)
        offset: Offset for pagination

    Returns:
        List of audit log entries
    """
    try:
        logs = await audit_service.get_logs(
            start_time=start_time,
            end_time=end_time,
            actor_id=actor_id,
            actor_type=actor_type,
            action_type=action_type,
            resource_type=resource_type,
            resource_id=resource_id,
            status=status,
            limit=limit,
            offset=offset,
        )

        # Log the audit log retrieval (meta-logging)
        filter_details = {}
        if start_time:
            filter_details["start_time"] = start_time.isoformat()
        if end_time:
            filter_details["end_time"] = end_time.isoformat()
        if actor_id:
            filter_details["actor_id"] = actor_id
        if actor_type:
            filter_details["actor_type"] = actor_type
        if action_type:
            filter_details["action_type"] = action_type
        if resource_type:
            filter_details["resource_type"] = resource_type
        if resource_id:
            filter_details["resource_id"] = resource_id
        if status:
            filter_details["status"] = status

        await audit_service.log_event(
            actor_id=current_user["id"],
            actor_type="human",
            action_type="read",
            resource_type="audit_logs",
            resource_id=None,
            status="success",
            details={
                "filters": filter_details,
                "limit": limit,
                "offset": offset,
                "result_count": len(logs),
            },
            request=request,
        )

        return logs

    except Exception as e:
        logger.error(f"Failed to retrieve audit logs: {e}")

        # Log the failure
        await audit_service.log_event(
            actor_id=current_user["id"],
            actor_type="human",
            action_type="read",
            resource_type="audit_logs",
            resource_id=None,
            status="failure",
            details={"error": str(e)},
            request=request,
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve audit logs: {e}",
        )
