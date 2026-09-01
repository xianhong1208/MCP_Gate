"""Scheduler: purge expired OAuth data, enforce event/audit retention, and run MCP service health checks."""

import logging
from datetime import timedelta
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session

import db.database as database
from db.models import local_now
from src.adapters import (
    AuditLogAdapter, OAuthAuthRequestAdapter, OAuthCodeAdapter, OAuthTokenAdapter, ServiceAdapter,
    TokenUsageAdapter,
)

logger = logging.getLogger(__name__)


class CleanupScheduler:
    """Cleanup scheduler and health monitor (singleton)."""

    _instance: Optional["CleanupScheduler"] = None

    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self._is_running = False
        self.oauth_cleanup_hours = 6
        self.usage_retention_days = 30
        self.audit_retention_days = 90
        self.health_check_seconds = 30
        self.health_check_enabled = True
        self._ws_manager = None

    @classmethod
    def get_instance(cls) -> "CleanupScheduler":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def configure(self, oauth_cleanup_hours: int = 6, usage_retention_days: int = 30,
                  audit_retention_days: int = 90, health_check_seconds: int = 30,
                  health_check_enabled: bool = True):
        self.oauth_cleanup_hours = oauth_cleanup_hours
        self.usage_retention_days = usage_retention_days
        self.audit_retention_days = audit_retention_days
        self.health_check_seconds = health_check_seconds
        self.health_check_enabled = health_check_enabled

    def set_ws_manager(self, ws_manager) -> None:
        self._ws_manager = ws_manager

    def start(self):
        if self._is_running:
            logger.warning("Scheduler is already running")
            return
        self.scheduler.add_job(self._cleanup_oauth, IntervalTrigger(hours=self.oauth_cleanup_hours),
                               id="cleanup_oauth", name="Clean up expired OAuth codes/requests/tokens",
                               replace_existing=True)
        self.scheduler.add_job(self._cleanup_old_usage, CronTrigger(hour=3, minute=0),
                               id="cleanup_old_usage", name="Clean up old token events", replace_existing=True)
        self.scheduler.add_job(self._cleanup_old_audit_logs, CronTrigger(hour=4, minute=0),
                               id="cleanup_old_audit_logs", name="Clean up old audit logs", replace_existing=True)
        if self.health_check_enabled:
            self.scheduler.add_job(self._health_check_task, IntervalTrigger(seconds=self.health_check_seconds),
                                   id="health_check", name="Check MCP service health", replace_existing=True)
        self.scheduler.start()
        self._is_running = True
        logger.info("Scheduler started")

    def stop(self):
        if self._is_running:
            self.scheduler.shutdown(wait=False)
            self._is_running = False
            logger.info("Scheduler stopped")

    def is_running(self) -> bool:
        return self._is_running

    async def run_all_cleanup_now(self) -> dict:
        return {
            "expired_oauth": await self._cleanup_oauth(),
            "old_usage": await self._cleanup_old_usage(),
            "old_audit_logs": await self._cleanup_old_audit_logs(),
        }

    async def _cleanup_oauth(self) -> int:
        db: Session = database.make_session()
        try:
            n = OAuthAuthRequestAdapter.delete_expired(db)
            n += OAuthCodeAdapter.delete_expired(db)
            n += OAuthTokenAdapter.delete_expired(db)
            if n:
                logger.info(f"Cleaned up {n} expired OAuth records")
            return n
        except Exception as e:
            db.rollback()
            logger.error(f"Error cleaning up OAuth records: {e}")
            return 0
        finally:
            db.close()

    async def _cleanup_old_usage(self) -> int:
        db: Session = database.make_session()
        try:
            deleted = TokenUsageAdapter.delete_older_than(db, local_now() - timedelta(days=self.usage_retention_days))
            if deleted:
                logger.info(f"Cleaned up {deleted} old token events")
            return deleted
        except Exception as e:
            db.rollback()
            logger.error(f"Error cleaning up token events: {e}")
            return 0
        finally:
            db.close()

    async def _cleanup_old_audit_logs(self) -> int:
        db: Session = database.make_session()
        try:
            deleted = AuditLogAdapter.delete_older_than(db, local_now() - timedelta(days=self.audit_retention_days))
            if deleted:
                logger.info(f"Cleaned up {deleted} old audit logs")
            return deleted
        except Exception as e:
            db.rollback()
            logger.error(f"Error cleaning up audit logs: {e}")
            return 0
        finally:
            db.close()

    async def _health_check_task(self) -> dict:
        from src.discovery.health_monitor import resolve_service_auth_token
        from src.discovery.scanner import get_scanner

        db: Session = database.make_session()
        results = {"checked": 0, "online": 0, "offline": 0, "error": 0}
        try:
            services = ServiceAdapter.get_services_for_health_check(db)
            scanner = get_scanner()
            for service in services:
                try:
                    auth_token = resolve_service_auth_token(db, service)
                    verify_result = await scanner.verify_mcp_service(
                        host=service.host, port=service.port, path=service.mcp_path,
                        protocol=service.protocol, auth_token=auth_token,
                    )
                    previous_status = service.health_status
                    results["checked"] += 1
                    if verify_result.success:
                        new_status, error_msg, reset_fail, increment_fail = "online", None, True, False
                        results["online"] += 1
                        if verify_result.server_name and verify_result.server_name != "(requires auth)":
                            new_desc = f"MCP service: {verify_result.server_name}"
                            if verify_result.server_version:
                                new_desc += f" v{verify_result.server_version}"
                            if verify_result.server_description:
                                new_desc += f"\n\n{verify_result.server_description}"
                            # Sync only the description; never overwrite the name the user chose
                            ServiceAdapter.update(db=db, service_id=str(service.id), description=new_desc)
                            db.refresh(service)
                    else:
                        error_msg, reset_fail, increment_fail = verify_result.error, False, True
                        fail_count = (service.health_fail_count or 0) + 1
                        if fail_count >= 3:
                            new_status = "offline"
                            results["offline"] += 1
                        else:
                            new_status = "error"
                            results["error"] += 1
                    ServiceAdapter.update_health(
                        db=db, service_id=str(service.id), status=new_status,
                        response_time_ms=verify_result.response_time_ms, error_message=error_msg,
                        reset_fail_count=reset_fail, increment_fail_count=increment_fail,
                    )
                    if new_status != previous_status and self._ws_manager:
                        try:
                            await self._ws_manager.broadcast_health_update(
                                service_id=str(service.id), service_name=service.name,
                                health={"status": new_status, "previous_status": previous_status,
                                        "response_time_ms": verify_result.response_time_ms,
                                        "error_message": error_msg},
                            )
                        except Exception as e:
                            logger.warning(f"Failed to broadcast health update: {e}")
                except Exception as e:
                    logger.error(f"Health check error for {service.name}: {e}")
                    results["error"] += 1
            return results
        except Exception as e:
            logger.error(f"Health check task error: {e}")
            return results
        finally:
            db.close()

    async def run_health_check_now(self) -> dict:
        return await self._health_check_task()


def get_scheduler() -> CleanupScheduler:
    return CleanupScheduler.get_instance()
