"""Scheduler: purge expired OAuth data, enforce event/audit retention, and run MCP service health checks."""

import asyncio
import logging
from datetime import timedelta
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session

import db.database as database
from db.models import local_now
from src.audit import record_scheduled_purge
from src.adapters import (
    AdminSessionAdapter, AuditLogAdapter, OAuthAuthRequestAdapter, OAuthClientAdapter, OAuthCodeAdapter,
    OAuthTokenAdapter, ServiceAdapter, TokenUsageAdapter,
)
from src.config import Config

logger = logging.getLogger(__name__)

# How often the signing-key job runs: a published key takes over at most this late (the first token issued after
# its activates_at promotes it sooner), and an automatic rotation is published at most this late
KEY_JOB_MINUTES = 1

# Consecutive failed checks after which a service is "offline" rather than "error"
OFFLINE_AFTER_FAILURES = 3


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
        self.health_check_concurrency = 8
        self.health_check_timeout_seconds = 10.0
        self.health_write_interval_minutes = 5
        self._ws_manager = None

    @classmethod
    def get_instance(cls) -> "CleanupScheduler":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def configure(self, oauth_cleanup_hours: int = 6, usage_retention_days: int = 30,
                  audit_retention_days: int = 90, health_check_seconds: int = 30,
                  health_check_enabled: bool = True, health_check_concurrency: int = 8,
                  health_check_timeout_seconds: float = 10.0, health_write_interval_minutes: int = 5):
        """Apply the `scheduler` config section (call before start(); the intervals are fixed when jobs are added)."""
        self.oauth_cleanup_hours = oauth_cleanup_hours
        self.usage_retention_days = usage_retention_days
        self.audit_retention_days = audit_retention_days
        self.health_check_seconds = health_check_seconds
        self.health_check_enabled = health_check_enabled
        self.health_check_concurrency = health_check_concurrency
        self.health_check_timeout_seconds = health_check_timeout_seconds
        self.health_write_interval_minutes = health_write_interval_minutes

    def set_ws_manager(self, ws_manager) -> None:
        self._ws_manager = ws_manager

    def start(self):
        if self._is_running:
            logger.warning("Scheduler is already running")
            return
        self.scheduler.add_job(self._cleanup_oauth, IntervalTrigger(hours=self.oauth_cleanup_hours),
                               id="cleanup_oauth", name="Clean up expired OAuth codes/requests/tokens and console sessions",
                               replace_existing=True)
        self.scheduler.add_job(self._cleanup_old_usage, CronTrigger(hour=3, minute=0),
                               id="cleanup_old_usage", name="Clean up old token events", replace_existing=True)
        self.scheduler.add_job(self._cleanup_old_audit_logs, CronTrigger(hour=4, minute=0),
                               id="cleanup_old_audit_logs", name="Clean up old audit logs", replace_existing=True)
        self.scheduler.add_job(self._signing_keys_task, IntervalTrigger(minutes=KEY_JOB_MINUTES),
                               id="signing_keys", name="Rotate, activate and delete signing keys (#30)",
                               replace_existing=True)
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
        """Run every clean-up job now. Returns {"results": {job: deleted | None}, "errors": {job: error type}};
        a failed job is reported, not counted as 0 (#23)."""
        results, errors = {}, {}
        for name, purge in self._purge_jobs():
            try:
                results[name] = self._run_purge(purge)
            except Exception as e:
                logger.error(f"Cleanup job {name} failed: {e}")
                results[name] = None
                errors[name] = type(e).__name__
        return {"results": results, "errors": errors}

    def _purge_jobs(self):
        return (("expired_oauth", self._purge_oauth), ("old_usage", self._purge_old_usage),
                ("old_audit_logs", self._purge_old_audit_logs))

    @staticmethod
    def _run_purge(purge) -> int:
        """Run one purge in its own session; raises on failure (after rolling back)."""
        db: Session = database.make_session()
        try:
            return purge(db)
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _scheduled(self, name: str, purge) -> int:
        """Scheduled runs have nobody to report to: log the failure and carry on."""
        try:
            return self._run_purge(purge)
        except Exception as e:
            logger.error(f"Cleanup job {name} failed: {e}")
            return 0

    async def _cleanup_oauth(self) -> int:
        return self._scheduled("expired_oauth", self._purge_oauth)

    async def _cleanup_old_usage(self) -> int:
        return self._scheduled("old_usage", self._purge_old_usage)

    async def _cleanup_old_audit_logs(self) -> int:
        return self._scheduled("old_audit_logs", self._purge_old_audit_logs)

    async def _signing_keys_task(self) -> Optional[dict]:
        db: Session = database.make_session()
        try:
            return self.run_signing_key_job(db)
        except Exception as e:
            db.rollback()
            logger.error(f"Signing key job failed: {e}")
            return None
        finally:
            db.close()

    @staticmethod
    def run_signing_key_job(db: Session) -> dict:
        """Promote a due published key, publish the next one when the rotation period is up, delete retired keys
        nothing needs any more (src/oauth/signing_keys.py); each step is audited as the scheduler (an activation
        by activate_due_key itself, wherever it happens)."""
        from src.audit import AuditAction
        from src.audit.audit_service import record_key_event
        from src.oauth import signing_keys

        done = signing_keys.run_key_maintenance(db)
        if done["published"]:
            record_key_event(db, AuditAction.OAUTH_KEY_ROTATE, done["published"], {"automatic": True})
        for kid in done["deleted"]:
            record_key_event(db, AuditAction.OAUTH_KEY_DELETE, kid)
        return done

    def _purge_oauth(self, db: Session) -> int:
        purged = OAuthAuthRequestAdapter.delete_expired(db)
        purged += OAuthCodeAdapter.delete_expired(db)
        purged += OAuthTokenAdapter.delete_expired(db)
        purged += AdminSessionAdapter.delete_expired(db)
        unused_days = Config.get_oauth_config().dcr_unused_client_days
        if unused_days and unused_days > 0:
            purged += OAuthClientAdapter.delete_unused_dcr(db, older_than=timedelta(days=unused_days))
        if purged:
            logger.info(f"Cleaned up {purged} expired OAuth records")
        record_scheduled_purge(db, "expired_oauth", purged)
        return purged

    def _purge_old_usage(self, db: Session) -> int:
        deleted = TokenUsageAdapter.delete_older_than(db, local_now() - timedelta(days=self.usage_retention_days))
        if deleted:
            logger.info(f"Cleaned up {deleted} old token events")
        record_scheduled_purge(db, "old_usage", deleted, {"retention_days": self.usage_retention_days})
        return deleted

    def _purge_old_audit_logs(self, db: Session) -> int:
        deleted = AuditLogAdapter.delete_older_than(db, local_now() - timedelta(days=self.audit_retention_days))
        if deleted:
            logger.info(f"Cleaned up {deleted} old audit logs")
        record_scheduled_purge(db, "old_audit_logs", deleted, {"retention_days": self.audit_retention_days})
        return deleted

    async def _health_check_task(self) -> dict:
        """One health round. The checks run concurrently (at most ``health_check_concurrency`` at a time, each cut
        off after ``health_check_timeout_seconds``), so one slow or hanging server no longer delays every other
        one; the results are then stored one by one in this session. A result is written only when it matters:
        the status changes, a failure streak is still counting towards "offline", or the stored check is older
        than ``health_write_interval_minutes`` (so "last checked" stays roughly current without a write per
        service per round)."""
        from src.discovery.health_monitor import resolve_service_auth_token
        from src.discovery.scanner import MCPVerifyResult, get_scanner

        db: Session = database.make_session()
        results = {"checked": 0, "online": 0, "offline": 0, "error": 0, "written": 0}
        try:
            services = ServiceAdapter.get_services_for_health_check(db)
            scanner = get_scanner()
            semaphore = asyncio.Semaphore(max(1, int(self.health_check_concurrency)))
            timeout = float(self.health_check_timeout_seconds)

            async def verify(target: dict) -> MCPVerifyResult:
                async with semaphore:
                    try:
                        return await asyncio.wait_for(scanner.verify_mcp_service(
                            host=target["host"], port=target["port"], path=target["path"],
                            protocol=target["protocol"], auth_token=target["auth_token"],
                        ), timeout=timeout)
                    except asyncio.TimeoutError:
                        return MCPVerifyResult(success=False, error=f"health check timed out after {timeout:g} s",
                                               response_time_ms=timeout * 1000)

            # Plain values captured up front: after a failed flush the ORM objects cannot be read until rollback
            targets = []
            for service in services:
                try:
                    auth_token = resolve_service_auth_token(db, service)
                except Exception as e:
                    db.rollback()
                    logger.error(f"Health check error for {service.name}: {e}")
                    results["error"] += 1
                    continue
                targets.append({
                    "service": service, "id": str(service.id), "name": service.name, "host": service.host,
                    "port": service.port, "path": service.mcp_path, "protocol": service.protocol,
                    "auth_token": auth_token, "previous": service.health_status,
                    "fail_count": service.health_fail_count or 0, "last_checked": service.health_last_checked,
                })
            outcomes = await asyncio.gather(*(verify(t) for t in targets), return_exceptions=True)

            for target, verify_result in zip(targets, outcomes):
                service, service_name, previous_status = target["service"], target["name"], target["previous"]
                try:
                    if isinstance(verify_result, BaseException):
                        raise verify_result
                    results["checked"] += 1
                    if verify_result.success:
                        new_status, error_msg, reset_fail, increment_fail = "online", None, True, False
                        # Fill the description from serverInfo only while it is empty or generated;
                        # never overwrite what the operator wrote (nor the name they chose)
                        if ServiceAdapter.adopt_server_description(
                                db, service, verify_result.server_name, verify_result.server_version,
                                verify_result.server_description):
                            db.refresh(service)
                    else:
                        error_msg, reset_fail, increment_fail = verify_result.error, False, True
                        fail_count = target["fail_count"] + 1
                        new_status = "offline" if fail_count >= OFFLINE_AFTER_FAILURES else "error"
                    if self._health_write_due(target, new_status):
                        ServiceAdapter.update_health(
                            db=db, service_id=target["id"], status=new_status,
                            response_time_ms=verify_result.response_time_ms, error_message=error_msg,
                            reset_fail_count=reset_fail, increment_fail_count=increment_fail,
                        )
                        results["written"] += 1
                    results[new_status] += 1  # counted once stored, so a failed write is not also "online"
                    if new_status != previous_status and self._ws_manager:
                        try:
                            await self._ws_manager.broadcast_health_update(
                                service_id=target["id"], service_name=service_name,
                                health={"status": new_status, "previous_status": previous_status,
                                        "response_time_ms": verify_result.response_time_ms,
                                        "error_message": error_msg},
                            )
                        except Exception as e:
                            logger.warning(f"Failed to broadcast health update: {e}")
                except Exception as e:
                    # Roll back so one failed write (e.g. a DataError on PostgreSQL) does not poison the session
                    # for every service after it in this round.
                    db.rollback()
                    logger.error(f"Health check error for {service_name}: {e}")
                    results["error"] += 1
            return results
        except Exception as e:
            logger.error(f"Health check task error: {e}")
            return results
        finally:
            db.close()

    def _health_write_due(self, target: dict, new_status: str) -> bool:
        if new_status != target["previous"]:
            return True
        if new_status != "online" and target["fail_count"] < OFFLINE_AFTER_FAILURES:
            return True  # the failure streak decides when "error" becomes "offline": keep counting
        last = target["last_checked"]
        return last is None or local_now() - last >= timedelta(minutes=self.health_write_interval_minutes)

    async def run_health_check_now(self) -> dict:
        return await self._health_check_task()


def get_scheduler() -> CleanupScheduler:
    return CleanupScheduler.get_instance()
