"""Admin console user and session adapters."""

from db.crud import AdminSessionCRUD, AdminUserCRUD, OwnerSlotTaken
from src.adapters.exceptions import ConflictError, NotFoundError


class AdminUserAdapter(AdminUserCRUD):

    @classmethod
    def get_existing(cls, db, user_id):
        user = cls.get_by_id(db, user_id)
        if not user:
            raise NotFoundError(code="auth.user_not_found", fallback="User not found")
        return user

    @classmethod
    def create(cls, db, **kwargs):
        try:
            return super().create(db, **kwargs)
        except OwnerSlotTaken:
            raise ConflictError(code="auth.setup_already_done", fallback="Setup already completed")
        except ValueError:
            raise ConflictError(code="auth.email_exists", fallback="Email already registered")


class AdminSessionAdapter(AdminSessionCRUD):
    """Server-side console session records (see db.models.AdminSession)."""
