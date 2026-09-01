"""Admin console user adapter."""

from db.crud import AdminUserCRUD
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
        except ValueError:
            raise ConflictError(code="auth.email_exists", fallback="Email already registered")
