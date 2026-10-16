from app.schemas.common import ORMModel


class PermissionOut(ORMModel):
    id: int
    name: str
    description: str | None = None
