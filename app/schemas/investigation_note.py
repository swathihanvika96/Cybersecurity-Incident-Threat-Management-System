from app.schemas.common import DT, ORMModel


class NoteOut(ORMModel):
    id: int
    incident_id: int | None = None
    investigation_id: int | None = None
    author_id: int | None = None
    note_type: str
    content: str
    created_at: DT
