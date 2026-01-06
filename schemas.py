# schemas.py
from datetime import datetime
from typing import Optional
from dataclasses import dataclass
from models import Event

@dataclass
class EventDTO:
    id: int
    owner_id: int
    event_type: str
    name1: str
    name2: Optional[str]
    # phone1: str
    # phone2: Optional[str]
    base_date: str
    timezone: str
    send_time: str
    # message: Optional[str]
    # send_whatsapp: bool
    create_calendar: bool
    milestone_offset_days: Optional[int]
    title: Optional[str]
    created_at: datetime
    updated_at: datetime

def event_to_dto(e: Event) -> EventDTO:
    base_date_str = e.base_date.strftime("%Y-%m-%d")
    return EventDTO(
        id=e.id,
        owner_id=e.owner_id,
        event_type=e.event_type,
        name1=e.name1,
        name2=e.name2,
        # phone1=e.phone1 or "",
        # phone2=e.phone2,
        base_date=base_date_str,
        timezone=e.timezone,
        send_time=e.send_time,
        # message=e.message,
        # send_whatsapp=e.send_whatsapp,
        create_calendar=e.create_calendar,
        milestone_offset_days=e.milestone_offset_days,
        title=e.title,
        created_at=e.created_at,
        updated_at=e.updated_at,
    )
